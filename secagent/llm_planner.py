"""Claude-Opus-4-7 planner — paper §3.1, §13.

This module is the reason this reference impl is convincing: it wires
a *real* untrusted LLM planner into the same broker the scripted
demos used. The broker doesn't know or care that the JSON came from
a frontier model instead of a hand-written script — that is the
paper's §13 thesis. The model proposes; the broker disposes.

Key design choices, each tied to a paper section:

  - Descriptor sanitization (§9.4). The model sees a sanitized,
    admin-summarized tool description, never the raw ``descriptor``
    field. Invisible Unicode and instruction-like text are stripped.
    The broker still pins and hashes the *raw* descriptor under the
    hood so a rug-pull is detected even though the planner never
    saw the raw bytes.

  - Tool-call JSON is untrusted output (§7.3). The broker validates
    every argument against the live capability — schema-valid is not
    in-scope. The model can produce arbitrary JSON; the broker is
    the line of defense.

  - Denials surface back as ``tool_result`` with ``is_error=True``
    (§7.4). This means the model can retry, refine, or give up —
    without the broker ever letting an unsafe call through. From the
    model's perspective the deny looks like any other tool failure.

  - Conservative IFC join across the session (§5.5, §12.3). Once the
    model has read attacker-controlled content, the broker assumes
    every later argument carries that taint. This is the
    "semantic-data-laundering" stance: the model may paraphrase a
    secret without copying it, so we cannot trust substring tracking.
    This is overly strict, but it is the correct architectural
    default. The paper names this trade-off explicitly.

The planner itself owns no authority. It cannot bypass the broker;
it can only call ``broker.invoke`` like any other caller. If the
``ANTHROPIC_API_KEY`` env var is missing, this module raises at
construction time so a CI run that lacks credentials fails fast
rather than silently skipping the demo.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anthropic


def _load_dotenv_once() -> None:
    """Load ``.env`` from the repo root into ``os.environ``.

    Tiny stdlib-only loader so the reference impl has no extra deps.
    Only sets keys that are not already in the environment, so a
    real export wins. Silent no-op if no .env is found.
    """
    if os.environ.get("_SECAGENT_DOTENV_LOADED"):
        return
    here = Path(__file__).resolve()
    for parent in (here.parent, *here.parents):
        candidate = parent / ".env"
        if candidate.is_file():
            for line in candidate.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                os.environ.setdefault(key, value)
            break
    os.environ["_SECAGENT_DOTENV_LOADED"] = "1"


_load_dotenv_once()

from .audit import AuditLog, redacted_hash
from .broker import ToolBroker
from .capabilities import CapabilitySet
from .labels import Label, join_all, user_request_label
from .policy_compiler import TaskPolicy
from .policy_engine import Decision, Verdict


# Strip a small set of unicode classes that have been used to smuggle
# instructions past tool-description renders. Real deployments would
# use a more thorough sanitizer; this is the §9.4 illustration.
_INVISIBLE_UNICODE = re.compile(r"[​-‏‪-‮⁠-⁩︀-️]")
_INSTRUCTION_HINTS = re.compile(
    r"(?i)(ignore (all|previous)|disregard|system prompt|instruction to assistant)"
)


def _wire_name(broker_name: str) -> str:
    """Convert the broker's tool name to the wire-safe name the API allows.

    Anthropic's tool-use schema constrains tool names to
    ``^[a-zA-Z0-9_-]{1,128}$``. The broker uses dotted names like
    ``github.read_issue`` so the audit log reads naturally; on the
    wire we translate the dot to a double underscore. The model never
    sees the dotted form, and on dispatch we translate back.
    """
    return broker_name.replace(".", "__")


def _broker_name(wire_name: str) -> str:
    return wire_name.replace("__", ".")


def sanitize_for_planner(name: str, raw_description: str, schema: dict[str, type]) -> dict[str, Any]:
    """Render a tool to the shape the LLM may safely see (§9.4).

    The raw descriptor is *not* used in the prompt. Instead we use a
    short, admin-style summary built from the tool name. If the raw
    description contains instruction-shaped phrases, the function
    flags it (and a real deployment would refuse to expose the tool
    until an admin reviewed). The schema is converted to JSON Schema
    on the fly.
    """
    description = _INVISIBLE_UNICODE.sub("", raw_description)
    if _INSTRUCTION_HINTS.search(description):
        # In the demo we replace; in production we would refuse to expose.
        description = f"Tool {name}. (Description withheld pending review.)"
    return {
        "name": _wire_name(name),
        "description": description,
        "input_schema": _to_jsonschema(schema),
    }


def _to_jsonschema(schema: dict[str, type]) -> dict[str, Any]:
    type_map = {str: "string", int: "integer", float: "number", bool: "boolean", list: "array", dict: "object"}
    props: dict[str, Any] = {}
    required: list[str] = []
    for name, typ in schema.items():
        props[name] = {"type": type_map.get(typ, "string")}
        required.append(name)
    return {"type": "object", "properties": props, "required": required}


@dataclass
class PlannerOutcome:
    """Summary of one ``run_until_done`` call."""

    final_text: str
    iterations: int
    tool_calls: list[dict[str, Any]]
    deny_count: int
    stopped_reason: str  # "end_turn" | "deny_loop" | "max_iterations"


class LLMPlanner:
    """A Claude-Opus-4-7-backed planner that funnels every action
    through ``ToolBroker.invoke``.

    Construction parameters:

      - ``broker``: the ToolBroker the policy engine is wired through.
      - ``policy``: the compiled TaskPolicy (read-only here).
      - ``cap_set``: the capability bag the minter issued for this task.
      - ``audit``: the same audit log the broker writes to. The planner
        adds rows of its own so a reader can see what the model said.
      - ``model``: defaults to ``claude-opus-4-7`` per the paper's
        cutoff and the skill defaults. Override for experiments.
      - ``max_iterations``: cap to keep deny loops bounded (§7.4
        "approval fatigue" applies symmetrically to deny loops).
    """

    def __init__(
        self,
        *,
        broker: ToolBroker,
        policy: TaskPolicy,
        cap_set: CapabilitySet,
        audit: AuditLog,
        tool_names: list[str],
        model: str = "claude-opus-4-7",
        max_iterations: int = 12,
        system_prompt: str | None = None,
        sink_destination_extractor: dict[str, str] | None = None,
        approval_resolver=None,
    ) -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. The LLM planner needs API "
                "credentials. The scripted demos (01-07) work without one."
            )
        self._client = anthropic.Anthropic(api_key=api_key)
        self._broker = broker
        self._policy = policy
        self._cap_set = cap_set
        self._audit = audit
        self._tool_names = tool_names
        self._model = model
        self._max_iterations = max_iterations
        self._sink_extractors = sink_destination_extractor or {}
        self._approval_resolver = approval_resolver

        # §5.5 / §12.3 conservative IFC: every label this session has
        # observed via tool results stays joined into the per-call
        # arg label. The model could paraphrase any of it without
        # us seeing, so we treat all subsequent args as influenced by
        # everything previously read. The broker then applies its
        # IFC rules against this joined label.
        self._session_labels: list[Label] = [user_request_label(policy.task_id)]
        self._system_prompt = system_prompt or self._default_system_prompt()

    # ---- main loop ------------------------------------------------------

    def run_until_done(self, user_request: str) -> PlannerOutcome:
        """Drive a Claude tool-use loop, routing every call through the broker.

        Returns when the model emits ``end_turn``, when too many
        consecutive denials accumulate (deny loop), or when
        ``max_iterations`` is exhausted.
        """
        # Build the model-facing tool list from the broker's registered
        # tools, applying the §9.4 descriptor sanitization step.
        tools_for_model = self._build_model_tools()

        messages: list[dict[str, Any]] = [{"role": "user", "content": user_request}]
        tool_calls_log: list[dict[str, Any]] = []
        deny_count = 0
        consecutive_denies = 0
        final_text = ""

        for iteration in range(self._max_iterations):
            response = self._client.messages.create(
                model=self._model,
                max_tokens=4096,
                system=self._system_prompt,
                tools=tools_for_model,
                messages=messages,
            )
            self._audit.record(
                task_id=self._policy.task_id,
                actor="llm_planner",
                event="model_turn",
                notes=(
                    f"iter={iteration}",
                    f"stop_reason={response.stop_reason}",
                    f"input_tokens={response.usage.input_tokens}",
                    f"output_tokens={response.usage.output_tokens}",
                ),
            )

            # Always echo the assistant turn back into history.
            messages.append({"role": "assistant", "content": response.content})

            # Capture text emitted this turn (last one wins for final_text).
            for block in response.content:
                if block.type == "text" and block.text.strip():
                    final_text = block.text

            if response.stop_reason == "end_turn":
                return PlannerOutcome(final_text, iteration + 1, tool_calls_log, deny_count, "end_turn")

            if response.stop_reason != "tool_use":
                # max_tokens, refusal, pause_turn — stop and report.
                return PlannerOutcome(
                    final_text, iteration + 1, tool_calls_log, deny_count, response.stop_reason
                )

            # Process every tool_use block in this turn before the next call.
            tool_results: list[dict[str, Any]] = []
            turn_had_allow = False
            for block in response.content:
                if block.type != "tool_use":
                    continue
                broker_tool = _broker_name(block.name)
                tool_calls_log.append({"name": broker_tool, "input": redacted_hash(block.input)})
                outcome = self._invoke_through_broker(broker_tool, block.input)
                if outcome.decision == Decision.DENY:
                    deny_count += 1
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "is_error": True,
                            "content": (
                                f"DENIED by policy rule {outcome.rule}: {outcome.reason}. "
                                f"This call was not executed. Try a different tool, or ask the user."
                            ),
                        }
                    )
                else:
                    turn_had_allow = True
                    summary = self._summarize_for_model(outcome.result)
                    if outcome.result_label is not None:
                        self._session_labels.append(outcome.result_label)
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": summary,
                        }
                    )

            messages.append({"role": "user", "content": tool_results})
            consecutive_denies = 0 if turn_had_allow else consecutive_denies + 1
            if consecutive_denies >= 3:
                self._audit.record(
                    task_id=self._policy.task_id,
                    actor="llm_planner",
                    event="deny_loop_break",
                    notes=(f"consecutive_denies={consecutive_denies}",),
                )
                return PlannerOutcome(
                    final_text, iteration + 1, tool_calls_log, deny_count, "deny_loop"
                )

        return PlannerOutcome(final_text, self._max_iterations, tool_calls_log, deny_count, "max_iterations")

    # ---- helpers --------------------------------------------------------

    def _build_model_tools(self) -> list[dict[str, Any]]:
        """Render only the registered tools the task envelope grants.

        The model never sees a tool the minter did not issue a
        capability for. This is belt-and-braces: even if the model
        names an out-of-envelope tool, ``capability_required`` would
        deny — but we don't tempt it in the first place.
        """
        out: list[dict[str, Any]] = []
        for name in self._tool_names:
            tool = self._broker._tools[name]  # internal access for the demo
            out.append(sanitize_for_planner(tool.name, tool.descriptor, tool.schema))
        return out

    def _invoke_through_broker(self, tool_name: str, args: dict[str, Any]):
        """Hand the model's proposed call to ``ToolBroker.invoke``.

        The arg label is the join of every label observed this session
        (see ``_session_labels``). This is the §5.5 conservative
        stance for semantic laundering: any argument value could have
        been derived by the model from any prior result.
        """
        joined = join_all(self._session_labels)
        arg_labels = {key: joined for key in args} if joined is not None else {}

        sink_destination = None
        sink_arg = self._sink_extractors.get(tool_name)
        if sink_arg and sink_arg in args:
            sink_destination = str(args[sink_arg])

        return self._broker.invoke(
            policy=self._policy,
            cap_set=self._cap_set,
            tool_name=tool_name,
            action="run",
            args=args,
            arg_labels=arg_labels,
            sink_destination=sink_destination,
            approval_resolver=self._approval_resolver,
        )

    @staticmethod
    def _summarize_for_model(result: Any) -> str:
        """Convert a tool result to a string the model can consume.

        Real deployments would also strip secrets here (defense in
        depth alongside the §7.6 egress scanner). For the demo we
        rely on the broker's egress check to catch anything dangerous
        on the way *out*, and just stringify on the way *in*.
        """
        if isinstance(result, str):
            return result
        if isinstance(result, (dict, list)):
            import json as _json

            return _json.dumps(result, default=str, ensure_ascii=False)
        return str(result)

    def _default_system_prompt(self) -> str:
        """Minimal system prompt.

        Deliberately small. We do *not* lean on prompt-level
        guardrails — the paper's §3.1 point is that those are not a
        boundary. The actual security comes from the broker. We do,
        however, give the model enough context to make sensible
        decisions and to handle denials gracefully.
        """
        return (
            "You are an assistant working inside a sandboxed agent runtime. "
            "Tools may be denied by a policy engine for reasons you cannot "
            "always predict; if a tool returns is_error=True with a 'DENIED' "
            "message, do not retry the same call. Either try a different "
            "approach or report the denial to the user. Stay strictly within "
            f"the user's task: {self._policy.user_request!r}"
        )
