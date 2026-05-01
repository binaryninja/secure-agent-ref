"""Demo 08 — LLM-backed research agent (paper §8.1, Pattern A, with a real model).

Same envelope as demo 01: the user wants a summary of a public page,
nothing else. The difference: the planner is Claude Opus 4.7 talking
to the broker via tool-use. The model proposes; the broker disposes.

Expected outcome: the model fetches the page through
``web.fetch_public`` and writes a summary. Every tool call shows up
in the audit log with the same provenance shape as demo 01.

Requires ``ANTHROPIC_API_KEY`` (loaded from .env at the repo root by
``secagent/llm_planner.py``). If absent, the planner raises at
construction; this demo will crash fast rather than skip silently.
"""

from __future__ import annotations

from _demo_runtime import banner, make_runtime, section

from secagent.labels import Confidentiality
from secagent.llm_planner import LLMPlanner
from secagent.policy_compiler import (
    SideEffectLevel,
    ToolGrant,
    compile_task,
)
from secagent.tools import FetchPublicURLTool


def main() -> int:
    banner("Demo 08 — LLM-backed research agent (Claude Opus 4.7)")
    rt = make_runtime()

    rt.broker.register(FetchPublicURLTool())

    user_request = (
        "Summarize the page at https://example.com/paper-summary in one sentence."
    )
    policy = compile_task(
        user="alice",
        tenant="acme",
        workflow="public_research",
        user_request=user_request,
        resources_in_scope=["https://example.com/paper-summary"],
        tool_grants=[
            ToolGrant(
                tool="web.fetch_public",
                action="run",
                scope={"url": ["https://example.com/paper-summary"]},
            ),
        ],
        max_side_effect=SideEffectLevel.READ_PUBLIC,
        readable_data_classes=[Confidentiality.PUBLIC],
    )
    cap_set = rt.minter.mint_for_task(policy)

    planner = LLMPlanner(
        broker=rt.broker,
        policy=policy,
        cap_set=cap_set,
        audit=rt.audit,
        tool_names=["web.fetch_public"],
    )

    section("Running the LLM planner")
    outcome = planner.run_until_done(user_request)
    print(f"  iterations:    {outcome.iterations}")
    print(f"  tool_calls:    {len(outcome.tool_calls)}  (denies: {outcome.deny_count})")
    print(f"  stop_reason:   {outcome.stopped_reason}")
    print(f"  final_text:    {outcome.final_text!r}")

    section("Audit trail (broker + planner)")
    print(rt.audit.pretty())

    assert outcome.stopped_reason == "end_turn", "benign task should reach end_turn"
    assert outcome.deny_count == 0, "no denies expected on this benign path"
    assert any(c["name"] == "web.fetch_public" for c in outcome.tool_calls), "model should have fetched"

    print("\nOK: the LLM stayed inside the envelope; broker recorded full provenance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
