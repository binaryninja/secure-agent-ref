"""Tool broker / MCP gateway — paper §7.3 and §9.

"The tool broker is the enforcement choke point." Every tool call,
memory write, and external send goes through ``ToolBroker.invoke``.
The §7.3 list of broker responsibilities maps directly to the steps
of ``invoke``:

  1. Register tools with stable identifiers      -> ``register``
  2. Pin tool versions and descriptors           -> ``DescriptorRegistry``
  3. Diff descriptor changes                     -> ``DescriptorRegistry.pin``
  4. Validate tool arguments against schemas     -> ``Tool.validate``
  5. Enforce task capabilities                   -> ``Capability.covers``
  6. Enforce IFC policies                        -> ``PolicyEngine.decide``
  7. Inject per-call credentials only after approval -> ``Tool.run``
  8. Strip ambient environment variables         -> ``sandbox.py``
  9. Route untrusted tools into sandboxes        -> tool category
 10. Log full provenance and decisions           -> ``AuditLog``
 11. Support emergency revocation                -> ``revoke``

§9.4 "Handling MCP Tool Poisoning" is implemented by hashing each
tool descriptor at registration time and refusing any later mutation
unless an admin explicitly re-pins. This catches the rug-pull case
where a server adds a new ``send`` or ``exec`` verb after approval.

The broker treats the planner's tool-call JSON as untrusted output
(§7.3 closing line). The `invoke` method is the chokepoint that runs
all the checks before any tool implementation is touched.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .audit import AuditLog, label_summary, redacted_hash
from .capabilities import Capability, CapabilitySet
from .egress import scan_for_secrets
from .labels import Label, join_all
from .policy_compiler import SideEffectLevel, TaskPolicy
from .policy_engine import CallContext, Decision, PolicyEngine, Verdict


# ---- Tool protocol -------------------------------------------------------


class Tool(Protocol):
    """Every tool exposes a stable name, a descriptor, a category,
    a side-effect level, an arg-schema, and a ``run`` method.

    The descriptor is the *human-facing* documentation. The schema is
    the *machine-readable* affordance shown to the planner. §9.4
    ("separate tool documentation for humans from tool affordance
    schema for models") says these should be different artifacts so
    that injection attempts in human-readable text don't reach the
    planner. The broker enforces that split.
    """

    name: str
    version: str
    descriptor: str
    category: str  # "read_public", "read_private", "github_public_write", "external_send", "code_execution", "memory_write"
    side_effect: SideEffectLevel
    schema: dict[str, type]

    def validate(self, args: dict[str, Any]) -> None: ...
    def run(self, args: dict[str, Any], context: "ToolRunContext") -> tuple[Any, Label]: ...


@dataclass(frozen=True)
class ToolRunContext:
    """Side-channel context the broker passes to ``Tool.run``.

    Contains the joined argument label (so a memory-write tool, for
    example, can record the provenance of the data it is about to
    persist) and the matched capability. Tools that don't need it can
    ignore the parameter.
    """

    task_id: str
    args_label: Label | None
    capability_id: str | None


# ---- Descriptor pinning --------------------------------------------------


@dataclass(frozen=True)
class PinnedDescriptor:
    name: str
    version: str
    descriptor_hash: str
    category: str
    side_effect: SideEffectLevel


class DescriptorRegistry:
    """§9.3 #2-3: pin descriptors and refuse drift.

    Maintains a content-hash for each registered tool descriptor.
    On every ``invoke``, the broker recomputes the hash and refuses
    if it does not match the pinned value. The only way to update is
    ``re_pin``, which writes an audit record and is intended to be
    called by an admin tool, not by the planner.
    """

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit
        self._pinned: dict[str, PinnedDescriptor] = {}

    @staticmethod
    def hash_descriptor(descriptor: str) -> str:
        # Full SHA-256. Earlier drafts truncated to 16 hex (64 bits)
        # which is fine for accidental drift but birthday-attackable
        # by an adversary who controls the descriptor. §9.4 wants the
        # pin to survive a hostile MCP server, so we keep all 256 bits.
        return hashlib.sha256(descriptor.encode("utf-8")).hexdigest()

    def pin(self, tool: Tool) -> PinnedDescriptor:
        if tool.name in self._pinned:
            raise ValueError(f"tool {tool.name!r} already pinned; use re_pin")
        pinned = PinnedDescriptor(
            name=tool.name,
            version=tool.version,
            descriptor_hash=self.hash_descriptor(tool.descriptor),
            category=tool.category,
            side_effect=tool.side_effect,
        )
        self._pinned[tool.name] = pinned
        self._audit.record(
            task_id="-",
            actor="broker",
            event="pin_descriptor",
            tool=tool.name,
            notes=(f"version={tool.version}", f"hash={pinned.descriptor_hash}", f"category={tool.category}"),
        )
        return pinned

    def re_pin(self, tool: Tool, *, admin_approver: str) -> PinnedDescriptor:
        prev = self._pinned.get(tool.name)
        new = PinnedDescriptor(
            name=tool.name,
            version=tool.version,
            descriptor_hash=self.hash_descriptor(tool.descriptor),
            category=tool.category,
            side_effect=tool.side_effect,
        )
        self._pinned[tool.name] = new
        self._audit.record(
            task_id="-",
            actor="broker",
            event="repin_descriptor",
            tool=tool.name,
            approver=admin_approver,
            notes=(
                f"prev_hash={prev.descriptor_hash if prev else 'none'}",
                f"new_hash={new.descriptor_hash}",
                f"prev_version={prev.version if prev else 'none'}",
                f"new_version={tool.version}",
            ),
        )
        return new

    def verify(self, tool: Tool) -> tuple[bool, str]:
        pinned = self._pinned.get(tool.name)
        if pinned is None:
            return False, f"tool {tool.name!r} is not pinned; broker refuses unpinned tools"
        live_hash = self.hash_descriptor(tool.descriptor)
        if live_hash != pinned.descriptor_hash:
            return False, (
                f"descriptor drift on {tool.name!r}: pinned={pinned.descriptor_hash} "
                f"live={live_hash}; admin re-pin required"
            )
        return True, "ok"


# ---- Approval queue ------------------------------------------------------


@dataclass
class PendingApproval:
    task_id: str
    verdict: Verdict
    ctx_summary: dict[str, Any]
    approved: bool | None = None
    approver: str | None = None


class ApprovalQueue:
    """§7.4 + §11 checklist 'reserve human approval for risk transitions.'

    The queue is filled when the policy engine returns
    APPROVAL_REQUIRED. Demos show a human approving or denying at the
    queue level so the broker can resume.
    """

    def __init__(self) -> None:
        self._pending: dict[str, PendingApproval] = {}

    def submit(self, key: str, item: PendingApproval) -> None:
        self._pending[key] = item

    def approve(self, key: str, *, approver: str) -> None:
        item = self._pending[key]
        item.approved = True
        item.approver = approver

    def deny(self, key: str, *, approver: str) -> None:
        item = self._pending[key]
        item.approved = False
        item.approver = approver

    def status(self, key: str) -> PendingApproval | None:
        return self._pending.get(key)


# ---- Broker --------------------------------------------------------------


@dataclass(frozen=True)
class InvocationOutcome:
    decision: Decision
    rule: str
    reason: str
    result: Any | None
    result_label: Label | None
    capability_id: str | None
    audit_key: str  # used to pair with approvals


class ToolBroker:
    """The chokepoint. ``invoke`` is the only path to a side effect.

    Construction wires up the audit log, descriptor registry, policy
    engine, and approval queue. ``register`` pins each tool. ``invoke``
    walks every check in order: descriptor verify, schema validate,
    capability match, label join, policy decide, approval if needed,
    egress scan if the tool is a sink, and finally the tool's ``run``.
    """

    def __init__(
        self,
        *,
        audit: AuditLog,
        policy_engine: PolicyEngine,
        approvals: ApprovalQueue | None = None,
    ) -> None:
        self._audit = audit
        self._policy = policy_engine
        self._approvals = approvals or ApprovalQueue()
        self._registry = DescriptorRegistry(audit)
        self._tools: dict[str, Tool] = {}
        self._revoked: set[str] = set()

    # -- registration ------------------------------------------------------

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool
        self._registry.pin(tool)

    def re_pin(self, tool: Tool, *, admin_approver: str) -> None:
        self._tools[tool.name] = tool
        self._registry.re_pin(tool, admin_approver=admin_approver)

    def revoke(self, capability_id: str) -> None:
        """§7.3 #11 emergency revocation."""
        self._revoked.add(capability_id)
        self._audit.record(
            task_id="-",
            actor="broker",
            event="revoke_capability",
            capability_id=capability_id,
        )

    @property
    def registry(self) -> DescriptorRegistry:
        return self._registry

    @property
    def approvals(self) -> ApprovalQueue:
        return self._approvals

    # -- invocation --------------------------------------------------------

    def invoke(
        self,
        *,
        policy: TaskPolicy,
        cap_set: CapabilitySet,
        tool_name: str,
        action: str,
        args: dict[str, Any],
        arg_labels: dict[str, Label] | None = None,
        sink_destination: str | None = None,
        approval_resolver: Callable[[str, Verdict], bool] | None = None,
    ) -> InvocationOutcome:
        """Run the §7.3 chain and return an InvocationOutcome.

        ``arg_labels`` is the per-argument provenance the caller
        learned when reading the data. The broker joins them into a
        single label and hands that to the policy engine — this is
        the §5.1 propagation that lets rules reason about flows.

        ``approval_resolver`` is a callable ``(audit_key, verdict) ->
        bool`` used by demos to simulate a human approver in-line.
        Production wires this to a UI.
        """
        arg_labels = arg_labels or {}
        audit_key = f"{policy.task_id}:{tool_name}:{action}:{redacted_hash(args)}"

        # Step 1: tool must be registered and descriptor must match.
        tool = self._tools.get(tool_name)
        if tool is None:
            return self._record_deny(policy, tool_name, action, args, arg_labels, audit_key,
                                     "tool_not_registered", f"unknown tool {tool_name!r}")
        ok, reason = self._registry.verify(tool)
        if not ok:
            return self._record_deny(policy, tool_name, action, args, arg_labels, audit_key,
                                     "descriptor_pin_mismatch", reason)

        # Step 2: schema validation. Schema-valid does not mean
        # in-scope (paper §11 checklist explicitly), but it does
        # eliminate one class of injection where the model is steered
        # to pass exotic types into a tool that crashes on them.
        try:
            tool.validate(args)
        except Exception as exc:
            return self._record_deny(policy, tool_name, action, args, arg_labels, audit_key,
                                     "schema_invalid", str(exc))

        # Step 3: capability match. The minter issued a set; we pick
        # the first one that covers this exact (tool, action, args)
        # tuple. Per §4.4 if no capability covers, fail closed.
        matched: Capability | None = None
        cap_reason = "no capabilities for this tool/action"
        for cap in cap_set.find(tool_name, action):
            if cap.capability_id in self._revoked:
                cap_reason = f"capability {cap.capability_id} revoked"
                continue
            ok, reason = cap.covers(tool_name, action, args)
            if ok:
                matched = cap
                break
            cap_reason = reason

        # Step 4: build the call context and ask the policy engine.
        joined = join_all(arg_labels.values())
        ctx = CallContext(
            policy=policy,
            cap_set=cap_set,
            matched_capability=matched,
            tool=tool_name,
            action=action,
            args=args,
            args_label=joined,
            side_effect=tool.side_effect,
            sink_destination=sink_destination,
            tool_category=tool.category,
        )
        verdict = self._policy.decide(ctx)
        self._audit.record(
            task_id=policy.task_id,
            actor="policy_engine",
            event="policy_decide",
            tool=tool_name,
            action=action,
            args_redacted={k: redacted_hash(v) for k, v in args.items()},
            args_label_summary=label_summary(joined),
            capability_id=matched.capability_id if matched else None,
            decision=verdict.decision.value,
            rule=verdict.rule,
            sink_destination=sink_destination,
            notes=(verdict.reason,),
        )

        if verdict.decision == Decision.DENY:
            return InvocationOutcome(
                decision=Decision.DENY,
                rule=verdict.rule,
                reason=verdict.reason,
                result=None,
                result_label=None,
                capability_id=matched.capability_id if matched else None,
                audit_key=audit_key,
            )

        if verdict.decision == Decision.APPROVAL_REQUIRED:
            self._approvals.submit(
                audit_key,
                PendingApproval(
                    task_id=policy.task_id,
                    verdict=verdict,
                    ctx_summary={
                        "tool": tool_name,
                        "action": action,
                        "args": {k: redacted_hash(v) for k, v in args.items()},
                        "provenance": label_summary(joined),
                        "sink": sink_destination,
                        "capability": matched.capability_id if matched else None,
                    },
                ),
            )
            approved = approval_resolver(audit_key, verdict) if approval_resolver else False
            self._audit.record(
                task_id=policy.task_id,
                actor="broker",
                event="human_approval",
                tool=tool_name,
                action=action,
                decision="allow" if approved else "deny",
                approver="demo_human" if approval_resolver else "no_approver",
                notes=(verdict.reason,),
            )
            if not approved:
                return InvocationOutcome(
                    decision=Decision.DENY,
                    rule="human_approval_denied",
                    reason="approver did not authorize",
                    result=None,
                    result_label=None,
                    capability_id=matched.capability_id if matched else None,
                    audit_key=audit_key,
                )

        # Step 5: egress scan for sinks.
        if tool.category in {"external_send", "github_public_write"}:
            content = self._extract_content(args)
            findings = scan_for_secrets(content)
            if findings:
                self._audit.record(
                    task_id=policy.task_id,
                    actor="egress",
                    event="secret_scan_block",
                    tool=tool_name,
                    decision="deny",
                    rule="egress_secret_scan",
                    sink_destination=sink_destination,
                    notes=tuple(f"{f.pattern}: ...{f.excerpt}..." for f in findings),
                )
                return InvocationOutcome(
                    decision=Decision.DENY,
                    rule="egress_secret_scan",
                    reason=f"content matched {[f.pattern for f in findings]}",
                    result=None,
                    result_label=None,
                    capability_id=matched.capability_id if matched else None,
                    audit_key=audit_key,
                )

        # Step 6: actually run the tool. The broker is the only path.
        run_ctx = ToolRunContext(
            task_id=policy.task_id,
            args_label=joined,
            capability_id=matched.capability_id if matched else None,
        )
        result, result_label = tool.run(args, run_ctx)
        self._audit.record(
            task_id=policy.task_id,
            actor="broker",
            event="tool_call",
            tool=tool_name,
            action=action,
            args_redacted={k: redacted_hash(v) for k, v in args.items()},
            args_label_summary=label_summary(joined),
            capability_id=matched.capability_id if matched else None,
            decision="allow",
            rule=verdict.rule,
            sink_destination=sink_destination,
            content_hash=redacted_hash(result),
        )
        return InvocationOutcome(
            decision=Decision.ALLOW,
            rule=verdict.rule,
            reason=verdict.reason,
            result=result,
            result_label=result_label,
            capability_id=matched.capability_id if matched else None,
            audit_key=audit_key,
        )

    # -- helpers -----------------------------------------------------------

    def _record_deny(
        self,
        policy: TaskPolicy,
        tool_name: str,
        action: str,
        args: dict[str, Any],
        arg_labels: dict[str, Label],
        audit_key: str,
        rule: str,
        reason: str,
    ) -> InvocationOutcome:
        joined = join_all(arg_labels.values())
        self._audit.record(
            task_id=policy.task_id,
            actor="broker",
            event="invoke_deny",
            tool=tool_name,
            action=action,
            args_redacted={k: redacted_hash(v) for k, v in args.items()},
            args_label_summary=label_summary(joined),
            decision="deny",
            rule=rule,
            notes=(reason,),
        )
        return InvocationOutcome(
            decision=Decision.DENY,
            rule=rule,
            reason=reason,
            result=None,
            result_label=None,
            capability_id=None,
            audit_key=audit_key,
        )

    @staticmethod
    def _extract_content(args: dict[str, Any]) -> str:
        """Concatenate stringy fields so the egress scanner sees them all.

        §7.6 lists many sink shapes; in this reference we glue every
        string-valued field together. Real deployments would walk a
        structured payload tree.
        """
        parts: list[str] = []
        for v in args.values():
            if isinstance(v, str):
                parts.append(v)
            else:
                parts.append(json.dumps(v, default=str))
        return "\n".join(parts)
