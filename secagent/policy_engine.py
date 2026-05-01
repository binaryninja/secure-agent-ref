"""Policy engine — paper §7.4.

"The policy engine should combine RBAC/ABAC, object capabilities, and
information-flow rules." This module is the deterministic core: a
list of named rules, each pure-functional, run in order against a
``Decision`` context built from the proposed tool call. The first rule
that matches wins.

The four rules below mirror the YAML example in §7.4 of the paper:

  1. no_private_to_public_github     — sensitive→public sink, deny
  2. untrusted_content_cannot_select_shell_command
                                      — low integrity into code exec
                                        sink, require approval
  3. allow_repo_scoped_read           — read with capability in scope, allow
  4. block_network_from_code_sandbox_by_default
                                      — sandbox network not in envelope, deny

Add more rules by extending ``DEFAULT_RULES``. Every rule has a name so
the audit log can record which one fired (§11.6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .audit import AuditLog
from .capabilities import Capability, CapabilitySet
from .labels import Confidentiality, Integrity, Label
from .policy_compiler import SideEffectLevel, TaskPolicy


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    rule: str
    reason: str


@dataclass(frozen=True)
class CallContext:
    """Everything a rule needs to make a decision.

    Built by the broker on each proposed tool call. Holds the task
    policy, the capability the broker matched, the proposed
    arguments, the joined label of those arguments (provenance), the
    side-effect level the tool declares it produces, and the sink
    destination if the tool is a sink (§7.6).
    """

    policy: TaskPolicy
    cap_set: CapabilitySet
    matched_capability: Capability | None
    tool: str
    action: str
    args: dict[str, Any]
    args_label: Label | None  # joined label across all tainted args
    side_effect: SideEffectLevel
    sink_destination: str | None = None
    tool_category: str = ""  # "code_execution", "external_send", "github_public_write", ...


Rule = Callable[[CallContext], Verdict | None]


# ---- Rules ---------------------------------------------------------------


def rule_capability_required(ctx: CallContext) -> Verdict | None:
    """Foundational rule: no capability, no call (§4.4)."""
    if ctx.matched_capability is None:
        return Verdict(
            Decision.DENY,
            "capability_required",
            f"no capability covers {ctx.tool}.{ctx.action} with these args",
        )
    return None


def rule_no_private_to_public_github(ctx: CallContext) -> Verdict | None:
    """§7.4 example: block tenant-private content reaching a public sink.

    This is the GitHub MCP toxic-flow class (paper §1.1). A read of a
    private repository labels its result TENANT_PRIVATE; a public PR
    or issue comment is a public sink. Joining one into the other
    must fail.
    """
    if ctx.tool_category != "github_public_write":
        return None
    if ctx.args_label is None:
        return None
    if ctx.args_label.confidentiality >= Confidentiality.TENANT_PRIVATE:
        return Verdict(
            Decision.DENY,
            "no_private_to_public_github",
            f"argument carries {ctx.args_label.confidentiality.name} from {ctx.args_label.origin}; "
            f"public github write is not an allowed sink for it",
        )
    return None


def rule_untrusted_content_cannot_select_shell_command(ctx: CallContext) -> Verdict | None:
    """§7.4 example: low-integrity taint into code execution -> approval.

    Maps directly to the §11 checklist item "block low-integrity content
    from controlling high-impact actions." Generated code arguments
    derived from untrusted external input must escalate.
    """
    if ctx.tool_category != "code_execution":
        return None
    if ctx.args_label is None:
        return None
    if ctx.args_label.integrity <= Integrity.UNTRUSTED_EXTERNAL:
        return Verdict(
            Decision.APPROVAL_REQUIRED,
            "untrusted_content_cannot_select_shell_command",
            f"code arg integrity={ctx.args_label.integrity.name} from {ctx.args_label.origin}",
        )
    return None


def rule_block_network_from_code_sandbox_by_default(ctx: CallContext) -> Verdict | None:
    """§7.4: sandbox network is opt-in per task envelope.

    Policy-layer enforcement only. The broker refuses to launch a
    code-execution tool when ``network=True`` is requested by a task
    whose envelope did not declare ``network_required``. The sandbox
    runtime in this reference (a Linux subprocess with rlimits and a
    stripped env) does not contain egress at the kernel layer —
    netns/iptables and Firecracker/gVisor (paper §6.2/§6.3) are the
    production answer. So this rule prevents a *cooperative* planner
    from asking for network when it shouldn't have it; it does NOT
    prevent a snippet that just shells out to ``curl`` from doing so.
    """
    if ctx.tool_category != "code_execution":
        return None
    requested_network = bool(ctx.args.get("network", False))
    if requested_network and not ctx.policy.network_required:
        return Verdict(
            Decision.DENY,
            "block_network_from_code_sandbox_by_default",
            "task envelope did not declare network_required (policy-layer block; "
            "kernel-layer egress containment is out of scope for this reference)",
        )
    return None


def rule_external_send_recipient_allowlist(ctx: CallContext) -> Verdict | None:
    """§7.6 + §11 sink set: external sends must hit an allowlisted recipient."""
    if ctx.tool_category != "external_send":
        return None
    recipient = ctx.sink_destination or str(ctx.args.get("to", ""))
    if recipient not in ctx.policy.allowed_recipients:
        return Verdict(
            Decision.DENY,
            "external_send_recipient_allowlist",
            f"recipient {recipient!r} not in task allowlist {list(ctx.policy.allowed_recipients)}",
        )
    return None


def rule_side_effect_within_envelope(ctx: CallContext) -> Verdict | None:
    """§7.1: tool side-effect must not exceed the task ceiling."""
    if ctx.side_effect > ctx.policy.max_side_effect:
        return Verdict(
            Decision.DENY,
            "side_effect_within_envelope",
            f"tool side_effect={ctx.side_effect.name} exceeds "
            f"task max_side_effect={ctx.policy.max_side_effect.name}",
        )
    return None


def rule_approval_at_or_above_threshold(ctx: CallContext) -> Verdict | None:
    """§7.4 approval gate. Run *after* the deny rules so we don't ask
    a human to approve something that policy already forbids."""
    if ctx.side_effect >= ctx.policy.approval_threshold:
        return Verdict(
            Decision.APPROVAL_REQUIRED,
            "approval_at_or_above_threshold",
            f"side_effect {ctx.side_effect.name} >= threshold "
            f"{ctx.policy.approval_threshold.name}",
        )
    return None


def rule_default_allow(ctx: CallContext) -> Verdict | None:
    """Terminal rule: nothing else fired, the capability already covers the call."""
    return Verdict(Decision.ALLOW, "default_allow", "no deny rule matched and capability is in scope")


DEFAULT_RULES: tuple[Rule, ...] = (
    rule_capability_required,
    rule_side_effect_within_envelope,
    rule_no_private_to_public_github,
    rule_external_send_recipient_allowlist,
    rule_block_network_from_code_sandbox_by_default,
    rule_untrusted_content_cannot_select_shell_command,
    rule_approval_at_or_above_threshold,
    rule_default_allow,
)


class PolicyEngine:
    """Runs rules in order; first non-None verdict wins."""

    def __init__(self, audit: AuditLog, rules: tuple[Rule, ...] = DEFAULT_RULES) -> None:
        self._audit = audit
        self._rules = rules

    def decide(self, ctx: CallContext) -> Verdict:
        for rule in self._rules:
            verdict = rule(ctx)
            if verdict is not None:
                return verdict
        # Should not happen if DEFAULT_RULES ends with rule_default_allow.
        return Verdict(Decision.DENY, "no_rule_matched", "fail closed")
