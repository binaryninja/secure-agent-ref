"""Demo 01 — Pattern A: read-only research agent (paper §8.1).

This is the easy case: the user asks the agent to summarize a public
webpage. The §8.1 envelope says no private data, no email, no
sandbox network, only fetch_public allowed. The benign planner
script below stays inside the envelope; the call goes through.

The point of the demo is to show what *success* looks like when the
broker is in the path: the audit log records every step with full
provenance, and the controls have not blocked anything because the
task never tried to leave its scope.
"""

from __future__ import annotations

from _demo_runtime import banner, make_runtime, section

from secagent.labels import Confidentiality, user_request_label
from secagent.policy_compiler import (
    SideEffectLevel,
    ToolGrant,
    compile_task,
)
from secagent.tools import FetchPublicURLTool


def main() -> int:
    banner("Demo 01 — Read-only research agent (paper §8.1, Pattern A)")
    rt = make_runtime()

    fetch = FetchPublicURLTool()
    rt.broker.register(fetch)

    # §7.1 envelope: only what the task needs. No write tools, no
    # email, no private data, no network on the sandbox.
    policy = compile_task(
        user="alice",
        tenant="acme",
        workflow="public_research",
        user_request="Summarize the public summary at example.com/paper-summary.",
        resources_in_scope=["https://example.com/paper-summary"],
        tool_grants=[
            ToolGrant(
                tool="web.fetch_public",
                action="run",
                scope={"url": ["https://example.com/paper-summary"]},
                notes="research",
            ),
        ],
        max_side_effect=SideEffectLevel.READ_PUBLIC,
        readable_data_classes=[Confidentiality.PUBLIC],
        approval_threshold=SideEffectLevel.EXTERNAL_SEND,
        ttl_seconds=120,
    )
    cap_set = rt.minter.mint_for_task(policy)

    section("Proposed call: fetch the public summary")
    outcome = rt.broker.invoke(
        policy=policy,
        cap_set=cap_set,
        tool_name="web.fetch_public",
        action="run",
        args={"url": "https://example.com/paper-summary"},
        arg_labels={"url": user_request_label(policy.task_id)},
    )
    print(f"  decision: {outcome.decision.value}  rule={outcome.rule}")
    print(f"  result:   {outcome.result!r}")

    section("Audit trail")
    print(rt.audit.pretty())

    assert outcome.decision.value == "allow", "benign read should allow"
    print("\nOK: research agent stayed inside its envelope.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
