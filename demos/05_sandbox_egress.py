"""Demo 05 — Code sandbox profile and egress (paper §6.6, §11.5).

Generated code runs under the §6.6 profile: empty environment,
ephemeral scratch directory, resource limits, no inherited fds.
This demo runs a snippet that *tries* to read host secrets out of
its environment and confirms it sees nothing.

It also shows the §11.5 IFC rule:
``rule_untrusted_content_cannot_select_shell_command``. When the
proposed code argument carries an UNTRUSTED_EXTERNAL label
(constructed from web content, say), the policy engine routes the
call to human approval rather than executing it directly.

What this demo proves vs. does not prove
----------------------------------------
Step 1 proves:  the sandbox really starts with an empty env, even
                when the parent process has secrets in its env. That
                is a *real* isolation property at the env-strip layer.
Step 2 proves:  the policy engine routes UNTRUSTED_EXTERNAL-tainted
                code to the approval queue. The deny is on the policy
                edge, not on the kernel edge.
Step 3 proves:  the policy rule ``block_network_from_code_sandbox_by_default``
                refuses to launch when ``network=True`` is requested
                without ``network_required`` in the envelope. This is
                policy-layer enforcement. It does NOT prove that a
                cooperative-looking snippet which then shells out to
                ``curl`` is contained — the reference sandbox shares
                the host network namespace. Production deployments
                need netns/iptables, Firecracker, or gVisor (paper
                §6.2, §6.3). The README's "Scope and gaps" section is
                explicit about this.
"""

from __future__ import annotations

from _demo_runtime import banner, make_runtime, section

from secagent.labels import Confidentiality, Integrity, Label, user_request_label
from secagent.policy_compiler import (
    SideEffectLevel,
    ToolGrant,
    compile_task,
)
from secagent.policy_engine import Verdict
from secagent.tools import RunPythonTool


def main() -> int:
    banner("Demo 05 — Sandbox profile and IFC for code execution")
    rt = make_runtime()

    policy = compile_task(
        user="alice",
        tenant="acme",
        workflow="data_analysis",
        user_request="Run a quick data check.",
        resources_in_scope=[],
        tool_grants=[ToolGrant(tool="sandbox.run_python", action="run", scope={})],
        max_side_effect=SideEffectLevel.EXECUTE_CODE,
        code_execution_required=True,
        network_required=False,
        approval_threshold=SideEffectLevel.EXECUTE_CODE,
    )
    cap_set = rt.minter.mint_for_task(policy)

    rt.broker.register(RunPythonTool(rt.sandbox, task_id=policy.task_id))

    # Always-approve resolver for the trusted-code path.
    def approve(audit_key: str, verdict: Verdict) -> bool:
        return True

    section("Step 1 — trusted code; the sandbox should see no host secrets")
    probe = """
import os
suspicious = [k for k in os.environ if k.startswith(('AWS_', 'GITHUB', 'OPENAI', 'SSH'))]
print('env_keys=', sorted(os.environ.keys()))
print('suspicious=', suspicious)
"""
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
    print(f"  exit:     {out.result.exit_code}")
    print(f"  stdout:   {out.result.stdout.strip()}")
    assert out.decision.value == "allow"
    assert "suspicious= []" in out.result.stdout, "sandbox leaked host env"

    section("Step 2 — untrusted-tainted code escalates to approval; we deny")
    # Imagine the planner assembled this snippet from a web page it
    # just fetched. The arg label carries that provenance.
    web_label = Label(
        confidentiality=Confidentiality.PUBLIC,
        integrity=Integrity.UNTRUSTED_EXTERNAL,
        origin="web.public:https://example.com/snippet",
        purpose=policy.task_id,
    )

    def deny(audit_key: str, verdict: Verdict) -> bool:
        print(f"  approver sees: {verdict.rule}: {verdict.reason}")
        return False

    out2 = rt.broker.invoke(
        policy=policy,
        cap_set=cap_set,
        tool_name="sandbox.run_python",
        action="run",
        args={"code": "print('hi from web-derived snippet')", "network": False},
        arg_labels={"code": web_label},
        approval_resolver=deny,
    )
    print(f"  decision: {out2.decision.value}  rule={out2.rule}")
    assert out2.decision.value == "deny"
    assert out2.rule == "human_approval_denied"

    section("Step 3 — sandbox tool call with network=True is denied at the policy layer")
    out3 = rt.broker.invoke(
        policy=policy,
        cap_set=cap_set,
        tool_name="sandbox.run_python",
        action="run",
        args={"code": "print('would phone home')", "network": True},
        arg_labels={"code": user_request_label(policy.task_id)},
        approval_resolver=approve,
    )
    print(f"  decision: {out3.decision.value}  rule={out3.rule}")
    print(f"  reason:   {out3.reason}")
    assert out3.decision.value == "deny"
    assert out3.rule == "block_network_from_code_sandbox_by_default"

    print(
        "\nOK: env-strip is real (Step 1); policy refuses UNTRUSTED-tainted code "
        "(Step 2); policy refuses sandbox launches that ask for network when the "
        "envelope did not grant it (Step 3).\n"
        "   Caveat: kernel-layer network containment is NOT demonstrated here — "
        "a snippet that shells out to ``curl`` would still reach the network on "
        "this reference sandbox. See README 'Scope and gaps'."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
