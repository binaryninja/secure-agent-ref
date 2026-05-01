"""Code execution tool — wraps ``CodeSandbox``.

This is the §6.6 sandbox surfaced to the planner. The category is
``code_execution`` so the policy engine routes it to the
``rule_block_network_from_code_sandbox_by_default`` and
``rule_untrusted_content_cannot_select_shell_command`` rules.

Note: the Tool itself does not own the CodeSandbox singleton —
callers pass one in at construction. This keeps demos
deterministic and the audit log shared.
"""

from __future__ import annotations

from typing import Any

from ..labels import Label
from ..policy_compiler import SideEffectLevel
from ..sandbox import CodeSandbox, SandboxResult


class RunPythonTool:
    name = "sandbox.run_python"
    version = "1.0.0"
    descriptor = (
        "Execute a Python snippet in an isolated sandbox. No host "
        "secrets, no network unless network_required is set on the "
        "task envelope, ephemeral filesystem."
    )
    category = "code_execution"
    side_effect = SideEffectLevel.EXECUTE_CODE
    schema = {"code": str, "network": bool}

    def __init__(self, sandbox: CodeSandbox, task_id: str) -> None:
        self._sandbox = sandbox
        self._task_id = task_id

    def validate(self, args: dict[str, Any]) -> None:
        if not isinstance(args.get("code"), str):
            raise ValueError("code must be str")
        # network is optional and defaults to False
        if "network" in args and not isinstance(args["network"], bool):
            raise ValueError("network must be bool")

    def run(self, args: dict[str, Any], context=None) -> tuple[SandboxResult, Label]:
        result = self._sandbox.run_python(
            task_id=self._task_id,
            code=args["code"],
            network_allowed=bool(args.get("network", False)),
        )
        return result, result.artifact_label
