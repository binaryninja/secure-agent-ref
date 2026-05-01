"""Sandbox profile for code execution — paper §6 and §6.6.

The paper is explicit (§6.0): sandboxing controls what untrusted
*computation* can do; capability control governs what the agent's
actions are *authorized* to do. This module is the former. It
demonstrates the §6.6 profile:

  - ephemeral environment
  - no default network
  - read-only input mount
  - separate writable scratch directory
  - no host secrets in env
  - CPU/memory/process/disk/wall-clock limits
  - artifact scanning before export
  - deterministic teardown

A reference impl cannot ship Firecracker or gVisor, so this module
uses the strongest isolation available in stdlib: a subprocess with
``os.execvpe`` style env stripping, ``resource`` rlimits on Linux,
and an explicit empty PATH. Where a production deployment would mount
Firecracker, the comments mark the gap. The demo (§8.5) and the
README make this trade-off explicit.

The artifact returned to the broker carries a Label with
ATTACKER_CONTROLLED integrity (§6.6: "If generated code writes a
report, that report is untrusted output and must be scanned, labeled,
and policy-checked before leaving the sandbox").
"""

from __future__ import annotations

import os
import resource
import secrets
import subprocess
import sys
import tempfile
from dataclasses import dataclass

from .audit import AuditLog
from .labels import Confidentiality, Integrity, Label


@dataclass(frozen=True)
class SandboxResult:
    sandbox_id: str
    exit_code: int
    stdout: str
    stderr: str
    artifact_label: Label  # output is always untrusted-external integrity
    timed_out: bool


class CodeSandbox:
    """Run model-generated code with a deny-by-default profile.

    A real deployment uses Firecracker or gVisor (paper §6.2, §6.3).
    This implementation makes the *boundary* visible — env strip,
    no PATH, resource limits, no inherited fds — but it shares the
    host kernel and is not a security boundary against a determined
    Linux exploit. Use it as a reference for the profile, not as a
    production sandbox. The README is explicit about this.
    """

    def __init__(
        self,
        audit: AuditLog,
        *,
        cpu_seconds: int = 2,
        memory_mb: int = 256,
        wall_clock_seconds: int = 5,
    ) -> None:
        self._audit = audit
        self._cpu = cpu_seconds
        self._mem = memory_mb * 1024 * 1024
        self._wall = wall_clock_seconds

    def run_python(
        self,
        *,
        task_id: str,
        code: str,
        network_allowed: bool = False,
    ) -> SandboxResult:
        """Execute ``code`` with the §6.6 profile.

        ``network_allowed`` is ignored on this reference impl (we have
        no kernel-level network namespace to drop) but it is
        propagated into the audit log so a reader can see that the
        broker passed the policy decision through.
        """
        sandbox_id = "sb_" + secrets.token_hex(6)

        # §6.6: separate writable scratch directory; ephemeral.
        with tempfile.TemporaryDirectory(prefix=f"{sandbox_id}_") as scratch:
            # §6.6 + §11.3: empty environment. No host secrets, no
            # PATH, no PYTHONPATH, no AWS_*, no GITHUB_TOKEN, no
            # SSH_AUTH_SOCK. The few entries we set are the minimum
            # the Python interpreter needs to start.
            env = {
                "HOME": scratch,
                "TMPDIR": scratch,
                "LANG": "C.UTF-8",
                # Note the absence of PATH — child must use absolute argv[0].
            }

            # §6.6 deterministic teardown: wall-clock and resource
            # limits applied via preexec_fn. Linux only; the reference
            # impl skips on non-Linux and notes the gap.
            preexec = _make_rlimit_setter(self._cpu, self._mem) if sys.platform == "linux" else None

            try:
                proc = subprocess.run(
                    [sys.executable, "-I", "-c", code],
                    env=env,
                    cwd=scratch,
                    capture_output=True,
                    text=True,
                    timeout=self._wall,
                    preexec_fn=preexec,
                    check=False,
                )
                timed_out = False
                stdout, stderr, exit_code = proc.stdout, proc.stderr, proc.returncode
            except subprocess.TimeoutExpired as e:
                timed_out = True
                stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
                stderr = (e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")) + "\n[wall-clock timeout]"
                exit_code = -1

        # §6.6: any artifact leaving the sandbox is untrusted-external
        # integrity. The broker should scan it (egress.py) before
        # routing it to a sink.
        artifact_label = Label(
            confidentiality=Confidentiality.PUBLIC,
            integrity=Integrity.UNTRUSTED_EXTERNAL,
            origin=f"sandbox:{sandbox_id}",
            purpose=task_id,
            notes=("sandbox_output",),
        )

        self._audit.record(
            task_id=task_id,
            actor="sandbox",
            event="sandbox_run",
            sandbox_id=sandbox_id,
            notes=(
                f"exit_code={exit_code}",
                f"timed_out={timed_out}",
                f"network_allowed={network_allowed}",
                f"cpu={self._cpu}s mem={self._mem // (1024*1024)}MB wall={self._wall}s",
            ),
        )

        return SandboxResult(
            sandbox_id=sandbox_id,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            artifact_label=artifact_label,
            timed_out=timed_out,
        )


def _make_rlimit_setter(cpu_seconds: int, memory_bytes: int):
    """Closure used as ``preexec_fn`` to apply rlimits in the child."""

    def _set_limits() -> None:
        # §6.6 CPU and memory bounds. RLIMIT_AS bounds total VM size,
        # RLIMIT_CPU bounds user-CPU. RLIMIT_NPROC blocks forkbombs.
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
        # Drop core dumps; they can leak data.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    return _set_limits
