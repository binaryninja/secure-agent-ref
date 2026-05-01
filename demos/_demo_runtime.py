"""Shared wiring for demos.

Each demo is short on purpose — just the user request, the planner
script, and the assertions. This module builds a fully-wired runtime
(audit, policy engine, broker, memory guard, sandbox) so every demo
starts from the same baseline.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `python demos/01_*.py` to import secagent without an install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dataclasses import dataclass

from secagent.audit import AuditLog
from secagent.broker import ApprovalQueue, ToolBroker
from secagent.memory import MemoryGuard
from secagent.minter import CapabilityMinter
from secagent.policy_engine import PolicyEngine
from secagent.sandbox import CodeSandbox


@dataclass
class Runtime:
    audit: AuditLog
    minter: CapabilityMinter
    engine: PolicyEngine
    broker: ToolBroker
    memory: MemoryGuard
    sandbox: CodeSandbox
    approvals: ApprovalQueue


def make_runtime() -> Runtime:
    audit = AuditLog()
    engine = PolicyEngine(audit)
    approvals = ApprovalQueue()
    broker = ToolBroker(audit=audit, policy_engine=engine, approvals=approvals)
    return Runtime(
        audit=audit,
        minter=CapabilityMinter(audit),
        engine=engine,
        broker=broker,
        memory=MemoryGuard(audit),
        sandbox=CodeSandbox(audit),
        approvals=approvals,
    )


def banner(title: str) -> None:
    line = "=" * len(title)
    print(f"\n{line}\n{title}\n{line}")


def section(title: str) -> None:
    print(f"\n--- {title} ---")
