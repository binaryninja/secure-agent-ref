"""Provenance audit log — paper §11.6.

"Without provenance, incident response cannot distinguish a model
mistake from an injection-driven flow." Every action recorded here
includes the data origins that influenced its arguments, the
capability used, the policy decision, and the sink it reached.

This is a reference implementation, so the log is an in-memory list
that ``str()``-formats nicely. A production deployment would write
JSONL to an immutable store (paper §8.4, §11.6) — the schema below
is what they should put there.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .labels import Label


@dataclass(frozen=True)
class AuditRecord:
    """One row in the provenance log.

    The schema deliberately matches the §11.6 list: user request,
    task policy, capability grants, tool calls, tool arguments, tool
    result labels, data origins that influenced each call, policy
    decision, human approval, sandbox id, sink destination, redacted
    content hash.
    """

    timestamp: float
    task_id: str
    actor: str  # "broker", "minter", "policy_engine", "sandbox", "memory_guard", "egress"
    event: str  # "tool_call", "policy_decide", "mint_capability", "memory_write", ...
    tool: str | None = None
    action: str | None = None
    args_redacted: dict[str, Any] | None = None
    args_label_summary: str | None = None  # joined provenance string
    capability_id: str | None = None
    decision: str | None = None  # "allow" | "deny" | "approval_required" | "audit_only"
    rule: str | None = None  # which rule fired (matches policy_engine names)
    sink_destination: str | None = None
    sandbox_id: str | None = None
    approver: str | None = None
    content_hash: str | None = None
    notes: tuple[str, ...] = ()


class AuditLog:
    """In-memory provenance log with a JSONL exporter for demos."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def record(self, **kwargs: Any) -> AuditRecord:
        kwargs.setdefault("timestamp", time.time())
        rec = AuditRecord(**kwargs)
        self._records.append(rec)
        return rec

    def all(self) -> list[AuditRecord]:
        return list(self._records)

    def for_task(self, task_id: str) -> list[AuditRecord]:
        return [r for r in self._records if r.task_id == task_id]

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(asdict(r), default=str) for r in self._records)

    def pretty(self) -> str:
        """Human-friendly rendering for demo output."""
        lines: list[str] = []
        for r in self._records:
            head = f"[{r.actor:>13}] {r.event}"
            if r.tool:
                head += f" tool={r.tool}.{r.action}"
            if r.decision:
                head += f"  -> {r.decision}"
                if r.rule:
                    head += f" (rule={r.rule})"
            lines.append(head)
            if r.args_label_summary:
                lines.append(f"               provenance: {r.args_label_summary}")
            if r.sink_destination:
                lines.append(f"               sink:       {r.sink_destination}")
            for note in r.notes:
                lines.append(f"               note:       {note}")
        return "\n".join(lines)


def redacted_hash(value: Any) -> str:
    """Stable hash so audit logs reference content without storing it."""
    blob = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()[:16]


def label_summary(label: Label | None) -> str | None:
    """One-line summary of a label for audit display."""
    if label is None:
        return None
    return (
        f"conf={label.confidentiality.name} "
        f"int={label.integrity.name} "
        f"origin={label.origin}"
    )
