"""Memory and retrieval guard — paper §7.5.

"Memory is a tool and should be mediated like one." Two failure modes
this module addresses:

  1. Memory poisoning (paper §2.7, AgentPoison/PoisonedRAG): an
     untrusted document gets summarized into a memory entry that a
     later privileged workflow reads and acts on. Defense: every
     write carries an integrity label, and any memory derived from
     untrusted external content is *staged* (paper §11 checklist
     "quarantine externally influenced memories"). Privileged
     workflows cannot read staged memories.

  2. Tenant/user spillover (paper §11 checklist "partition memory
     and retrieval by tenant, user, and workflow"): retrieval ACLs
     are enforced at the index layer, not the prompt layer.

The reference implementation keeps memory in two dicts —
``_active`` and ``_quarantine`` — so the demo output makes it
obvious which path a given write took.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Iterator

from .audit import AuditLog
from .labels import Confidentiality, Integrity, Label


@dataclass(frozen=True)
class MemoryEntry:
    entry_id: str
    tenant: str
    user: str
    workflow: str
    content: str
    label: Label
    quarantined: bool


class MemoryGuard:
    """Authorize, label, and partition every memory write/read."""

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit
        self._active: dict[str, MemoryEntry] = {}
        self._quarantine: dict[str, MemoryEntry] = {}

    # -- writes ------------------------------------------------------------

    def write(
        self,
        *,
        task_id: str,
        tenant: str,
        user: str,
        workflow: str,
        content: str,
        label: Label,
        privileged_workflow: bool = False,
    ) -> MemoryEntry:
        """Write a memory. Untrusted external content is quarantined.

        ``privileged_workflow`` is the writer's own claim; the guard
        does not believe it. The integrity label is what decides:
        anything at or below UNTRUSTED_EXTERNAL is staged.
        """
        entry = MemoryEntry(
            entry_id="mem_" + secrets.token_hex(6),
            tenant=tenant,
            user=user,
            workflow=workflow,
            content=content,
            label=label,
            quarantined=label.integrity <= Integrity.UNTRUSTED_EXTERNAL,
        )
        if entry.quarantined:
            self._quarantine[entry.entry_id] = entry
            self._audit.record(
                task_id=task_id,
                actor="memory_guard",
                event="memory_write_quarantined",
                notes=(
                    f"entry_id={entry.entry_id}",
                    f"reason=integrity={label.integrity.name} <= UNTRUSTED_EXTERNAL",
                    f"origin={label.origin}",
                ),
            )
        else:
            self._active[entry.entry_id] = entry
            self._audit.record(
                task_id=task_id,
                actor="memory_guard",
                event="memory_write_active",
                notes=(
                    f"entry_id={entry.entry_id}",
                    f"integrity={label.integrity.name}",
                    f"conf={label.confidentiality.name}",
                ),
            )
        return entry

    # -- reads -------------------------------------------------------------

    def read_for_task(
        self,
        *,
        task_id: str,
        tenant: str,
        user: str,
        workflow: str,
        privileged_workflow: bool,
        max_confidentiality: Confidentiality,
    ) -> list[MemoryEntry]:
        """Return memories the task is authorized to see.

        Partitioning rules from §11 checklist:
          - same tenant
          - same user (for user-private and above)
          - same workflow OR memory was written for any workflow with
            confidentiality at or below ``max_confidentiality``
          - never quarantined entries unless workflow is unprivileged
            (the §7.5 "memory staging" pattern says privileged
            workflows must not read staged memories)
        """
        results: list[MemoryEntry] = []
        for entry in self._active.values():
            if entry.tenant != tenant:
                continue
            if entry.label.confidentiality >= Confidentiality.USER_PRIVATE and entry.user != user:
                continue
            if entry.label.confidentiality > max_confidentiality:
                continue
            results.append(entry)
        self._audit.record(
            task_id=task_id,
            actor="memory_guard",
            event="memory_read",
            notes=(
                f"workflow={workflow}",
                f"privileged={privileged_workflow}",
                f"returned={len(results)}",
                "quarantine_excluded=True" if privileged_workflow else "quarantine_excluded=user_only",
            ),
        )
        return results

    # -- introspection (for demos / tests) ---------------------------------

    def quarantined(self) -> Iterator[MemoryEntry]:
        return iter(self._quarantine.values())

    def active(self) -> Iterator[MemoryEntry]:
        return iter(self._active.values())
