"""Memory write/read tools — wrap ``MemoryGuard``.

Surfaced to the planner so a demo can show the §11 checklist
"authorize and label every memory write; quarantine externally
influenced memories" path. The MemoryGuard is the actual enforcer;
these tools are just thin adapters.
"""

from __future__ import annotations

from typing import Any

from ..labels import Confidentiality, Integrity, Label
from ..memory import MemoryEntry, MemoryGuard
from ..policy_compiler import SideEffectLevel


class MemoryWriteTool:
    name = "memory.write"
    version = "1.0.0"
    descriptor = "Persist a fact into long-term memory for this user/workflow."
    category = "memory_write"
    side_effect = SideEffectLevel.WRITE_PRIVATE
    schema = {"content": str, "workflow": str}

    def __init__(
        self,
        guard: MemoryGuard,
        *,
        task_id: str,
        tenant: str,
        user: str,
    ) -> None:
        self._guard = guard
        self._task_id = task_id
        self._tenant = tenant
        self._user = user

    def validate(self, args: dict[str, Any]) -> None:
        if not isinstance(args.get("content"), str):
            raise ValueError("content must be str")
        if not isinstance(args.get("workflow"), str):
            raise ValueError("workflow must be str")

    def run(self, args: dict[str, Any], context=None) -> tuple[MemoryEntry, Label]:
        # The label written to memory is the joined provenance the
        # broker computed across all argument labels (§5.1). The guard
        # then decides whether to quarantine based on integrity.
        label = context.args_label if context and context.args_label else Label(
            confidentiality=Confidentiality.USER_PRIVATE,
            integrity=Integrity.UNTRUSTED_EXTERNAL,  # default to untrusted if no provenance
            origin="memory.write:no_provenance",
            purpose=self._task_id,
        )
        entry = self._guard.write(
            task_id=self._task_id,
            tenant=self._tenant,
            user=self._user,
            workflow=args["workflow"],
            content=args["content"],
            label=label,
        )
        return entry, label


class MemoryReadTool:
    name = "memory.read"
    version = "1.0.0"
    descriptor = "Read curated memory entries for the current task."
    category = "read_private"
    side_effect = SideEffectLevel.READ_PRIVATE
    schema = {"workflow": str, "privileged": bool}

    def __init__(
        self,
        guard: MemoryGuard,
        *,
        task_id: str,
        tenant: str,
        user: str,
    ) -> None:
        self._guard = guard
        self._task_id = task_id
        self._tenant = tenant
        self._user = user

    def validate(self, args: dict[str, Any]) -> None:
        if not isinstance(args.get("workflow"), str):
            raise ValueError("workflow required")
        if not isinstance(args.get("privileged"), bool):
            raise ValueError("privileged must be bool")

    def run(self, args: dict[str, Any], context=None) -> tuple[list[MemoryEntry], Label]:
        entries = self._guard.read_for_task(
            task_id=self._task_id,
            tenant=self._tenant,
            user=self._user,
            workflow=args["workflow"],
            privileged_workflow=args["privileged"],
            max_confidentiality=Confidentiality.USER_PRIVATE,
        )
        # The label on the *result list* is the join of the entries.
        # If empty, default to USER_PRIVATE/TOOL_TRUSTED so the broker
        # still has a label to reason about.
        if entries:
            label = entries[0].label
            for e in entries[1:]:
                label = label.join(e.label)
        else:
            label = Label(
                confidentiality=Confidentiality.USER_PRIVATE,
                integrity=Integrity.TOOL_TRUSTED,
                origin="memory.empty",
                purpose=self._task_id,
            )
        return entries, label
