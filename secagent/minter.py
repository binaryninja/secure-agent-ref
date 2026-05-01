"""Capability minting service — paper §7.2.

"The minting service issues short-lived capabilities and credentials.
It should prefer downstream-native scopes where possible." This
reference implementation only mints in-process Capability objects
because it has no real downstream services, but the comments mark
where a production deployment would call out to GitHub, IAM, or an
object store to obtain a fine-grained token.

The minter's policy: it only issues capabilities that are *named in
the task envelope*. If the task envelope did not request a tool, the
minter refuses, even if the call site asks. This is the §4.3
"minted per task" rule — no broad, ambient capability bag exists.
"""

from __future__ import annotations

import time
from typing import Any

from .audit import AuditLog
from .capabilities import Capability, CapabilitySet, _new_id
from .policy_compiler import TaskPolicy


class CapabilityMinter:
    """Issues per-task, short-lived capabilities against a TaskPolicy."""

    def __init__(self, audit: AuditLog) -> None:
        self._audit = audit

    def mint_for_task(self, policy: TaskPolicy) -> CapabilitySet:
        """Mint exactly the capabilities the task envelope requested.

        Each capability's TTL is the task expiry, not a fixed default,
        so capabilities cannot outlive their task (§4.3). In a real
        deployment this is also where you would call the downstream
        service — e.g. GitHub fine-grained token endpoint — so the
        bearer token never lives longer than the task.
        """
        caps: list[Capability] = []
        for grant in policy.tool_grants:
            cap = Capability(
                capability_id=_new_id(),
                task_id=policy.task_id,
                tool=grant.tool,
                action=grant.action,
                scope=dict(grant.scope),
                expires_at=policy.expires_at,
                notes=(f"task={policy.task_id}", f"workflow={policy.workflow}", grant.notes),
            )
            caps.append(cap)
            self._audit.record(
                task_id=policy.task_id,
                actor="minter",
                event="mint_capability",
                tool=grant.tool,
                action=grant.action,
                capability_id=cap.capability_id,
                notes=(f"scope={grant.scope}", f"ttl={int(policy.expires_at - time.time())}s"),
            )
        return CapabilitySet(task_id=policy.task_id, capabilities=tuple(caps))

    def attenuate(
        self,
        cap_set: CapabilitySet,
        capability_id: str,
        **scope_overrides: Any,
    ) -> CapabilitySet:
        """Narrow an existing capability and return an updated set.

        Used by the broker when a tool itself wants to hand off a
        narrower grant to a sub-step (e.g., a directory read grant
        attenuating to one path). Attenuation only narrows (§4.1) —
        the Capability.attenuate method enforces that.
        """
        for cap in cap_set.capabilities:
            if cap.capability_id == capability_id:
                narrower = cap.attenuate(**scope_overrides)
                self._audit.record(
                    task_id=cap.task_id,
                    actor="minter",
                    event="attenuate_capability",
                    tool=cap.tool,
                    action=cap.action,
                    capability_id=narrower.capability_id,
                    notes=(f"parent={cap.capability_id}", f"new_scope={narrower.scope}"),
                )
                return cap_set.with_added(narrower)
        raise KeyError(f"no capability {capability_id!r} in set")
