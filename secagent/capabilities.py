"""Object capabilities — paper §4.

A capability is an "unforgeable grant to perform an operation on a
resource" (§4 opening). In agent systems they should be:

  - explicit  — the planner receives a handle, not ambient access
  - narrow    — bounded by resource scope (one repo, not all repos)
  - attenuable — a broad grant can be narrowed but never widened
  - expiring   — TTLs in minutes, not hours (§4.3, §11 checklist)
  - auditable  — every grant carries the task that requested it

This module defines ``Capability`` and the rules for attenuation.
The minter (``minter.py``) is what actually issues them. The broker
(``broker.py``) is what checks them on every tool call.

The unforgeability story in this reference impl is "the broker only
honors Capability objects it received from the minter." A real
deployment would back this with downstream-native scopes (fine-grained
GitHub tokens, IAM session policies, signed URLs — §7.2) so that even
if the broker is bypassed the downstream service fails closed.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field, replace
from typing import Any


@dataclass(frozen=True)
class Capability:
    """A narrow, expiring, task-scoped grant.

    The combination of ``tool``, ``action``, and ``scope`` names exactly
    one operation on one resource (§4.1). ``task_id`` binds the grant
    to a single user request (§4.3). ``expires_at`` enforces short
    lifetimes (§4.3, §11 checklist).
    """

    capability_id: str  # opaque, unique; used by the audit log
    task_id: str  # which compiled task policy minted this
    tool: str  # e.g. "github.read_file"
    action: str  # e.g. "read", "send", "exec"
    scope: dict[str, Any]  # e.g. {"repo": "acme/public-ui", "branch": "main"}
    expires_at: float  # unix seconds
    notes: tuple[str, ...] = ()  # human-readable provenance, e.g. "minted for: summarize issues"
    parent_id: str | None = None  # if produced by attenuate()

    def is_expired(self, now: float | None = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at

    def attenuate(self, **scope_overrides: Any) -> "Capability":
        """Return a strictly narrower capability.

        Per §4.1, "a handle can be attenuated: a broad repository read
        grant can be narrowed to one path." This helper only allows
        overriding existing scope keys — it cannot add new keys, since
        that would widen rather than narrow.
        """
        for key in scope_overrides:
            if key not in self.scope:
                raise ValueError(
                    f"attenuate cannot widen scope: key {key!r} not present in parent"
                )
        new_scope = {**self.scope, **scope_overrides}
        return replace(
            self,
            capability_id=_new_id(),
            scope=new_scope,
            parent_id=self.capability_id,
            notes=self.notes + (f"attenuated_from={self.capability_id}",),
        )

    def covers(self, tool: str, action: str, args: dict[str, Any]) -> tuple[bool, str]:
        """Is this capability sufficient for the proposed call?

        Returns (ok, reason). The broker uses this on every call. The
        check has three parts: tool/action match, scope containment,
        and not-yet-expired. Any mismatch fails closed (§4.4).
        """
        if self.is_expired():
            return False, f"capability {self.capability_id} expired"
        if self.tool != tool:
            return False, f"capability is for {self.tool!r}, not {tool!r}"
        if self.action != action:
            return False, f"capability allows {self.action!r}, not {action!r}"
        for key, allowed in self.scope.items():
            if key not in args:
                return False, f"call missing scoped argument {key!r}"
            if not _scope_contains(allowed, args[key]):
                return False, f"argument {key}={args[key]!r} outside scope {allowed!r}"
        return True, "ok"


def _scope_contains(allowed: Any, requested: Any) -> bool:
    """Is ``requested`` within ``allowed``?

    Supported shapes:
      - exact equality
      - allowed is a list/tuple/set: requested must be a member
      - allowed is a dict {"prefix": "..."}: requested must startswith
      - allowed is a dict {"max": N}: requested must be <= N
      - allowed is a dict {"in": [...]}: requested must be a member
    """
    if isinstance(allowed, (list, tuple, set)):
        return requested in allowed
    if isinstance(allowed, dict):
        if "prefix" in allowed:
            return isinstance(requested, str) and requested.startswith(allowed["prefix"])
        if "max" in allowed:
            try:
                return float(requested) <= float(allowed["max"])
            except (TypeError, ValueError):
                return False
        if "in" in allowed:
            return requested in allowed["in"]
        return allowed == requested
    return allowed == requested


def _new_id() -> str:
    return "cap_" + secrets.token_hex(6)


@dataclass(frozen=True)
class CapabilitySet:
    """The bag of capabilities a task holds.

    The planner never sees this directly. It sees the *names* of
    available tools (rendered through descriptor sanitization, §9.4)
    and proposes calls; the broker matches the call against the set.
    """

    task_id: str
    capabilities: tuple[Capability, ...] = field(default_factory=tuple)

    def find(self, tool: str, action: str) -> tuple[Capability, ...]:
        return tuple(c for c in self.capabilities if c.tool == tool and c.action == action and not c.is_expired())

    def with_added(self, *caps: Capability) -> "CapabilitySet":
        return CapabilitySet(task_id=self.task_id, capabilities=self.capabilities + caps)
