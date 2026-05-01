"""Information-flow labels — paper §5.1.

Every datum that enters the planner's context — tool result, retrieval
chunk, memory entry, user message — carries a Label. The label is the
substrate that lets the policy engine reason about flows from sources
to sinks (§5, §7.4).

Confidentiality answers "who may see this." Integrity answers "how
much should we trust this to influence decisions." Origin records
where it came from so an auditor can reconstruct the path. Purpose
binds the label to the task that read it (§4.2).

Labels join (the lub) when data is mixed: a string built from a
public web page and a tenant-private record is tenant-private, and
its integrity is the *minimum* of its inputs, not the maximum. This
is the standard taint-tracking semantics — taint only ever spreads.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Iterable


class Confidentiality(IntEnum):
    """§5.1 confidentiality lattice. Higher = more sensitive."""

    PUBLIC = 0
    INTERNAL = 1
    USER_PRIVATE = 2
    TENANT_PRIVATE = 3
    SECRET = 4


class Integrity(IntEnum):
    """§5.1 integrity lattice. Higher = more trustworthy.

    Note the inversion: ATTACKER_CONTROLLED is the *least* trusted, so
    it has the lowest value. The IFC rule "low-integrity content cannot
    control high-impact actions" (§5.2, §11.5) becomes a numeric check.
    """

    ATTACKER_CONTROLLED = 0
    UNTRUSTED_EXTERNAL = 1
    TOOL_TRUSTED = 2
    USER_TRUSTED = 3
    SYSTEM_TRUSTED = 4


@dataclass(frozen=True)
class Label:
    """An immutable IFC label attached to a piece of data.

    Frozen so that propagation cannot accidentally mutate a parent
    label. Use ``join`` to combine two labels under taint semantics.
    """

    confidentiality: Confidentiality
    integrity: Integrity
    origin: str  # e.g. "github.public_issue:acme/ui#42", "user_input"
    purpose: str  # task id this datum was read under
    created_at: float = field(default_factory=time.time)
    expires_at: float | None = None  # §5.1 lifetime
    notes: tuple[str, ...] = ()

    def is_expired(self, now: float | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) >= self.expires_at

    def join(self, other: "Label") -> "Label":
        """Combine two labels using lattice join semantics.

        Confidentiality climbs to the *higher* level (more sensitive
        wins). Integrity falls to the *lower* level (less trusted
        wins). Origin and purpose accumulate so the audit log can
        reconstruct provenance (§11.6).
        """
        return Label(
            confidentiality=Confidentiality(
                max(self.confidentiality, other.confidentiality)
            ),
            integrity=Integrity(min(self.integrity, other.integrity)),
            origin=f"{self.origin}+{other.origin}",
            purpose=self.purpose if self.purpose == other.purpose else f"{self.purpose}+{other.purpose}",
            expires_at=_min_expiry(self.expires_at, other.expires_at),
            notes=tuple(set(self.notes + other.notes)),
        )


def join_all(labels: Iterable[Label]) -> Label | None:
    """Fold ``join`` over an iterable of labels. Returns None if empty."""
    out: Label | None = None
    for lab in labels:
        out = lab if out is None else out.join(lab)
    return out


def _min_expiry(a: float | None, b: float | None) -> float | None:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def public_label(origin: str, purpose: str) -> Label:
    """Convenience for the common "fetched from a public source" case."""
    return Label(
        confidentiality=Confidentiality.PUBLIC,
        integrity=Integrity.UNTRUSTED_EXTERNAL,
        origin=origin,
        purpose=purpose,
    )


def user_request_label(purpose: str) -> Label:
    """The user's own request is trusted but its content is still data.

    Per CaMeL (§5.2), the trusted query may set control flow but the
    rest of the planner context cannot. We mark user requests as
    USER_TRUSTED + INTERNAL, which keeps them above the
    untrusted-external threshold used by the §11.5 IFC rule.
    """
    return Label(
        confidentiality=Confidentiality.INTERNAL,
        integrity=Integrity.USER_TRUSTED,
        origin="user_request",
        purpose=purpose,
    )


def attenuate(label: Label, **changes) -> Label:
    """Return a copy of ``label`` with the given fields changed.

    Used by tools that want to *raise* confidentiality or *lower*
    integrity on a derived value — e.g. a webpage that the connector
    knows is attacker-influenced should drop to ATTACKER_CONTROLLED.
    """
    return replace(label, **changes)
