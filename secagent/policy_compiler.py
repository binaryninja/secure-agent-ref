"""Task policy compiler — paper §7.1.

"The task policy compiler turns a user request into a structured
authorization envelope." This module is intentionally simple: a
dictionary of named workflows mapped to envelopes. A real deployment
would parse the user request with a separate small model, validate
the parse against an admin-approved workflow registry, and require
human approval for any workflow not on the registry.

The point that matters for the reference impl is *what an envelope
contains*: the §7.1 list — user, tenant, workflow type, resources in
scope, required tools, max side-effect level, allowed recipients, data
classes readable, data classes writable, code/network needs, approval
thresholds, expiration time. Everything downstream — the minter, the
policy engine, the broker — reads from this envelope. If the envelope
does not say a tool is needed, no capability is minted; if no
capability is minted, the broker fails closed (§4.4).
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from .labels import Confidentiality


class SideEffectLevel(IntEnum):
    """§11.2 risk hierarchy compressed into a maximum side-effect ceiling."""

    PURE_TRANSFORM = 0
    READ_PUBLIC = 1
    READ_PRIVATE = 2
    WRITE_PRIVATE = 3
    EXTERNAL_SEND = 4
    EXECUTE_CODE = 5
    ADMIN_MUTATE = 6
    FINANCIAL_LEGAL = 7


@dataclass(frozen=True)
class ToolGrant:
    """A request the policy compiler makes to the minter.

    The compiler does not mint capabilities; it describes what the
    task needs. The minter (§7.2) issues short-lived capabilities
    against this description, attenuated to the resources actually
    in scope.
    """

    tool: str
    action: str
    scope: dict[str, Any]
    notes: str = ""


@dataclass(frozen=True)
class TaskPolicy:
    """The §7.1 authorization envelope.

    Constructed once at task start; immutable for the life of the
    task. The broker, minter, policy engine, memory guard, and
    egress controller all read from this single object.
    """

    task_id: str
    user: str
    tenant: str
    workflow: str
    user_request: str
    resources_in_scope: tuple[str, ...]
    tool_grants: tuple[ToolGrant, ...]
    max_side_effect: SideEffectLevel
    allowed_recipients: tuple[str, ...]
    readable_data_classes: tuple[Confidentiality, ...]
    writable_data_classes: tuple[Confidentiality, ...]
    network_required: bool
    code_execution_required: bool
    approval_threshold: SideEffectLevel  # actions at or above this require human approval
    expires_at: float
    notes: tuple[str, ...] = ()


def compile_task(
    *,
    user: str,
    tenant: str,
    workflow: str,
    user_request: str,
    resources_in_scope: list[str],
    tool_grants: list[ToolGrant],
    max_side_effect: SideEffectLevel,
    allowed_recipients: list[str] | None = None,
    readable_data_classes: list[Confidentiality] | None = None,
    writable_data_classes: list[Confidentiality] | None = None,
    network_required: bool = False,
    code_execution_required: bool = False,
    approval_threshold: SideEffectLevel = SideEffectLevel.EXTERNAL_SEND,
    ttl_seconds: int = 600,
    notes: list[str] | None = None,
) -> TaskPolicy:
    """Build a TaskPolicy.

    Defaults are deliberately conservative: no recipients, only public
    data readable, no network, no code execution, approval required
    at EXTERNAL_SEND and above. The §7.1 example from the paper —
    "summarize open issues in acme/public-ui" — would call this with
    a single read tool grant, READ_PUBLIC ceiling, and no recipients.
    """
    return TaskPolicy(
        task_id="task_" + secrets.token_hex(6),
        user=user,
        tenant=tenant,
        workflow=workflow,
        user_request=user_request,
        resources_in_scope=tuple(resources_in_scope),
        tool_grants=tuple(tool_grants),
        max_side_effect=max_side_effect,
        allowed_recipients=tuple(allowed_recipients or ()),
        readable_data_classes=tuple(readable_data_classes or [Confidentiality.PUBLIC]),
        writable_data_classes=tuple(writable_data_classes or ()),
        network_required=network_required,
        code_execution_required=code_execution_required,
        approval_threshold=approval_threshold,
        expires_at=time.time() + ttl_seconds,
        notes=tuple(notes or ()),
    )
