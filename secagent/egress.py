"""Output and egress control — paper §7.6 and §11.

"A secure runtime treats every external write as a sink. It applies
IFC before the write, scans for secrets, enforces destination
allowlists, and records an audit event." This module is the
secret/PII scanner the broker calls just before a sink fires.

The §7.6 list of sinks is broader than HTTP: emails, chat messages,
pull requests, issue comments, calendar invites, image URLs,
webhooks, DNS queries, package names, commit messages, file names,
browser navigation, tool error messages, public logs. The broker
classifies each tool with a category (see ``broker.py``); this module
is the content-side check that catches secrets sneaking out
regardless of the destination allowlist.

The destination allowlist itself lives in the task policy
(``allowed_recipients``) and is enforced by
``rule_external_send_recipient_allowlist`` in ``policy_engine.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Patterns are deliberately simple so the demos remain readable. A
# production deployment would use a proper secret scanner (gitleaks,
# trufflehog) and PII classifier — the §11.6 audit fields are the
# same either way.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("slack_token", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    # Beacon-shaped URL: image src that looks like an exfil hop. Paper
    # §7.6 lists "image URLs" explicitly as a sink class.
    ("beacon_url", re.compile(r"https?://[^\s]*[?&](data|leak|token|payload)=", re.IGNORECASE)),
)


@dataclass(frozen=True)
class ScanFinding:
    pattern: str
    excerpt: str  # short snippet around the match


def scan_for_secrets(content: str) -> list[ScanFinding]:
    """Return findings for each secret-like pattern in ``content``.

    Used by the broker just before a sink fires. The presence of any
    finding flips the broker decision to deny (§7.6: "scans for secrets
    [...] before the write").
    """
    findings: list[ScanFinding] = []
    for name, pat in _SECRET_PATTERNS:
        m = pat.search(content)
        if m:
            start = max(0, m.start() - 12)
            end = min(len(content), m.end() + 12)
            findings.append(ScanFinding(pattern=name, excerpt=content[start:end]))
    return findings


def is_destination_allowed(destination: str, allowlist: tuple[str, ...]) -> bool:
    """Strict membership. The policy engine has the same check; this
    helper exists so a tool implementation can fail fast before
    constructing a payload.
    """
    return destination in allowlist
