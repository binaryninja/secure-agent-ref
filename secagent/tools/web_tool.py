"""Public-URL fetch — used by the read-only research agent (paper §8.1).

Returns deterministic canned content so demos do not depend on the
internet. The label is PUBLIC + UNTRUSTED_EXTERNAL: anything from
the web is attacker-capable for integrity, public for confidentiality.
"""

from __future__ import annotations

from typing import Any

from ..labels import Confidentiality, Integrity, Label
from ..policy_compiler import SideEffectLevel


class FetchPublicURLTool:
    name = "web.fetch_public"
    version = "1.0.0"
    descriptor = "Fetch a public webpage and return its text."
    category = "read_public"
    side_effect = SideEffectLevel.READ_PUBLIC
    schema = {"url": str}

    def __init__(self, fixtures: dict[str, str] | None = None) -> None:
        self._fixtures = fixtures or {
            "https://example.com/paper-summary": (
                "The paper argues that the LLM planner should be treated "
                "as untrusted and that authorization belongs in deterministic "
                "policy outside the model."
            ),
        }

    def validate(self, args: dict[str, Any]) -> None:
        if not isinstance(args.get("url"), str):
            raise ValueError("url required")
        if not args["url"].startswith(("http://", "https://")):
            raise ValueError("url must be http/https")

    def run(self, args: dict[str, Any], context=None) -> tuple[str, Label]:
        body = self._fixtures.get(args["url"], f"(no fixture for {args['url']})")
        label = Label(
            confidentiality=Confidentiality.PUBLIC,
            integrity=Integrity.UNTRUSTED_EXTERNAL,
            origin=f"web.public:{args['url']}",
            purpose="-",
        )
        return body, label
