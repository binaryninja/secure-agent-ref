"""Scripted planner — paper §1, §3.1.

The paper's central design move is to treat the planner as untrusted
(§13: "treat the LLM planner as untrusted"). The reference impl
takes that to its logical conclusion: there is no LLM here, only a
hand-written sequence of tool calls. This is *not* a limitation —
it is precisely how the controls should work. If the broker can deny
attacker actions when the "planner" is a worst-case adversary, it
can deny them when the planner is a confused frontier model.

Two scripted planners are provided:

  - ``BenignPlanner``: the legitimate sequence for a task.
  - ``HijackedPlanner``: a sequence representing what an injected
    LLM might propose after reading attacker text. This is the
    "compromised until proven otherwise" stance from §13.

Demos pick whichever planner fits the scenario.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator

from .labels import Label


@dataclass(frozen=True)
class ProposedCall:
    """One step the planner wants the broker to invoke.

    ``arg_labels`` is filled in by the caller after a tool returns —
    the planner itself does not assign labels; connectors do. The
    field exists on the proposed call because in real systems the
    planner picks arguments from previously read data, and the
    broker must know which provenance came along for the ride.
    """

    tool: str
    action: str
    args: dict[str, Any]
    arg_labels: dict[str, Label] = field(default_factory=dict)
    sink_destination: str | None = None
    note: str = ""


@dataclass
class ScriptedPlanner:
    """Iterates over a pre-written list of proposed calls.

    ``feedback`` is how a demo plumbs labels learned from earlier
    calls back into later ones. ``next_call`` returns ``None`` when
    the script is exhausted.
    """

    script: list[ProposedCall]
    cursor: int = 0

    def next_call(self) -> ProposedCall | None:
        if self.cursor >= len(self.script):
            return None
        call = self.script[self.cursor]
        self.cursor += 1
        return call

    def feedback(self, key: str, label: Label) -> None:
        """Plumb a learned label into the *next* proposed call.

        The demo decides which arg name (``key``) inherits the label.
        This represents the case where a planner constructs a tool
        argument by quoting earlier tool output.
        """
        if self.cursor < len(self.script):
            upcoming = self.script[self.cursor]
            upcoming.arg_labels[key] = label
