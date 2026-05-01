"""Demo tools for the reference agent.

Each tool is intentionally small so the broker's enforcement chain
(``broker.invoke``) is visible end-to-end. Every tool exposes the
fields the ``Tool`` protocol in ``broker.py`` requires:

  - ``name``, ``version`` — identity and pin target
  - ``descriptor``        — *human-facing* documentation only
  - ``schema``            — the model-facing affordance
  - ``category``          — used by the policy engine to route rules
  - ``side_effect``       — used by the §7.1 ceiling check
  - ``validate(args)``    — schema check
  - ``run(args)``         — returns (result, label)

§9.4 split: ``descriptor`` is rendered into the planner prompt only
after sanitization. The schema is what the planner actually uses to
pick arguments. The reference impl's planner (``planner.py``) only
sees a sanitized name + schema, never the raw descriptor.
"""

from .github_tools import GitHubReadIssueTool, GitHubReadPrivateFileTool, GitHubCreatePublicPRTool
from .email_tools import ReadEmailTool, SendEmailTool
from .sandbox_tool import RunPythonTool
from .memory_tool import MemoryWriteTool, MemoryReadTool
from .web_tool import FetchPublicURLTool

__all__ = [
    "GitHubReadIssueTool",
    "GitHubReadPrivateFileTool",
    "GitHubCreatePublicPRTool",
    "ReadEmailTool",
    "SendEmailTool",
    "RunPythonTool",
    "MemoryWriteTool",
    "MemoryReadTool",
    "FetchPublicURLTool",
]
