"""secagent — Reference implementation of the controls described in
"Sandboxing and Capability Control for Tool-Using Autonomous Agents."

This is reference quality, not production quality. The goal is that an
engineer can read each module alongside the paper and see exactly what
control it implements. Module-level docstrings cite the paper section
they correspond to.

The paper's central thesis: the LLM planner is untrusted. Authorization
must live in deterministic policy outside the model. This package never
imports an LLM client — the "planner" is a scripted sequence, which is
sufficient because the controls do not depend on what the planner is.
"""

__version__ = "0.1.0"
