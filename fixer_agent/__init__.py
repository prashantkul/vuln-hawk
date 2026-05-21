"""Fixer Agent — auto-remediation for confirmed vulnerabilities.

Reads a vuln-hawk report, generates code fixes via sub-agents,
verifies them, and creates a pull request.

``root_agent`` is exposed lazily so tool submodules can be imported
without requiring the ``google-adk`` package.
"""

from __future__ import annotations

__all__ = ["root_agent"]


def __getattr__(name: str):
    if name == "root_agent":
        from fixer_agent.agent import root_agent

        return root_agent
    raise AttributeError(f"module 'fixer_agent' has no attribute {name!r}")
