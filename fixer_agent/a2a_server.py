"""Expose the fixer agent as an A2A (Agent-to-Agent) server.

Run with:
    uvicorn fixer_agent.a2a_server:app --host 0.0.0.0 --port 8001

The vuln_agent can then call this via RemoteA2aAgent pointed at
http://localhost:8001/.well-known/agent.json
"""

from __future__ import annotations

import os

from google.adk.a2a.utils.agent_to_a2a import to_a2a

from fixer_agent.agent import root_agent

_host = os.environ.get("VULN_AGENT_FIXER_A2A_HOST", "localhost")
_port = int(os.environ.get("VULN_AGENT_FIXER_A2A_PORT", "8001"))

app = to_a2a(
    root_agent,
    host=_host,
    port=_port,
    protocol="http",
)
