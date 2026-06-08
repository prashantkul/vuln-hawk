"""Fixer-agent security gateway.

Composes with the base vuln_agent security module but relaxes the
command denylist to permit ``git`` operations (needed for branching,
committing, and PR creation).  All other constraints — credential
scrubbing, output truncation, path-escape detection, rate limits —
are inherited unchanged.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

from vuln_agent.security import (
    ARG_DENYLIST_PATTERNS,
    CREDENTIAL_PATTERNS,
    MAX_OUTPUT_BYTES,
    _check_code_snippet,
    _scrub_output,
)

MAX_CALLS_PER_SESSION = int(os.environ.get("VULN_AGENT_MAX_TOOL_CALLS", "2500"))

FIXER_COMMAND_DENYLIST = frozenset([
    "curl", "wget", "nc", "netcat", "ncat", "docker", "podman",
    "ssh", "scp", "sftp", "pip", "pip3", "npm", "yarn",
])

_call_count = 0
_denied_count = 0


def reset_session() -> None:
    global _call_count, _denied_count
    _call_count = 0
    _denied_count = 0


def _target_root() -> Path:
    root = os.environ.get("TARGET_CODEBASE_ROOT")
    if root:
        return Path(root).resolve()
    default = Path(__file__).resolve().parent.parent / "targets" / "vulnerable_flask_app"
    return default.resolve()


def _path_in_target(filepath: str) -> bool:
    root = _target_root()
    try:
        resolved = (root / filepath).resolve()
        resolved.relative_to(root)
        return True
    except (ValueError, OSError):
        return False


def before_tool_callback(tool, args, tool_context) -> Optional[dict]:
    global _call_count, _denied_count

    _call_count += 1

    if _call_count > MAX_CALLS_PER_SESSION:
        _denied_count += 1
        return {"status": "error", "error": f"Session tool call limit exceeded ({MAX_CALLS_PER_SESSION})"}

    tool_name = tool.name if hasattr(tool, "name") else str(tool)

    if tool_name == "run_python_snippet":
        code = args.get("code", "")
        result = _check_code_snippet(code)
        if result:
            _denied_count += 1
            return result

    if tool_name == "search_code":
        pattern = args.get("pattern", "")
        for cred_pattern in CREDENTIAL_PATTERNS:
            if cred_pattern.search(pattern):
                _denied_count += 1
                return {"status": "error", "error": "Credential pattern in search query"}

    if tool_name in ("write_file", "apply_fix"):
        filepath = args.get("filepath", "")
        if not filepath:
            _denied_count += 1
            return {"status": "error", "error": "filepath is required"}
        if not _path_in_target(filepath):
            _denied_count += 1
            return {"status": "error", "error": f"Path escapes target root: {filepath}"}

    if tool_name == "git_commit":
        files = args.get("files", "")
        file_list = files.split(",") if isinstance(files, str) else (files or [])
        for f in file_list:
            f = f.strip()
            if f and not _path_in_target(f):
                _denied_count += 1
                return {"status": "error", "error": f"File escapes target root: {f}"}

    if tool_name == "create_fix_branch":
        branch_name = args.get("branch_name", "")
        if not re.match(r"^[a-zA-Z0-9/_.-]+$", branch_name):
            _denied_count += 1
            return {"status": "error", "error": f"Invalid branch name: {branch_name}"}

    if tool_name == "run_target_tests":
        command = args.get("command", "")
        if command:
            first_word = command.split()[0] if command.split() else ""
            basename = os.path.basename(first_word)
            for blocked in FIXER_COMMAND_DENYLIST:
                if blocked in command.lower():
                    _denied_count += 1
                    return {"status": "error", "error": f"Blocked command in test runner: {blocked}"}

    for key, val in args.items():
        if not isinstance(val, str):
            continue
        for pattern in ARG_DENYLIST_PATTERNS:
            if pattern.search(val):
                _denied_count += 1
                return {"status": "error", "error": "Blocked pattern in tool argument"}

    return None


def after_tool_callback(tool, args, tool_context, tool_response) -> Optional[dict]:
    return _scrub_output(tool_response)


def on_tool_error_callback(tool, args, tool_context, error) -> Optional[dict]:
    return {"status": "error", "error": f"Tool execution failed: {type(error).__name__}: {error}"}
