"""Write-capable tool primitives for the fixer agent.

Read-only tools (read_file, search_code, analyze_python_ast,
list_directory) are imported directly from vuln_agent.tools.
This module adds the mutating tools: file writing, git operations,
test execution, and PR creation.

All paths are resolved relative to TARGET_CODEBASE_ROOT and
validated to prevent escapes.
"""

from __future__ import annotations

import ast
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from vuln_agent.config import REPO_ROOT
from vuln_agent.tools import (
    _safe_resolve,
    _target_root,
    analyze_python_ast,
    list_directory,
    read_file,
    search_code,
)


def load_report(report_path: str = "") -> dict:
    """Load a vulnerability report from a file path. Accepts absolute paths
    or paths relative to the vuln-hawk repo root. Use this to ingest a
    report for fix generation — do NOT upload files as attachments.

    Args:
        report_path: REQUIRED. Path to the report JSON file.
            Examples:
              "eval/results/claude-pygoat-report-20260516.json"
              "/absolute/path/to/report.json"

    Returns:
        dict with 'status', 'summary', 'findings' (list), and 'total_findings'.
    """
    if not report_path:
        return {"status": "error", "error": "report_path is required. Provide the path to a report JSON file."}

    path = Path(report_path)
    if not path.is_absolute():
        path = REPO_ROOT / report_path
    path = path.resolve()

    if not path.exists():
        return {"status": "error", "error": f"Report file not found: {report_path}"}

    try:
        from vuln_agent.report import from_json_file
        report = from_json_file(path)
    except Exception as exc:
        return {"status": "error", "error": f"Failed to parse report: {exc}"}

    if report.parse_error:
        return {"status": "error", "error": f"Report parse error: {report.parse_error}"}

    findings_dicts = []
    for f in report.findings:
        findings_dicts.append({
            "id": f.id,
            "vuln_class": f.vuln_class,
            "file": f.file,
            "function": f.function,
            "line_range": f.line_range,
            "severity": f.severity,
            "confidence": f.confidence,
            "data_flow": f.data_flow,
            "suggested_fix": f.suggested_fix,
            "poc_request": f.proof_of_concept.request,
            "poc_validated": f.proof_of_concept.live_validated,
        })

    return {
        "status": "ok",
        "summary": report.summary,
        "findings": findings_dicts,
        "total_findings": len(findings_dicts),
    }


def write_file(
    filepath: str = "",
    content: str = "",
    start_line: int = -1,
    end_line: int = -1,
) -> dict:
    """Write content to a file in the target codebase. When start_line and
    end_line are provided, only those lines are replaced (surgical edit).
    Otherwise the entire file is overwritten.

    Args:
        filepath: REQUIRED. Path relative to the target codebase root.
        content: REQUIRED. The content to write.
        start_line: Starting line number for surgical replacement (1-indexed).
            Use -1 to overwrite the entire file.
        end_line: Ending line number for surgical replacement (inclusive).
            Use -1 to overwrite the entire file.

    Returns:
        dict with 'status' and a unified diff of the change.
    """
    if not filepath:
        return {"status": "error", "error": "filepath is required"}
    if not content and content != "":
        return {"status": "error", "error": "content is required"}

    resolved = _safe_resolve(filepath)
    if resolved is None:
        return {"status": "error", "error": f"Path escapes target root: {filepath}"}

    resolved.parent.mkdir(parents=True, exist_ok=True)

    if start_line > 0 and end_line > 0:
        if not resolved.exists():
            return {"status": "error", "error": f"File does not exist for surgical edit: {filepath}"}
        old_text = resolved.read_text(encoding="utf-8", errors="replace")
        old_lines = old_text.splitlines(keepends=True)
        total = len(old_lines)
        s = max(1, start_line) - 1
        e = min(total, end_line)
        new_content_lines = content.splitlines(keepends=True)
        if new_content_lines and not new_content_lines[-1].endswith("\n"):
            new_content_lines[-1] += "\n"
        new_lines = old_lines[:s] + new_content_lines + old_lines[e:]
        new_text = "".join(new_lines)
    else:
        old_text = resolved.read_text(encoding="utf-8", errors="replace") if resolved.exists() else ""
        new_text = content
        if new_text and not new_text.endswith("\n"):
            new_text += "\n"

    resolved.write_text(new_text, encoding="utf-8")

    import difflib
    diff = "".join(difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=f"a/{filepath}",
        tofile=f"b/{filepath}",
    ))

    return {"status": "ok", "filepath": filepath, "diff": diff or "(no changes)"}


def apply_fix(
    filepath: str = "",
    original_code: str = "",
    fixed_code: str = "",
) -> dict:
    """Find-and-replace original_code with fixed_code in a file.
    Safer than line-based replacement when the exact code to replace is
    known.

    Args:
        filepath: REQUIRED. Path relative to the target codebase root.
        original_code: REQUIRED. The exact code snippet to find and replace.
        fixed_code: REQUIRED. The replacement code.

    Returns:
        dict with 'status' and a unified diff of the change.
    """
    if not filepath:
        return {"status": "error", "error": "filepath is required"}
    if not original_code:
        return {"status": "error", "error": "original_code is required"}

    resolved = _safe_resolve(filepath)
    if resolved is None:
        return {"status": "error", "error": f"Path escapes target root: {filepath}"}
    if not resolved.exists():
        return {"status": "error", "error": f"File does not exist: {filepath}"}

    old_text = resolved.read_text(encoding="utf-8", errors="replace")

    if original_code not in old_text:
        original_stripped = "\n".join(line.rstrip() for line in original_code.splitlines())
        old_stripped = "\n".join(line.rstrip() for line in old_text.splitlines())
        if original_stripped not in old_stripped:
            return {
                "status": "error",
                "error": "original_code not found in file. Read the file first to get the exact content.",
            }
        lines = old_text.splitlines(keepends=True)
        stripped_lines = [line.rstrip() + "\n" for line in lines]
        old_stripped_text = "".join(stripped_lines)
        new_stripped_text = old_stripped_text.replace(original_stripped + "\n", fixed_code.rstrip() + "\n", 1)
        orig_idx = old_stripped_text.index(original_stripped)
        char_count = 0
        start_line = 0
        for i, line in enumerate(stripped_lines):
            if char_count >= orig_idx:
                start_line = i
                break
            char_count += len(line)
        new_text = new_stripped_text
    else:
        new_text = old_text.replace(original_code, fixed_code, 1)

    resolved.write_text(new_text, encoding="utf-8")

    import difflib
    diff = "".join(difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=f"a/{filepath}",
        tofile=f"b/{filepath}",
    ))

    return {"status": "ok", "filepath": filepath, "diff": diff or "(no changes)"}


def check_syntax(filepath: str = "") -> dict:
    """Check that a Python file has valid syntax using ast.parse.

    Args:
        filepath: REQUIRED. Path relative to the target codebase root.

    Returns:
        dict with 'status' ('ok' or 'error') and optional 'error' message.
    """
    if not filepath:
        return {"status": "error", "error": "filepath is required"}

    resolved = _safe_resolve(filepath)
    if resolved is None:
        return {"status": "error", "error": f"Path escapes target root: {filepath}"}
    if not resolved.exists():
        return {"status": "error", "error": f"File does not exist: {filepath}"}

    try:
        source = resolved.read_text(encoding="utf-8", errors="replace")
        ast.parse(source, filename=filepath)
        return {"status": "ok", "filepath": filepath, "message": "Syntax valid"}
    except SyntaxError as exc:
        return {
            "status": "error",
            "filepath": filepath,
            "error": f"Syntax error at line {exc.lineno}: {exc.msg}",
        }


def _verify_git_root() -> dict | None:
    """Verify TARGET_CODEBASE_ROOT is the root of its own git repo, not a
    subdirectory of a parent repo (like vuln-hawk itself).  Returns an
    error dict if the check fails, or None if OK."""
    root = _target_root()

    check = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True, cwd=str(root),
    )
    if check.returncode != 0:
        return {"status": "error", "error": f"Target directory is not inside a git repository: {root}"}

    toplevel = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, cwd=str(root),
    )
    git_root = Path(toplevel.stdout.strip()).resolve()

    if git_root != root:
        return {
            "status": "error",
            "error": (
                f"TARGET_CODEBASE_ROOT ({root}) is a subdirectory of "
                f"another git repo ({git_root}). The fixer agent would "
                f"create branches/commits in that parent repo instead of "
                f"the target. Set TARGET_CODEBASE_ROOT to an independent "
                f"git repository (clone the target repo to a separate "
                f"directory first)."
            ),
        }
    return None


def create_fix_branch(branch_name: str = "", base_ref: str = "HEAD") -> dict:
    """Create a new git branch for the fixes in the target repository.

    Args:
        branch_name: REQUIRED. Branch name (alphanumeric, hyphens, slashes,
            dots, underscores only).
        base_ref: Git ref to branch from. Defaults to HEAD.

    Returns:
        dict with 'status' and 'branch_name'.
    """
    if not branch_name:
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S")
        prefix = os.environ.get("VULN_AGENT_FIXER_BRANCH_PREFIX", "vuln-hawk/auto-fix")
        branch_name = f"{prefix}-{ts}"

    if not re.match(r"^[a-zA-Z0-9/_.\-]+$", branch_name):
        return {"status": "error", "error": f"Invalid branch name: {branch_name}"}

    root = _target_root()

    err = _verify_git_root()
    if err:
        return err

    status = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True, text=True, cwd=str(root),
    )
    if status.stdout.strip():
        return {
            "status": "error",
            "error": "Working tree has uncommitted changes. Commit or stash them first.",
        }

    result = subprocess.run(
        ["git", "checkout", "-b", branch_name, base_ref],
        capture_output=True, text=True, cwd=str(root),
    )
    if result.returncode != 0:
        return {"status": "error", "error": f"git checkout -b failed: {result.stderr.strip()}"}

    return {"status": "ok", "branch_name": branch_name, "message": f"Created branch {branch_name}"}


def git_commit(files: str = "", message: str = "") -> dict:
    """Stage specific files and create a git commit in the target repository.

    Args:
        files: REQUIRED. Comma-separated list of file paths relative to the
            target codebase root.
        message: REQUIRED. Commit message.

    Returns:
        dict with 'status', 'commit_sha', and 'message'.
    """
    if not files:
        return {"status": "error", "error": "files is required (comma-separated paths)"}
    if not message:
        return {"status": "error", "error": "message is required"}

    root = _target_root()
    err = _verify_git_root()
    if err:
        return err

    file_list = [f.strip() for f in files.split(",") if f.strip()]

    for f in file_list:
        resolved = _safe_resolve(f)
        if resolved is None:
            return {"status": "error", "error": f"File escapes target root: {f}"}

    add_result = subprocess.run(
        ["git", "add"] + file_list,
        capture_output=True, text=True, cwd=str(root),
    )
    if add_result.returncode != 0:
        return {"status": "error", "error": f"git add failed: {add_result.stderr.strip()}"}

    commit_result = subprocess.run(
        ["git", "commit", "-m", message],
        capture_output=True, text=True, cwd=str(root),
    )
    if commit_result.returncode != 0:
        return {"status": "error", "error": f"git commit failed: {commit_result.stderr.strip()}"}

    sha_result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, cwd=str(root),
    )
    sha = sha_result.stdout.strip()[:12]

    return {"status": "ok", "commit_sha": sha, "message": f"Committed {len(file_list)} file(s): {sha}"}


def git_diff(filepath: str = "") -> dict:
    """Show the git diff for the target repository or a specific file.

    Args:
        filepath: Optional. Path relative to target root. If empty, shows
            all uncommitted changes.

    Returns:
        dict with 'status' and 'diff'.
    """
    root = _target_root()
    cmd = ["git", "diff"]
    if filepath:
        resolved = _safe_resolve(filepath)
        if resolved is None:
            return {"status": "error", "error": f"Path escapes target root: {filepath}"}
        cmd.extend(["--", filepath])

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(root))
    return {"status": "ok", "diff": result.stdout or "(no changes)"}


_SAFE_TEST_MODULES = frozenset(["pytest", "unittest", "nose2", "tox", "trial"])

_STANDALONE_RUNNERS = frozenset(["pytest", "tox", "nose2", "trial"])


def _validate_test_command(command: str) -> str | None:
    """Validate that a command matches a known test runner pattern.
    Returns an error message if invalid, None if OK."""
    import shlex
    try:
        parts = shlex.split(command)
    except ValueError:
        return f"Unparseable command: {command}"
    if not parts:
        return "Empty command"
    executable = os.path.basename(parts[0])

    if executable in _STANDALONE_RUNNERS:
        return None

    is_python = executable in ("python", "python3") or executable == os.path.basename(sys.executable)
    if is_python and len(parts) >= 3:
        if parts[1] == "-m" and parts[2] in _SAFE_TEST_MODULES:
            return None
        if os.path.basename(parts[1]) == "manage.py" and len(parts) >= 3 and parts[2] == "test":
            return None
    if is_python and len(parts) >= 2:
        if parts[1] == "-c":
            return "python -c is not allowed — use python -m <test_runner> instead"

    if executable == "manage.py" and len(parts) >= 2 and parts[1] == "test":
        return None

    return (
        f"Command must be a known test runner pattern: "
        f"pytest, python -m pytest, tox, manage.py test, etc. Got: {command}"
    )


def run_target_tests(command: str = "", timeout: int = 120) -> dict:
    """Discover and run the test suite in the target repository.

    Args:
        command: Explicit test command to run. If empty, auto-discovers
            the test runner (pytest, django manage.py test, tox).
            Must start with an allowed test runner (pytest, python -m pytest,
            tox, manage.py test, etc.).
        timeout: Timeout in seconds. Defaults to 120.

    Returns:
        dict with 'status', 'passed' (bool), 'command', 'stdout', 'stderr'.
    """
    root = _target_root()
    test_timeout = int(os.environ.get("VULN_AGENT_FIXER_TEST_TIMEOUT", str(timeout)))

    if not command:
        command = _discover_test_command(root)

    if not command:
        return {
            "status": "ok",
            "passed": None,
            "command": "",
            "stdout": "",
            "stderr": "",
            "message": "No test runner found in target repository",
        }

    validation_error = _validate_test_command(command)
    if validation_error:
        return {"status": "error", "error": validation_error}

    import shlex
    try:
        cmd_parts = shlex.split(command)
    except ValueError:
        return {"status": "error", "error": f"Unparseable command: {command}"}

    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=test_timeout,
        )
        passed = result.returncode == 0
        return {
            "status": "ok",
            "passed": passed,
            "command": command,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-2000:],
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "passed": False,
            "command": command,
            "stdout": "",
            "stderr": f"Tests timed out after {test_timeout}s",
        }


def _discover_test_command(root: Path) -> str:
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text()
        if "[tool.pytest" in text or "pytest" in text:
            return f"{sys.executable} -m pytest"

    if (root / "pytest.ini").exists() or (root / "setup.cfg").exists():
        return f"{sys.executable} -m pytest"

    if (root / "tox.ini").exists():
        return "tox"

    if (root / "manage.py").exists():
        return f"{sys.executable} manage.py test"

    test_dirs = [root / "tests", root / "test"]
    for d in test_dirs:
        if d.is_dir():
            return f"{sys.executable} -m pytest"

    return ""


def create_pull_request(
    title: str = "",
    body: str = "",
    base_branch: str = "",
) -> dict:
    """Create a pull request using the GitHub CLI (gh).

    Args:
        title: REQUIRED. PR title (under 70 characters).
        body: REQUIRED. PR body in markdown.
        base_branch: Base branch for the PR. If empty, uses the repo default.

    Returns:
        dict with 'status', 'pr_url', and 'message'.
    """
    if not title:
        return {"status": "error", "error": "title is required"}
    if not body:
        return {"status": "error", "error": "body is required"}

    root = _target_root()
    err = _verify_git_root()
    if err:
        return err

    gh_check = subprocess.run(
        ["gh", "auth", "status"],
        capture_output=True, text=True, cwd=str(root),
    )
    if gh_check.returncode != 0:
        return {
            "status": "error",
            "error": "gh CLI not authenticated. Run 'gh auth login' first.",
        }

    current_branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True, text=True, cwd=str(root),
    )
    branch = current_branch.stdout.strip()

    push_result = subprocess.run(
        ["git", "push", "-u", "origin", branch],
        capture_output=True, text=True, cwd=str(root),
    )
    if push_result.returncode != 0:
        return {"status": "error", "error": f"git push failed: {push_result.stderr.strip()}"}

    cmd = ["gh", "pr", "create", "--title", title, "--body", body]
    if base_branch:
        cmd.extend(["--base", base_branch])

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(root))
    if result.returncode != 0:
        return {"status": "error", "error": f"gh pr create failed: {result.stderr.strip()}"}

    pr_url = result.stdout.strip()
    return {"status": "ok", "pr_url": pr_url, "message": f"PR created: {pr_url}"}


def save_report(report_json: str = "") -> dict:
    """Save the vulnerability report to a JSON file in the target codebase.
    Creates a .vuln-hawk/ directory in the target root.

    Args:
        report_json: REQUIRED. The report JSON string to save.

    Returns:
        dict with 'status' and 'path' of the saved file.
    """
    if not report_json:
        return {"status": "error", "error": "report_json is required"}

    root = _target_root()
    report_dir = root / ".vuln-hawk"
    report_dir.mkdir(parents=True, exist_ok=True)

    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = report_dir / f"report-{ts}.json"

    try:
        data = json.loads(report_json)
        report_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except (json.JSONDecodeError, TypeError):
        report_path.write_text(report_json, encoding="utf-8")

    return {
        "status": "ok",
        "path": str(report_path.relative_to(root)),
        "message": f"Report saved to {report_path.relative_to(root)}",
    }
