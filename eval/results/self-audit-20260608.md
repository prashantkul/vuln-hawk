# Self-Audit: Security Review of vuln-hawk

**Date:** 2026-06-08
**Branch:** `feature/nemotron-openrouter-support`
**Scope:** All commits since `claude/vulnerability-discovery-agent-VZ77d` (32 commits)
**Reviewer:** Claude Opus 4.6 (automated security review)

## Summary

Security review of the Nemotron/OpenRouter support branch identified one
HIGH-severity command injection vulnerability in the fixer agent's test
runner tool. The vulnerability was caused by `subprocess.run(shell=True)`
accepting LLM-provided command strings with no validation, combined with a
defined-but-never-wired security denylist. Fixed in this branch.

## Findings

### VULN-SELF-001: Command Injection via `run_target_tests`

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Confidence** | 9/10 |
| **Category** | Command Injection |
| **File** | `fixer_agent/tools.py:434` |
| **Related** | `fixer_agent/security.py:27-30` (dead code) |
| **Status** | **FIXED** |

**Description:**
`run_target_tests(command)` passed the LLM-provided `command` string directly
to `subprocess.run(command, shell=True)`. The fixer agent's security gateway
defined `FIXER_COMMAND_DENYLIST` (blocking curl, wget, nc, docker, ssh, pip,
etc.) but this denylist was never referenced in `before_tool_callback` — dead
code. The only protection was the generic `ARG_DENYLIST_PATTERNS` from
`vuln_agent/security.py`, which catch cloud metadata IPs, docker socket paths,
and `$()` / backtick command substitution patterns, but do NOT catch direct
shell commands like `rm -rf /`, `cat /etc/shadow`, or `python3 -c '...'`.

**Attack vector:**
The fixer agent reads vulnerability reports from file paths or A2A protocol. A
crafted report containing prompt injection (e.g., in `suggested_fix` or
`data_flow` fields) could instruct the LLM to call
`run_target_tests(command="malicious_command")`. Since `FIXER_COMMAND_DENYLIST`
was dead code, the command would execute on the host with full shell
interpretation.

**Fix applied (two layers):**

1. **Removed `shell=True`**: `run_target_tests` now uses `shlex.split()` to
   parse the command into a list and passes it to `subprocess.run()` without
   `shell=True`. This eliminates shell metacharacter interpretation entirely.

2. **Allowlist validation**: Added `_validate_test_command()` that verifies the
   command starts with a known test runner (`pytest`, `python -m pytest`, `tox`,
   `manage.py test`, `unittest`, `nose2`, `trial`). Arbitrary commands are
   rejected before execution.

3. **Wired up `FIXER_COMMAND_DENYLIST`**: Added a `run_target_tests` check in
   `fixer_agent/security.py:before_tool_callback` that scans the command string
   against the denylist as a defense-in-depth layer.

## Methodology

- Full diff review of all 32 commits (785KB diff)
- Focused analysis on security-critical modules: `security.py`, `tools.py`,
  `target_manager.py` across both `vuln_agent/` and `fixer_agent/`
- Traced data flows from LLM tool parameters to dangerous sinks
- Verified security gateway coverage for each tool in both agents
- Applied false-positive filtering criteria (exclusion rules + precedents)
- Independent verification subtask confirmed finding at 9/10 confidence

## Not flagged (reviewed and cleared)

- **`send_poc_request` SSRF**: Path must start with `/`, URL host is a
  Docker container IP (not user-controlled), `--internal` network blocks
  egress. Metadata endpoint check covers path-based SSRF.
- **`load_report` arbitrary file read**: Accepts absolute paths but output is
  filtered through the report parser (structured finding fields, not raw
  content). Credential scrubbing in after_tool_callback provides defense.
- **`write_file` / `apply_fix` path traversal**: Both use `_safe_resolve()`
  with `resolve()` + `relative_to()` containment. Security gateway adds a
  second check via `_path_in_target()`.
- **`git_commit` injection**: Uses list-form subprocess (no `shell=True`),
  files validated with `_safe_resolve()`.
- **`create_fix_branch` injection**: Branch name validated with strict
  alphanumeric regex in security callback.
- **Docker network isolation**: `--internal` bridge, no gateway, no egress.
  Sender sandbox is stdlib-only, non-root, memory-limited.
