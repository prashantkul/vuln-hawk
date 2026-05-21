"""Fixer agent — auto-remediation for PoC-confirmed vulnerabilities.

Reads a vulnerability report (from file or via A2A), proposes a fix
plan, then spawns fixer and reviewer sub-agents to generate and verify
code patches.  Applies approved fixes to a feature branch, runs tests,
and creates a pull request.

    Root (Opus)
      ├── Phase 1: ingest report, filter to HIGH-confidence findings
      ├── Phase 2: propose fix plan, wait for user confirmation
      ├── create_fix_team(plan) → injects fixer_0..N
      ├── transfer_to_agent("fixer_0") .. ("fixer_N")
      ├── create_fix_review_team(fixes) → injects reviewer_0..M
      ├── transfer_to_agent("reviewer_0") .. ("reviewer_M")
      └── Phase 5: apply approved fixes, run tests, create PR
"""

from __future__ import annotations

import json
import os

from google.adk.agents import Agent

from vuln_agent.config import ModelConfig, create_llm, GENERATE_CONTENT_CONFIG

from fixer_agent.security import (
    after_tool_callback,
    before_tool_callback,
    on_tool_error_callback,
)
from fixer_agent.tools import (
    apply_fix,
    check_syntax,
    create_fix_branch,
    create_pull_request,
    git_commit,
    git_diff,
    run_target_tests,
    save_report,
    write_file,
)
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    search_code,
)


_cfg = ModelConfig()


def _escape_for_adk(text: str) -> str:
    return text.replace("{", "(").replace("}", ")")


_AGENT_KWARGS = dict(
    before_tool_callback=before_tool_callback,
    after_tool_callback=after_tool_callback,
    on_tool_error_callback=on_tool_error_callback,
)
if GENERATE_CONTENT_CONFIG:
    _AGENT_KWARGS["generate_content_config"] = GENERATE_CONTENT_CONFIG


# ── Fixer sub-agent instruction ─────────────────────────────────────

FIXER_INSTRUCTION = """\
You are fixer agent `{name}`. Generate a minimal, correct code fix for
a confirmed vulnerability.

## Vulnerability to fix
{finding_details}

## Rules

1. Read the vulnerable file using `read_file` and understand the full
   context (surrounding functions, imports, how the vulnerable code is
   called).
2. Generate the MINIMAL fix. Change as few lines as possible.
3. Do NOT refactor unrelated code. Preserve all existing functionality.
4. Use idiomatic secure patterns:
   - SQL Injection → parameterized queries (use %s placeholders, pass params list)
   - Command Injection → subprocess with list args, no shell=True
   - Path Traversal → os.path.realpath + prefix check, or werkzeug.utils.secure_filename
   - SSTI → pass user input as template context, never embed in template string
   - SSRF → URL allowlisting, validate scheme and host
   - XSS → proper output encoding / autoescape
   - Insecure Deserialization → use safe loaders (yaml.safe_load, json)
   - Hardcoded Secret → read from environment variable via os.environ
   - IDOR → add authorization/ownership checks
5. If the fix requires new imports, include them in `imports_needed`.

## Output

<fix finding_id="{finding_id}" file="{file}">
  <original_code>
  The EXACT lines being replaced — copy them verbatim from read_file output
  </original_code>
  <fixed_code>
  The replacement code with the vulnerability fixed
  </fixed_code>
  <explanation>
  Why this fix addresses the vulnerability without breaking functionality
  </explanation>
  <commit_message>
  fix({vuln_class_lower}): brief description of what was fixed
  </commit_message>
  <imports_needed>
  Any new import lines required, or NONE
  </imports_needed>
</fix>

When done, transfer back to `fixer_root_agent`.
"""


# ── Reviewer sub-agent instruction ──────────────────────────────────

REVIEWER_INSTRUCTION = """\
You are reviewer agent `{name}`. Your job is to independently verify
that a proposed code fix is correct and safe.

## Fix to review
{fix_details}

## Steps

1. Read the original file using `read_file` to understand the context.
2. Verify the original_code matches the actual file content.
3. Check that the fixed_code actually addresses the vulnerability:
   - Does it eliminate the attack vector?
   - Does it use the correct secure pattern?
4. Check that the fix does NOT introduce new issues:
   - No new SQL injection, command injection, etc.
   - No broken functionality (return values, side effects preserved)
   - Correct syntax and style consistency
5. Check that any new imports are necessary and safe.

## Output

<review finding_id="{finding_id}" verdict="APPROVED|REJECTED">
  <analysis>
  Your analysis of the fix
  </analysis>
  <reason>
  Why you approved or rejected. If rejected, explain exactly what is wrong
  and how to fix it.
  </reason>
</review>

When done, transfer back to `fixer_root_agent`.
"""


# ── Dynamic team creation tools ─────────────────────────────────────

_root_agent: Agent | None = None


def _inject_sub_agents(agents: list[Agent]) -> None:
    for agent in agents:
        agent.parent_agent = _root_agent
    _root_agent.sub_agents.extend(agents)


def _clear_sub_agents(prefix: str) -> None:
    to_remove = [a for a in _root_agent.sub_agents if a.name.startswith(prefix)]
    for agent in to_remove:
        agent.parent_agent = None
    _root_agent.sub_agents = [a for a in _root_agent.sub_agents if a not in to_remove]


def create_fix_team(fix_plan_json: str = "") -> dict:
    """Dynamically create fixer sub-agents from a fix plan. Each fixer
    generates a code patch for one vulnerability finding.

    Args:
        fix_plan_json: REQUIRED. A JSON array of objects, each with keys:
            finding_id, vuln_class, file, function, line_range, severity,
            data_flow, suggested_fix.
            Example: '[("finding_id":"F1","vuln_class":"SQL Injection","file":"db.py",
            "function":"search_users","line_range":[42,51],"severity":"CRITICAL",
            "data_flow":"request.args -> f-string -> cursor.execute",
            "suggested_fix":"Use parameterized queries")]'

    Returns:
        dict with fixer names created. Transfer to each one to start fixing.
    """
    if not fix_plan_json:
        return {"status": "error", "error": "fix_plan_json is required."}
    try:
        fix_plan = json.loads(fix_plan_json) if isinstance(fix_plan_json, str) else fix_plan_json
    except (json.JSONDecodeError, TypeError) as exc:
        return {"status": "error", "error": f"Invalid JSON: {exc}"}
    if not isinstance(fix_plan, list):
        return {"status": "error", "error": "fix_plan_json must be a JSON array."}

    _clear_sub_agents("fixer_")
    fixers = []
    for i, finding in enumerate(fix_plan):
        if not isinstance(finding, dict):
            continue

        finding_id = finding.get("finding_id", f"F{i + 1}")
        vuln_class = finding.get("vuln_class", "Unknown")
        file = finding.get("file", "")
        function = finding.get("function", "")
        line_range = finding.get("line_range", [])
        severity = finding.get("severity", "")
        data_flow = finding.get("data_flow", "")
        suggested_fix = finding.get("suggested_fix", "")

        finding_details = (
            f"Finding ID: {finding_id}\n"
            f"Vulnerability Class: {vuln_class}\n"
            f"File: {file}\n"
            f"Function: {function}\n"
            f"Line Range: {line_range}\n"
            f"Severity: {severity}\n"
            f"Data Flow: {data_flow}\n"
            f"Suggested Fix Hint: {suggested_fix}"
        )

        name = f"fixer_{i}"
        agent = Agent(
            name=name,
            model=create_llm(_cfg.fixer),
            description=f"Fix generator for {finding_id}: {vuln_class} in {file}",
            instruction=FIXER_INSTRUCTION.format(
                name=name,
                finding_details=_escape_for_adk(finding_details),
                finding_id=finding_id,
                file=file,
                vuln_class_lower=vuln_class.lower().replace(" ", "-"),
            ),
            tools=[read_file, search_code, analyze_python_ast, list_directory],
            **_AGENT_KWARGS,
        )
        fixers.append(agent)

    _inject_sub_agents(fixers)
    names = [a.name for a in fixers]
    return {
        "status": "ok",
        "fixers_created": names,
        "instruction": (
            f"Created {len(names)} fixer agents: {', '.join(names)}. "
            "Transfer to each one to generate fixes. They will report "
            "back with <fix> XML blocks."
        ),
    }


def create_fix_review_team(fixes_json: str = "") -> dict:
    """Dynamically create reviewer sub-agents to verify proposed fixes.
    Each reviewer checks one fix for correctness and safety.

    Args:
        fixes_json: REQUIRED. A JSON array of objects, each with keys:
            finding_id, file, original_code, fixed_code, explanation,
            vuln_class.
            Example: '[("finding_id":"F1","file":"db.py",
            "original_code":"...","fixed_code":"...","explanation":"...",
            "vuln_class":"SQL Injection")]'

    Returns:
        dict with reviewer names created. Transfer to each one to start review.
    """
    if not fixes_json:
        return {"status": "error", "error": "fixes_json is required."}
    try:
        fixes = json.loads(fixes_json) if isinstance(fixes_json, str) else fixes_json
    except (json.JSONDecodeError, TypeError) as exc:
        return {"status": "error", "error": f"Invalid JSON: {exc}"}
    if not isinstance(fixes, list):
        return {"status": "error", "error": "fixes_json must be a JSON array."}

    _clear_sub_agents("reviewer_")
    reviewers = []
    for i, fix in enumerate(fixes):
        if not isinstance(fix, dict):
            continue

        finding_id = fix.get("finding_id", f"F{i + 1}")
        file = fix.get("file", "")
        original_code = fix.get("original_code", "")
        fixed_code = fix.get("fixed_code", "")
        explanation = fix.get("explanation", "")
        vuln_class = fix.get("vuln_class", "")

        fix_details = (
            f"Finding ID: {finding_id}\n"
            f"Vulnerability Class: {vuln_class}\n"
            f"File: {file}\n\n"
            f"Original Code:\n```\n{original_code}\n```\n\n"
            f"Fixed Code:\n```\n{fixed_code}\n```\n\n"
            f"Fixer's Explanation: {explanation}"
        )

        name = f"reviewer_{i}"
        agent = Agent(
            name=name,
            model=create_llm(_cfg.verifier),
            description=f"Fix reviewer for {finding_id}: {vuln_class} in {file}",
            instruction=REVIEWER_INSTRUCTION.format(
                name=name,
                fix_details=_escape_for_adk(fix_details),
                finding_id=finding_id,
            ),
            tools=[read_file, search_code, analyze_python_ast],
            **_AGENT_KWARGS,
        )
        reviewers.append(agent)

    _inject_sub_agents(reviewers)
    names = [a.name for a in reviewers]
    return {
        "status": "ok",
        "reviewers_created": names,
        "instruction": (
            f"Created {len(names)} reviewer agents: {', '.join(names)}. "
            "Transfer to each one to verify the fix. They will report "
            "back with <review> XML blocks containing APPROVED/REJECTED."
        ),
    }


# ── Root agent ──────────────────────────────────────────────────────

ROOT_INSTRUCTION = """\
You are a senior security engineer leading the auto-remediation of
confirmed vulnerabilities. You MUST follow the phases below IN ORDER.

## Available tools

**Read tools** (use in all phases):
- `read_file(filepath)` — read source code
- `search_code(pattern)` — grep for patterns
- `analyze_python_ast(filepath, analysis_type)` — extract structure
- `list_directory(path, recursive)` — browse project

**Team tools** (Phases 3 and 4):
- `create_fix_team(fix_plan_json)` — spawn fixer sub-agents
- `create_fix_review_team(fixes_json)` — spawn reviewer sub-agents
- After creating a team, use `transfer_to_agent(agent_name)` to delegate

**Write tools** (Phase 5):
- `apply_fix(filepath, original_code, fixed_code)` — apply a code fix
- `write_file(filepath, content, start_line, end_line)` — write to file
- `check_syntax(filepath)` — validate Python syntax
- `create_fix_branch(branch_name)` — create a git feature branch
- `git_commit(files, message)` — stage and commit files
- `git_diff(filepath)` — show changes
- `run_target_tests(command, timeout)` — run the test suite
- `create_pull_request(title, body)` — open a GitHub PR

## PHASE 1: REPORT INGESTION

Print: "=== PHASE 1: REPORT INGESTION ==="

1. If the user provides a report file path, use `read_file` to load it.
   If the user pastes findings directly, parse them from the message.
   If findings arrive via A2A, they will be in the message payload.

2. List each finding: ID, vuln_class, severity, file, function, line_range.

3. Filter to only HIGH confidence findings with proof of concept.
   Tell the user how many findings you will fix and which ones.

## PHASE 2: FIX PLANNING

Print: "=== PHASE 2: FIX PLANNING ==="

For each finding:
1. Read the vulnerable file and understand the code context.
2. Determine the best fix strategy (parameterized queries, input
   validation, safe API usage, etc.).

Present the fix plan to the user:

=== FIX PLAN ===
F1 (CRITICAL) SQL Injection in db.py::search_users (lines 42-51)
   Strategy: Replace string concatenation with parameterized query
   Risk: Low — same query semantics, just parameterized

F2 (HIGH) Command Injection in utils.py::run_command (lines 30-38)
   Strategy: Use subprocess with list args, remove shell=True
   Risk: Medium — callers may depend on shell expansion

ASK THE USER: "Does this fix plan look good? Should I proceed?"
Wait for user confirmation before continuing.

## PHASE 3: FIX GENERATION

Print: "=== PHASE 3: FIX GENERATION ==="

1. Build a JSON array of the findings to fix. Each object needs:
   finding_id, vuln_class, file, function, line_range, severity,
   data_flow, suggested_fix.

2. Call `create_fix_team(fix_plan_json)` with this array.

3. Transfer to each fixer one at a time:
   - "Transferring to fixer_0" then transfer_to_agent("fixer_0")
   - Wait for the <fix> XML response
   - Continue until all fixers have reported

4. Collect all generated fixes. Summarize: which succeeded, which failed.

## PHASE 4: FIX VERIFICATION

Print: "=== PHASE 4: FIX VERIFICATION ==="

1. Build a JSON array of the generated fixes. Each object needs:
   finding_id, file, original_code, fixed_code, explanation, vuln_class.

2. Call `create_fix_review_team(fixes_json)` with this array.

3. Transfer to each reviewer one at a time:
   - "Transferring to reviewer_0" then transfer_to_agent("reviewer_0")
   - Wait for the <review> XML response
   - Continue until all reviewers have reported

4. Collect verdicts:
   - APPROVED: proceed to apply
   - REJECTED: note the reason, skip this fix (or retry once with
     the rejection feedback)

## PHASE 5: APPLY FIXES & CREATE PR

Print: "=== PHASE 5: APPLYING FIXES ==="

1. Call `create_fix_branch()` to create a new branch.

2. For each APPROVED fix, in order:
   a. Call `apply_fix(filepath, original_code, fixed_code)` to patch the file.
   b. If the fix needs new imports, use `write_file` to add them at the
      top of the file (read the file first to find the right insertion point).
   c. Call `check_syntax(filepath)` to verify the file is still valid Python.
      If syntax fails, revert by re-applying the original code and skip this fix.
   d. Call `git_commit(files, message)` with the fixer's commit message.
   e. Call `git_diff()` to verify the change looks correct.

3. Call `run_target_tests()` to run the test suite. Report results.

4. Call `create_pull_request(title, body)` with:
   - Title: "fix: Auto-remediate N vulnerabilities found by vuln-hawk"
   - Body: A markdown table of all fixes applied:
     | Finding | Severity | Class | File | Function | Status |
     Include test results and a review checklist.

5. Print the final summary: branch name, PR URL, test results, which
   fixes were applied and which were skipped.

## CRITICAL RULES
- Follow phases IN ORDER. Do not skip phases.
- ALWAYS wait for user confirmation after Phase 2 before proceeding.
- Generate MINIMAL fixes — do not refactor surrounding code.
- One commit per finding for clean git history.
- If a fix fails syntax check, skip it rather than breaking the codebase.
- Report the full summary at the end.
"""


_root_tools = [
    read_file,
    search_code,
    list_directory,
    analyze_python_ast,
    write_file,
    apply_fix,
    check_syntax,
    create_fix_branch,
    git_commit,
    git_diff,
    run_target_tests,
    create_pull_request,
    save_report,
    create_fix_team,
    create_fix_review_team,
]


root_agent = Agent(
    name="fixer_root_agent",
    model=create_llm(_cfg.fixer),
    description=(
        "Security fix agent that auto-remediates confirmed vulnerabilities "
        "by generating code patches, verifying them, and creating pull requests."
    ),
    instruction=ROOT_INSTRUCTION,
    tools=_root_tools,
    **_AGENT_KWARGS,
)

_root_agent = root_agent
