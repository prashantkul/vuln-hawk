"""ADK agent definition — dynamic sub-agent spawning for `adk web`.

Root agent does recon, spawns scanner sub-agents, then spawns analyzer
sub-agents that must submit proof-of-concept validation. The root
reviews each PoC before including it in the final report.

    Root (configurable model)
      ├── Phase 1: recon with tools
      ├── create_scan_team(areas)  → injects scanner_0..N
      ├── transfer_to_agent("scanner_0") .. ("scanner_N")
      ├── create_analysis_team(flags) → injects analyzer_0..M
      ├── transfer_to_agent("analyzer_0") .. ("analyzer_M")
      │   └── each analyzer submits PoC proof back to root
      └── Phase 4: root validates PoCs, produces final report
"""

from __future__ import annotations

from google.adk.agents import Agent

from vuln_agent.config import ModelConfig, create_llm, GENERATE_CONTENT_CONFIG, MAX_PARALLEL_SCANNERS, LIVE_POC_ENABLED
from vuln_agent.security import (
    after_model_callback,
    after_tool_callback,
    before_tool_callback,
    on_tool_error_callback,
)
from vuln_agent.tools import (
    analyze_python_ast,
    list_directory,
    read_file,
    run_python_snippet,
    search_code,
)
from fixer_agent.tools import save_report

if LIVE_POC_ENABLED:
    from vuln_agent.tools import send_poc_request, start_target_app, stop_target_app


_cfg = ModelConfig()

def _escape_for_adk(text: str) -> str:
    """Remove curly braces from dynamic content so ADK's instruction
    template engine doesn't try to resolve them as state variables.
    ADK's regex {+[^{}]*}+ matches both {var} and {{var}}."""
    return text.replace("{", "(").replace("}", ")")


_AGENT_KWARGS = dict(
    before_tool_callback=before_tool_callback,
    after_tool_callback=after_tool_callback,
    after_model_callback=after_model_callback,
    on_tool_error_callback=on_tool_error_callback,
)
if GENERATE_CONTENT_CONFIG:
    _AGENT_KWARGS["generate_content_config"] = GENERATE_CONTENT_CONFIG


# ── Scanner instruction ──────────────────────────────────────────────

SCANNER_INSTRUCTION = """\
You are scanner agent `{name}` assigned to a specific area of the codebase.

## Your assignment
{assignment}

## Steps

1. Use `read_file` to read the assigned file(s).
2. For each function, identify user-controlled inputs and dangerous sinks.
3. Determine if user input reaches a sink without adequate validation.
4. Use `search_code` to check for middleware or validation helpers.
5. Use `analyze_python_ast` with "calls" to confirm invoked sinks.

## Output

Report findings as XML:

<scanner_findings>
<flag function="fn_name" line="42" sink="cursor.execute"
      confidence="HIGH|MEDIUM|LOW"
      vuln_class="SQL Injection|Command Injection|Path Traversal|SSTI|IDOR|SSRF|Hardcoded Secret|XSS|Insecure Deserialization|XXE">
Data flow: source -> transforms -> sink. Note mitigations.
</flag>
<safe function="other_fn" line="55" reason="Uses parameterized query"/>
</scanner_findings>

Mark safe functions explicitly. When done, transfer back to `vuln_discovery_agent`.
"""


# ── Analyzer instruction (with PoC validation) ───────────────────────

ANALYZER_INSTRUCTION = """\
You are analyzer agent `{name}`. Investigate these scanner flags,
CONFIRM or REJECT each, and for every confirmed finding you MUST
provide a concrete proof of concept (PoC).

## Scanner flags to investigate
{scanner_flags}

## Methodology

For EACH flag:
1. Read the flagged function and its callers.
2. Trace the complete path from user input to sink.
3. Check for mitigations (validation, parameterization, allowlists).
4. Determine if mitigations can be bypassed.
5. Use `search_code` to find how the flagged function is called.
6. Use `run_python_snippet` if you need custom AST analysis.

## Proof of Concept Requirements

For each CONFIRMED finding, you MUST include:

1. **poc_request**: The exact HTTP request or input that triggers the
   vulnerability. Include method, path, headers, body — everything
   needed to reproduce.
2. **poc_expected_behavior**: What happens when the PoC fires —
   specific observable outcome (e.g., "returns all rows from users
   table", "executes `id` command on server", "reads /etc/passwd").
3. **poc_validation_steps**: Step-by-step instructions to verify the
   exploit works. Include what to look for in the response.
4. **why_not_false_positive**: Explain why this is a real vulnerability,
   not a false positive. Reference the specific code path that lacks
   mitigation.

## Output

<analyzer_results>
<confirmed id="A1" function="sql_lab" file="views.py" line_range="150-162"
           vuln_class="SQL Injection" severity="CRITICAL" confidence="HIGH"
           data_flow="request.POST.get('name') -> string concat -> objects.raw()">
  <poc_request>POST /sql_lab HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=admin&amp;pass=' OR '1'='1</poc_request>
  <poc_expected_behavior>Bypasses authentication, returns first user record
regardless of password. The injected SQL becomes:
SELECT * FROM introduction_login WHERE user='admin' AND password='' OR '1'='1'</poc_expected_behavior>
  <poc_validation_steps>
1. Send the POST request above to /sql_lab
2. Observe response contains user1 data without valid password
3. Confirm by trying: pass=' UNION SELECT user,password FROM introduction_login--
   which should dump all credentials</poc_validation_steps>
  <why_not_false_positive>Line 158 builds SQL via string concatenation:
"SELECT * FROM introduction_login WHERE user='"+name+"' AND password='"+password+"'"
No parameterized binding, no input sanitization, no escaping. The raw()
call executes the string directly against the database.</why_not_false_positive>
  <suggested_fix>Use parameterized queries: login.objects.raw(
'SELECT * FROM introduction_login WHERE user=%s AND password=%s',
[name, password])</suggested_fix>
</confirmed>
<rejected function="get_user_by_id" file="db.py" line_range="55-65"
          reason="Uses parameterized query with %s placeholder"/>
</analyzer_results>

Precision is paramount — a false positive is worse than a miss.
When done, transfer back to `vuln_discovery_agent`.
"""

_LIVE_POC_ANALYZER_ADDENDUM = """

## Live PoC Validation

You have `send_poc_request(method, path, headers, body)` which sends real
HTTP requests to the running target application.

For each CONFIRMED finding:
1. Craft the exploit request using `send_poc_request`.
2. Examine the response — does it prove exploitation?
3. Include the actual HTTP status and response body in your output.
4. If the response does NOT demonstrate exploitation, reconsider
   whether the finding is truly exploitable.

Add a `<poc_response>` tag inside each `<confirmed>` element with the
actual HTTP status and key parts of the response body.
"""

if LIVE_POC_ENABLED:
    ANALYZER_INSTRUCTION += _LIVE_POC_ANALYZER_ADDENDUM


# ── Verifier instruction ─────────────────────────────────────────────

VERIFIER_INSTRUCTION = """\
You are verifier agent `{name}`. Your job is to INDEPENDENTLY validate
vulnerability findings by reproducing the proof of concept.

## Confirmed findings to verify
{confirmed_findings}

For EACH finding above, you must:

1. Read the source code at the specified file and line range to understand
   the vulnerability.
2. Verify the data flow: trace from user input to dangerous sink yourself.
   Do NOT trust the analyzer's trace blindly.
3. Check for mitigations the analyzer may have missed (input validation,
   middleware, decorators, type coercion).
4. If `send_poc_request` is available (live PoC mode), send the exploit
   request and observe the actual response.
5. Assign a verdict: VERIFIED, DISPUTED, or INVALID.

## Output

<verification_results>
<verified id="V1" original_id="A1" function="sql_lab" file="views.py"
          vuln_class="SQL Injection" severity="CRITICAL">
  <data_flow_confirmed>Yes — request.POST['name'] concatenated into SQL
string at line 158, passed to objects.raw() at line 162. No parameterized
binding, no input sanitization anywhere in the call chain.</data_flow_confirmed>
  <poc_result>PASS — sent POST /sql_lab with name=admin, pass=' OR '1'='1
and received HTTP 200 with user data returned without valid password.</poc_result>
  <verdict>VERIFIED</verdict>
</verified>
<disputed id="V2" original_id="A3" function="cmd_lab" file="views.py"
          vuln_class="Command Injection">
  <reason>The re.sub at line 420 strips protocols but does NOT prevent
semicolon injection. However, the subprocess call uses Popen with
stdout/stderr capture, limiting observable impact. Severity should be
HIGH not CRITICAL.</reason>
  <verdict>DISPUTED — downgrade severity to HIGH</verdict>
</disputed>
<invalid id="V3" original_id="A5" function="safe_func" file="utils.py">
  <reason>Analyzer missed the secure_filename() call at line 88 which
sanitizes the input before it reaches os.path.join.</reason>
  <verdict>INVALID — false positive</verdict>
</invalid>
</verification_results>

## Rules
- You are an independent reviewer. Challenge every finding.
- VERIFIED: data flow confirmed, PoC works (or would work), no mitigations.
- DISPUTED: finding is real but severity/details are wrong.
- INVALID: false positive — mitigations exist or data flow is broken.
- Be skeptical. It is better to dispute a real finding than to pass a false one.

When done, transfer back to `vuln_discovery_agent`.
"""

_LIVE_POC_VERIFIER_ADDENDUM = """

## Live PoC Validation

You have `send_poc_request(method, path, headers, body)` to send real
HTTP requests to the running target. For each finding:

1. Reproduce the analyzer's PoC using `send_poc_request`.
2. Check the response — does it match the expected exploitation behavior?
3. If the PoC fails, mark as INVALID or DISPUTED with the actual response.
4. Include the HTTP status and response body in your verdict.
"""

if LIVE_POC_ENABLED:
    VERIFIER_INSTRUCTION += _LIVE_POC_VERIFIER_ADDENDUM


# ── Dynamic team creation tools ──────────────────────────────────────

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


def create_scan_team(focus_areas_json: str = "") -> dict:
    """Dynamically create scanner sub-agents from focus areas identified during
    reconnaissance. Each scanner becomes a transfer target visible in the UI.
    After calling this, use transfer_to_agent to delegate to each scanner.

    Args:
        focus_areas_json: REQUIRED. A JSON string containing a list of objects,
            each with keys: file, functions, sinks, description.
            Example: '[{"file":"views.py","functions":"sql_lab,cmd_lab","sinks":"objects.raw","description":"SQL injection"}]'

    Returns:
        dict with scanner names created. Transfer to each one to start scanning.
    """
    import json
    if not focus_areas_json:
        return {"status": "error", "error": "focus_areas_json is required. Pass a JSON array string."}
    try:
        focus_areas = json.loads(focus_areas_json) if isinstance(focus_areas_json, str) else focus_areas_json
    except (json.JSONDecodeError, TypeError) as exc:
        return {"status": "error", "error": f"Invalid JSON: {exc}"}
    if not isinstance(focus_areas, list):
        return {"status": "error", "error": "focus_areas_json must be a JSON array."}

    _clear_sub_agents("scanner_")
    n = min(len(focus_areas), MAX_PARALLEL_SCANNERS)
    scanners = []
    for i, area in enumerate(focus_areas[:n]):
        if isinstance(area, dict):
            file = area.get("file", "")
            functions = area.get("functions", "")
            sinks = area.get("sinks", "")
            description = area.get("description", "")
        else:
            file = functions = sinks = ""
            description = str(area)

        assignment = (
            f"File: {file}\n"
            f"Functions: {functions}\n"
            f"Known sinks: {sinks}\n"
            f"Context: {description}"
        )
        name = f"scanner_{i}"
        agent = Agent(
            name=name,
            model=create_llm(_cfg.scanner),
            description=f"Security scanner for {file}: {description}",
            instruction=SCANNER_INSTRUCTION.format(name=name, assignment=_escape_for_adk(assignment)),
            tools=[read_file, search_code, analyze_python_ast],
            **_AGENT_KWARGS,
        )
        scanners.append(agent)

    _inject_sub_agents(scanners)
    names = [a.name for a in scanners]
    return {
        "status": "ok",
        "scanners_created": names,
        "instruction": (
            f"Created {len(names)} scanner agents: {', '.join(names)}. "
            "Now transfer to each one to start scanning. Transfer to them "
            "one at a time — each will report back when done."
        ),
    }


def create_analysis_team(flag_sets_json: str = "") -> dict:
    """Dynamically create analyzer sub-agents from scanner findings.
    Each analyzer becomes a transfer target visible in the UI.
    Analyzers MUST submit proof-of-concept validation for each confirmed finding.

    Args:
        flag_sets_json: REQUIRED. A JSON string containing a list of objects,
            each with key "flags_xml" containing the scanner_findings XML.
            Example: '[{"flags_xml":"<scanner_findings>...</scanner_findings>"}]'

    Returns:
        dict with analyzer names created. Transfer to each one to start analysis.
    """
    import json
    if not flag_sets_json:
        return {"status": "error", "error": "flag_sets_json is required. Pass a JSON array string."}
    try:
        flag_sets = json.loads(flag_sets_json) if isinstance(flag_sets_json, str) else flag_sets_json
    except (json.JSONDecodeError, TypeError) as exc:
        return {"status": "error", "error": f"Invalid JSON: {exc}"}
    if not isinstance(flag_sets, list):
        return {"status": "error", "error": "flag_sets_json must be a JSON array."}

    _clear_sub_agents("analyzer_")
    analyzers = []
    for i, flag_set in enumerate(flag_sets):
        if isinstance(flag_set, dict):
            flags_xml = flag_set.get("flags_xml", "")
        else:
            flags_xml = str(flag_set)

        name = f"analyzer_{i}"
        analyzer_tools = [read_file, search_code, list_directory, analyze_python_ast, run_python_snippet]
        if LIVE_POC_ENABLED:
            analyzer_tools.append(send_poc_request)
        agent = Agent(
            name=name,
            model=create_llm(_cfg.analyzer),
            description=f"Deep security analyzer for flag set {i}",
            instruction=ANALYZER_INSTRUCTION.format(name=name, scanner_flags=_escape_for_adk(flags_xml)),
            tools=analyzer_tools,
            **_AGENT_KWARGS,
        )
        analyzers.append(agent)

    _inject_sub_agents(analyzers)
    names = [a.name for a in analyzers]
    return {
        "status": "ok",
        "analyzers_created": names,
        "instruction": (
            f"Created {len(names)} analyzer agents: {', '.join(names)}. "
            "Now transfer to each one to start deep analysis. Each will "
            "report back with confirmed/rejected findings INCLUDING proof "
            "of concept for each confirmed vulnerability."
        ),
    }


def create_verification_team(confirmed_findings_json: str = "") -> dict:
    """Dynamically create verifier sub-agents to independently validate
    analyzer findings. Each verifier reviews a set of confirmed findings,
    checks the data flow, and reproduces the PoC if live mode is enabled.

    Args:
        confirmed_findings_json: REQUIRED. A JSON string containing a list of
            objects, each with key "findings_xml" containing the analyzer_results
            XML with confirmed elements.
            Example: '[{"findings_xml":"<analyzer_results>...</analyzer_results>"}]'

    Returns:
        dict with verifier names created. Transfer to each one to start verification.
    """
    import json
    if not confirmed_findings_json:
        return {"status": "error", "error": "confirmed_findings_json is required. Pass a JSON array string."}
    try:
        confirmed_findings = json.loads(confirmed_findings_json) if isinstance(confirmed_findings_json, str) else confirmed_findings_json
    except (json.JSONDecodeError, TypeError) as exc:
        return {"status": "error", "error": f"Invalid JSON: {exc}"}
    if not isinstance(confirmed_findings, list):
        return {"status": "error", "error": "confirmed_findings_json must be a JSON array."}

    _clear_sub_agents("verifier_")
    verifiers = []
    for i, finding_set in enumerate(confirmed_findings):
        if isinstance(finding_set, dict):
            findings_xml = finding_set.get("findings_xml", "")
        else:
            findings_xml = str(finding_set)

        name = f"verifier_{i}"
        verifier_tools = [read_file, search_code, list_directory, analyze_python_ast, run_python_snippet]
        if LIVE_POC_ENABLED:
            verifier_tools.append(send_poc_request)
        agent = Agent(
            name=name,
            model=create_llm(_cfg.verifier),
            description=f"Independent verifier for finding set {i}",
            instruction=VERIFIER_INSTRUCTION.format(name=name, confirmed_findings=_escape_for_adk(findings_xml)),
            tools=verifier_tools,
            **_AGENT_KWARGS,
        )
        verifiers.append(agent)

    _inject_sub_agents(verifiers)
    names = [a.name for a in verifiers]
    return {
        "status": "ok",
        "verifiers_created": names,
        "instruction": (
            f"Created {len(names)} verifier agents: {', '.join(names)}. "
            "Now transfer to each one to start independent verification. "
            "Each will review findings and report VERIFIED/DISPUTED/INVALID."
        ),
    }


# ── Root agent ───────────────────────────────────────────────────────

ROOT_INSTRUCTION = """\
You are a senior security researcher (strategist) leading a vulnerability
audit of a Python web application codebase. You MUST follow the phases
below IN ORDER. Announce each phase before starting it.

## Available tools

**Recon tools** (use in Phase 1):
- `list_directory(path, recursive)` — map project structure
- `read_file(filepath)` — read source code
- `search_code(pattern)` — grep for dangerous patterns
- `analyze_python_ast(filepath, analysis_type)` — extract routes, imports, calls, strings

**Team tools** (use in Phase 2, 3, and 4):
- `create_scan_team(focus_areas)` — spawns N scanner sub-agents
- `create_analysis_team(flag_sets)` — spawns M analyzer sub-agents
- `create_verification_team(confirmed_findings)` — spawns K verifier sub-agents
- After creating a team, use `transfer_to_agent(agent_name)` to delegate

**Other**:
- `run_python_snippet(code)` — custom analysis in sandboxed Python

## PHASE 1: RECONNAISSANCE

Print: "=== PHASE 1: RECONNAISSANCE ==="

Do ALL of these steps yourself:

Step 1.1: Call `list_directory(".", recursive=True)` to map the project.

Step 1.2: For each Python file found, call `analyze_python_ast(filepath, "routes")`
to find HTTP endpoints (entry points for attacks).

Step 1.3: Call `analyze_python_ast(filepath, "imports")` on key files to
identify dangerous modules (subprocess, os, pickle, yaml, sqlite3, etc.).

Step 1.4: Search for dangerous sinks using `search_code`:
- `search_code("cursor.execute\\|objects.raw")` — SQL injection
- `search_code("subprocess\\|os.system\\|os.popen")` — command injection
- `search_code("eval\\|exec")` — code execution
- `search_code("pickle.loads\\|yaml.load")` — insecure deserialization
- `search_code("render_template_string\\|parseString")` — SSTI / XXE
- `search_code("requests.get\\|urlopen")` — SSRF
- `search_code("send_file\\|os.path.join")` — path traversal
- `search_code("SECRET_KEY\\|secret\\|password")` — hardcoded secrets

Step 1.5: Read the critical files where sinks were found using `read_file`.

Step 1.6: Summarize your findings. List each file, its dangerous sinks,
and which functions need scanning.

## PHASE 2: SCANNING

Print: "=== PHASE 2: SCANNING ==="

Step 2.1: Build a list of focus areas. Each focus area is a dict with:
- "file": the filename
- "functions": comma-separated function names to examine
- "sinks": the dangerous sinks found in that file
- "description": what to look for

Step 2.2: Call `create_scan_team(focus_areas)` with your list.

Step 2.3: Transfer to EACH scanner one at a time:
- Say "Transferring to scanner_0" then call transfer_to_agent("scanner_0")
- Wait for scanner_0 to report back
- Say "Transferring to scanner_1" then call transfer_to_agent("scanner_1")
- Continue until all scanners have reported

Step 2.4: Collect and summarize all scanner findings.

## PHASE 3: DEEP ANALYSIS

Print: "=== PHASE 3: DEEP ANALYSIS ==="

Step 3.0: If live PoC is enabled (you have `start_target_app` tool),
call `start_target_app()` NOW. Wait for the "ok" response before
proceeding. If it fails, continue with static analysis only.

Step 3.1: Collect all scanner flags with confidence MEDIUM or HIGH.
Group them by file into flag sets.

Step 3.2: Call `create_analysis_team(flag_sets)` where each item has:
- "flags_xml": the <scanner_findings> XML from that scanner

Step 3.3: Transfer to EACH analyzer one at a time:
- Say "Transferring to analyzer_0" then call transfer_to_agent("analyzer_0")
- Wait for confirmed/rejected findings with PoC proof
- Continue until all analyzers have reported

Step 3.4: Collect all confirmed findings from analyzers.

## PHASE 4: INDEPENDENT VERIFICATION

Print: "=== PHASE 4: INDEPENDENT VERIFICATION ==="

Step 4.1: Collect the <analyzer_results> XML blocks containing ONLY the
<confirmed> elements from each analyzer.

Step 4.2: Call `create_verification_team(confirmed_findings)` where each
item has:
- "findings_xml": the <analyzer_results> XML with confirmed findings

Step 4.3: Transfer to EACH verifier one at a time:
- Say "Transferring to verifier_0" then call transfer_to_agent("verifier_0")
- Wait for VERIFIED/DISPUTED/INVALID verdicts
- Continue until all verifiers have reported

Step 4.4: Collect verification results. Note which findings are VERIFIED,
which are DISPUTED (need severity adjustment), and which are INVALID
(false positives to drop).

Step 4.5: If you started the target app earlier, call `stop_target_app()`
now to clean up Docker containers.

## PHASE 5: FINAL REPORT

Print: "=== PHASE 5: FINAL REPORT ==="

Step 5.1: Include ONLY findings that verifiers marked as VERIFIED.
For DISPUTED findings, adjust severity as recommended.
DROP all INVALID findings.

Step 5.2: Produce the FINAL report as a single fenced JSON block with
this schema. Use square brackets for the outer array and each finding
object:

  "summary": one-paragraph overview
  "findings": array of objects, each with:
    "id": "F1", "F2", etc.
    "vuln_class": SQL Injection, Command Injection, Path Traversal, SSTI, IDOR, SSRF, Hardcoded Secret, XSS, Insecure Deserialization, XXE
    "file": relative path
    "function": handler name
    "line_range": [start, end]
    "severity": CRITICAL, HIGH, MEDIUM, or LOW
    "confidence": HIGH, MEDIUM, or LOW
    "data_flow": source -> transforms -> sink
    "proof_of_concept": object with "request", "expected_behavior", "validation_steps"
    "suggested_fix": short remediation

## PHASE 6: SAVE REPORT & OFFER AUTO-FIX

Step 6.1: Call `save_report(report_json)` with the JSON report you just
produced (the entire fenced JSON block content). This persists it to
`.vuln-hawk/report-{timestamp}.json` in the target codebase.

Step 6.2: If findings were found, ask the user:
"Would you like me to hand off these findings to the fixer agent for
auto-remediation? The fixer will generate code patches, verify them,
and create a pull request."

If the user says yes and the fixer agent is available via A2A, transfer
to `fixer_agent` with the report. If the fixer is not running, tell the
user to launch it with:
  `adk web fixer_agent` (standalone) or
  `uvicorn fixer_agent.a2a_server:app --port 8001` (A2A mode)

## CRITICAL RULES
- Follow the phases IN ORDER. Do not skip phases.
- Announce each phase transition clearly.
- NEVER use external static analysis tools. Reason through the code yourself.
- Focus on vulnerabilities that are ACTUALLY EXPLOITABLE.
- Every finding MUST have a concrete, reproducible proof of concept.
- REJECT findings if the PoC is weak, the data flow has gaps, or mitigations exist.
- Precision over recall — only include HIGH confidence findings.
- You are the final decision maker.
"""

_LIVE_POC_ROOT_ADDENDUM = """

## LIVE PoC VALIDATION (ENABLED)

You have `start_target_app` and `stop_target_app` tools. The target
application will run in an isolated Docker container. A sender sandbox
on the same network executes the actual HTTP requests.

**IMPORTANT: Follow this sequence exactly.**

**BEFORE Phase 3 (after Phase 2 scanning is complete):**
1. Call `start_target_app()`. This builds the Docker image (may take
   30-60 seconds on first run), starts the target container, and waits
   for it to become healthy.
2. Check the response. If status is "ok", proceed. If status is "error",
   report the error and skip live PoC — fall back to static analysis only.
3. The response includes `target_url` — you do NOT need this, the
   analyzers and verifiers use it automatically via `send_poc_request`.

**DURING Phase 3 and Phase 4:**
- Analyzers have `send_poc_request(method, path, headers_json, body,
  content_type)` to fire real HTTP requests at the running target.
- Verifiers also have `send_poc_request` to independently reproduce PoCs.
- URL-encode special characters in query strings (spaces = %20,
  single quotes = %27, equals = %3D).

**AFTER Phase 4 (after all verifiers have reported):**
1. Call `stop_target_app()` to clean up containers and network.
2. Then proceed to Phase 5 (final report).
"""

if LIVE_POC_ENABLED:
    ROOT_INSTRUCTION += _LIVE_POC_ROOT_ADDENDUM


_root_tools = [
    read_file,
    search_code,
    list_directory,
    analyze_python_ast,
    run_python_snippet,
    create_scan_team,
    create_analysis_team,
    create_verification_team,
    save_report,
]
if LIVE_POC_ENABLED:
    _root_tools.extend([start_target_app, stop_target_app])


root_agent = Agent(
    name="vuln_discovery_agent",
    model=create_llm(_cfg.root),
    description=(
        "Senior security strategist that audits Python web application "
        "codebases by dynamically spawning scanner, analyzer, and verifier sub-agents."
    ),
    instruction=ROOT_INSTRUCTION,
    tools=_root_tools,
    **_AGENT_KWARGS,
)

_root_agent = root_agent
