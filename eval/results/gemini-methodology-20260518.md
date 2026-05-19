# Vulnerability Audit Methodology — Gemini 3.1 Pro

Agent-generated explanation of its 5-phase audit approach on the bundled Flask app.

## Strategy Overview

My overall strategy followed a systematic, multi-agent approach combining
static code analysis with dynamic validation. This ensured high precision
and eliminated false positives.

## Phase 1: Reconnaissance (Static Analysis & Triage)

I began by mapping the project structure and analyzing the Abstract Syntax
Tree (AST) of the Python files to identify HTTP routes (entry points) and
library imports.

I used grep-like searches to locate known dangerous sinks (e.g.,
`render_template_string`, `cursor.execute`, `subprocess.run`,
`os.path.join`).

I read the source code of these critical files to manually trace the data
flow from the request parameters (sources) to the dangerous functions
(sinks), identifying both genuine vulnerabilities and intentional
false-positive traps.

## Phase 2: Scanning (Distributed Triage)

Based on my reconnaissance, I defined specific "focus areas" (file,
function, and sink mappings).

I dynamically spawned a team of specialized scanner agents, assigning each
one a specific file. These scanners reviewed the code to confirm the
vulnerable data flows and explicitly ruled out safe implementations (like
parameterized queries or sanitized inputs).

## Phase 3: Deep Analysis (Dynamic Exploitation & PoC Generation)

To prove the vulnerabilities were actually exploitable, I spun up the
target application in an isolated local Docker container.

I created a team of analyzer agents and handed them the scanners'
high-confidence findings.

The analyzers dynamically interacted with the live application, crafting
payloads to bypass expected application behavior and generating concrete
Proof-of-Concept (PoC) HTTP requests (e.g., extracting the `/etc/passwd`
file or evaluating template payloads).

## Phase 4: Independent Verification (Sanity Checking)

To maintain a high bar for quality and prevent AI hallucinations, I passed
the analyzers' confirmed PoCs to a separate team of independent verifiers.

Each verifier blindly re-tested the PoCs against the live application and
double-checked the static data flows to ensure the findings were 100%
reproducible and correctly categorized.

After verification, I tore down the live application environment.

## Phase 5: Final Reporting

I aggregated only the findings that survived the independent verification
phase.

I compiled these into a structured JSON report detailing the vulnerability
class, severity, precise data flow, reproducible PoC steps, and actionable
remediation advice for the developers.

## Key Insight

This funnel-like strategy — starting broad with static patterns, narrowing
down via static data-flow analysis, and ultimately proving the flaws with
dynamic PoCs — ensures maximum coverage while maintaining zero false
positives.

## Session Stats

- Agents: 18 (1 root + 5 scanners + 5 analyzers + 7 verifiers)
- Events: 164
- Model calls: 82
- Total tokens: 2,400,919
- Live PoC requests: 17 (10 by analyzers + 7 by verifiers)
- Result: 8/8 TP, 0 FP, 0 traps triggered, F1 = 1.000
