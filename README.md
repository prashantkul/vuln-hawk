# vuln-hawk

An LLM-based vulnerability discovery agent built with [Google's Agent
Development Kit (ADK)](https://google.github.io/adk-docs/). Supports
[Gemini](https://ai.google.dev/gemini-api/docs/models),
[Claude](https://docs.anthropic.com/en/docs/), and
[NVIDIA Nemotron](https://build.nvidia.com/nvidia/nemotron-3-ultra-550b-a55b)
(via [OpenRouter](https://openrouter.ai/)) as backends — including
mixed-provider configs (e.g., Nemotron root + Gemini scanners).

## Research goals

This project investigates whether a general-purpose LLM, given only
shell-like primitives and a disciplined audit methodology, can locate
exploitable vulnerabilities in Python web applications with useful
precision. The agent is deliberately denied high-level static
analyzers (Bandit, Semgrep, CodeQL): it has file reads, regex search,
AST introspection, directory listing, and a sandboxed Python
interpreter, and must reason about data flows itself.

Five design choices anchor the experiment:

1. **Shell-only tools.** Restricting the tool surface to low-level
   primitives forces the model to compose its own detection approach.
2. **Dynamic multi-agent pipeline.** A root strategist partitions the
   codebase and spawns N scanner, M analyzer, and K verifier sub-agents
   at runtime. Agent count scales with codebase size.
3. **Systematic data-flow reasoning.** Each agent's prompt enforces
   trace-from-source-to-sink methodology across vulnerability classes.
4. **Live PoC validation.** Confirmed findings are validated by firing
   real HTTP requests from a sandboxed sender container against the
   target app running in an isolated Docker network.
5. **Precision over recall.** The agent drops any finding it cannot
   fully justify. False positives are a more expensive error than misses.

## Architecture

### 5-phase pipeline (`adk web`)

```mermaid
block-beta
    columns 1

    block:phase1:1
        columns 3
        space
        ROOT["🔍 Root Strategist\n(configurable)\n\nlist_directory · read_file\nsearch_code · analyze_python_ast"]
        space
    end

    space

    block:phase2:1
        columns 6
        S0["Scanner 0\n(configurable)"]
        S1["Scanner 1\n(configurable)"]
        S2["Scanner 2\n(configurable)"]
        S3["Scanner 3\n(configurable)"]
        S4["Scanner 4\n(configurable)"]
        S5["Scanner N\n(configurable)"]
    end

    space

    block:phase3:1
        columns 4
        A0["Analyzer 0\n(configurable)\n+ send_poc_request"]
        A1["Analyzer 1\n(configurable)\n+ send_poc_request"]
        A2["Analyzer 2\n(configurable)\n+ send_poc_request"]
        A3["Analyzer M\n(configurable)\n+ send_poc_request"]
    end

    space

    block:phase4:1
        columns 4
        V0["Verifier 0\n(configurable)\n+ send_poc_request"]
        V1["Verifier 1\n(configurable)\n+ send_poc_request"]
        V2["Verifier 2\n(configurable)\n+ send_poc_request"]
        V3["Verifier K\n(configurable)\n+ send_poc_request"]
    end

    space

    block:phase5:1
        columns 3
        space
        REPORT["📋 Root Strategist\n(configurable)\n\nReview PoCs → drop INVALID\n→ JSON Vulnerability Report"]
        space
    end

    phase1 -- "focus areas" --> phase2
    phase2 -- "scanner_findings XML" --> phase3
    phase3 -- "confirmed + PoC proof" --> phase4
    phase4 -- "VERIFIED / DISPUTED / INVALID" --> phase5

    style phase1 fill:#1e3a5f,color:#fff,stroke:#2563eb
    style phase2 fill:#064e3b,color:#fff,stroke:#10b981
    style phase3 fill:#4c1d95,color:#fff,stroke:#8b5cf6
    style phase4 fill:#7c2d12,color:#fff,stroke:#f97316
    style phase5 fill:#1e3a5f,color:#fff,stroke:#2563eb
    style ROOT fill:#2563eb,color:#fff,stroke:#1d4ed8
    style REPORT fill:#2563eb,color:#fff,stroke:#1d4ed8
    style S0 fill:#10b981,color:#fff,stroke:#059669
    style S1 fill:#10b981,color:#fff,stroke:#059669
    style S2 fill:#10b981,color:#fff,stroke:#059669
    style S3 fill:#10b981,color:#fff,stroke:#059669
    style S4 fill:#10b981,color:#fff,stroke:#059669
    style S5 fill:#10b981,color:#fff,stroke:#059669
    style A0 fill:#8b5cf6,color:#fff,stroke:#7c3aed
    style A1 fill:#8b5cf6,color:#fff,stroke:#7c3aed
    style A2 fill:#8b5cf6,color:#fff,stroke:#7c3aed
    style A3 fill:#8b5cf6,color:#fff,stroke:#7c3aed
    style V0 fill:#f97316,color:#fff,stroke:#ea580c
    style V1 fill:#f97316,color:#fff,stroke:#ea580c
    style V2 fill:#f97316,color:#fff,stroke:#ea580c
    style V3 fill:#f97316,color:#fff,stroke:#ea580c
```

### How agent count is determined

Sub-agents are created **dynamically at runtime** — the number depends
on what the root agent discovers during reconnaissance:

| Phase | Agent type | How many? | What decides? |
|-------|-----------|-----------|---------------|
| 2 | Scanners | N (1–6) | One per focus area found in Phase 1. Root groups files by vulnerability class (e.g., SQL sinks together, RCE sinks together). Capped by `VULN_AGENT_MAX_SCANNERS` (default 6). |
| 3 | Analyzers | M (1–N) | One per scanner that raised flags. If a scanner found nothing, no analyzer is created for it. |
| 4 | Verifiers | K (1–M) | One per analyzer that confirmed findings. If an analyzer rejected all flags, no verifier is created. |

A small Flask app with 5 files might get 3 scanners, 2 analyzers, and
2 verifiers. PyGoat (80 files) got 6 scanners, 4 analyzers, and 3
verifiers. The root agent makes the grouping decision based on its
recon — it can merge related files into one scanner or split a large
file across multiple.

All sub-agents are injected into `root_agent.sub_agents` at runtime
and become visible in `adk web` via `transfer_to_agent`.

### Live PoC sandbox (when `VULN_AGENT_LIVE_POC=true`)

```mermaid
graph LR
    subgraph "vulnhawk-poc-net (--internal, no internet)"
        TARGET["🎯 Target App\nFlask / Django\nport 5000 or 8000"]
        SENDER["📡 PoC Sender\npython:3.13-slim\nurllib only"]
        SENDER -- "HTTP request" --> TARGET
    end

    HOST["🖥️ Host\nadk web"] -- "docker exec" --> SENDER

    style TARGET fill:#ef4444,color:#fff,stroke:#dc2626,stroke-width:2px
    style SENDER fill:#f59e0b,color:#000,stroke:#d97706,stroke-width:2px
    style HOST fill:#6366f1,color:#fff,stroke:#4f46e5,stroke-width:2px
```

The host never sends HTTP to the target directly. All PoC traffic is
container-to-container inside the isolated Docker network.

### Security layers

```mermaid
block-beta
    columns 1
    L1["Layer 1: Security Gateway\nCommand denylist · arg blocklist · credential scrubbing\nturn limits (2500) · output truncation (102KB)"]
    L2["Layer 2: Docker Network Isolation\n--internal bridge · no egress · container-to-container only"]
    L3["Layer 3: Container Hardening\nNon-root user · memory limits · stdlib only · no network tools"]

    style L1 fill:#2563eb,color:#fff,stroke:#1d4ed8,stroke-width:2px
    style L2 fill:#7c3aed,color:#fff,stroke:#6d28d9,stroke-width:2px
    style L3 fill:#dc2626,color:#fff,stroke:#b91c1c,stroke-width:2px
```

Token usage is tracked per agent in the session state (visible in the
`adk web` State tab).

## Project layout

```
vuln-hawk/
├── vuln_agent/
│   ├── agent.py              # 5-phase multi-agent for adk web
│   ├── config.py             # Model config, backend, thinking, live PoC
│   ├── pipeline.py           # CLI pipeline with ParallelAgent
│   ├── target_manager.py     # Docker lifecycle for live PoC
│   ├── security.py           # Security gateway callbacks
│   ├── tools.py              # Shell-like tools + PoC tools
│   ├── prompts.py            # System instructions (single-agent mode)
│   └── report.py             # JSON report parser
├── sandbox/
│   ├── Dockerfile            # Code execution sandbox
│   └── Dockerfile.sender     # PoC sender sandbox
├── targets/
│   ├── vulnerable_flask_app/ # 8 planted vulns + 10 FP traps + Dockerfile
│   └── pygoat/               # OWASP PyGoat (Django) + Dockerfile
├── eval/
│   ├── ground_truth.json     # Labelled findings + traps
│   ├── run_eval.py           # Precision / recall / F1 scorer
│   ├── compaction_experiment.py
│   └── results/
├── docker-compose.yml        # Manual testing setup
├── pyproject.toml
├── .env.example
└── README.md
```

## Setup

```bash
uv venv && source .venv/bin/activate
uv sync
cp .env.example .env
# Add your API key(s) to .env
```

### Configuration (.env)

| Variable | Default | Description |
|---|---|---|
| **Provider** | | |
| `GOOGLE_API_KEY` | | Google AI API key (for Gemini) |
| `ANTHROPIC_API_KEY` | | Anthropic API key (for Claude) |
| `OPENROUTER_API_KEY` | | OpenRouter API key (for Nemotron and other OpenRouter models) |
| `VULN_AGENT_BACKEND` | `anthropic` | Backend for Claude models (`anthropic` or `vertex`). Gemini and OpenRouter auto-detect from the model string. |
| **Per-role models** | | |
| `VULN_AGENT_ROOT_MODEL` | `gemini-2.5-pro` | Root strategist |
| `VULN_AGENT_SCANNER_MODEL` | `gemini-2.5-flash` | Scanner sub-agents |
| `VULN_AGENT_ANALYZER_MODEL` | `gemini-2.5-flash` | Analyzer sub-agents |
| `VULN_AGENT_VERIFIER_MODEL` | `gemini-2.5-flash` | Verifier sub-agents |
| **Thinking** | | |
| `VULN_AGENT_THINKING_LEVEL` | | Gemini: `MINIMAL` / `LOW` / `MEDIUM` / `HIGH` |
| `VULN_AGENT_THINKING_BUDGET` | | Token budget (both providers) |
| **Live PoC** | | |
| `VULN_AGENT_LIVE_POC` | `false` | Enable live exploit validation |
| `VULN_AGENT_POC_TIMEOUT` | `10` | HTTP request timeout (seconds) |
| `VULN_AGENT_POC_STARTUP_TIMEOUT` | `60` | Target health check timeout |
| **Pipeline** | | |
| `VULN_AGENT_MAX_SCANNERS` | `6` | Max scanner sub-agents |
| `VULN_AGENT_SANDBOX` | `local` | `local` or `docker` for code execution |
| `TARGET_CODEBASE_ROOT` | `targets/vulnerable_flask_app` | Target codebase path |

Model strings are auto-routed by prefix: `gemini-*` to Google AI,
`openrouter/*` to OpenRouter via LiteLlm, all others to the
configured backend.

**Gemini (default):**
```
GOOGLE_API_KEY=your-key
VULN_AGENT_ROOT_MODEL=gemini-2.5-pro
VULN_AGENT_SCANNER_MODEL=gemini-2.5-flash
VULN_AGENT_ANALYZER_MODEL=gemini-2.5-flash
VULN_AGENT_VERIFIER_MODEL=gemini-2.5-flash
VULN_AGENT_THINKING_BUDGET=8192
```

**Claude:**
```
ANTHROPIC_API_KEY=your-key
VULN_AGENT_ROOT_MODEL=claude-opus-4-6
VULN_AGENT_SCANNER_MODEL=claude-sonnet-4-6
VULN_AGENT_ANALYZER_MODEL=claude-sonnet-4-6
VULN_AGENT_VERIFIER_MODEL=claude-sonnet-4-6
```

**NVIDIA Nemotron (via OpenRouter):**
```
OPENROUTER_API_KEY=your-key
VULN_AGENT_ROOT_MODEL=openrouter/nvidia/nemotron-3-ultra-550b-a55b
VULN_AGENT_SCANNER_MODEL=openrouter/nvidia/nemotron-3-ultra-550b-a55b
VULN_AGENT_ANALYZER_MODEL=openrouter/nvidia/nemotron-3-ultra-550b-a55b
VULN_AGENT_VERIFIER_MODEL=openrouter/nvidia/nemotron-3-ultra-550b-a55b
```

## Running the agent

**Interactive UI** (5-phase multi-agent, visible in `adk web`):

```bash
adk web
# select "vuln_discovery_agent" and send:
#   Audit the target codebase for vulnerabilities.
```

**With live PoC validation** (requires Docker):

```bash
# Set VULN_AGENT_LIVE_POC=true in .env, then:
adk web
```

**CLI pipeline** (ParallelAgent for concurrent scanning):

```bash
python eval/run_eval.py --pipeline
```

**Against PyGoat**:

```bash
# Set TARGET_CODEBASE_ROOT=targets/pygoat in .env, then:
adk web
```

**Docker Compose** (manual testing):

```bash
docker compose up -d                   # Flask target + sender
docker compose --profile pygoat up -d  # PyGoat instead
docker compose down                    # cleanup
```

## Target apps

### Bundled Flask app (8 vulns + 10 traps)

| ID | Class | File | What's wrong |
|----|-------|------|-------------|
| VULN-001 | SQL Injection | `db.py` | f-string interpolation into `cursor.execute` |
| VULN-002 | Command Injection | `utils.py` | user filename in `subprocess.run(..., shell=True)` |
| VULN-003 | Path Traversal | `upload.py` | `os.path.join(UPLOAD_DIR, filename)` without sanitisation |
| VULN-004 | SSTI | `app.py` | `render_template_string(f"...{user_message}...")` |
| VULN-005 | IDOR | `auth.py` | `login_required` checks session, not ownership |
| VULN-006a | Hardcoded Secret | `app.py` | `app.secret_key` hardcoded in source |
| VULN-006b | Hardcoded Secret | `app.py` | API key `sk-live-...` hardcoded in CONFIG |
| VULN-007 | SSRF | `utils.py` | `requests.get(user_url)` with no allowlist |

Ten false-positive traps test whether the agent traces data flows or
falls back to syntactic pattern matching. See `eval/ground_truth.json`.

### PyGoat (OWASP)

Django-based intentionally vulnerable application with SQL injection,
command injection, XSS, XXE, SSRF, SSTI, insecure deserialization,
broken access control, and more. No ground truth file yet — the agent
discovers vulns and we review manually.

## Results

### Bundled Flask app — model comparison (8 vulns, 10 traps)

| Metric | Claude Opus 4.6 | Gemini 3.1 Pro | Nemotron 3 Ultra 550B |
|---|---|---|---|
| True positives | 7 | 8 | 3 |
| False positives | 0 | 0 | 0 |
| False negatives | 1 | 0 | 5 |
| Traps triggered | 0 | 0 | 0 |
| Precision | 1.000 | 1.000 | 1.000 |
| Recall | 0.875 | 1.000 | 0.375 |
| F1 | 0.933 | 1.000 | 0.545 |

All three models avoided all 10 false-positive traps. Nemotron
correctly identified the 3 highest-signal vulnerabilities (hardcoded
secret, command injection, SSRF with DNS rebinding) and produced the
most precise SSRF analysis — identifying the TOCTOU DNS rebinding
bypass that other models flagged only as generic SSRF.

### Bundled Flask app — live PoC validation

All 5 testable exploits confirmed via sandboxed sender container:

| Vuln | PoC | Proof |
|---|---|---|
| SQL Injection | `GET /search?q=%27%20OR%20%271%27%3D%271` | All 3 users dumped |
| SSTI | `GET /error?msg={{7*7}}` | Response: `49` |
| Command Injection | `POST /convert {"filename":"x; echo PWNED"}` | `PWNED` in stdout |
| Path Traversal | `GET /download?filename=../../../../etc/passwd` | `/etc/passwd` contents |
| SSRF | `GET /preview?url=http://localhost:5000/healthz` | Internal endpoint fetched |

### PyGoat — 17 findings across 10 vuln classes

| ID | Class | File | Function | Severity |
|----|-------|------|----------|----------|
| F1 | SQL Injection | views.py | sql_lab | CRITICAL |
| F2 | SQL Injection | views.py | injection_sql_lab | CRITICAL |
| F3 | Command Injection | views.py | cmd_lab | CRITICAL |
| F4 | Command Injection | views.py | cmd_lab2 (eval) | CRITICAL |
| F5 | Insecure Deserialization | views.py | insec_des_lab (pickle) | CRITICAL |
| F6 | XXE | views.py | xxe_parse | HIGH |
| F7 | Insecure Deserialization | views.py | a9_lab (yaml) | CRITICAL |
| F8 | Path Traversal | views.py | ssrf_lab | HIGH |
| F9 | SSRF | views.py | ssrf_lab2 | HIGH |
| F10 | SSTI | views.py | ssti_lab | HIGH |
| F11 | Command Injection | mitre.py | mitre_lab_25_api (eval, unauth) | CRITICAL |
| F12 | Command Injection | mitre.py | mitre_lab_17_api (nmap, unauth) | CRITICAL |
| F13 | Command Injection | apis.py | log_function_checker (file write) | CRITICAL |
| F14 | Command Injection | apis.py | A6_disscussion_api_2 (file write) | CRITICAL |
| F15 | Hardcoded Secret | settings.py | SECRET_KEY | CRITICAL |
| F16 | Hardcoded Secret | settings.py | SECRET_COOKIE_KEY (JWT) | HIGH |
| F17 | Hardcoded Secret | views.py | a1_broken_access_lab_3 | MEDIUM |

## Agent methodology

The root agent follows a five-phase approach. From the
[PyGoat methodology walkthrough](eval/results/claude-pygoat-methodology-20260516.md):

```
Phase 1  Reconnaissance    Read everything, identify all sinks
Phase 2  Scanning           Trace data flows per sink (N agents)
Phase 3  Deep Analysis      Confirm/reject with PoC proof (M agents)
Phase 4  Verification       Independent review + live PoC (K agents)
Phase 5  Final Report       Only VERIFIED findings with proof
```

Key design behaviors:

- **Adaptive team sizing**: Scanner count scales with codebase complexity
- **Independent verification**: Verifiers re-trace data flows from scratch
  and can mark findings VERIFIED, DISPUTED, or INVALID
- **Live PoC**: Real HTTP requests fired from sandboxed container,
  response proves (or disproves) exploitability
- **Deliberate exclusions**: Documents why certain patterns were NOT
  flagged (e.g., version-dependent, auto-escaped by framework)

## Open questions

- Per-class detection rate across different vuln classes
- False-positive trap rate and reasoning patterns behind errors
- Effect of dynamic agent count on audit quality
- Effect of trajectory compaction on precision and recall
- Token efficiency across model configurations
- Live PoC validation rate: what fraction of static findings are
  confirmed by live testing?
