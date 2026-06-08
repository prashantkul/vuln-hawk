"""Model and pipeline configuration.

Supports three backends:
  - anthropic: Direct Anthropic API (ANTHROPIC_API_KEY)
  - vertex:    Anthropic models via Vertex AI (GOOGLE_CLOUD_PROJECT + LOCATION)
  - gemini:    Google Gemini models (GOOGLE_API_KEY or Vertex AI)

Each agent role (root, scanner, analyzer) can use a different model
string, allowing mixed-provider setups (e.g., Gemini root + Claude
scanners).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from google.adk.models.base_llm import BaseLlm

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)


# ── Default model strings per provider ───────────────────────────────

SONNET_MODEL = os.environ.get("VULN_AGENT_SONNET_MODEL", "claude-sonnet-4-6")
HAIKU_MODEL = os.environ.get("VULN_AGENT_HAIKU_MODEL", "claude-haiku-4-5-20251001")
OPUS_MODEL = os.environ.get("VULN_AGENT_OPUS_MODEL", "claude-opus-4-6")
GEMINI_PRO_MODEL = os.environ.get("VULN_AGENT_GEMINI_PRO_MODEL", "gemini-2.5-pro")
GEMINI_FLASH_MODEL = os.environ.get("VULN_AGENT_GEMINI_FLASH_MODEL", "gemini-2.5-flash")

# Valid Gemini models (as of May 2026):
#   Stable: gemini-2.5-pro, gemini-2.5-flash, gemini-2.5-flash-lite, gemini-3.1-flash-lite
#   Preview: gemini-3.1-pro-preview, gemini-3-flash-preview

NEMOTRON_MODEL = os.environ.get(
    "VULN_AGENT_NEMOTRON_MODEL",
    "openrouter/nvidia/nemotron-3-ultra-550b-a55b",
)

BACKEND = os.environ.get("VULN_AGENT_BACKEND", "anthropic").lower()

# ── Thinking config ─────────────────────────────────────────────────
# THINKING_LEVEL: Gemini only. One of: MINIMAL, LOW, MEDIUM, HIGH.
# THINKING_BUDGET: Token budget (both Gemini and Claude). Positive int.
THINKING_LEVEL = os.environ.get("VULN_AGENT_THINKING_LEVEL", "")
THINKING_BUDGET = os.environ.get("VULN_AGENT_THINKING_BUDGET", "")


# ── LLM factory ──────────────────────────────────────────────────────

def _detect_backend(model: str) -> str:
    """Infer the backend from the model string if not explicitly set."""
    if model.startswith("gemini"):
        return "gemini"
    if model.startswith("openrouter/"):
        return "openrouter"
    return BACKEND


def _is_gemini_backend() -> bool:
    """Check if the root model is Gemini (determines thinking config style)."""
    root_model = os.environ.get("VULN_AGENT_ROOT_MODEL", "")
    return root_model.startswith("gemini") or BACKEND == "gemini"


def _build_generate_content_config():
    """Build GenerateContentConfig with thinking if configured.

    Gemini: supports thinking_level (MINIMAL/LOW/MEDIUM/HIGH) OR thinking_budget.
    Claude: supports thinking_budget only (>= 1024, must be < max_tokens which defaults to 8192).
    """
    from google.genai import types

    if not THINKING_LEVEL and not THINKING_BUDGET:
        return None

    is_gemini = _is_gemini_backend()

    # Budget takes precedence — Gemini only allows one of level or budget.
    if THINKING_BUDGET and THINKING_BUDGET.isdigit():
        budget = int(THINKING_BUDGET)
        if not is_gemini and budget >= 8192:
            budget = 4096
        return types.GenerateContentConfig(
            thinking_config=types.ThinkingConfig(thinking_budget=budget),
        )

    # Named levels — Gemini only. Skip for Claude.
    if THINKING_LEVEL and is_gemini:
        named_levels = {"MINIMAL", "LOW", "MEDIUM", "HIGH"}
        if THINKING_LEVEL.upper() in named_levels:
            return types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level=THINKING_LEVEL.upper()),
            )

    return None


GENERATE_CONTENT_CONFIG = _build_generate_content_config()


def create_llm(model: str) -> BaseLlm:
    """Return an LLM instance for the given model string.

    Auto-detects the backend from the model name:
      - gemini-*       → Gemini (Google AI / Vertex AI)
      - openrouter/*   → LiteLlm (OpenRouter)
      - claude-*       → AnthropicLlm or Claude (depending on VULN_AGENT_BACKEND)

    This allows mixed configs like root=gemini-2.5-pro, scanner=claude-sonnet-4-6.
    """
    backend = _detect_backend(model)

    if backend == "gemini":
        from google.adk.models.google_llm import Gemini
        return Gemini(model=model)

    if backend == "openrouter":
        from google.adk.models.lite_llm import LiteLlm

        class _SerializableLiteLlm(LiteLlm):
            def model_dump(self, **kwargs):
                d = super().model_dump(**kwargs)
                d.pop("llm_client", None)
                return d

        return _SerializableLiteLlm(model=model, drop_params=True)

    from google.adk.models.anthropic_llm import AnthropicLlm, Claude

    if backend == "vertex":
        return Claude(model=model)
    return AnthropicLlm(model=model)



# ── Per-role model config ────────────────────────────────────────────

def _env_or(key: str, default: str) -> str:
    """Read a model from env, falling back to default."""
    return os.environ.get(key, default)


@dataclass(frozen=True)
class ModelConfig:
    root: str = _env_or("VULN_AGENT_ROOT_MODEL", OPUS_MODEL)
    scanner: str = _env_or("VULN_AGENT_SCANNER_MODEL", SONNET_MODEL)
    analyzer: str = _env_or("VULN_AGENT_ANALYZER_MODEL", SONNET_MODEL)
    verifier: str = _env_or("VULN_AGENT_VERIFIER_MODEL", SONNET_MODEL)
    fixer: str = _env_or("VULN_AGENT_FIXER_MODEL", OPUS_MODEL)
    single: str = _env_or("VULN_AGENT_SINGLE_MODEL", SONNET_MODEL)


MAX_PARALLEL_SCANNERS = int(os.environ.get("VULN_AGENT_MAX_SCANNERS", "6"))

# ── Fixer agent settings ───────────────────────────────────────────
FIXER_MAX_RETRIES = int(os.environ.get("VULN_AGENT_FIXER_MAX_RETRIES", "2"))
FIXER_TEST_TIMEOUT = int(os.environ.get("VULN_AGENT_FIXER_TEST_TIMEOUT", "120"))
FIXER_BRANCH_PREFIX = os.environ.get("VULN_AGENT_FIXER_BRANCH_PREFIX", "vuln-hawk/auto-fix")
FIXER_A2A_PORT = int(os.environ.get("VULN_AGENT_FIXER_A2A_PORT", "8001"))


# ── Live PoC validation ─────────────────────────────────────────────

LIVE_POC_ENABLED = os.environ.get("VULN_AGENT_LIVE_POC", "false").lower() == "true"
LIVE_POC_NETWORK = os.environ.get("VULN_AGENT_POC_NETWORK", "vulnhawk-poc-net")
LIVE_POC_CONTAINER_NAME = os.environ.get("VULN_AGENT_POC_CONTAINER", "vulnhawk-target")
LIVE_POC_REQUEST_TIMEOUT = int(os.environ.get("VULN_AGENT_POC_TIMEOUT", "10"))
LIVE_POC_MAX_RESPONSE_BYTES = int(os.environ.get("VULN_AGENT_POC_MAX_RESPONSE", "8192"))
LIVE_POC_STARTUP_TIMEOUT = int(os.environ.get("VULN_AGENT_POC_STARTUP_TIMEOUT", "60"))

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class TargetConfig:
    """Configuration for a target application to run in Docker."""
    name: str
    dockerfile_dir: str
    port: int
    health_path: str = "/"
    command: tuple[str, ...] | None = None


def _resolve_target_dir(rel: str) -> str:
    return str(REPO_ROOT / rel)


TARGET_CONFIGS: dict[str, TargetConfig] = {
    "vulnerable_flask_app": TargetConfig(
        name="vulnerable_flask_app",
        dockerfile_dir=_resolve_target_dir("targets/vulnerable_flask_app"),
        port=5000,
    ),
    "pygoat": TargetConfig(
        name="pygoat",
        dockerfile_dir=_resolve_target_dir("targets/pygoat"),
        port=8000,
        command=(
            "sh", "-c",
            "python3 -c \"import re; "
            "s=open('/app/pygoat/settings.py').read(); "
            "s=re.sub(r'ALLOWED_HOSTS.*', 'ALLOWED_HOSTS = [\\\"*\\\"]', s); "
            "open('/app/pygoat/settings.py','w').write(s)\" && "
            "gunicorn --bind 0.0.0.0:8000 --workers 2 pygoat.wsgi",
        ),
    ),
}


def detect_target_name() -> str:
    """Auto-detect target name from TARGET_CODEBASE_ROOT."""
    root = os.environ.get("TARGET_CODEBASE_ROOT", "")
    for name in TARGET_CONFIGS:
        if name in root:
            return name
    return "vulnerable_flask_app"
