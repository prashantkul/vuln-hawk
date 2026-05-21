"""Parser for the agent's structured vulnerability report.

The agent emits a JSON block delimited by ```json fences. This module
extracts and validates that block, returning a normalised dictionary the
evaluation harness can score against ground truth. Lenient by design —
language models occasionally produce trailing commentary, partial fences,
or stray whitespace, and we'd rather salvage a usable report than fail
hard.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


_JSON_BLOCK = re.compile(r"```json\s*(.*?)```", re.DOTALL | re.IGNORECASE)
_BARE_BLOCK = re.compile(r"\{[\s\S]*\}")


@dataclass
class ProofOfConcept:
    request: str = ""
    expected_behavior: str = ""
    validation_steps: str = ""
    live_validated: bool = False
    live_response_status: int = 0
    live_response_body: str = ""

@dataclass
class Finding:
    id: str = ""
    vuln_class: str = ""
    file: str = ""
    function: str = ""
    line_range: list[int] = field(default_factory=list)
    severity: str = ""
    confidence: str = ""
    data_flow: str = ""
    example_exploit: str = ""
    proof_of_concept: ProofOfConcept = field(default_factory=ProofOfConcept)
    suggested_fix: str = ""


@dataclass
class Report:
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    raw: str = ""
    parse_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)
        d.pop("parse_error", None) if not self.parse_error else None
        return d


def _coerce_finding(item: dict[str, Any], idx: int) -> Finding:
    raw_range = item.get("line_range") or []
    if isinstance(raw_range, list):
        coerced_range = [int(x) for x in raw_range if isinstance(x, (int, float, str)) and str(x).lstrip("-").isdigit()]
    else:
        coerced_range = []
    return Finding(
        id=str(item.get("id") or f"F{idx + 1}"),
        vuln_class=str(item.get("vuln_class") or item.get("class") or ""),
        file=str(item.get("file") or ""),
        function=str(item.get("function") or ""),
        line_range=coerced_range,
        severity=str(item.get("severity") or "").upper(),
        confidence=str(item.get("confidence") or "").upper(),
        data_flow=str(item.get("data_flow") or ""),
        example_exploit=str(item.get("example_exploit") or ""),
        proof_of_concept=_coerce_poc(item.get("proof_of_concept")),
        suggested_fix=str(item.get("suggested_fix") or ""),
    )


def _coerce_poc(raw: Any) -> ProofOfConcept:
    if not raw or not isinstance(raw, dict):
        return ProofOfConcept()
    return ProofOfConcept(
        request=str(raw.get("request") or ""),
        expected_behavior=str(raw.get("expected_behavior") or ""),
        validation_steps=str(raw.get("validation_steps") or ""),
        live_validated=bool(raw.get("live_validated", False)),
        live_response_status=int(raw.get("live_response_status", 0) or 0),
        live_response_body=str(raw.get("live_response_body") or ""),
    )


def parse_report(text: str) -> Report:
    """Extract a Report from the agent's final message text."""
    if not text:
        return Report(parse_error="empty response", raw=text or "")

    candidates: list[str] = []
    for m in _JSON_BLOCK.finditer(text):
        candidates.append(m.group(1).strip())
    if not candidates:
        # Last-ditch: grab the largest brace-balanced JSON-looking blob.
        m = _BARE_BLOCK.search(text)
        if m:
            candidates.append(m.group(0))

    last_err = ""
    for blob in candidates:
        try:
            data = json.loads(blob)
        except json.JSONDecodeError as exc:
            last_err = f"JSONDecodeError: {exc}"
            continue
        if not isinstance(data, dict):
            last_err = "top-level JSON is not an object"
            continue
        findings_raw = data.get("findings") or []
        findings = [
            _coerce_finding(it, i)
            for i, it in enumerate(findings_raw)
            if isinstance(it, dict)
        ]
        return Report(
            summary=str(data.get("summary") or ""),
            findings=findings,
            raw=text,
        )

    return Report(parse_error=last_err or "no JSON block found", raw=text)


def from_json_file(path: Path | str) -> Report:
    """Load a Report from a JSON file.

    Accepts either extracted JSON (with a top-level ``findings`` key) or
    raw agent output text containing a fenced ``json`` block.
    """
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "findings" in data:
            findings = [
                _coerce_finding(f, i)
                for i, f in enumerate(data.get("findings", []))
                if isinstance(f, dict)
            ]
            return Report(summary=str(data.get("summary", "")), findings=findings, raw=text)
    except json.JSONDecodeError:
        pass
    return parse_report(text)
