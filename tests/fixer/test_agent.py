"""Tests for fixer_agent.agent — validates sub-agent factories,
fix XML parsing patterns, and report ingestion.
"""

from __future__ import annotations

import json

import pytest

from fixer_agent.agent import (
    create_fix_review_team,
    create_fix_team,
    root_agent,
)
from vuln_agent.report import Finding, ProofOfConcept, Report, from_json_file


class TestCreateFixTeam:
    def test_creates_fixers_from_json(self):
        plan = json.dumps([
            {
                "finding_id": "F1",
                "vuln_class": "SQL Injection",
                "file": "db.py",
                "function": "search_users",
                "line_range": [42, 51],
                "severity": "CRITICAL",
                "data_flow": "request.args -> f-string -> cursor.execute",
                "suggested_fix": "Use parameterized queries",
            },
            {
                "finding_id": "F2",
                "vuln_class": "Command Injection",
                "file": "utils.py",
                "function": "run_command",
                "line_range": [30, 38],
                "severity": "HIGH",
                "data_flow": "request.form -> subprocess shell=True",
                "suggested_fix": "Use subprocess with list args",
            },
        ])
        result = create_fix_team(plan)
        assert result["status"] == "ok"
        assert len(result["fixers_created"]) == 2
        assert result["fixers_created"] == ["fixer_0", "fixer_1"]

    def test_empty_json_rejected(self):
        result = create_fix_team("")
        assert result["status"] == "error"

    def test_invalid_json_rejected(self):
        result = create_fix_team("not json")
        assert result["status"] == "error"
        assert "Invalid JSON" in result["error"]

    def test_non_array_rejected(self):
        result = create_fix_team('{"key": "value"}')
        assert result["status"] == "error"
        assert "JSON array" in result["error"]


class TestCreateFixReviewTeam:
    def test_creates_reviewers_from_json(self):
        fixes = json.dumps([
            {
                "finding_id": "F1",
                "file": "db.py",
                "original_code": "cursor.execute(f'SELECT * FROM users WHERE name = {name}')",
                "fixed_code": "cursor.execute('SELECT * FROM users WHERE name = ?', (name,))",
                "explanation": "Replaced f-string with parameterized query",
                "vuln_class": "SQL Injection",
            },
        ])
        result = create_fix_review_team(fixes)
        assert result["status"] == "ok"
        assert len(result["reviewers_created"]) == 1
        assert result["reviewers_created"] == ["reviewer_0"]

    def test_empty_json_rejected(self):
        result = create_fix_review_team("")
        assert result["status"] == "error"


class TestRootAgent:
    def test_root_agent_exists(self):
        assert root_agent is not None
        assert root_agent.name == "fixer_root_agent"

    def test_root_agent_has_tools(self):
        tool_names = [t.__name__ if hasattr(t, "__name__") else t.name for t in root_agent.tools]
        assert "read_file" in tool_names
        assert "apply_fix" in tool_names
        assert "write_file" in tool_names
        assert "create_fix_branch" in tool_names
        assert "git_commit" in tool_names
        assert "create_fix_team" in tool_names
        assert "create_fix_review_team" in tool_names
        assert "create_pull_request" in tool_names
        assert "run_target_tests" in tool_names

    def test_root_agent_has_sub_agent_factories(self):
        tool_names = [t.__name__ if hasattr(t, "__name__") else t.name for t in root_agent.tools]
        assert "create_fix_team" in tool_names
        assert "create_fix_review_team" in tool_names


class TestReportFromJsonFile:
    def test_loads_extracted_json(self, tmp_path):
        report_data = {
            "summary": "Found 2 vulnerabilities",
            "findings": [
                {
                    "id": "F1",
                    "vuln_class": "SQL Injection",
                    "file": "db.py",
                    "function": "search_users",
                    "line_range": [42, 51],
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "data_flow": "request.args -> cursor.execute",
                    "suggested_fix": "Use parameterized queries",
                },
            ],
        }
        path = tmp_path / "report.json"
        path.write_text(json.dumps(report_data))

        report = from_json_file(path)
        assert len(report.findings) == 1
        assert report.findings[0].vuln_class == "SQL Injection"
        assert report.findings[0].file == "db.py"
        assert report.summary == "Found 2 vulnerabilities"

    def test_loads_fenced_json(self, tmp_path):
        text = """Some agent output text...

```json
{
  "summary": "Test report",
  "findings": [
    {
      "id": "F1",
      "vuln_class": "Command Injection",
      "file": "utils.py",
      "function": "run_cmd",
      "line_range": [10, 20],
      "severity": "HIGH",
      "confidence": "HIGH"
    }
  ]
}
```

More agent commentary...
"""
        path = tmp_path / "raw_report.txt"
        path.write_text(text)

        report = from_json_file(path)
        assert len(report.findings) == 1
        assert report.findings[0].vuln_class == "Command Injection"

    def test_empty_file(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text("")
        report = from_json_file(path)
        assert report.parse_error

    def test_finding_dataclass_fields(self):
        finding = Finding(
            id="F1",
            vuln_class="SQL Injection",
            file="db.py",
            function="search_users",
            line_range=[42, 51],
            severity="CRITICAL",
            confidence="HIGH",
            data_flow="request.args -> cursor.execute",
            proof_of_concept=ProofOfConcept(
                request="GET /search?name=' OR 1=1--",
                expected_behavior="Returns all users",
                live_validated=True,
            ),
            suggested_fix="Use parameterized queries",
        )
        assert finding.proof_of_concept.live_validated is True
        assert finding.severity == "CRITICAL"
