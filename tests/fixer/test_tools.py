"""Tests for fixer_agent.tools — validates write_file path containment,
surgical edits, apply_fix find-and-replace, syntax checking, branch
name validation, and test runner discovery.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from fixer_agent.tools import (
    apply_fix,
    check_syntax,
    create_fix_branch,
    git_commit,
    git_diff,
    run_target_tests,
    save_report,
    write_file,
)


@pytest.fixture
def target_repo(tmp_path, monkeypatch):
    """Create a minimal git-initialized target repo."""
    monkeypatch.setenv("TARGET_CODEBASE_ROOT", str(tmp_path))

    subprocess.run(["git", "init"], cwd=str(tmp_path), capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(tmp_path), capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(tmp_path), capture_output=True,
    )

    app_py = tmp_path / "app.py"
    app_py.write_text(
        'import os\n'
        'import subprocess\n'
        '\n'
        'def run_command(user_input):\n'
        '    result = subprocess.run(user_input, shell=True, capture_output=True)\n'
        '    return result.stdout\n'
        '\n'
        'SECRET_KEY = "hardcoded-secret-123"\n'
    )

    db_py = tmp_path / "db.py"
    db_py.write_text(
        'import sqlite3\n'
        '\n'
        'def search_users(name):\n'
        '    conn = sqlite3.connect("app.db")\n'
        '    cursor = conn.cursor()\n'
        '    cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n'
        '    return cursor.fetchall()\n'
    )

    subprocess.run(["git", "add", "."], cwd=str(tmp_path), capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=str(tmp_path), capture_output=True,
    )

    return tmp_path


class TestWriteFile:
    def test_full_overwrite(self, target_repo):
        result = write_file("app.py", "x = 1\n")
        assert result["status"] == "ok"
        assert (target_repo / "app.py").read_text() == "x = 1\n"

    def test_surgical_edit(self, target_repo):
        result = write_file("app.py", "    result = subprocess.run([user_input], capture_output=True)", 5, 5)
        assert result["status"] == "ok"
        content = (target_repo / "app.py").read_text()
        assert "shell=True" not in content
        assert "[user_input]" in content

    def test_path_escape_blocked(self, target_repo):
        result = write_file("../../etc/passwd", "pwned")
        assert result["status"] == "error"
        assert "escapes" in result["error"]

    def test_creates_parent_dirs(self, target_repo):
        result = write_file("src/new_file.py", "x = 1\n")
        assert result["status"] == "ok"
        assert (target_repo / "src" / "new_file.py").exists()

    def test_diff_output(self, target_repo):
        result = write_file("db.py", "# fixed\n")
        assert result["status"] == "ok"
        assert "---" in result["diff"]
        assert "+++" in result["diff"]


class TestApplyFix:
    def test_exact_match_replacement(self, target_repo):
        result = apply_fix(
            "db.py",
            '    cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")',
            '    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))',
        )
        assert result["status"] == "ok"
        content = (target_repo / "db.py").read_text()
        assert "?" in content
        assert "f\"SELECT" not in content

    def test_original_not_found(self, target_repo):
        result = apply_fix("db.py", "this does not exist in the file", "replacement")
        assert result["status"] == "error"
        assert "not found" in result["error"]

    def test_path_escape_blocked(self, target_repo):
        result = apply_fix("../../etc/passwd", "old", "new")
        assert result["status"] == "error"

    def test_file_not_found(self, target_repo):
        result = apply_fix("nonexistent.py", "old", "new")
        assert result["status"] == "error"


class TestCheckSyntax:
    def test_valid_python(self, target_repo):
        result = check_syntax("app.py")
        assert result["status"] == "ok"

    def test_invalid_python(self, target_repo):
        (target_repo / "broken.py").write_text("def foo(\n")
        result = check_syntax("broken.py")
        assert result["status"] == "error"
        assert "Syntax error" in result["error"]

    def test_path_escape(self, target_repo):
        result = check_syntax("../../etc/passwd")
        assert result["status"] == "error"


class TestCreateFixBranch:
    def test_creates_branch(self, target_repo):
        result = create_fix_branch("vuln-hawk/test-fix")
        assert result["status"] == "ok"
        assert result["branch_name"] == "vuln-hawk/test-fix"

        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True, cwd=str(target_repo),
        )
        assert branch.stdout.strip() == "vuln-hawk/test-fix"

    def test_invalid_branch_name(self, target_repo):
        result = create_fix_branch("branch; rm -rf /")
        assert result["status"] == "error"
        assert "Invalid branch name" in result["error"]

    def test_auto_generates_name(self, target_repo):
        result = create_fix_branch()
        assert result["status"] == "ok"
        assert "vuln-hawk/auto-fix" in result["branch_name"]

    def test_dirty_working_tree_blocked(self, target_repo):
        (target_repo / "dirty.py").write_text("x = 1")
        subprocess.run(["git", "add", "dirty.py"], cwd=str(target_repo), capture_output=True)
        result = create_fix_branch("test-branch")
        assert result["status"] == "error"
        assert "uncommitted" in result["error"]


class TestGitCommit:
    def test_commit(self, target_repo):
        create_fix_branch("fix-branch")
        (target_repo / "app.py").write_text("# fixed\n")
        result = git_commit("app.py", "fix: test commit")
        assert result["status"] == "ok"
        assert result["commit_sha"]

    def test_missing_files(self, target_repo):
        result = git_commit("", "message")
        assert result["status"] == "error"
        assert "files is required" in result["error"]

    def test_missing_message(self, target_repo):
        result = git_commit("app.py", "")
        assert result["status"] == "error"
        assert "message is required" in result["error"]


class TestGitDiff:
    def test_no_changes(self, target_repo):
        result = git_diff()
        assert result["status"] == "ok"
        assert "no changes" in result["diff"]

    def test_with_changes(self, target_repo):
        (target_repo / "app.py").write_text("# changed\n")
        result = git_diff("app.py")
        assert result["status"] == "ok"
        assert "changed" in result["diff"]


class TestRunTargetTests:
    def test_no_test_runner(self, target_repo):
        result = run_target_tests()
        assert result["status"] == "ok"
        assert result["passed"] is None
        assert "No test runner" in result["message"]

    def test_with_pytest(self, target_repo):
        tests_dir = target_repo / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_basic.py").write_text(
            "def test_one():\n    assert 1 + 1 == 2\n"
        )
        result = run_target_tests()
        assert result["status"] == "ok"
        assert result["passed"] is True

    def test_explicit_command(self, target_repo):
        result = run_target_tests(command="echo 'tests passed'")
        assert result["status"] == "ok"
        assert result["passed"] is True


class TestSaveReport:
    def test_save_json(self, target_repo):
        import json
        report = json.dumps({"summary": "test", "findings": []})
        result = save_report(report)
        assert result["status"] == "ok"
        assert ".vuln-hawk" in result["path"]
        assert (target_repo / ".vuln-hawk").is_dir()

    def test_empty_report(self, target_repo):
        result = save_report("")
        assert result["status"] == "error"
