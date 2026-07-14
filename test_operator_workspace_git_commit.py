"""Tests for hermes_workspace_git_commit and the session-scoped git:commit verb."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import operator_policy as op
import operator_sessions as op_sessions
import operator_workspace as ows


def _run_git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _run_git(["init", "-q"], repo)
    _run_git(["config", "user.email", "test@example.test"], repo)
    _run_git(["config", "user.name", "Test"], repo)
    (repo / "README.md").write_text("hello\n", encoding="utf-8")
    _run_git(["add", "README.md"], repo)
    _run_git(["commit", "-q", "-m", "initial"], repo)
    return repo


@pytest.fixture
def clean_env(monkeypatch):
    for name in [
        op.OPERATOR_ENABLED_ENV, op.OPERATOR_LEVEL_ENV, op.OPERATOR_APPLY_MODE_ENV,
        op.OPERATOR_ALLOWED_PROFILES_ENV, op.OPERATOR_ALLOWED_PATHS_ENV,
        op.OPERATOR_DENIED_PATHS_ENV, op.OWNER_ACK_ENV,
        op_sessions.SESSION_ROOT_ENV, op_sessions.ACTIVE_SESSION_ID_ENV,
    ]:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def audit_override(tmp_path):
    log = tmp_path / "audit.jsonl"
    op.set_audit_log_override(log)
    yield log
    op.set_audit_log_override(None)


def _make_session(tmp_path, repo, *, verbs, session_id="ops-commit-test", duration_seconds=600):
    session_root = tmp_path / "sessions"
    return op_sessions.create_session(
        {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": [str(repo)],
            "writable_roots": [str(repo)],
            "verbs": verbs,
        },
        duration_seconds=duration_seconds,
        root=session_root,
        session_id=session_id,
    ), session_root


def _activate(monkeypatch, record, session_root):
    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(session_root))
    monkeypatch.setenv(op_sessions.ACTIVE_SESSION_ID_ENV, record.session_id)


def test_commit_happy_path(git_repo, clean_env, audit_override, monkeypatch, tmp_path):
    record, session_root = _make_session(
        tmp_path, git_repo, verbs={"git": ["commit"], "filesystem": ["read", "edit"]}
    )
    _activate(monkeypatch, record, session_root)

    (git_repo / "new_file.txt").write_text("content\n", encoding="utf-8")
    baseline = _run_git(["rev-parse", "HEAD"], git_repo)
    branch = _run_git(["branch", "--show-current"], git_repo)

    out = json.loads(ows.hermes_workspace_git_commit(
        workdir=str(git_repo),
        expected_branch=branch,
        expected_baseline=baseline,
        allowed_files=["new_file.txt"],
        message="add new_file.txt",
        dry_run=False,
    ))
    assert out["success"] is True
    assert out["commit_hash"] and out["commit_hash"] != baseline
    assert out["files"] == ["new_file.txt"]

    log = ["push", "--force", "origin", branch]  # never executed; sanity only
    assert "push" not in _run_git(["log", "-1", "--format=%s"], git_repo)  # commit msg, not a push


def test_commit_requires_git_commit_verb(git_repo, clean_env, audit_override, monkeypatch, tmp_path):
    record, session_root = _make_session(tmp_path, git_repo, verbs={"git": ["fetch"]})
    _activate(monkeypatch, record, session_root)
    (git_repo / "new_file.txt").write_text("content\n", encoding="utf-8")
    baseline = _run_git(["rev-parse", "HEAD"], git_repo)
    branch = _run_git(["branch", "--show-current"], git_repo)

    out = json.loads(ows.hermes_workspace_git_commit(
        workdir=str(git_repo),
        expected_branch=branch,
        expected_baseline=baseline,
        allowed_files=["new_file.txt"],
        message="add new_file.txt",
        dry_run=False,
    ))
    assert out["success"] is False
    assert "commit" in out["error"].lower() or "verb" in out["error"].lower()
    # File must remain uncommitted.
    assert _run_git(["rev-parse", "HEAD"], git_repo) == baseline


def test_commit_rejects_out_of_scope_dirty_file(git_repo, clean_env, audit_override, monkeypatch, tmp_path):
    record, session_root = _make_session(tmp_path, git_repo, verbs={"git": ["commit"]})
    _activate(monkeypatch, record, session_root)
    (git_repo / "approved.txt").write_text("ok\n", encoding="utf-8")
    (git_repo / "unapproved.txt").write_text("surprise\n", encoding="utf-8")
    baseline = _run_git(["rev-parse", "HEAD"], git_repo)
    branch = _run_git(["branch", "--show-current"], git_repo)

    out = json.loads(ows.hermes_workspace_git_commit(
        workdir=str(git_repo),
        expected_branch=branch,
        expected_baseline=baseline,
        allowed_files=["approved.txt"],
        message="add approved.txt",
        dry_run=False,
    ))
    assert out["success"] is False
    assert "unapproved" in out["error"] or "out_of_scope" in out["error"].lower() or "unapproved.txt" in out["error"]
    assert _run_git(["rev-parse", "HEAD"], git_repo) == baseline


def test_commit_rejects_branch_mismatch(git_repo, clean_env, audit_override, monkeypatch, tmp_path):
    record, session_root = _make_session(tmp_path, git_repo, verbs={"git": ["commit"]})
    _activate(monkeypatch, record, session_root)
    (git_repo / "f.txt").write_text("x\n", encoding="utf-8")
    baseline = _run_git(["rev-parse", "HEAD"], git_repo)

    out = json.loads(ows.hermes_workspace_git_commit(
        workdir=str(git_repo),
        expected_branch="not-the-real-branch",
        expected_baseline=baseline,
        allowed_files=["f.txt"],
        message="msg",
        dry_run=False,
    ))
    assert out["success"] is False
    assert "branch" in out["error"].lower()


def test_commit_rejects_baseline_mismatch(git_repo, clean_env, audit_override, monkeypatch, tmp_path):
    record, session_root = _make_session(tmp_path, git_repo, verbs={"git": ["commit"]})
    _activate(monkeypatch, record, session_root)
    branch = _run_git(["branch", "--show-current"], git_repo)
    (git_repo / "f.txt").write_text("x\n", encoding="utf-8")

    out = json.loads(ows.hermes_workspace_git_commit(
        workdir=str(git_repo),
        expected_branch=branch,
        expected_baseline="0" * 40,
        allowed_files=["f.txt"],
        message="msg",
        dry_run=False,
    ))
    assert out["success"] is False
    assert "baseline" in out["error"].lower()


def test_commit_rejects_non_toplevel_workdir(git_repo, clean_env, audit_override, monkeypatch, tmp_path):
    record, session_root = _make_session(tmp_path, git_repo, verbs={"git": ["commit"]})
    _activate(monkeypatch, record, session_root)
    subdir = git_repo / "src"
    subdir.mkdir()
    (subdir / "f.txt").write_text("x\n", encoding="utf-8")
    baseline = _run_git(["rev-parse", "HEAD"], git_repo)
    branch = _run_git(["branch", "--show-current"], git_repo)

    out = json.loads(ows.hermes_workspace_git_commit(
        workdir=str(subdir),
        expected_branch=branch,
        expected_baseline=baseline,
        allowed_files=["src/f.txt"],
        message="msg",
        dry_run=False,
    ))
    assert out["success"] is False


def test_commit_never_amends_never_pushes_never_changes_branch(git_repo, clean_env, audit_override, monkeypatch, tmp_path):
    """The tool has no amend/push/checkout code path at all; this just proves
    a normal commit leaves history length +1 and branch/HEAD-ref semantics
    (i.e. no rewrite happened) rather than trying to invoke forbidden verbs
    through this tool (which has no parameter surface for them)."""
    record, session_root = _make_session(tmp_path, git_repo, verbs={"git": ["commit"]})
    _activate(monkeypatch, record, session_root)
    before_count = int(_run_git(["rev-list", "--count", "HEAD"], git_repo))
    before_branch = _run_git(["branch", "--show-current"], git_repo)
    baseline = _run_git(["rev-parse", "HEAD"], git_repo)
    (git_repo / "f.txt").write_text("x\n", encoding="utf-8")

    out = json.loads(ows.hermes_workspace_git_commit(
        workdir=str(git_repo),
        expected_branch=before_branch,
        expected_baseline=baseline,
        allowed_files=["f.txt"],
        message="msg",
        dry_run=False,
    ))
    assert out["success"] is True
    after_count = int(_run_git(["rev-list", "--count", "HEAD"], git_repo))
    after_branch = _run_git(["branch", "--show-current"], git_repo)
    assert after_count == before_count + 1
    assert after_branch == before_branch


def test_expired_session_cannot_commit(git_repo, clean_env, audit_override, monkeypatch, tmp_path):
    record, session_root = _make_session(
        tmp_path, git_repo, verbs={"git": ["commit"]}, duration_seconds=60,
    )
    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(session_root))
    monkeypatch.setenv(op_sessions.ACTIVE_SESSION_ID_ENV, record.session_id)
    (git_repo / "f.txt").write_text("x\n", encoding="utf-8")
    baseline = _run_git(["rev-parse", "HEAD"], git_repo)
    branch = _run_git(["branch", "--show-current"], git_repo)

    # Advance the wall clock past expiry and drive the full tool path (not
    # just the session library) to prove the running server would refuse.
    future = record.expires_at + 10
    monkeypatch.setattr(op_sessions.time, "time", lambda: future)

    out = json.loads(ows.hermes_workspace_git_commit(
        workdir=str(git_repo),
        expected_branch=branch,
        expected_baseline=baseline,
        allowed_files=["f.txt"],
        message="msg",
        dry_run=False,
    ))
    assert out["success"] is False
    # An expired session is now treated identically to no active session at
    # all (the service must keep running rather than raise) — see
    # active_session() in operator_sessions.py. The tool-level message is
    # correspondingly generic; what matters is that mutation is refused.
    assert "active operator session" in out["error"].lower()
    assert _run_git(["rev-parse", "HEAD"], git_repo) == baseline


def test_revoked_session_cannot_commit(git_repo, clean_env, audit_override, monkeypatch, tmp_path):
    record, session_root = _make_session(tmp_path, git_repo, verbs={"git": ["commit"]})
    _activate(monkeypatch, record, session_root)
    op_sessions.revoke_session(record.session_id, root=session_root)

    (git_repo / "f.txt").write_text("x\n", encoding="utf-8")
    baseline = _run_git(["rev-parse", "HEAD"], git_repo)
    branch = _run_git(["branch", "--show-current"], git_repo)

    out = json.loads(ows.hermes_workspace_git_commit(
        workdir=str(git_repo),
        expected_branch=branch,
        expected_baseline=baseline,
        allowed_files=["f.txt"],
        message="msg",
        dry_run=False,
    ))
    assert out["success"] is False
    # A revoked session is now treated identically to no active session at
    # all (see active_session() in operator_sessions.py) — the important
    # property is that mutation is refused, not the specific wording.
    assert "active operator session" in out["error"].lower()
