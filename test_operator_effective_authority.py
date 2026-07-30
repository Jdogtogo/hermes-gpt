"""Regression tests for effective operator-authority resolution.

Pins the repair for the "approved session vs read_only runtime" mismatch:
status tools and mutation guards must consume ONE resolution path
(operator_sessions.resolve_effective_authority), lapsed sessions must be
visible as such (identity + expiry + reason) instead of silently downgrading
to an unexplained read_only, and in an explicitly session-governed deployment
stale environment variables must never outrank the authoritative session
record -- in either direction (env cannot re-grant lapsed authority; a valid
session cannot mask an explicit security failure of the persisted state).
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import operator_policy as op
import operator_sessions as sessions
import operator_workspace as ows
import server


def sample_policy(read_root: Path, write_root: Path) -> dict:
    return {
        "policy_template": "sandbox",
        "level": "workspace",
        "apply_mode": "direct",
        "readable_roots": [str(read_root), str(write_root)],
        "writable_roots": [str(write_root)],
        "egress_hosts": ["localhost"],
        "git_remotes": ["github.com/Jdogtogo/*"],
        "hard_denied_paths": [str(read_root / ".ssh")],
        "verbs": {
            "filesystem": ["read", "edit"],
            "git": ["fetch", "push"],
            "tests": ["run"],
        },
    }


@pytest.fixture
def session_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "sessions"
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(root))
    monkeypatch.delenv(sessions.ACTIVE_SESSION_ID_ENV, raising=False)
    for name in [
        op.OPERATOR_ENABLED_ENV,
        op.OPERATOR_LEVEL_ENV,
        op.OPERATOR_APPLY_MODE_ENV,
        op.OPERATOR_ALLOWED_PATHS_ENV,
        op.OWNER_ACK_ENV,
    ]:
        monkeypatch.delenv(name, raising=False)
    op.set_audit_log_override(tmp_path / "audit.jsonl")
    yield root
    op.set_audit_log_override(None)


def _approved_session(root: Path, read_root: Path, write_root: Path, **kwargs):
    read_root.mkdir(parents=True, exist_ok=True)
    write_root.mkdir(parents=True, exist_ok=True)
    record = sessions.create_session(sample_policy(read_root, write_root), root=root, **kwargs)
    sessions._write_active_pointer(record.session_id, root=root)
    return record


# 1. Approved active workspace session -----------------------------------------

def test_active_session_grants_workspace_direct_and_permits_mutation(session_env, tmp_path):
    write_root = tmp_path / "ws"
    _approved_session(session_env, tmp_path / "read", write_root)

    authority = sessions.resolve_effective_authority()
    assert authority.is_active is True
    assert authority.status == "active"
    assert authority.level == "workspace"
    assert authority.apply_mode == "direct"
    assert authority.failure_reason is None
    assert str(write_root) in authority.writable_roots

    policy = op.OperatorPolicy()
    assert policy.level == "workspace"
    assert policy.apply_mode == "direct"
    assert policy.session_status == "active"
    policy.require_level("workspace")  # must not raise
    policy.require_write_path(write_root)  # inside approved root: permitted

    # The real workspace mutation tool accepts the call (dry-run plan --
    # requires no Docker execution, but passes every guard on the way).
    out = ows.hermes_workspace_exec(
        argv=["python", "--version"], workdir=str(write_root),
        dry_run=True, docker_binary="/bin/echo",
    )
    parsed = json.loads(out)
    assert parsed.get("would_run") is True or parsed.get("success") is True


# 2. Service/runtime reload -----------------------------------------------------

def test_fresh_process_reloads_persisted_session_authority(session_env, tmp_path):
    write_root = tmp_path / "ws"
    _approved_session(session_env, tmp_path / "read", write_root)

    code = (
        "import json, operator_policy as op\n"
        "p = op.OperatorPolicy()\n"
        "print(json.dumps({'level': p.level, 'apply_mode': p.apply_mode, 'status': p.session_status}))\n"
    )
    env = dict(os.environ)
    env[sessions.SESSION_ROOT_ENV] = str(session_env)
    env.pop(op.OPERATOR_LEVEL_ENV, None)
    env.pop(op.OPERATOR_APPLY_MODE_ENV, None)
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        env=env, cwd=str(Path(__file__).resolve().parent), timeout=60,
    )
    assert result.returncode == 0, result.stderr
    parsed = json.loads(result.stdout.strip())
    assert parsed == {"level": "workspace", "apply_mode": "direct", "status": "active"}


# 3. Expired session ------------------------------------------------------------

def test_expired_session_fails_closed_with_visible_reason(session_env, tmp_path):
    record = _approved_session(session_env, tmp_path / "read", tmp_path / "ws", now=1000, duration_seconds=60)

    authority = sessions.resolve_effective_authority(now=5000)
    assert authority.is_active is False
    assert authority.status == "expired"
    assert authority.level == "read_only"
    assert authority.apply_mode == "dry_run"
    assert authority.pointed_session_id == record.session_id
    assert authority.expires_at == record.expires_at
    assert "expired" in (authority.failure_reason or "")

    # Mirror the live sidecar units: operator mode enabled via env while the
    # session governs authority.
    os.environ[op.OPERATOR_ENABLED_ENV] = "1"
    try:
        policy = op.OperatorPolicy()  # real clock: still expired
    finally:
        os.environ.pop(op.OPERATOR_ENABLED_ENV, None)
    assert policy.level == "read_only"
    assert policy.session_status == "expired"
    with pytest.raises(PermissionError, match="does not satisfy required level"):
        policy.require_level("workspace")
    # The guard error must explain the session cause, not suggest env vars.
    try:
        policy.require_level("workspace")
    except PermissionError as exc:
        assert "expired" in str(exc)
        assert op.OPERATOR_LEVEL_ENV not in str(exc)

    out = ows.hermes_workspace_exec(
        argv=["python", "--version"], workdir=str(tmp_path / "ws"), dry_run=False,
    )
    parsed = json.loads(out)
    assert parsed.get("success") is not True


# 4. Revoked session ------------------------------------------------------------

def test_revoked_session_fails_closed(session_env, tmp_path):
    record = _approved_session(session_env, tmp_path / "read", tmp_path / "ws")
    sessions.revoke_session(record.session_id, root=session_env)

    authority = sessions.resolve_effective_authority()
    assert authority.status == "revoked"
    assert authority.is_active is False
    assert authority.level == "read_only"

    policy = op.OperatorPolicy()
    assert policy.level == "read_only"
    out = ows.hermes_workspace_exec(
        argv=["python", "--version"], workdir=str(tmp_path / "ws"), dry_run=False,
    )
    assert json.loads(out).get("success") is not True


# 5. Missing session ------------------------------------------------------------

def test_missing_session_stays_read_only(session_env, tmp_path):
    sessions._write_active_pointer("ops_does_not_exist", root=session_env)

    authority = sessions.resolve_effective_authority()
    assert authority.status == "missing"
    assert authority.is_active is False
    assert authority.level == "read_only"
    assert op.OperatorPolicy().level == "read_only"


def test_session_governed_fallback_is_permanent_fixed_read_only_baseline(
    session_env, monkeypatch
):
    # Even aggressively permissive stale environment values cannot broaden
    # authority when the deployment is session-governed and no approved
    # session is active.
    monkeypatch.setenv(op.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "owner")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "direct")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PATHS_ENV, "/etc,/home/jfroh/.hermes/config.yaml")

    policy = op.OperatorPolicy()

    assert policy.level == "read_only"
    assert policy.apply_mode == "dry_run"
    assert policy.writable_roots == []
    assert policy.mutation_allowed is False
    assert policy.verbs == {"filesystem": ["read"]}
    assert Path("/home/jfroh/.hermes/ops-brain") in policy.readable_roots
    assert Path("/etc") not in policy.allowed_paths
    assert Path("/home/jfroh/.hermes/config.yaml") not in policy.allowed_paths


# 6. Malformed session state ----------------------------------------------------

def test_malformed_snapshot_fails_closed(session_env, tmp_path):
    record = _approved_session(session_env, tmp_path / "read", tmp_path / "ws")
    db = sessions.db_path(session_env)
    with sqlite3.connect(db) as connection:
        connection.execute(
            "UPDATE policy_snapshots SET canonical_json = ? WHERE snapshot_hash = ?",
            ("{not valid json", record.snapshot_hash),
        )

    authority = sessions.resolve_effective_authority()
    assert authority.status == "malformed"
    assert authority.is_active is False
    assert authority.level == "read_only"
    policy = op.OperatorPolicy()
    assert policy.level == "read_only"
    out = ows.hermes_workspace_exec(
        argv=["python", "--version"], workdir=str(tmp_path / "ws"), dry_run=False,
    )
    assert json.loads(out).get("success") is not True


# 7. Session approved for a different workspace ---------------------------------

def test_mutation_outside_approved_root_is_rejected(session_env, tmp_path):
    _approved_session(session_env, tmp_path / "read", tmp_path / "ws")
    other = tmp_path / "other"
    other.mkdir()

    out = ows.hermes_workspace_exec(
        argv=["python", "--version"], workdir=str(other), dry_run=True,
        docker_binary="/bin/echo",
    )
    parsed = json.loads(out)
    assert parsed.get("success") is not True
    assert parsed.get("would_run") is not True


# 8. Status and mutation guard consistency --------------------------------------

def test_status_tools_and_guards_share_one_resolution(session_env, tmp_path):
    record = _approved_session(session_env, tmp_path / "read", tmp_path / "ws", now=1000, duration_seconds=60)
    # Session is expired on the real clock: status must SAY so, and the guard
    # must reject for the same stated reason.
    status = json.loads(server.hermes_operator_status())
    assert status["level"] == "read_only"
    assert status["session"]["status"] == "expired"
    assert status["session"]["pointed_session_id"] == record.session_id
    assert status["session"]["expires_at"] == record.expires_at
    assert "expired" in (status["session"]["failure_reason"] or "")

    session_status = json.loads(server.hermes_operator_session_status())
    assert session_status["success"] is False
    assert session_status["session_status"] == "expired"
    assert session_status["pointed_session_id"] == record.session_id
    assert session_status["effective_level"] == "read_only"

    policy = op.OperatorPolicy()
    assert policy.level == status["level"]
    assert policy.session_status == status["session"]["status"]


def test_status_reports_active_session_consistently(session_env, tmp_path):
    write_root = tmp_path / "ws"
    record = _approved_session(session_env, tmp_path / "read", write_root)

    status = json.loads(server.hermes_operator_status())
    assert status["level"] == "workspace"
    assert status["apply_mode"] == "direct"
    assert status["session"]["status"] == "active"
    assert status["session"]["session_id"] == record.session_id
    assert str(write_root) in status["session"]["writable_roots"]

    session_status = json.loads(server.hermes_operator_session_status())
    assert session_status["success"] is True
    assert session_status["session_id"] == record.session_id
    assert session_status["level"] == "workspace"
    assert session_status["apply_mode"] == "direct"


# 9. Stale environment cannot override the session record ----------------------

def test_stale_env_defaults_do_not_override_active_session(session_env, tmp_path, monkeypatch):
    _approved_session(session_env, tmp_path / "read", tmp_path / "ws")
    # Stale env says read_only/dry_run (as the sidecar units do): the valid
    # approved session must still govern.
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "read_only")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "dry_run")

    policy = op.OperatorPolicy()
    assert policy.level == "workspace"
    assert policy.apply_mode == "direct"


def test_env_cannot_regrant_authority_after_session_lapses(session_env, tmp_path, monkeypatch):
    record = _approved_session(session_env, tmp_path / "read", tmp_path / "ws")
    sessions.revoke_session(record.session_id, root=session_env)
    # A stale/hostile env grant must not resurrect authority in a
    # session-governed deployment.
    monkeypatch.setenv(op.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "workspace")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "direct")

    policy = op.OperatorPolicy()
    assert policy.level == "read_only"
    assert policy.apply_mode == "dry_run"
    assert policy.session_status == "revoked"


def test_valid_session_does_not_override_explicit_security_failure(session_env, tmp_path):
    if os.name != "posix":
        pytest.skip("POSIX permission semantics required")
    record = _approved_session(session_env, tmp_path / "read", tmp_path / "ws")
    # The session row itself is valid, but the persisted state is
    # group/other-writable -- an explicit security failure that must win.
    os.chmod(sessions.db_path(session_env), 0o666)

    authority = sessions.resolve_effective_authority()
    assert authority.is_active is False
    assert authority.status == "malformed"
    assert "writable" in (authority.failure_reason or "")
    assert op.OperatorPolicy().level == "read_only"
    # restore so tmp cleanup isn't affected
    os.chmod(sessions.db_path(session_env), 0o600)
    assert record.session_id  # silence unused warning


# 10. Session-bound profile allowlists -----------------------------------------

def test_active_session_profile_snapshot_overrides_stale_env(session_env, tmp_path, monkeypatch):
    read_root = tmp_path / "read"
    write_root = tmp_path / "ws"
    read_root.mkdir(parents=True)
    write_root.mkdir(parents=True)
    policy_data = sample_policy(read_root, write_root)
    policy_data["allowed_profiles"] = ["default", "backend-eng"]
    record = sessions.create_session(policy_data, root=session_env)
    sessions._write_active_pointer(record.session_id, root=session_env)
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PROFILES_ENV, "default")

    policy = op.OperatorPolicy()
    assert set(policy.allowed_profiles) == {"default", "backend-eng"}
    assert op.profile_is_allowed("backend-eng", policy.allowed_profiles) is True


def test_legacy_session_without_profile_snapshot_uses_env_fallback(session_env, tmp_path, monkeypatch):
    _approved_session(session_env, tmp_path / "read", tmp_path / "ws")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PROFILES_ENV, "default,gemini-flash")

    policy = op.OperatorPolicy()
    assert policy.allowed_profiles == ["default", "gemini-flash"]


def test_explicit_empty_session_profile_snapshot_denies_all(session_env, tmp_path, monkeypatch):
    read_root = tmp_path / "read"
    write_root = tmp_path / "ws"
    read_root.mkdir(parents=True)
    write_root.mkdir(parents=True)
    policy_data = sample_policy(read_root, write_root)
    policy_data["allowed_profiles"] = []
    record = sessions.create_session(policy_data, root=session_env)
    sessions._write_active_pointer(record.session_id, root=session_env)
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PROFILES_ENV, "*")

    policy = op.OperatorPolicy()
    assert policy.allowed_profiles == []
    assert op.profile_is_allowed("default", policy.allowed_profiles) is False
    assert op.profile_is_allowed("backend-eng", policy.allowed_profiles) is False
