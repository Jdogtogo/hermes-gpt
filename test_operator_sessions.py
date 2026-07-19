from __future__ import annotations

import json
from pathlib import Path

import pytest

import operator_policy as op
import operator_sessions as sessions


def sample_policy(read_root: Path, write_root: Path) -> dict:
    return {
        "policy_template": "sandbox",
        "level": "workspace",
        "apply_mode": "direct",
        "readable_roots": [str(read_root)],
        "writable_roots": [str(write_root)],
        "egress_hosts": ["localhost"],
        "git_remotes": ["github.com/Jdogtogo/*"],
        "hard_denied_paths": [str(read_root / ".ssh")],
        "verbs": {
            "filesystem": ["read", "edit"],
            "git": ["fetch", "push"],
            "service": ["restart"],
        },
    }


@pytest.fixture
def session_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "sessions"
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(root))
    for name in [
        op.OPERATOR_ENABLED_ENV,
        op.OPERATOR_LEVEL_ENV,
        op.OPERATOR_APPLY_MODE_ENV,
        op.OPERATOR_ALLOWED_PATHS_ENV,
        op.OWNER_ACK_ENV,
    ]:
        monkeypatch.delenv(name, raising=False)
    yield root
    op.set_audit_log_override(None)


def test_snapshot_hash_is_deterministic(session_env, tmp_path):
    read_root = tmp_path / "read"
    write_root = tmp_path / "write"
    first = sample_policy(read_root, write_root)
    second = {
        "verbs": {"git": ["push", "fetch"], "filesystem": ["edit", "read"], "service": ["restart"]},
        "hard_denied_paths": [str(read_root / ".ssh")],
        "git_remotes": ["github.com/Jdogtogo/*"],
        "egress_hosts": ["localhost"],
        "writable_roots": [str(write_root)],
        "readable_roots": [str(read_root)],
        "apply_mode": "direct",
        "level": "workspace",
        "policy_template": "sandbox",
    }

    assert sessions.snapshot_hash(first) == sessions.snapshot_hash(second)
    assert sessions.canonical_policy(first) == sessions.canonical_policy(second)


def test_session_uses_immutable_snapshot_after_template_changes(session_env, tmp_path, monkeypatch):
    read_root = tmp_path / "read"
    write_root = tmp_path / "write"
    read_root.mkdir()
    write_root.mkdir()
    policy = sample_policy(read_root, write_root)
    created = sessions.create_session(policy, duration_seconds=600, session_id="ops-test")
    original_hash = created.snapshot_hash

    policy["writable_roots"] = [str(tmp_path / "other")]
    assert sessions.snapshot_hash(policy) != original_hash

    monkeypatch.setenv(sessions.ACTIVE_SESSION_ID_ENV, "ops-test")
    active = op.OperatorPolicy()
    assert active.snapshot_hash == original_hash
    active.require_workspace_path(write_root / "file.txt")
    with pytest.raises(PermissionError):
        active.require_workspace_path(tmp_path / "other" / "file.txt")


def test_hard_deny_overrides_read_and_write_grants(session_env, tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    denied = root / ".ssh"
    denied.mkdir(parents=True)
    sessions.create_session(sample_policy(root, root), duration_seconds=600, session_id="ops-deny")
    monkeypatch.setenv(sessions.ACTIVE_SESSION_ID_ENV, "ops-deny")
    policy = op.OperatorPolicy()

    with pytest.raises(PermissionError):
        policy.require_read_path(denied / "id_rsa")
    with pytest.raises(PermissionError):
        policy.require_workspace_path(denied / "id_rsa")


def test_resource_and_verb_qualifiers(session_env, tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    sessions.create_session(sample_policy(root, root), duration_seconds=600, session_id="ops-verbs")
    monkeypatch.setenv(sessions.ACTIVE_SESSION_ID_ENV, "ops-verbs")
    policy = op.OperatorPolicy()

    policy.require_read_path(root / "README.md")
    policy.require_workspace_path(root / "README.md")
    policy.require_egress_host("localhost")
    policy.require_git_remote("git@github.com:Jdogtogo/hermes-gpt.git", verb="push")
    with pytest.raises(PermissionError):
        policy.require_egress_host("example.com")
    with pytest.raises(PermissionError):
        policy.require_git_remote("git@github.com:Other/repo.git", verb="push")
    with pytest.raises(PermissionError):
        policy.require_force_push()
    with pytest.raises(PermissionError):
        policy.require_recursive_delete()


def test_expiry_and_revocation_fail_closed(session_env, tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    sessions.create_session(sample_policy(root, root), duration_seconds=60, session_id="ops-expire", now=1000)
    with pytest.raises(PermissionError, match="expired"):
        sessions.load_session("ops-expire", now=2000)

    sessions.create_session(sample_policy(root, root), duration_seconds=600, session_id="ops-revoke", now=1000)
    assert sessions.revoke_session("ops-revoke", now=1100) is True
    with pytest.raises(PermissionError, match="revoked"):
        sessions.load_session("ops-revoke", now=1101)


def test_audit_records_include_snapshot_hash(session_env, tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    record = sessions.create_session(sample_policy(root, root), duration_seconds=600, session_id="ops-audit")
    monkeypatch.setenv(sessions.ACTIVE_SESSION_ID_ENV, "ops-audit")
    log = tmp_path / "audit.jsonl"
    op.set_audit_log_override(log)

    written = op.audit_record(
        tool="unit",
        level="workspace",
        apply_mode="direct",
        dry_run=False,
        success=True,
    )

    assert written["session_id"] == "ops-audit"
    assert written["snapshot_hash"] == record.snapshot_hash
    line = json.loads(log.read_text(encoding="utf-8").strip())
    assert line["snapshot_hash"] == record.snapshot_hash
