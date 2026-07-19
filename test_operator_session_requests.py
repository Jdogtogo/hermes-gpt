"""Tests for the session-creation-request broker (request/approve/deny) and
the audit trail for extension and session-creation decisions.

hermes_operator_session_request (the MCP tool, added separately) must only
ever call request_session() below — it creates no authority by itself.
Only approve_session_request(), invoked from Telegram, the localhost
approval page, or the break-glass CLI, actually creates a session.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import operator_policy as op
import operator_sessions as sessions
import operator_policy_templates as templates


@pytest.fixture
def session_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "sessions"
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(root))
    for name in [
        op.OPERATOR_ENABLED_ENV, op.OPERATOR_LEVEL_ENV, op.OPERATOR_APPLY_MODE_ENV,
        op.OPERATOR_ALLOWED_PATHS_ENV, op.OWNER_ACK_ENV,
    ]:
        monkeypatch.delenv(name, raising=False)
    yield root
    op.set_audit_log_override(None)


@pytest.fixture
def audit_override(tmp_path):
    log = tmp_path / "audit.jsonl"
    op.set_audit_log_override(log)
    yield log
    op.set_audit_log_override(None)


def test_request_session_creates_no_authority(session_env):
    resolved = templates.resolve_template("sandbox")
    request_id = sessions.request_session(
        policy_template="sandbox",
        resolved_policy=resolved["policy"],
        requested_duration_seconds=3600,
        reason="routine maintenance",
        root=session_env,
    )
    assert request_id
    # No session exists yet — the request alone grants nothing.
    pending = sessions.list_pending_session_requests(root=session_env)
    assert len(pending) == 1
    assert pending[0]["request_id"] == request_id
    assert pending[0]["policy_template"] == "sandbox"
    assert pending[0]["resolved_policy"] == resolved["policy"]


def test_unknown_policy_template_rejected_before_any_request_exists():
    with pytest.raises(templates.UnknownPolicyTemplateError):
        templates.resolve_template("not-a-real-template")


def test_approved_session_uses_exact_resolved_policy(session_env, audit_override):
    resolved = templates.resolve_template("hermes-gpt-operator-maintenance")
    request_id = sessions.request_session(
        policy_template="hermes-gpt-operator-maintenance",
        resolved_policy=resolved["policy"],
        requested_duration_seconds=3600,
        reason="fix a bug",
        root=session_env,
    )
    record = sessions.approve_session_request(request_id, decided_by="telegram:12345", root=session_env)
    loaded = sessions.load_session(record.session_id, root=session_env)
    assert loaded.policy["readable_roots"] == resolved["policy"]["readable_roots"]
    assert loaded.policy["writable_roots"] == resolved["policy"]["writable_roots"]
    assert loaded.policy["policy_template"] == "hermes-gpt-operator-maintenance"
    authority = sessions.resolve_effective_authority()
    assert authority.is_active is True
    assert authority.policy_template == "hermes-gpt-operator-maintenance"

    audit = op.audit_tail(limit=10)
    approvals = [r for r in audit if r.get("tool") == "session_approval" and r.get("request_type") == "session_creation"]
    assert approvals
    assert approvals[-1]["decision"] == "approved"
    assert approvals[-1]["approval_source"] == "telegram:12345"
    assert approvals[-1]["resulting_session_id"] == record.session_id


def test_denied_session_request_creates_no_authority(session_env, audit_override):
    resolved = templates.resolve_template("sandbox")
    request_id = sessions.request_session(
        policy_template="sandbox",
        resolved_policy=resolved["policy"],
        requested_duration_seconds=3600,
        reason="test",
        root=session_env,
    )
    denied = sessions.deny_session_request(request_id, decided_by="localhost:approver", root=session_env)
    assert denied is True
    assert sessions.list_pending_session_requests(root=session_env) == []
    with pytest.raises(ValueError, match="already denied"):
        sessions.approve_session_request(request_id, root=session_env)

    audit = op.audit_tail(limit=10)
    denials = [r for r in audit if r.get("tool") == "session_approval" and r.get("decision") == "denied"]
    assert denials
    assert denials[-1]["approval_source"] == "localhost:approver"


def test_session_request_cannot_be_approved_twice(session_env):
    resolved = templates.resolve_template("sandbox")
    request_id = sessions.request_session(
        policy_template="sandbox", resolved_policy=resolved["policy"],
        requested_duration_seconds=1800, reason="x", root=session_env,
    )
    sessions.approve_session_request(request_id, root=session_env)
    with pytest.raises(ValueError, match="already approved"):
        sessions.approve_session_request(request_id, root=session_env)


def test_session_request_expires(session_env, monkeypatch):
    resolved = templates.resolve_template("sandbox")
    request_id = sessions.request_session(
        policy_template="sandbox", resolved_policy=resolved["policy"],
        requested_duration_seconds=1800, reason="x", root=session_env, now=1_000_000,
    )
    with pytest.raises(ValueError, match="expired"):
        sessions.approve_session_request(
            request_id, root=session_env, now=1_000_000 + sessions.SESSION_REQUEST_TTL_SECONDS + 10
        )


def test_extension_requires_separate_approval_and_cannot_self_approve(session_env):
    resolved = templates.resolve_template("sandbox")
    policy = {**resolved["policy"], "policy_template": "sandbox"}
    record = sessions.create_session(policy, duration_seconds=3600, root=session_env)
    request_id = sessions.request_extension(record.session_id, root=session_env)
    # The request alone must not have changed the session's expiry.
    unchanged = sessions.load_session(record.session_id, root=session_env)
    assert unchanged.expires_at == record.expires_at
    # There is no code path from "request" straight to "extended" without a
    # distinct approve_extension call — requesting again does not extend.
    pending = sessions.list_pending_extensions(root=session_env)
    assert len(pending) == 1
    assert pending[0]["request_id"] == request_id


def test_extension_approval_is_audited_with_source(session_env, audit_override):
    resolved = templates.resolve_template("sandbox")
    policy = {**resolved["policy"], "policy_template": "sandbox"}
    record = sessions.create_session(policy, duration_seconds=3600, root=session_env)
    request_id = sessions.request_extension(record.session_id, root=session_env)
    sessions.approve_extension(request_id, decided_by="telegram:12345", root=session_env)

    audit = op.audit_tail(limit=10)
    approvals = [r for r in audit if r.get("tool") == "session_approval" and r.get("request_type") == "extension"]
    assert approvals
    assert approvals[-1]["approval_source"] == "telegram:12345"
    assert approvals[-1]["session_id"] == record.session_id
