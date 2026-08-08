"""End-to-end tests for standing authority through the existing 41-tool surface."""

from __future__ import annotations

import json
import time

import pytest

import operator_manifest
import operator_policy as op_policy
import operator_policy_templates as op_templates
import operator_sessions as op_sessions
import operator_standing_authority as op_standing
import server


@pytest.fixture
def standing_env(tmp_path, monkeypatch):
    root = tmp_path / "sessions"
    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(root))
    monkeypatch.delenv(op_sessions.ACTIVE_SESSION_ID_ENV, raising=False)
    monkeypatch.setenv("HERMES_GPT_RISK_BASED_AUTHORITY_ENABLED", "1")
    monkeypatch.delenv(op_policy.OPERATOR_ENABLED_ENV, raising=False)
    monkeypatch.delenv(op_policy.OPERATOR_LEVEL_ENV, raising=False)
    monkeypatch.delenv(op_policy.OPERATOR_APPLY_MODE_ENV, raising=False)
    op_policy.set_audit_log_override(tmp_path / "audit.jsonl")
    yield root
    op_policy.set_audit_log_override(None)


def _request_and_approve_standing(root, *, now=1_000):
    response = json.loads(
        server.hermes_operator_session_request(
            policy_template="hermes-contained-maintenance-standing",
            requested_duration_minutes=30,
            reason="contained maintenance test",
            authority_mode="standing",
        )
    )
    assert response["success"] is True
    assert response["authority_mode"] == "standing"
    assert response["approval_forecast"]["risk_class"] == "low"
    assert response["approval_forecast"]["tier"] == 1
    assert response["approval_forecast"]["standing_authority_eligible"] is True
    record = op_sessions.approve_session_request(
        response["request_id"],
        decided_by="telegram:12345",
        root=root,
        now=now,
    )
    return response, record


def test_noneligible_template_cannot_request_standing(standing_env):
    response = json.loads(
        server.hermes_operator_session_request(
            policy_template="hermes-gpt-operator-maintenance",
            requested_duration_minutes=30,
            reason="must fail",
            authority_mode="standing",
        )
    )
    assert response["success"] is False
    assert "not eligible for standing authority" in response["safe_message"]
    assert op_sessions.list_pending_session_requests(root=standing_env) == []


def test_approval_creates_session_and_persisted_standing_authority(standing_env):
    _, record = _request_and_approve_standing(standing_env)
    assert record.approval_state == "approved"
    authorities = op_standing.list_standing_authorities(root=standing_env)
    assert len(authorities) == 1
    standing = authorities[0]
    assert standing.created_by == "telegram:12345"
    assert standing.policy_template == "hermes-contained-maintenance-standing"
    assert standing.risk_decision.standing_authority_eligible is True
    assert standing.approved_risk_factors.single_writer_verified is True
    assert standing.approved_risk_factors.untracked_delete_protected is True
    assert standing.approved_risk_factors.version_controlled_rollback is True
    assert standing.operational_deadline == record.expires_at


def test_expired_bootstrap_session_falls_back_to_standing_authority(standing_env):
    _, record = _request_and_approve_standing(standing_env, now=1_000)
    assert record.expires_at < int(time.time())
    policy = op_policy.OperatorPolicy()
    assert policy.session_status == "standing"
    assert policy.session_id.startswith("sa_")
    assert policy.expires_at is None
    assert policy.level == "workspace"
    assert policy.apply_mode == "direct"
    assert policy.mutation_allowed is True
    assert policy.allowed_branches == ["codex/operator-session-chatgpt-20260713"]
    assert policy.egress_hosts == []
    assert policy.service_units == []


def test_status_reports_standing_without_adding_a_tool(standing_env):
    _request_and_approve_standing(standing_env, now=1_000)
    status = json.loads(server.hermes_operator_session_status())
    assert status["success"] is True
    assert status["authority_kind"] == "standing"
    assert status["standing_authority_id"].startswith("sa_")
    assert status["expires_at"] is None
    assert operator_manifest.EXPECTED_TOOL_COUNT == 41
    assert len(operator_manifest.CANONICAL_TOOL_NAMES) == 41
    assert not any("standing_authority" in name for name in operator_manifest.CANONICAL_TOOL_NAMES)


def test_template_risk_escalation_invalidates_standing(standing_env, monkeypatch):
    _request_and_approve_standing(standing_env, now=1_000)
    escalated = op_templates.resolve_template("hermes-contained-maintenance-standing")
    escalated["policy"]["service_units"] = ["hermes-gpt-chatgpt-operator.service"]
    escalated["policy"]["verbs"]["services"] = ["restart"]
    original_resolve = op_templates.resolve_template

    def fake_resolve(name):
        if name == "hermes-contained-maintenance-standing":
            return escalated
        return original_resolve(name)

    monkeypatch.setattr(op_templates, "resolve_template", fake_resolve)
    policy = op_policy.OperatorPolicy()
    assert policy.session_status == "standing_invalid"
    assert policy.level == "read_only"
    assert policy.apply_mode == "dry_run"
    assert policy.mutation_allowed is False
    assert "hash changed" in (policy.session_failure_reason or "").lower() or "risk" in (
        policy.session_failure_reason or ""
    ).lower()


def test_emergency_revoke_uses_existing_revoke_tool(standing_env):
    _request_and_approve_standing(standing_env, now=1_000)
    active = op_policy.OperatorPolicy()
    standing_id = active.session_id
    response = json.loads(server.hermes_operator_session_revoke(standing_id))
    assert response == {
        "success": True,
        "revoked": True,
        "authority_id": standing_id,
        "authority_kind": "standing",
    }
    revoked = op_standing.load_standing_authority(standing_id, root=standing_env)
    assert revoked.is_revoked() is True
    policy = op_policy.OperatorPolicy()
    assert policy.session_status != "standing"
    assert policy.level == "read_only"
    assert policy.mutation_allowed is False


def test_standing_cannot_be_extended(standing_env):
    _request_and_approve_standing(standing_env, now=1_000)
    response = json.loads(server.hermes_operator_session_request_extension(30))
    assert response["success"] is False
    assert "cannot be extended" in response["safe_message"]
