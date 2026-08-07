"""Tests for hermes_operator_session_request: it must only ever create a
pending approval request, never authority by itself, and must only ever
accept a named policy template -- never raw roots/verbs/policy JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import operator_policy as op_policy
import operator_sessions as op_sessions
import operator_policy_templates as op_templates
import server


@pytest.fixture
def isolated_session_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "sessions"
    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(root))
    monkeypatch.delenv(op_sessions.ACTIVE_SESSION_ID_ENV, raising=False)
    yield root


@pytest.fixture
def audit_override(tmp_path):
    log = tmp_path / "audit.jsonl"
    op_policy.set_audit_log_override(log)
    yield log
    op_policy.set_audit_log_override(None)


def test_request_creates_pending_only_no_authority(isolated_session_root, audit_override):
    out = json.loads(server.hermes_operator_session_request(
        policy_template="sandbox", requested_duration_minutes=60, reason="routine test",
    ))
    assert out["success"] is True
    assert out["status"] == "pending"
    assert out["request_id"]
    # The tool itself created no session -- there must be no active one.
    assert op_sessions.active_session() is None
    pending = op_sessions.list_pending_session_requests(root=isolated_session_root)
    assert len(pending) == 1
    assert pending[0]["request_id"] == out["request_id"]


def test_request_returns_resolved_policy_not_just_template_name(isolated_session_root, audit_override):
    out = json.loads(server.hermes_operator_session_request(
        policy_template="hermes-gpt-operator-maintenance",
        requested_duration_minutes=30,
        reason="maintenance",
    ))
    assert out["success"] is True
    tmpl = op_templates.resolve_template("hermes-gpt-operator-maintenance")
    # The returned/stored/approver-shown snapshot carries the template's branch
    # restriction alongside its policy block, so the human approver sees it and
    # OperatorPolicy can enforce it at commit time.
    expected = {
        **tmpl["policy"],
        "allowed_branches": tmpl["allowed_branches"],
        "authority_mode": "session",
        "standing_authority_eligible": False,
    }
    assert out["resolved_policy"] == expected
    assert out["resolved_policy"]["allowed_branches"] == [
        "codex/operator-session-chatgpt-20260713"
    ]


def test_request_snapshot_carries_template_branch_restriction(isolated_session_root, audit_override):
    """The pending request stored for approval must carry allowed_branches, so
    the approved session snapshot enforces it (regression: it was dropped)."""
    out = json.loads(server.hermes_operator_session_request(
        policy_template="tax-calculator-controller",
        requested_duration_minutes=60,
        reason="reviewed development",
    ))
    assert out["success"] is True
    pending = op_sessions.list_pending_session_requests(root=isolated_session_root)
    assert len(pending) == 1
    assert pending[0]["resolved_policy"]["allowed_branches"] == [
        "feat/projection-architecture-discovery"
    ]


def test_unknown_template_rejected(isolated_session_root, audit_override):
    out = json.loads(server.hermes_operator_session_request(
        policy_template="does-not-exist", requested_duration_minutes=60, reason="x",
    ))
    assert out["success"] is False
    assert "OPERATOR_SESSION_REQUEST_TEMPLATE_ERROR" in out["code"]
    assert op_sessions.list_pending_session_requests(root=isolated_session_root) == []


def test_active_tax_calculator_template_creates_pending_request_only(
    isolated_session_root, audit_override
):
    out = json.loads(server.hermes_operator_session_request(
        policy_template="tax-calculator-controller",
        requested_duration_minutes=60,
        reason="reviewed line-ending repair",
    ))
    assert out["success"] is True
    assert out["status"] == "pending"
    assert out["resolved_policy"]["writable_roots"] == ["/mnt/c/Dev/Tax Calculator"]
    assert op_sessions.active_session() is None
    pending = op_sessions.list_pending_session_requests(root=isolated_session_root)
    assert len(pending) == 1
    assert pending[0]["policy_template"] == "tax-calculator-controller"


def test_missing_reason_rejected(isolated_session_root, audit_override):
    out = json.loads(server.hermes_operator_session_request(
        policy_template="sandbox", requested_duration_minutes=60, reason="",
    ))
    assert out["success"] is False
    assert op_sessions.list_pending_session_requests(root=isolated_session_root) == []


def test_requested_duration_capped_by_template_max(isolated_session_root, audit_override):
    out = json.loads(server.hermes_operator_session_request(
        policy_template="sandbox", requested_duration_minutes=999999, reason="x",
    ))
    assert out["success"] is True
    template = op_templates.resolve_template("sandbox")
    assert out["requested_duration_seconds"] <= template["max_duration_seconds"]


def test_approval_audit_records_risk_and_scope_evidence(isolated_session_root, audit_override):
    out = json.loads(server.hermes_operator_session_request(
        policy_template="sandbox", requested_duration_minutes=10, reason="audit evidence",
    ))
    assert out["success"] is True
    op_sessions.approve_session_request(
        out["request_id"], decided_by="telegram:test", root=isolated_session_root
    )
    records = [json.loads(line) for line in audit_override.read_text(encoding="utf-8").splitlines()]
    approval = next(record for record in records if record.get("tool") == "session_approval")
    text = json.dumps(approval, sort_keys=True)
    assert '"risk_class"' in text
    assert '"risk_tier"' in text
    assert '"risk_factors_hash"' in text
    assert '"policy_template": "sandbox"' in text
    assert '"approver": "telegram:test"' in text


def test_cannot_submit_raw_roots_or_policy_json(isolated_session_root, audit_override):
    """The tool signature has no roots/verbs/policy parameter at all -- there
    is no channel through which a remote caller could smuggle one in."""
    import inspect
    sig = inspect.signature(server.hermes_operator_session_request)
    assert set(sig.parameters) == {
        "policy_template", "requested_duration_minutes", "reason", "authority_mode"
    }


def test_notify_failure_never_breaks_the_tool(isolated_session_root, audit_override, monkeypatch):
    """If the localhost approval centre is unreachable, the request must
    still be recorded -- notification is best-effort only. (conftest.py
    blocks real httpx.post globally, which exercises exactly this path.)"""
    out = json.loads(server.hermes_operator_session_request(
        policy_template="sandbox", requested_duration_minutes=60, reason="x",
    ))
    assert out["success"] is True


def test_notify_forwards_to_localhost_approval_centre_only(isolated_session_root, audit_override, monkeypatch):
    """The internet-facing chatgpt-operator connector must never hold the
    Telegram bot token itself -- it forwards to the loopback-only approval
    centre, which is the only process that ever imports
    operator_approval_notify."""
    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        class FakeResponse:
            status_code = 200
        return FakeResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    server.hermes_operator_session_request(
        policy_template="sandbox", requested_duration_minutes=60, reason="forward test",
    )

    assert len(calls) == 1
    assert calls[0]["url"] == "http://127.0.0.1:7690/notify"
    body = calls[0]["json"]
    assert body["request_type"] == "session_creation"
    assert body["details"]["reason"] == "forward test"
