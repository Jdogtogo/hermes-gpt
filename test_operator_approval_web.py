"""Tests for the localhost-only Hermes Approvals web centre."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import operator_approval_notify as approval_notify
import operator_auth as op_auth
import operator_policy as op_policy
import operator_sessions as op_sessions
import operator_policy_templates as op_templates
import operator_approval_web as web


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    auth_root = tmp_path / "auth"
    session_root = tmp_path / "sessions"
    monkeypatch.setenv(op_auth.AUTH_ISSUER_URL_ENV, "https://operator.example.test")
    monkeypatch.setenv(op_auth.AUTH_RESOURCE_URL_ENV, "https://operator.example.test/mcp")
    monkeypatch.setenv(op_auth.AUTH_ROOT_ENV, str(auth_root))
    monkeypatch.setenv(op_auth.AUTH_SCOPE_ENV, "hermes:operator")
    monkeypatch.setenv(op_auth.AUTH_USERNAME_ENV, "justin")
    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(session_root))
    monkeypatch.delenv(op_sessions.ACTIVE_SESSION_ID_ENV, raising=False)
    config = op_auth.AuthRuntimeConfig.from_env()
    op_auth.bootstrap_credentials(config)
    web._csrf_tokens.clear()
    yield {"auth_root": auth_root, "session_root": session_root}
    op_policy.set_audit_log_override(None)


@pytest.fixture
def audit_override(tmp_path):
    log = tmp_path / "audit.jsonl"
    op_policy.set_audit_log_override(log)
    yield log
    op_policy.set_audit_log_override(None)


def _csrf_from_page(html_text: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html_text) or re.search(
        r'id="page-csrf-token" value="([^"]+)"', html_text
    )
    assert match, "expected a csrf token in the rendered page"
    return match.group(1)


def test_page_binds_and_renders(env, audit_override):
    with TestClient(web.app) as client:
        resp = client.get("/approvals")
        assert resp.status_code == 200
        assert "Hermes Approvals" in resp.text
        assert "Pending OAuth connection requests" in resp.text


def test_oauth_request_appears_and_approve_completes_it(env, audit_override):
    provider = web._oauth_provider()
    import asyncio
    from pydantic import AnyUrl
    from mcp.server.auth.provider import AuthorizationParams
    from mcp.shared.auth import OAuthClientInformationFull

    client_info = OAuthClientInformationFull(
        client_id="client-1", client_id_issued_at=1,
        redirect_uris=[AnyUrl("https://chatgpt.example.test/oauth/callback")],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"], response_types=["code"],
        scope="hermes:operator",
    )
    asyncio.run(provider.register_client(client_info))
    params = AuthorizationParams(
        state="s1", scopes=["hermes:operator"], code_challenge="A" * 43,
        redirect_uri=AnyUrl("https://chatgpt.example.test/oauth/callback"),
        redirect_uri_provided_explicitly=True, resource="https://operator.example.test/mcp",
    )
    asyncio.run(provider.authorize(client_info, params))
    request_id = provider.list_pending_requests()[0]["request_id"]

    with TestClient(web.app) as client:
        page = client.get("/approvals")
        assert "client-1" in page.text
        csrf = _csrf_from_page(page.text)
        resp = client.post(
            "/approvals/oauth/approve",
            data={"csrf_token": csrf, "request_id": request_id},
            follow_redirects=False,
        )
        assert resp.status_code == 303

    assert web._oauth_provider().list_pending_requests() == []
    audit = op_policy.audit_tail(limit=10)
    approvals = [r for r in audit if r.get("tool") == "oauth_approval" and r.get("decision") == "approved"]
    assert approvals
    assert approvals[-1]["approval_source"] == "localhost"


def test_csrf_token_is_one_time_use(env, audit_override):
    with TestClient(web.app) as client:
        page = client.get("/approvals")
        csrf = _csrf_from_page(page.text)
        first = client.post(
            "/approvals/oauth/deny",
            data={"csrf_token": csrf, "request_id": "nonexistent"},
            follow_redirects=False,
        )
        # First use is accepted at the CSRF layer (fails later for a
        # different reason: the request_id doesn't exist).
        assert first.status_code in (303, 400)
        replay = client.post(
            "/approvals/oauth/deny",
            data={"csrf_token": csrf, "request_id": "nonexistent"},
            follow_redirects=False,
        )
        assert replay.status_code == 400
        assert "Invalid or expired" in replay.text


def test_missing_csrf_token_rejected(env, audit_override):
    with TestClient(web.app) as client:
        resp = client.post(
            "/approvals/oauth/deny",
            data={"csrf_token": "not-a-real-token", "request_id": "x"},
            follow_redirects=False,
        )
        assert resp.status_code == 400


def test_session_request_approve_via_web(env, audit_override):
    resolved = op_templates.resolve_template("sandbox")
    request_id = op_sessions.request_session(
        policy_template="sandbox", resolved_policy=resolved["policy"],
        requested_duration_seconds=1800, reason="test via web",
        root=env["session_root"],
    )
    with TestClient(web.app) as client:
        page = client.get("/approvals")
        assert request_id in page.text
        assert "test via web" in page.text
        csrf = _csrf_from_page(page.text)
        resp = client.post(
            "/approvals/session/approve",
            data={"csrf_token": csrf, "request_id": request_id},
            follow_redirects=False,
        )
        assert resp.status_code == 303
    assert op_sessions.active_session() is not None


def test_session_request_deny_via_web_creates_no_authority(env, audit_override):
    resolved = op_templates.resolve_template("sandbox")
    request_id = op_sessions.request_session(
        policy_template="sandbox", resolved_policy=resolved["policy"],
        requested_duration_seconds=1800, reason="test", root=env["session_root"],
    )
    with TestClient(web.app) as client:
        page = client.get("/approvals")
        csrf = _csrf_from_page(page.text)
        client.post(
            "/approvals/session/deny",
            data={"csrf_token": csrf, "request_id": request_id},
            follow_redirects=False,
        )
    assert op_sessions.active_session() is None


def test_telegram_resolve_approves_session(env, audit_override):
    resolved = op_templates.resolve_template("sandbox")
    request_id = op_sessions.request_session(
        policy_template="sandbox", resolved_policy=resolved["policy"],
        requested_duration_seconds=1800, reason="via telegram", root=env["session_root"],
    )
    with TestClient(web.app) as client:
        resp = client.post(
            "/telegram-resolve",
            json={"request_id": request_id, "decision": "approve", "caller_id": "12345"},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
    assert op_sessions.active_session() is not None
    audit = op_policy.audit_tail(limit=10)
    approvals = [r for r in audit if r.get("approval_source") == "telegram:12345"]
    assert approvals


def test_telegram_resolve_infers_extension_type(env, audit_override):
    record = op_sessions.create_session(
        {**op_templates.resolve_template("sandbox")["policy"], "policy_template": "sandbox"},
        duration_seconds=3600, root=env["session_root"],
    )
    request_id = op_sessions.request_extension(record.session_id, root=env["session_root"])
    with TestClient(web.app) as client:
        resp = client.post(
            "/telegram-resolve",
            json={"request_id": request_id, "decision": "approve", "caller_id": "999"},
        )
        assert resp.status_code == 200
    updated = op_sessions.load_session(record.session_id, root=env["session_root"])
    assert updated.expires_at > record.expires_at


def test_extension_page_shows_actual_requested_duration(env, audit_override):
    """The approval page must show the duration actually stored for the
    request, and must agree with what Telegram shows for the same request --
    an approver who checks either surface has to see the same number."""
    record = op_sessions.create_session(
        {**op_templates.resolve_template("sandbox")["policy"], "policy_template": "sandbox"},
        duration_seconds=3600, root=env["session_root"],
    )
    op_sessions.request_extension(
        record.session_id, seconds=4 * 60 * 60, root=env["session_root"]
    )
    with TestClient(web.app) as client:
        resp = client.get("/approvals")
        assert resp.status_code == 200
    assert "240 minutes" in resp.text
    assert "Approve 240 minutes" in resp.text
    # Same request, same rendering on the Telegram surface.
    pending = op_sessions.list_pending_extensions(root=env["session_root"])[0]
    assert approval_notify.format_requested_duration(
        pending["requested_seconds"]
    ) == "240 minutes"


def test_extension_page_fails_closed_on_malformed_duration(env, audit_override, monkeypatch):
    """A malformed stored duration must render the explicit unknown sentinel
    rather than raising (which would 500 the whole approval page and block
    every pending approval, not just this one)."""
    monkeypatch.setattr(
        op_sessions,
        "list_pending_extensions",
        lambda *a, **k: [
            {"request_id": "ext_bad", "session_id": "ops_x", "requested_seconds": "not-a-number"}
        ],
    )
    with TestClient(web.app) as client:
        resp = client.get("/approvals")
        assert resp.status_code == 200
    assert approval_notify.UNKNOWN_DURATION in resp.text


def test_rendered_page_never_contains_secrets(env, audit_override):
    resolved = op_templates.resolve_template("sandbox")
    op_sessions.request_session(
        policy_template="sandbox", resolved_policy=resolved["policy"],
        requested_duration_seconds=1800, reason="x", root=env["session_root"],
    )
    with TestClient(web.app) as client:
        page = client.get("/approvals").text
    lowered = page.lower()
    for forbidden in ["password", "access_token", "refresh_token", "code_verifier", "bot_token"]:
        assert forbidden not in lowered


def test_main_rejects_non_loopback_host(monkeypatch):
    import sys
    monkeypatch.setattr(sys, "argv", ["operator_approval_web.py", "--host", "0.0.0.0"])
    with pytest.raises(SystemExit, match="loopback"):
        web.main()


def test_notify_endpoint_forwards_to_notify_module(env, audit_override, monkeypatch):
    """This is the only process allowed to actually send Telegram messages
    -- the internet-facing chatgpt-operator connector forwards here instead
    of importing operator_approval_notify itself."""
    calls = []

    def fake_notify(request_type, request_id, details):
        calls.append((request_type, request_id, details))
        return True

    import operator_approval_notify
    monkeypatch.setattr(operator_approval_notify, "notify_pending_request", fake_notify)

    with TestClient(web.app) as client:
        resp = client.post(
            "/notify",
            json={"request_type": "oauth", "request_id": "abc123", "details": {"client_id": "c1"}},
        )
    assert resp.status_code == 200
    assert resp.json() == {"success": True}
    assert calls == [("oauth", "abc123", {"client_id": "c1"})]


def test_notify_endpoint_rejects_malformed_body(env, audit_override):
    with TestClient(web.app) as client:
        resp = client.post("/notify", json={"request_type": "oauth"})
    assert resp.status_code == 400
    assert resp.json()["success"] is False
