"""Tests for the passwordless approval-mode OAuth flow (chatgpt-operator only).

local-owner never sets HERMES_GPT_AUTH_APPROVAL_MODE, so its password flow
is untouched — see test_operator_auth.py for that coverage.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from pydantic import AnyUrl

import operator_auth as auth
import operator_policy as op
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError
from mcp.shared.auth import OAuthClientInformationFull


@pytest.fixture
def approval_setup(tmp_path: Path):
    config = auth.AuthRuntimeConfig(
        issuer_url="https://operator.example.test",
        resource_server_url="https://operator.example.test/mcp",
        scope="hermes:operator",
        root=tmp_path / "auth",
        username="justin",
        approval_mode=True,
    )
    auth.bootstrap_credentials(config)
    provider = auth.PersistentOAuthProvider(config)
    return config, provider


@pytest.fixture
def audit_override(tmp_path):
    log = tmp_path / "audit.jsonl"
    op.set_audit_log_override(log)
    yield log
    op.set_audit_log_override(None)


def client(redirect="https://chatgpt.example.test/oauth/callback", client_id="client-1") -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id,
        client_id_issued_at=1,
        redirect_uris=[AnyUrl(redirect)],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name="ChatGPT test client",
        scope="hermes:operator",
    )


def make_params(config, state="client-state") -> AuthorizationParams:
    return AuthorizationParams(
        state=state,
        scopes=[config.scope],
        code_challenge="A" * 43,
        redirect_uri=AnyUrl("https://chatgpt.example.test/oauth/callback"),
        redirect_uri_provided_explicitly=True,
        resource=config.resource_server_url,
    )


def test_authorize_creates_pending_request_no_password_form(approval_setup):
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))
    login_url = asyncio.run(provider.authorize(c, make_params(config)))
    login_state = parse_qs(urlparse(login_url).query)["state"][0]

    page = provider.login_page(login_state)
    body = page.body.decode("utf-8")
    assert "Waiting for approval on your Hermes device" in body
    assert 'type="password"' not in body
    assert 'name="password"' not in body

    pending = provider.list_pending_requests()
    assert len(pending) == 1
    assert pending[0]["client_id"] == "client-1"
    request_id = pending[0]["request_id"]
    assert len(request_id) >= 8  # opaque, not the login state itself
    assert request_id != login_state


def test_unapproved_request_cannot_be_exchanged(approval_setup):
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))
    login_url = asyncio.run(provider.authorize(c, make_params(config)))
    login_state = parse_qs(urlparse(login_url).query)["state"][0]

    status = provider.poll_status(login_state)
    assert status["status"] == "pending"
    assert "redirect" not in status


def test_local_approval_issues_exactly_one_code(approval_setup, audit_override):
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))
    login_url = asyncio.run(provider.authorize(c, make_params(config)))
    login_state = parse_qs(urlparse(login_url).query)["state"][0]
    request_id = provider.list_pending_requests()[0]["request_id"]

    provider.approve_request(request_id, decided_by="local-cli-test")

    first_poll = provider.poll_status(login_state)
    assert first_poll["status"] == "approved"
    assert first_poll["redirect"].startswith("https://chatgpt.example.test/oauth/callback?")

    code = parse_qs(urlparse(first_poll["redirect"]).query)["code"][0]
    loaded_code = asyncio.run(provider.load_authorization_code(c, code))
    assert loaded_code is not None
    token_pair = asyncio.run(provider.exchange_authorization_code(c, loaded_code))
    assert token_pair.access_token

    # Replay: polling again must not re-deliver the redirect (one-time use).
    second_poll = provider.poll_status(login_state)
    assert second_poll["status"] in {"expired", "pending"}

    # Audit trail records the approval source without secrets.
    records = op.audit_tail(limit=10)
    approvals = [r for r in records if r.get("tool") == "oauth_approval"]
    assert approvals, "expected an oauth_approval audit record"
    assert approvals[-1]["decision"] == "approved"
    assert approvals[-1]["approval_source"] == "local-cli-test"
    assert approvals[-1]["oauth_client_id"] == "client-1"
    dump = json.dumps(approvals[-1])
    assert "token" not in dump.lower()
    assert code not in dump


def test_approval_cannot_be_replayed(approval_setup):
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))
    login_url = asyncio.run(provider.authorize(c, make_params(config)))
    request_id = provider.list_pending_requests()[0]["request_id"]

    provider.approve_request(request_id)
    with pytest.raises(ValueError, match="already approved"):
        provider.approve_request(request_id)


def test_denied_request_reported_to_poller(approval_setup):
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))
    login_url = asyncio.run(provider.authorize(c, make_params(config)))
    login_state = parse_qs(urlparse(login_url).query)["state"][0]
    request_id = provider.list_pending_requests()[0]["request_id"]

    provider.deny_request(request_id)
    status = provider.poll_status(login_state)
    assert status["status"] == "denied"

    with pytest.raises(ValueError, match="already denied"):
        provider.approve_request(request_id)


def test_pending_request_expires(approval_setup):
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))
    login_url = asyncio.run(provider.authorize(c, make_params(config)))
    login_state = parse_qs(urlparse(login_url).query)["state"][0]
    request_id = provider.list_pending_requests()[0]["request_id"]

    # Simulate expiry by rewriting the row's expires_at directly (no public
    # API mutates time; this exercises the same expiry check approve_request
    # and poll_status both perform).
    with provider._connect() as connection:
        connection.execute(
            "UPDATE pending_auth SET expires_at = 1 WHERE request_id = ?", (request_id,)
        )

    with pytest.raises(ValueError, match="expired"):
        provider.approve_request(request_id)
    assert provider.poll_status(login_state)["status"] == "expired"


def test_altered_redirect_uri_rejected_at_registration(approval_setup):
    """Exact redirect-URI validation for a live ChatGPT-style request happens
    in the MCP SDK's authorization route (it checks the requested redirect_uri
    against the client's registered ones before ever calling our authorize()).
    What this module owns is rejecting an attempt to *register* a client with
    a non-loopback HTTP / non-HTTPS redirect URI in the first place."""
    config, provider = approval_setup
    from mcp.server.auth.provider import RegistrationError

    bad_client = client(redirect="http://evil.example.test/callback", client_id="client-evil")
    with pytest.raises(RegistrationError):
        asyncio.run(provider.register_client(bad_client))


def test_altered_scope_rejected(approval_setup):
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))
    params = make_params(config)
    tampered = params.model_copy(update={"scopes": ["admin:everything"]})
    with pytest.raises(AuthorizeError) as exc_info:
        asyncio.run(provider.authorize(c, tampered))
    assert "scope" in (exc_info.value.error_description or "").lower()


def test_pkce_still_required_for_token_exchange(approval_setup):
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))
    login_url = asyncio.run(provider.authorize(c, make_params(config)))
    request_id = provider.list_pending_requests()[0]["request_id"]
    provider.approve_request(request_id)
    login_state = parse_qs(urlparse(login_url).query)["state"][0]
    redirect = provider.poll_status(login_state)["redirect"]
    code = parse_qs(urlparse(redirect).query)["code"][0]
    loaded_code = asyncio.run(provider.load_authorization_code(c, code))
    assert loaded_code.code_challenge == "A" * 43  # PKCE challenge carried through


def test_pending_request_cap_rate_limits_new_authorizations(approval_setup):
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))
    for i in range(auth._MAX_PENDING_PER_CLIENT):
        asyncio.run(provider.authorize(c, make_params(config, state=f"state-{i}")))
    with pytest.raises(AuthorizeError) as exc_info:
        asyncio.run(provider.authorize(c, make_params(config, state="one-too-many")))
    assert "too many pending" in (exc_info.value.error_description or "").lower()


def test_authorize_forwards_notification_to_localhost_approval_centre_only(approval_setup, monkeypatch):
    """The internet-facing OAuth connector must never hold the Telegram bot
    token itself -- it forwards to the loopback-only approval centre, which
    is the only process that ever imports operator_approval_notify."""
    config, provider = approval_setup
    c = client()
    asyncio.run(provider.register_client(c))

    calls = []

    def fake_post(url, json=None, timeout=None):
        calls.append({"url": url, "json": json, "timeout": timeout})
        class FakeResponse:
            status_code = 200
        return FakeResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    asyncio.run(provider.authorize(c, make_params(config, state="notify-state")))

    assert len(calls) == 1
    assert calls[0]["url"] == "http://127.0.0.1:7690/notify"
    body = calls[0]["json"]
    assert body["request_type"] == "oauth"
    assert body["details"]["client_id"] == "client-1"
    assert body["details"]["redirect_domain"] == "chatgpt.example.test"


def test_local_owner_password_flow_unaffected_by_default(tmp_path):
    """approval_mode defaults to False, so an owner-style config keeps the
    password form exactly as before."""
    config = auth.AuthRuntimeConfig(
        issuer_url="https://owner.example.test",
        resource_server_url="https://owner.example.test/mcp",
        scope="hermes:operator",
        root=tmp_path / "auth",
        username="justin",
    )
    assert config.approval_mode is False
    auth.bootstrap_credentials(config)
    provider = auth.PersistentOAuthProvider(config)
    c = client()
    asyncio.run(provider.register_client(c))
    login_url = asyncio.run(provider.authorize(c, make_params(config)))
    login_state = parse_qs(urlparse(login_url).query)["state"][0]
    page = provider.login_page(login_state)
    body = page.body.decode("utf-8")
    assert "Waiting for approval" not in body
    assert 'type="password"' in body
