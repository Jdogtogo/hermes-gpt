"""Regression tests for ChatGPT-compatible Dynamic Client Registration.

These exercise the public ASGI app exactly as ``main()`` serves it: the FastMCP
streamable-HTTP app wrapped by ``dcr_compat.normalize_public_client_registration``.
They reproduce the real (redacted) ChatGPT registration payload and prove that
authorization-code + PKCE S256, redirect validation, scope enforcement and
bearer protection of ``/mcp`` are all preserved.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

import dcr_compat
import operator_auth as op_auth
import server

REDIRECT_URI = "https://chatgpt.com/connector_platform_oauth_redirect"

# Exact (redacted) metadata captured from a real ChatGPT connector registration:
# token_endpoint_auth_method is "client_secret_post" and no client_secret / scope
# is sent.
CHATGPT_DCR_PAYLOAD = {
    "client_name": "ChatGPT",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "redirect_uris": [REDIRECT_URI],
    "token_endpoint_auth_method": "client_secret_post",
}


def _password_from_initial(path: Path) -> str:
    return next(
        line.split(": ", 1)[1]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("password: ")
    )


def _pkce() -> tuple[str, str]:
    verifier = "correct-horse-battery-staple-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("utf-8")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    return verifier, challenge


class _Ctx:
    def __init__(self, app, config, password):
        self.app = app
        self.config = config
        self.password = password


@pytest.fixture
def ctx(monkeypatch, tmp_path):
    auth_root = tmp_path / "auth"
    config = op_auth.AuthRuntimeConfig(
        issuer_url="https://mcp.example.test",
        resource_server_url="https://mcp.example.test/mcp",
        scope="hermes:operator",
        root=auth_root,
        username="justin",
    )
    op_auth.bootstrap_credentials(config)
    password = _password_from_initial(config.initial_login_path)
    for key, value in {
        server.ENABLE_BRIDGE_ENV: "1",
        op_auth.AUTH_ENABLED_ENV: "1",
        op_auth.AUTH_ISSUER_URL_ENV: config.issuer_url,
        op_auth.AUTH_RESOURCE_URL_ENV: config.resource_server_url,
        op_auth.AUTH_ROOT_ENV: str(auth_root),
        op_auth.AUTH_SCOPE_ENV: config.scope,
        op_auth.AUTH_USERNAME_ENV: config.username,
    }.items():
        monkeypatch.setenv(key, value)
    built = server.build_server(http=True, transport="streamable-http")
    app = dcr_compat.normalize_public_client_registration(built.streamable_http_app())
    return _Ctx(app, config, password)


def _register_public(client, payload=None) -> str:
    resp = client.post("/register", json=dict(payload or CHATGPT_DCR_PAYLOAD))
    assert resp.status_code == 201, resp.text
    assert resp.json()["token_endpoint_auth_method"] == "none"
    assert not resp.json().get("client_secret")
    return resp.json()["client_id"]


def _authorize_and_login(client, ctx, client_id, challenge, redirect_uri=REDIRECT_URI):
    authorize = client.get(
        "/authorize",
        params={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "client-state",
            "scope": ctx.config.scope,
            "resource": ctx.config.resource_server_url,
        },
        follow_redirects=False,
    )
    assert authorize.status_code == 302, authorize.text
    login_url = authorize.headers["location"]
    login_state = parse_qs(urlparse(login_url).query)["state"][0]
    login = client.post(
        "/login/callback",
        data={"username": ctx.config.username, "password": ctx.password, "state": login_state},
        follow_redirects=False,
    )
    assert login.status_code == 302, login.text
    callback = login.headers["location"]
    return parse_qs(urlparse(callback).query)["code"][0]


# 1. The exact ChatGPT DCR payload succeeds and registers a *public* client.
def test_exact_chatgpt_payload_registers_public(ctx):
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        resp = client.post("/register", json=dict(CHATGPT_DCR_PAYLOAD))
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["token_endpoint_auth_method"] == "none"
        assert not body.get("client_secret")
        assert body["client_id"]


# 2. A normal public-client registration (token_endpoint_auth_method=none) succeeds.
def test_public_none_registration_succeeds(ctx):
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        resp = client.post(
            "/register",
            json={
                "redirect_uris": [REDIRECT_URI],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "client_name": "public client",
                "scope": ctx.config.scope,
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["token_endpoint_auth_method"] == "none"
        assert not resp.json().get("client_secret")


# 2b. A confidential *method* with no secret material is also normalized to public.
def test_client_secret_basic_without_secret_normalized(ctx):
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        resp = client.post(
            "/register",
            json={
                "redirect_uris": [REDIRECT_URI],
                "token_endpoint_auth_method": "client_secret_basic",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["token_endpoint_auth_method"] == "none"
        assert not resp.json().get("client_secret")


# 3. Harmless unknown / optional RFC 7591 metadata is accepted.
def test_harmless_unknown_metadata_accepted(ctx):
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        resp = client.post(
            "/register",
            json={
                **CHATGPT_DCR_PAYLOAD,
                "software_id": "chatgpt-connector",
                "software_version": "1.2.3",
                "client_uri": "https://chatgpt.com",
                "tos_uri": "https://openai.com/terms",
                "contacts": ["ops@example.test"],
                "application_type": "web",
                "an_unrecognized_field": "ignored-by-server",
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["token_endpoint_auth_method"] == "none"


# 4. A genuine confidential client (secret material provided) remains rejected.
def test_confidential_client_with_secret_rejected(ctx):
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        resp = client.post(
            "/register",
            json={
                "redirect_uris": [REDIRECT_URI],
                "token_endpoint_auth_method": "client_secret_post",
                "client_secret": "a-provided-confidential-secret",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"] == "invalid_client_metadata"


def _assert_authorize_error_redirect(resp, expected_error="invalid_request"):
    """A rejected /authorize redirects to the client with an error and no code."""
    assert resp.status_code == 302, resp.text
    location = resp.headers["location"]
    assert location.startswith(REDIRECT_URI), location
    query = parse_qs(urlparse(location).query)
    assert query.get("error") == [expected_error], location
    assert "code" not in query, location
    assert "/login" not in location, location


# 5. Authorization without a PKCE code_challenge is rejected (error, no code).
def test_authorize_without_code_challenge_rejected(ctx):
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        cid = _register_public(client)
        resp = client.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "state": "s",
                "scope": ctx.config.scope,
                "resource": ctx.config.resource_server_url,
            },
            follow_redirects=False,
        )
        _assert_authorize_error_redirect(resp)


# 6. PKCE code_challenge_method=plain is rejected (only S256 accepted).
def test_authorize_plain_pkce_rejected(ctx):
    _, challenge = _pkce()
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        cid = _register_public(client)
        resp = client.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "plain",
                "state": "s",
                "scope": ctx.config.scope,
                "resource": ctx.config.resource_server_url,
            },
            follow_redirects=False,
        )
        _assert_authorize_error_redirect(resp)


# 7 + 8 + full flow. S256 authorization succeeds; correct verifier yields a
# bearer that works on /mcp; wrong verifier is rejected.
def test_full_chatgpt_style_flow_succeeds(ctx):
    verifier, challenge = _pkce()
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        cid = _register_public(client)
        code = _authorize_and_login(client, ctx, cid, challenge)

        wrong = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": cid,
                "code_verifier": "the-wrong-verifier",
                "resource": ctx.config.resource_server_url,
            },
        )
        assert wrong.status_code == 400, wrong.text
        assert wrong.json()["error"] == "invalid_grant"

        # Re-run authorize/login for a fresh, unused code.
        code = _authorize_and_login(client, ctx, cid, challenge)
        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": cid,
                "code_verifier": verifier,
                "resource": ctx.config.resource_server_url,
            },
        )
        assert token.status_code == 200, token.text
        tokens = token.json()
        assert tokens["token_type"] == "Bearer"
        assert tokens["refresh_token"]

        authed = client.get(
            "/mcp",
            headers={
                "Authorization": f"Bearer {tokens['access_token']}",
                "Accept": "text/event-stream",
            },
        )
        assert authed.status_code != 401


# 7b. S256 authorization redirects to the login page.
def test_s256_authorize_redirects_to_login(ctx):
    _, challenge = _pkce()
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        cid = _register_public(client)
        resp = client.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "client-state",
                "scope": ctx.config.scope,
                "resource": ctx.config.resource_server_url,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302, resp.text
        assert "/login" in resp.headers["location"]


# 9. An unregistered redirect URI is rejected at authorization.
def test_unregistered_redirect_uri_rejected(ctx):
    _, challenge = _pkce()
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        cid = _register_public(client)
        resp = client.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": "https://evil.example.test/callback",
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "s",
                "scope": ctx.config.scope,
                "resource": ctx.config.resource_server_url,
            },
            follow_redirects=False,
        )
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"] == "invalid_request"


# 10. An unsupported scope is rejected at registration.
def test_incorrect_scope_rejected(ctx):
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        resp = client.post(
            "/register",
            json={
                "redirect_uris": [REDIRECT_URI],
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "hermes:operator unsupported:scope",
            },
        )
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"] == "invalid_client_metadata"


# 10b. The login page CSP allows a form redirect to the client's callback origin.
# (Regression: form-action 'self' blocked the post-login 302 to ChatGPT, so the
# authorization code never reached the client.)
def test_login_page_csp_allows_client_redirect_origin(ctx):
    _, challenge = _pkce()
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        cid = _register_public(client)
        authorize = client.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "client-state",
                "scope": ctx.config.scope,
                "resource": ctx.config.resource_server_url,
            },
            follow_redirects=False,
        )
        login_url = authorize.headers["location"]
        page = client.get(login_url)
        assert page.status_code == 200
        csp = page.headers["content-security-policy"]
        # The client's callback origin must be permitted for the post-login redirect,
        # while same-origin and the tight defaults remain.
        assert "form-action 'self' https://chatgpt.com" in csp, csp
        assert "default-src 'none'" in csp
        assert "frame-ancestors 'none'" in csp


# 11. Unauthenticated /mcp still returns 401.
def test_unauthenticated_mcp_returns_401(ctx):
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        resp = client.get("/mcp", headers={"Accept": "text/event-stream"})
        assert resp.status_code == 401


# 12. An invalid bearer token is rejected on /mcp.
def test_invalid_bearer_token_rejected(ctx):
    with TestClient(ctx.app, base_url=ctx.config.issuer_url) as client:
        resp = client.get(
            "/mcp",
            headers={
                "Authorization": "Bearer not-a-real-token",
                "Accept": "text/event-stream",
            },
        )
        assert resp.status_code == 401
