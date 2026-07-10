from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from starlette.testclient import TestClient

import operator_auth as op_auth
import server


def _password_from_initial(path: Path) -> str:
    return next(
        line.split(": ", 1)[1]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.startswith("password: ")
    )


def test_sdk_http_oauth_flow_with_pkce(monkeypatch, tmp_path):
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

    monkeypatch.setenv(server.ENABLE_BRIDGE_ENV, "1")
    monkeypatch.setenv(op_auth.AUTH_ENABLED_ENV, "1")
    monkeypatch.setenv(op_auth.AUTH_ISSUER_URL_ENV, config.issuer_url)
    monkeypatch.setenv(op_auth.AUTH_RESOURCE_URL_ENV, config.resource_server_url)
    monkeypatch.setenv(op_auth.AUTH_ROOT_ENV, str(auth_root))
    monkeypatch.setenv(op_auth.AUTH_SCOPE_ENV, config.scope)
    monkeypatch.setenv(op_auth.AUTH_USERNAME_ENV, config.username)

    built = server.build_server(http=True, transport="streamable-http")
    verifier = "correct-horse-battery-staple-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("utf-8")).digest()
    ).decode("ascii").rstrip("=")
    redirect_uri = "https://chatgpt.example.test/oauth/callback"

    with TestClient(built.streamable_http_app(), base_url=config.issuer_url) as client:
        registration = client.post(
            "/register",
            json={
                "redirect_uris": [redirect_uri],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "client_name": "ChatGPT test connector",
                "scope": config.scope,
            },
        )
        assert registration.status_code == 201, registration.text
        client_id = registration.json()["client_id"]
        assert not registration.json().get("client_secret")

        authorize = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "client-state",
                "scope": config.scope,
                "resource": config.resource_server_url,
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302, authorize.text
        login_url = authorize.headers["location"]
        login_state = parse_qs(urlparse(login_url).query)["state"][0]

        login_page = client.get(login_url)
        assert login_page.status_code == 200
        assert "Authorize Hermes-GPT" in login_page.text

        login = client.post(
            "/login/callback",
            data={"username": config.username, "password": password, "state": login_state},
            follow_redirects=False,
        )
        assert login.status_code == 302, login.text
        callback = login.headers["location"]
        callback_params = parse_qs(urlparse(callback).query)
        code = callback_params["code"][0]
        assert callback_params["state"] == ["client-state"]

        wrong_verifier = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": "wrong-verifier",
                "resource": config.resource_server_url,
            },
        )
        assert wrong_verifier.status_code == 400
        assert wrong_verifier.json()["error"] == "invalid_grant"

        token_response = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": config.resource_server_url,
            },
        )
        assert token_response.status_code == 200, token_response.text
        tokens = token_response.json()
        assert tokens["token_type"] == "Bearer"
        assert tokens["refresh_token"]

        authenticated = client.get(
            "/mcp",
            headers={
                "Authorization": f"Bearer {tokens['access_token']}",
                "Accept": "text/event-stream",
            },
        )
        assert authenticated.status_code != 401

        refreshed = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "client_id": client_id,
                "scope": config.scope,
                "resource": config.resource_server_url,
            },
        )
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["access_token"] != tokens["access_token"]
