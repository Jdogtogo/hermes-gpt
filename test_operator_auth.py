from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from pydantic import AnyUrl
from starlette.requests import Request

import operator_auth as auth
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError
from mcp.shared.auth import OAuthClientInformationFull


def request_for_login() -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/login/callback",
        "raw_path": b"/login/callback",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"cf-connecting-ip", b"203.0.113.10")],
        "client": ("127.0.0.1", 12345),
        "server": ("mcp.example.test", 443),
    }
    return Request(scope)


@pytest.fixture
def auth_setup(tmp_path: Path):
    config = auth.AuthRuntimeConfig(
        issuer_url="https://mcp.example.test",
        resource_server_url="https://mcp.example.test/mcp",
        scope="hermes:operator",
        root=tmp_path / "auth",
        username="justin",
    )
    result = auth.bootstrap_credentials(config)
    assert result["created"] is True
    initial = config.initial_login_path.read_text(encoding="utf-8")
    password = next(
        line.split(": ", 1)[1]
        for line in initial.splitlines()
        if line.startswith("password: ")
    )
    provider = auth.PersistentOAuthProvider(config)
    return config, provider, password


def public_client() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="client-1",
        client_id_issued_at=1,
        redirect_uris=[AnyUrl("https://chatgpt.example.test/oauth/callback")],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name="ChatGPT test client",
        scope="hermes:operator",
    )


def test_bootstrap_files_are_private_and_secret_not_returned(auth_setup):
    config, _, password = auth_setup
    assert stat.S_IMODE(config.credential_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.initial_login_path.stat().st_mode) == 0o600
    payload = json.loads(config.credential_path.read_text(encoding="utf-8"))
    assert password not in config.credential_path.read_text(encoding="utf-8")
    assert "password_hash_hex" in payload
    assert "token_pepper_hex" in payload


def test_registration_accepts_only_public_pkce_clients(auth_setup):
    _, provider, _ = auth_setup
    client = public_client()
    asyncio.run(provider.register_client(client))
    loaded = asyncio.run(provider.get_client("client-1"))
    assert loaded is not None
    assert loaded.token_endpoint_auth_method == "none"

    confidential = public_client().model_copy(
        update={"client_id": "client-2", "token_endpoint_auth_method": "client_secret_post", "client_secret": "bad"}
    )
    with pytest.raises(RegistrationError) as exc_info:
        asyncio.run(provider.register_client(confidential))
    assert "public OAuth clients" in (exc_info.value.error_description or "")


def test_complete_oauth_flow_refresh_rotation_and_revocation(auth_setup):
    config, provider, password = auth_setup
    client = public_client()
    asyncio.run(provider.register_client(client))
    params = AuthorizationParams(
        state="client-state",
        scopes=[config.scope],
        code_challenge="A" * 43,
        redirect_uri=AnyUrl("https://chatgpt.example.test/oauth/callback"),
        redirect_uri_provided_explicitly=True,
        resource=config.resource_server_url,
    )
    login_url = asyncio.run(provider.authorize(client, params))
    login_state = parse_qs(urlparse(login_url).query)["state"][0]
    page = provider.login_page(login_state)
    assert page.status_code == 200
    assert "Authorize Hermes-GPT" in page.body.decode("utf-8")

    with pytest.raises(PermissionError, match="Invalid username or password"):
        provider.complete_login(
            username="justin",
            password="wrong-password",
            state=login_state,
            request=request_for_login(),
        )

    redirect = provider.complete_login(
        username="justin",
        password=password,
        state=login_state,
        request=request_for_login(),
    )
    redirect_params = parse_qs(urlparse(redirect).query)
    code = redirect_params["code"][0]
    assert redirect_params["state"] == ["client-state"]

    loaded_code = asyncio.run(provider.load_authorization_code(client, code))
    assert loaded_code is not None
    token_pair = asyncio.run(provider.exchange_authorization_code(client, loaded_code))
    assert token_pair.refresh_token
    access = asyncio.run(provider.load_access_token(token_pair.access_token))
    assert access is not None
    assert access.resource == config.resource_server_url
    assert access.scopes == [config.scope]

    refresh = asyncio.run(provider.load_refresh_token(client, token_pair.refresh_token))
    assert refresh is not None
    rotated = asyncio.run(provider.exchange_refresh_token(client, refresh, [config.scope]))
    assert rotated.access_token != token_pair.access_token
    assert rotated.refresh_token != token_pair.refresh_token
    assert asyncio.run(provider.load_access_token(token_pair.access_token)) is None
    assert asyncio.run(provider.load_refresh_token(client, token_pair.refresh_token)) is None

    rotated_access = asyncio.run(provider.load_access_token(rotated.access_token))
    assert rotated_access is not None
    asyncio.run(provider.revoke_token(rotated_access))
    assert asyncio.run(provider.load_access_token(rotated.access_token)) is None
    assert asyncio.run(provider.load_refresh_token(client, rotated.refresh_token or "")) is None

    database_bytes = config.db_path.read_bytes()
    assert token_pair.access_token.encode("utf-8") not in database_bytes
    assert (token_pair.refresh_token or "").encode("utf-8") not in database_bytes
    assert password.encode("utf-8") not in database_bytes


def test_wrong_resource_is_refused(auth_setup):
    config, provider, _ = auth_setup
    client = public_client()
    asyncio.run(provider.register_client(client))
    params = AuthorizationParams(
        state="state",
        scopes=[config.scope],
        code_challenge="B" * 43,
        redirect_uri=AnyUrl("https://chatgpt.example.test/oauth/callback"),
        redirect_uri_provided_explicitly=True,
        resource="https://attacker.example/mcp",
    )
    with pytest.raises(AuthorizeError) as exc_info:
        asyncio.run(provider.authorize(client, params))
    assert "does not match" in (exc_info.value.error_description or "")


def test_auth_config_requires_https(monkeypatch, tmp_path):
    monkeypatch.setenv(auth.AUTH_ISSUER_URL_ENV, "http://mcp.example.test")
    monkeypatch.setenv(auth.AUTH_RESOURCE_URL_ENV, "https://mcp.example.test/mcp")
    monkeypatch.setenv(auth.AUTH_ROOT_ENV, str(tmp_path / "auth"))
    with pytest.raises(ValueError, match="HTTPS"):
        auth.AuthRuntimeConfig.from_env()
