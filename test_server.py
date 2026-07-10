import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

import operator_auth as op_auth
import server


GATE_ENVS = [
    server.ENABLE_WRITE_ENV,
    server.ENABLE_MEMORY_WRITE_ENV,
    server.ENABLE_SESSION_SEARCH_ENV,
    server.ENABLE_TERMINAL_ENV,
    server.ENABLE_BRIDGE_ENV,
    server.UNSAFE_REMOTE_ENV,
    op_auth.AUTH_ENABLED_ENV,
    op_auth.AUTH_ISSUER_URL_ENV,
    op_auth.AUTH_RESOURCE_URL_ENV,
    op_auth.AUTH_ROOT_ENV,
    op_auth.AUTH_SCOPE_ENV,
    op_auth.AUTH_USERNAME_ENV,
]


def clear_gate_envs(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in GATE_ENVS:
        monkeypatch.delenv(name, raising=False)


def tool_names(mcp_server) -> list[str]:
    tools = asyncio.run(mcp_server.list_tools())
    return sorted(tool.name for tool in tools)


def tools_by_name(mcp_server):
    tools = asyncio.run(mcp_server.list_tools())
    return {tool.name: tool for tool in tools}


def test_default_tool_surface_is_read_or_local_metadata_only(monkeypatch):
    clear_gate_envs(monkeypatch)

    built = server.build_server()
    names = tool_names(built)

    # Original read-only / local-metadata tools must still be present.
    for required in [
        "hermes_memory",
        "hermes_read_file",
        "hermes_search_files",
        "hermes_skill_list",
        "hermes_skill_view",
    ]:
        assert required in names

    # Broad mutating tools must NOT be exposed without their env flags.
    for forbidden in [
        "hermes_write_file",
        "hermes_patch",
        "hermes_run_command",
        "hermes_session_search",
        "bridge_status",
        "bridge_read",
        "bridge_submit_command",
        "bridge_read_result",
        "bridge_write_adjudication",
    ]:
        assert forbidden not in names

    # Operator / Owner Mode tools are always registered (with refusal when
    # the policy is disabled). Verify the core read-only + representative
    # mutating tools are present.
    for operator_tool in [
        "hermes_operator_policy",
        "hermes_operator_status",
        "hermes_operator_audit_tail",
        "hermes_operator_doctor",
        "hermes_operator_snapshot",
        "hermes_release_doctor",
        "hermes_operator_recover",
        "hermes_cron_list",
        "hermes_cron_status",
        "hermes_skill_diff",
        "hermes_config_get",
        "hermes_env_status",
        "hermes_gateway_status",
        "hermes_git_status",
        "hermes_git_diff",
        "hermes_cron_run",
        "hermes_skill_create",
        "hermes_owner_run_command",
    ]:
        assert operator_tool in names

    for tool in tools_by_name(built).values():
        assert tool.meta == {"securitySchemes": [{"type": "noauth"}]}


def test_bridge_tools_require_explicit_gate_for_stdio(monkeypatch):
    clear_gate_envs(monkeypatch)
    monkeypatch.setenv(server.ENABLE_BRIDGE_ENV, "1")
    names = tool_names(server.build_server(transport="stdio"))
    for required in [
        "bridge_status",
        "bridge_read",
        "bridge_submit_command",
        "bridge_read_result",
        "bridge_write_adjudication",
    ]:
        assert required in names


def test_http_bridge_refuses_without_oauth(monkeypatch):
    clear_gate_envs(monkeypatch)
    monkeypatch.setenv(server.ENABLE_BRIDGE_ENV, "1")
    with pytest.raises(RuntimeError, match="refused over HTTP/SSE"):
        server.build_server(http=True, transport="streamable-http")


def test_authenticated_http_bridge_requires_bearer_token(monkeypatch, tmp_path):
    clear_gate_envs(monkeypatch)
    auth_root = tmp_path / "auth"
    config = op_auth.AuthRuntimeConfig(
        issuer_url="https://mcp.example.test",
        resource_server_url="https://mcp.example.test/mcp",
        scope="hermes:operator",
        root=auth_root,
        username="justin",
    )
    op_auth.bootstrap_credentials(config)
    monkeypatch.setenv(server.ENABLE_BRIDGE_ENV, "1")
    monkeypatch.setenv(op_auth.AUTH_ENABLED_ENV, "1")
    monkeypatch.setenv(op_auth.AUTH_ISSUER_URL_ENV, config.issuer_url)
    monkeypatch.setenv(op_auth.AUTH_RESOURCE_URL_ENV, config.resource_server_url)
    monkeypatch.setenv(op_auth.AUTH_ROOT_ENV, str(auth_root))
    monkeypatch.setenv(op_auth.AUTH_SCOPE_ENV, config.scope)
    monkeypatch.setenv(op_auth.AUTH_USERNAME_ENV, config.username)

    built = server.build_server(http=True, transport="streamable-http")
    names = tool_names(built)
    assert "bridge_submit_command" in names
    for tool in tools_by_name(built).values():
        assert tool.meta == {
            "securitySchemes": [{"type": "oauth2", "scopes": [config.scope]}]
        }

    app = built.streamable_http_app()
    with TestClient(app) as client:
        protected = client.get("/mcp")
        assert protected.status_code == 401
        assert "Bearer" in protected.headers.get("www-authenticate", "")

        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        payload = metadata.json()
        assert payload["resource"] == config.resource_server_url
        assert [value.rstrip("/") for value in payload["authorization_servers"]] == [
            config.issuer_url.rstrip("/")
        ]

        authorization_metadata = client.get("/.well-known/oauth-authorization-server")
        assert authorization_metadata.status_code == 200
        assert authorization_metadata.json()["registration_endpoint"].endswith("/register")

        health = client.get("/health/auth")
        assert health.status_code == 200
        assert health.text == "oauth-enabled"


def test_env_gates_expose_high_risk_tools(monkeypatch):
    clear_gate_envs(monkeypatch)
    monkeypatch.setenv(server.ENABLE_WRITE_ENV, "1")
    monkeypatch.setenv(server.ENABLE_TERMINAL_ENV, "1")
    monkeypatch.setenv(server.ENABLE_SESSION_SEARCH_ENV, "1")

    names = tool_names(server.build_server())

    assert "hermes_write_file" in names
    assert "hermes_patch" in names
    assert "hermes_run_command" in names
    assert "hermes_session_search" in names


def test_memory_write_actions_are_disabled_by_default(monkeypatch):
    clear_gate_envs(monkeypatch)
    monkeypatch.setattr(server, "require_imports", lambda: None)
    monkeypatch.setattr(
        server,
        "memory_tool",
        SimpleNamespace(memory_tool=lambda **kwargs: "should not be called"),
    )

    with pytest.raises(RuntimeError, match=server.ENABLE_MEMORY_WRITE_ENV):
        server.hermes_memory(action="add", target="memory", content="x")


def test_memory_search_remains_available(monkeypatch):
    clear_gate_envs(monkeypatch)
    captured = {}

    def fake_memory_tool(**kwargs):
        captured.update(kwargs)
        return "memory search ok"

    monkeypatch.setattr(server, "require_imports", lambda: None)
    monkeypatch.setattr(server, "memory_tool", SimpleNamespace(memory_tool=fake_memory_tool))

    assert server.hermes_memory(action="search", target="memory") == "memory search ok"
    assert captured["action"] == "search"


def test_terminal_direct_call_is_disabled_by_default(monkeypatch):
    clear_gate_envs(monkeypatch)
    monkeypatch.setattr(server, "require_imports", lambda: None)
    monkeypatch.setattr(
        server,
        "terminal_tool",
        SimpleNamespace(terminal_tool=lambda **kwargs: "should not be called"),
    )

    with pytest.raises(RuntimeError, match=server.ENABLE_TERMINAL_ENV):
        server.hermes_run_command("echo nope")


def test_terminal_timeout_is_capped_when_enabled(monkeypatch):
    clear_gate_envs(monkeypatch)
    monkeypatch.setenv(server.ENABLE_TERMINAL_ENV, "1")
    captured = {}

    def fake_terminal_tool(command, timeout=None, workdir=None):
        captured.update({"command": command, "timeout": timeout, "workdir": workdir})
        return "ok"

    monkeypatch.setattr(server, "require_imports", lambda: None)
    monkeypatch.setattr(server, "terminal_tool", SimpleNamespace(terminal_tool=fake_terminal_tool))

    assert server.hermes_run_command("echo ok", timeout=999) == "ok"
    assert captured["timeout"] == 120


def test_remote_profile_requires_explicit_unsafe_ack(monkeypatch):
    clear_gate_envs(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["server.py", "--http", "--profile", "remote"])

    with pytest.raises(SystemExit, match="Remote profile requires HERMES_GPT_AUTH_ENABLED=1"):
        server.main()


def test_default_hermes_root_normalizes_profile_scoped_env(monkeypatch):
    monkeypatch.setenv(
        "HERMES_HOME", r"C:\Users\asimo\AppData\Local\hermes\profiles\hermes-senior-engineer"
    )
    assert server._default_hermes_root() == Path(r"C:\Users\asimo\AppData\Local\hermes")
    assert server._hermes_root_for_operator() == Path(r"C:\Users\asimo\AppData\Local\hermes")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_http_initialize_smoke(monkeypatch):
    port = free_port()
    env = os.environ.copy()
    for name in GATE_ENVS:
        env.pop(name, None)

    proc = subprocess.Popen(
        [sys.executable, "server.py", "--http", "--host", "127.0.0.1", "--port", str(port)],
        cwd=os.path.dirname(__file__),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        deadline = time.time() + 10
        last_error = None
        response_text = None
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "1"},
            },
        }
        data = json.dumps(payload).encode("utf-8")
        while time.time() < deadline:
            try:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/mcp",
                    data=data,
                    method="POST",
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                    },
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    response_text = response.read().decode("utf-8")
                    break
            except Exception as exc:
                last_error = exc
                time.sleep(0.25)
        if response_text is None:
            raise AssertionError(f"HTTP MCP server did not respond: {last_error}")

        parsed = json.loads(response_text)
        assert parsed["result"]["serverInfo"]["name"] == "hermes-gpt"
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
