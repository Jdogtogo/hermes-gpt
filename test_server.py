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
import operator_policy as op_policy
import operator_sessions as op_sessions
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
    op_policy.OPERATOR_ENABLED_ENV,
    op_policy.OPERATOR_LEVEL_ENV,
    op_policy.OPERATOR_APPLY_MODE_ENV,
    op_policy.OPERATOR_ALLOWED_PROFILES_ENV,
    op_policy.OPERATOR_ALLOWED_PATHS_ENV,
    op_policy.OPERATOR_DENIED_PATHS_ENV,
    op_policy.OWNER_ACK_ENV,
    op_sessions.SESSION_ROOT_ENV,
    op_sessions.ACTIVE_SESSION_ID_ENV,
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


def enable_restricted_env(monkeypatch: pytest.MonkeyPatch, allowed_path: Path) -> None:
    clear_gate_envs(monkeypatch)
    monkeypatch.setenv(op_policy.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op_policy.OPERATOR_LEVEL_ENV, "read_only")
    monkeypatch.setenv(op_policy.OPERATOR_APPLY_MODE_ENV, "dry_run")
    monkeypatch.setenv(op_policy.OPERATOR_ALLOWED_PROFILES_ENV, "default")
    monkeypatch.setenv(op_policy.OPERATOR_ALLOWED_PATHS_ENV, str(allowed_path))


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


def test_chatgpt_restricted_tool_surface_is_allowlisted(monkeypatch, tmp_path):
    enable_restricted_env(monkeypatch, tmp_path)

    built = server.build_server(
        http=True,
        transport="streamable-http",
        profile=server.CHATGPT_RESTRICTED_PROFILE,
    )
    names = tool_names(built)

    assert names == sorted(server.RESTRICTED_TOOL_NAMES)
    for forbidden in [
        "hermes_owner_run_command",
        "hermes_owner_patch",
        "hermes_workspace_write_file",
        "hermes_gateway_restart",
        "hermes_config_set",
        "hermes_env_set_nonsecret",
        "hermes_run_command",
        "bridge_submit_command",
        "hermes_read_file",
    ]:
        assert forbidden not in names
    for tool in tools_by_name(built).values():
        assert tool.meta == {"securitySchemes": [{"type": "noauth"}]}


def test_chatgpt_restricted_refuses_high_risk_env(monkeypatch, tmp_path):
    enable_restricted_env(monkeypatch, tmp_path)
    monkeypatch.setenv(server.ENABLE_TERMINAL_ENV, "1")

    with pytest.raises(RuntimeError, match="high-risk env"):
        server.build_server(
            http=True,
            transport="streamable-http",
            profile=server.CHATGPT_RESTRICTED_PROFILE,
        )


def test_chatgpt_restricted_agent_denies_secret_path_before_execution(monkeypatch, tmp_path):
    allowed = tmp_path
    denied = tmp_path / ".ssh"
    denied.mkdir()
    enable_restricted_env(monkeypatch, allowed)
    called = False

    def should_not_call(**kwargs):
        nonlocal called
        called = True
        return json.dumps({"success": True})

    monkeypatch.setattr(
        server,
        "op_agent",
        SimpleNamespace(hermes_agent_run=should_not_call),
    )

    result = json.loads(
        server.hermes_restricted_agent_run(
            "Inspect this directory.",
            workdir=str(denied),
        )
    )

    assert result["success"] is False
    assert result["code"] == "RESTRICTED_AGENT_RUN_DENIED"
    assert called is False


def test_chatgpt_restricted_agent_forces_read_only_execution(monkeypatch, tmp_path):
    enable_restricted_env(monkeypatch, tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(server, "RUNTIME_TRANSPORT", "streamable-http")
    captured = {}

    def fake_agent_run(**kwargs):
        captured.update(kwargs)
        return json.dumps({"success": True, "returncode": 0})

    monkeypatch.setattr(
        server,
        "op_agent",
        SimpleNamespace(hermes_agent_run=fake_agent_run),
    )

    result = json.loads(
        server.hermes_restricted_agent_run(
            "Inspect this workspace.",
            workdir=str(tmp_path),
            timeout=server.RESTRICTED_AGENT_MAX_TIMEOUT_SECONDS,
        )
    )

    assert result["success"] is True
    assert captured["mode"] == "read_only"
    assert captured["allow_web"] is False
    assert captured["apply"] is False
    assert captured["transport"] == "streamable-http"


def test_local_owner_loopback_can_expose_bridge_without_oauth(monkeypatch):
    clear_gate_envs(monkeypatch)
    monkeypatch.setenv(server.ENABLE_BRIDGE_ENV, "1")

    built = server.build_server(
        http=True,
        host="127.0.0.1",
        transport="streamable-http",
        profile=server.LOCAL_OWNER_PROFILE,
    )

    assert "bridge_submit_command" in tool_names(built)


def enable_operator_session(monkeypatch, tmp_path: Path) -> None:
    auth_root = tmp_path / "auth"
    session_root = tmp_path / "sessions"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    config = op_auth.AuthRuntimeConfig(
        issuer_url="https://operator.example.test",
        resource_server_url="https://operator.example.test/mcp",
        scope="hermes:operator",
        root=auth_root,
        username="justin",
    )
    op_auth.bootstrap_credentials(config)
    record = op_sessions.create_session(
        {
            "policy_template": "sandbox",
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": [str(workspace)],
            "writable_roots": [str(workspace)],
            "egress_hosts": ["localhost"],
            "git_remotes": ["github.com/Jdogtogo/*"],
            "verbs": {"filesystem": ["read", "edit"], "git": ["fetch", "push"]},
        },
        duration_seconds=600,
        root=session_root,
        session_id="ops-endpoint",
    )
    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(session_root))
    monkeypatch.setenv(op_sessions.ACTIVE_SESSION_ID_ENV, record.session_id)
    monkeypatch.setenv(op_auth.AUTH_ENABLED_ENV, "1")
    monkeypatch.setenv(op_auth.AUTH_ISSUER_URL_ENV, config.issuer_url)
    monkeypatch.setenv(op_auth.AUTH_RESOURCE_URL_ENV, config.resource_server_url)
    monkeypatch.setenv(op_auth.AUTH_ROOT_ENV, str(auth_root))
    monkeypatch.setenv(op_auth.AUTH_SCOPE_ENV, config.scope)
    monkeypatch.setenv(op_auth.AUTH_USERNAME_ENV, config.username)


def test_chatgpt_operator_requires_oauth(monkeypatch, tmp_path):
    clear_gate_envs(monkeypatch)
    session_root = tmp_path / "sessions"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    record = op_sessions.create_session(
        {
            "policy_template": "sandbox",
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": [str(workspace)],
            "writable_roots": [str(workspace)],
        },
        duration_seconds=600,
        root=session_root,
        session_id="ops-noauth",
    )
    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(session_root))
    monkeypatch.setenv(op_sessions.ACTIVE_SESSION_ID_ENV, record.session_id)

    with pytest.raises(RuntimeError, match="OAuth"):
        server.build_server(
            http=True,
            transport="streamable-http",
            profile=server.CHATGPT_OPERATOR_PROFILE,
        )


def test_chatgpt_operator_tool_surface_is_authenticated_and_non_owner(monkeypatch, tmp_path):
    clear_gate_envs(monkeypatch)
    enable_operator_session(monkeypatch, tmp_path)

    built = server.build_server(
        http=True,
        transport="streamable-http",
        profile=server.CHATGPT_OPERATOR_PROFILE,
    )
    names = tool_names(built)

    for required in [
        "hermes_operator_session_status",
        "hermes_operator_session_request_extension",
        "hermes_operator_session_revoke",
        "hermes_operator_service_restart",
        "hermes_search_files",
        "hermes_workspace_read",
        "hermes_workspace_patch",
        "hermes_workspace_write_file",
        "hermes_workspace_run_test",
        "hermes_workspace_exec",
        "hermes_workspace_git_commit",
        "hermes_antigravity_smoke_test",
        "hermes_antigravity_dispatch",
        "hermes_antigravity_dispatch_status",
        "hermes_antigravity_dispatch_cancel",
        "hermes_delegate_task",
        "hermes_delegated_task_status",
        "hermes_delegated_task_result",
        "hermes_delegated_task_message",
        "hermes_delegated_task_continue",
        "hermes_delegated_task_cancel",
        "hermes_git_status",
        "hermes_git_diff",
    ]:
        assert required in names
    for forbidden in [
        "hermes_owner_run_command",
        "hermes_owner_patch",
        "hermes_owner_write_file",
        "bridge_submit_command",
        "hermes_restricted_agent_run",
        # hermes_agent_run is deliberately excluded: unrestricted agent
        # delegation could act as a proxy for capabilities outside this
        # profile's narrow, session-gated tool surface.
        "hermes_agent_run",
        "hermes_config_set",
        "hermes_config_patch",
        "hermes_env_set_nonsecret",
        "hermes_gateway_restart",
        "hermes_cron_run",
        "hermes_skill_delete",
        "hermes_skill_write_file",
    ]:
        assert forbidden not in names
    for tool in tools_by_name(built).values():
        assert tool.meta == {
            "securitySchemes": [{"type": "oauth2", "scopes": ["hermes:operator"]}]
        }


def test_operator_status_reports_actual_registered_tools(monkeypatch, tmp_path):
    """hermes_operator_status() must report exactly the live MCP tool surface.

    Regression guard for the stale-inventory defect: the status tool used to
    return a hardcoded list (default-profile tools, including hermes_agent_run
    and owner tools, and missing the session tools). It must instead derive
    from REGISTERED_TOOL_NAMES captured by register_tools().
    """
    clear_gate_envs(monkeypatch)
    enable_operator_session(monkeypatch, tmp_path)

    built = server.build_server(
        http=True,
        transport="streamable-http",
        profile=server.CHATGPT_OPERATOR_PROFILE,
    )
    live_names = tool_names(built)

    status = json.loads(server.hermes_operator_status())
    assert status["success"] is True
    assert status["mcp_profile"] == server.CHATGPT_OPERATOR_PROFILE
    # Self-report matches the actual live tool surface, exactly.
    assert sorted(status["registered_operator_tools"]) == live_names
    assert status["registered_tool_count"] == len(live_names)

    public_manifest = status["public_manifest"]
    assert public_manifest["applicable"] is True
    assert public_manifest["manifest_version"] == server.op_manifest.MANIFEST_VERSION
    assert public_manifest["expected_tool_count"] == 40
    assert public_manifest["registered_tool_count"] == len(live_names)
    assert public_manifest["schema_fingerprint"] == server.op_manifest.EXPECTED_SCHEMA_FINGERPRINT
    assert public_manifest["missing_tools"] == []
    assert public_manifest["unexpected_tools"] == []
    assert public_manifest["duplicate_tool_names"] == []
    assert public_manifest["schema_drift"] is False
    assert public_manifest["valid"] is True
    assert public_manifest["status"] == "PASS"

    # The session and narrowly gated maintenance tools must be reported...
    for required in [
        "hermes_operator_session_request",
        "hermes_operator_session_status",
        "hermes_operator_session_request_extension",
        "hermes_operator_session_revoke",
        "hermes_operator_service_restart",
        "hermes_approval_web_service_restart",
        "hermes_antigravity_review_start",
        "hermes_antigravity_review_status",
        "hermes_antigravity_review_cancel",
        "hermes_antigravity_smoke_test",
        "hermes_antigravity_dispatch",
        "hermes_antigravity_dispatch_status",
        "hermes_antigravity_dispatch_cancel",
    ]:
        assert required in status["registered_operator_tools"]
    # ...and the deliberately-excluded tools must not be.
    for forbidden in [
        "hermes_agent_run",
        "hermes_owner_run_command",
        "hermes_owner_patch",
        "hermes_owner_write_file",
    ]:
        assert forbidden not in status["registered_operator_tools"]


def test_computer_use_readonly_tools_route_to_bounded_host_diagnostics(monkeypatch, tmp_path):
    """The public tools must call only the bounded host-diagnostics adapter."""
    clear_gate_envs(monkeypatch)
    agent_root = tmp_path / "agent"
    hermes_root = tmp_path / ".hermes"
    calls = []
    monkeypatch.setattr(server, "HERMES_ROOT", agent_root)
    monkeypatch.setattr(server, "_default_hermes_root", lambda: hermes_root)
    monkeypatch.setattr(
        server.op_computer_use,
        "computer_use_status",
        lambda **kwargs: calls.append(("status", kwargs)) or json.dumps({"success": True}),
    )
    monkeypatch.setattr(
        server.op_computer_use,
        "computer_use_doctor",
        lambda **kwargs: calls.append(("doctor", kwargs)) or json.dumps({"success": True}),
    )

    assert json.loads(server.hermes_computer_use_status())["success"] is True
    assert json.loads(server.hermes_computer_use_doctor(timeout=27))["success"] is True
    assert calls == [
        ("status", {"agent_root": agent_root, "hermes_root": hermes_root}),
        ("doctor", {"timeout": 27, "agent_root": agent_root, "hermes_root": hermes_root}),
    ]


def test_computer_use_tools_in_operator_surface(monkeypatch, tmp_path):
    """Both computer-use tools must appear on the chatgpt-operator surface."""
    clear_gate_envs(monkeypatch)
    enable_operator_session(monkeypatch, tmp_path)

    built = server.build_server(
        http=True,
        transport="streamable-http",
        profile=server.CHATGPT_OPERATOR_PROFILE,
    )
    names = tool_names(built)
    assert "hermes_computer_use_status" in names
    assert "hermes_computer_use_doctor" in names
    assert sorted(server.op_manifest.CANONICAL_TOOL_NAMES) == sorted(names)


def test_antigravity_public_tools_route_to_tax_calculator_launcher(monkeypatch):
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        server.op_antigravity_tax,
        "start",
        lambda dry_run=True: calls.append(("start", dry_run)) or json.dumps({"success": True}),
    )
    monkeypatch.setattr(
        server.op_antigravity_tax,
        "status",
        lambda: calls.append(("status", None))
        or json.dumps({"success": True, "status": "running", "task_id": "agt_123"}),
    )
    monkeypatch.setattr(
        server.op_antigravity_tax,
        "cancel",
        lambda task_id, dry_run=True: calls.append(("cancel", (task_id, dry_run)))
        or json.dumps({"success": True}),
    )

    assert json.loads(server.hermes_antigravity_review_start(dry_run=True))["success"] is True
    assert json.loads(server.hermes_antigravity_review_status())["success"] is True
    assert json.loads(server.hermes_antigravity_review_cancel(dry_run=False))["success"] is True
    assert calls == [
        ("start", True),
        ("status", None),
        ("status", None),
        ("cancel", ("agt_123", False)),
    ]


def test_governed_antigravity_dispatch_tools_route_to_dispatch_module(monkeypatch):
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(
        server.op_antigravity_dispatch,
        "hermes_antigravity_smoke_test",
        lambda dry_run=True: calls.append(("smoke", dry_run)) or json.dumps({"success": True}),
    )
    monkeypatch.setattr(
        server.op_antigravity_dispatch,
        "hermes_antigravity_dispatch",
        lambda packet_path, dry_run=True: calls.append(("dispatch", (packet_path, dry_run)))
        or json.dumps({"success": True}),
    )
    monkeypatch.setattr(
        server.op_antigravity_dispatch,
        "hermes_antigravity_dispatch_status",
        lambda task_id: calls.append(("status", task_id)) or json.dumps({"success": True}),
    )
    monkeypatch.setattr(
        server.op_antigravity_dispatch,
        "hermes_antigravity_dispatch_cancel",
        lambda task_id, dry_run=True: calls.append(("cancel", (task_id, dry_run)))
        or json.dumps({"success": True}),
    )

    assert json.loads(server.hermes_antigravity_smoke_test(dry_run=True))["success"] is True
    assert json.loads(
        server.hermes_antigravity_dispatch("/approved/packet.json", dry_run=False)
    )["success"] is True
    assert json.loads(server.hermes_antigravity_dispatch_status("agd_123"))["success"] is True
    assert json.loads(
        server.hermes_antigravity_dispatch_cancel("agd_123", dry_run=False)
    )["success"] is True
    assert calls == [
        ("smoke", True),
        ("dispatch", ("/approved/packet.json", False)),
        ("status", "agd_123"),
        ("cancel", ("agd_123", False)),
    ]


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


def test_delegate_task_wrapper_passes_long_horizon_fields(monkeypatch, tmp_path):
    captured = {}

    def fake_delegate(**kwargs):
        captured.update(kwargs)
        return json.dumps({"success": True})

    monkeypatch.setattr(server.op_delegation, "hermes_delegate_task", fake_delegate)
    result = json.loads(
        server.hermes_delegate_task(
            prompt="Review the repository.",
            workdir=str(tmp_path),
            mode="read_only",
            profile="default",
            max_turns=50,
            timeout=1800,
            allow_web=False,
            total_task_window=28800,
            worker_slice_timeout=3600,
            maximum_continuations=8,
            resume_from_checkpoint=True,
            stop_on=[
                "completion",
                "material_scope_change",
                "unsafe_action",
                "repeated_failure",
                "authority_expiry",
            ],
        )
    )

    assert result["success"] is True
    assert captured["total_task_window"] == 28800
    assert captured["worker_slice_timeout"] == 3600
    assert captured["maximum_continuations"] == 8
    assert captured["resume_from_checkpoint"] is True
    assert set(captured["stop_on"]) == {
        "completion",
        "material_scope_change",
        "unsafe_action",
        "repeated_failure",
        "authority_expiry",
    }


def test_delegate_forecast_wrapper_passes_long_horizon_fields(monkeypatch, tmp_path):
    captured = {}

    def fake_forecast(**kwargs):
        captured.update(kwargs)
        return json.dumps({"success": True, "granted": True})

    monkeypatch.setattr(server.op_delegation, "hermes_delegate_task_forecast", fake_forecast)
    result = json.loads(
        server.hermes_delegate_task_forecast(
            workdir=str(tmp_path),
            mode="read_only",
            total_task_window=28800,
            worker_slice_timeout=3600,
            maximum_continuations=8,
            resume_from_checkpoint=True,
            stop_on=[
                "completion",
                "material_scope_change",
                "unsafe_action",
                "repeated_failure",
                "authority_expiry",
            ],
        )
    )

    assert result["granted"] is True
    assert captured["total_task_window"] == 28800
    assert captured["worker_slice_timeout"] == 3600
    assert captured["maximum_continuations"] == 8
    assert captured["resume_from_checkpoint"] is True
