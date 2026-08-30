from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import operator_computer_use_diagnostics as cu


def test_status_reports_real_agent_toolset_and_host_signals(monkeypatch, tmp_path):
    agent_root = tmp_path / "hermes-agent"
    agent_root.mkdir()
    (agent_root / "pyproject.toml").write_text(
        '[project]\nname = "hermes-agent"\nversion = "0.18.2"\n',
        encoding="utf-8",
    )
    (agent_root / "toolsets.py").write_text(
        'TOOLSETS = {"computer_use": {}, "browser": {}}\n',
        encoding="utf-8",
    )
    hermes_root = tmp_path / ".hermes"
    hermes_root.mkdir()
    (hermes_root / "config.yaml").write_text(
        "computer_use:\n  cua_telemetry: false\nsecret_value: must-not-appear\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
    monkeypatch.setattr(
        cu,
        "_resolve_binary",
        lambda name, preferred=None: f"/mock/{name}",
    )
    monkeypatch.setattr(
        cu,
        "_run_version",
        lambda argv, timeout=5: {"attempted": True, "returncode": 0, "output": "v1"},
    )
    monkeypatch.setattr(
        cu.shutil,
        "which",
        lambda name, path=None: f"/mock/{name}" if name in {"powershell.exe", "cmd.exe"} else None,
    )

    result = json.loads(cu.computer_use_status(agent_root=agent_root, hermes_root=hermes_root))

    assert result["success"] is True
    assert result["mode"] == "read_only_host_status"
    assert result["agent"]["version"] == "0.18.2"
    assert result["agent"]["toolsets"] == {"computer_use": True, "browser": True}
    assert result["configuration"]["computer_use"] == {"cua_telemetry": False}
    assert "must-not-appear" not in json.dumps(result)
    assert result["host"]["is_wsl"] is True
    assert result["commands"]["cua_driver"]["present"] is True
    assert result["commands"]["windows_bridge"]["powershell_exe"] is True
    assert result["guardrails"]["gui_actions"] is False
    assert result["guardrails"]["window_or_tab_enumeration"] is False


def test_doctor_uses_only_fixed_command_and_clamps_timeout(monkeypatch, tmp_path):
    agent_root = tmp_path / "hermes-agent"
    agent_root.mkdir()
    hermes_root = tmp_path / ".hermes"
    hermes_root.mkdir()
    observed = {}

    monkeypatch.setattr(
        cu,
        "_resolve_binary",
        lambda name, preferred=None: "/mock/hermes" if name == "hermes" else "/mock/cua-driver",
    )

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="doctor ok\n", stderr="")

    monkeypatch.setattr(cu.subprocess, "run", fake_run)

    result = json.loads(
        cu.computer_use_doctor(
            timeout=999,
            agent_root=agent_root,
            hermes_root=hermes_root,
        )
    )

    assert observed["argv"] == ["/mock/hermes", "computer-use", "doctor"]
    assert observed["timeout"] == 60
    assert observed["stdin"] is subprocess.DEVNULL
    assert observed["env"]["HERMES_CUA_DRIVER_CMD"] == "/mock/cua-driver"
    assert observed["env"]["HERMES_HOME"] == str(hermes_root)
    assert result["success"] is True
    assert result["status"] == "PASS"
    assert result["stdout"] == "doctor ok\n"
    assert result["guardrails"]["fixed_commands_only"] is True
    assert result["guardrails"]["screenshots"] is False
    assert result["guardrails"]["credentials_accessed"] is False


def test_doctor_timeout_is_bounded_and_returns_structured_result(monkeypatch, tmp_path):
    agent_root = tmp_path / "hermes-agent"
    agent_root.mkdir()
    hermes_root = tmp_path / ".hermes"
    hermes_root.mkdir()

    monkeypatch.setattr(
        cu,
        "_resolve_binary",
        lambda name, preferred=None: "/mock/hermes" if name == "hermes" else None,
    )

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output="partial", stderr="late")

    monkeypatch.setattr(cu.subprocess, "run", fake_run)

    result = json.loads(
        cu.computer_use_doctor(
            timeout=0,
            agent_root=agent_root,
            hermes_root=hermes_root,
        )
    )

    assert result["timeout_seconds"] == 1
    assert result["status"] == "TIMEOUT"
    assert result["returncode"] == 124
    assert result["stdout"] == "partial"
    assert result["stderr"] == "late"


def test_runtime_inventory_filters_ports_and_cron_payload(monkeypatch, tmp_path):
    hermes_root = tmp_path / ".hermes"
    cron_path = hermes_root / "profiles" / "default" / "cron" / "jobs.json"
    cron_path.parent.mkdir(parents=True)
    cron_path.write_text(
        json.dumps({"jobs": [{"id": "j1", "name": "safe", "enabled": True, "schedule": "0 * * * *", "prompt": "DO-NOT-RETURN"}]}),
        encoding="utf-8",
    )

    monkeypatch.setattr(cu, "_resolve_binary", lambda name, preferred=None: f"/mock/{name}")

    def fake_probe(argv, timeout=10):
        if argv[0].endswith("/ss"):
            return {"attempted": True, "returncode": 0, "stdout": "LISTEN 0 128 0.0.0.0:8787 0.0.0.0:* users:((\"python\",pid=123,fd=4))\nLISTEN 0 128 0.0.0.0:9999 0.0.0.0:*\n", "stderr": ""}
        if "list-units" in argv:
            return {"attempted": True, "returncode": 0, "stdout": "hermes-gateway.service loaded active running Hermes\nunrelated.service loaded active running Other\n", "stderr": ""}
        if "list-timers" in argv:
            return {"attempted": True, "returncode": 0, "stdout": "gmail-intake.timer next\n", "stderr": ""}
        if argv[0].endswith("/docker"):
            return {"attempted": True, "returncode": 0, "stdout": "searxng\tsearxng/image\t0.0.0.0:8888->8080/tcp\tUp\n", "stderr": ""}
        if "status" in argv:
            return {"attempted": True, "returncode": 0, "stdout": json.dumps({"BackendState": "Running", "Self": {"HostName": "desktop", "DNSName": "desktop.tailnet.ts.net.", "TailscaleIPs": ["100.1.2.3"], "Online": True, "Active": True}}), "stderr": ""}
        if "ip" in argv:
            return {"attempted": True, "returncode": 0, "stdout": "100.1.2.3\n", "stderr": ""}
        return {"attempted": True, "returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(cu, "_run_fixed_probe", fake_probe)
    result = cu._runtime_inventory(hermes_root)
    rendered = json.dumps(result)

    assert any(":8787" in line for line in result["listeners"]["matches"])
    assert not any(":9999" in line for line in result["listeners"]["matches"])
    assert result["tailscale"]["self"]["host_name"] == "desktop"
    assert result["docker"]["containers"][0].startswith("searxng")
    assert "DO-NOT-RETURN" not in rendered
    assert "prompt" not in rendered
    assert result["guardrails"]["arbitrary_command_input"] is False
