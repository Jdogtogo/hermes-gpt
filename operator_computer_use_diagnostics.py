from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import yaml

import operator_policy as op


MAX_OUTPUT_CHARS = 16_000
DEFAULT_AGENT_ROOT = Path("/home/jfroh/.hermes/hermes-agent")
DEFAULT_HERMES_ROOT = Path("/home/jfroh/.hermes")
DEFAULT_HERMES_CLI = Path("/home/jfroh/.local/bin/hermes")
SAFE_PATH = ":".join(
    [
        "/home/jfroh/.local/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/mnt/c/Windows/System32",
        "/mnt/c/Windows/System32/WindowsPowerShell/v1.0",
    ]
)


def _bounded(text: str) -> str:
    redacted = op.redact_output(text or "")
    if len(redacted) <= MAX_OUTPUT_CHARS:
        return redacted
    return redacted[:MAX_OUTPUT_CHARS] + f"\n... [truncated {len(redacted) - MAX_OUTPUT_CHARS} chars]"


def _resolve_binary(name: str, preferred: Path | None = None) -> str | None:
    if preferred is not None and preferred.is_file() and os.access(preferred, os.X_OK):
        return str(preferred)
    return shutil.which(name, path=SAFE_PATH)


def _run_version(argv: list[str], timeout: int = 5) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env={"PATH": SAFE_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        output = _bounded((completed.stdout or completed.stderr).strip())
        return {
            "attempted": True,
            "returncode": completed.returncode,
            "output": output,
        }
    except subprocess.TimeoutExpired:
        return {"attempted": True, "returncode": 124, "output": "version probe timed out"}
    except OSError as exc:
        return {"attempted": True, "returncode": 127, "output": _bounded(str(exc))}


def _agent_version(agent_root: Path) -> str | None:
    pyproject = agent_root / "pyproject.toml"
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    project = data.get("project")
    if isinstance(project, dict):
        value = project.get("version")
        if isinstance(value, str):
            return value
    return None


def _safe_computer_use_config(hermes_root: Path) -> dict[str, Any]:
    config_path = hermes_root / "config.yaml"
    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {"config_present": config_path.is_file(), "computer_use": {}}
    section = loaded.get("computer_use") if isinstance(loaded, dict) else None
    safe: dict[str, Any] = {}
    if isinstance(section, dict) and isinstance(section.get("cua_telemetry"), bool):
        safe["cua_telemetry"] = section["cua_telemetry"]
    return {"config_present": True, "computer_use": safe}


def _toolset_registration(agent_root: Path) -> dict[str, bool]:
    toolsets = agent_root / "toolsets.py"
    try:
        text = toolsets.read_text(encoding="utf-8")
    except OSError:
        return {"computer_use": False, "browser": False}
    return {
        "computer_use": '"computer_use"' in text,
        "browser": '"browser"' in text,
    }


def computer_use_status(
    *,
    agent_root: Path | None = None,
    hermes_root: Path | None = None,
) -> str:
    """Return bounded, read-only host capability diagnostics."""
    agent_root = (agent_root or DEFAULT_AGENT_ROOT).resolve(strict=False)
    hermes_root = (hermes_root or DEFAULT_HERMES_ROOT).resolve(strict=False)
    hermes_cli = _resolve_binary("hermes", DEFAULT_HERMES_CLI)
    driver_name = "cua-driver"
    driver_path = _resolve_binary(driver_name)
    proc_version = ""
    try:
        proc_version = Path("/proc/version").read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    is_wsl = bool(os.environ.get("WSL_DISTRO_NAME")) or "microsoft" in proc_version.lower()

    result = {
        "success": True,
        "capability": "computer_use",
        "mode": "read_only_host_status",
        "agent": {
            "root": str(agent_root),
            "root_present": agent_root.is_dir(),
            "version": _agent_version(agent_root),
            "toolsets": _toolset_registration(agent_root),
        },
        "configuration": _safe_computer_use_config(hermes_root),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "is_wsl": is_wsl,
            "wsl_distro": os.environ.get("WSL_DISTRO_NAME") or None,
            "display_available": bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
        },
        "commands": {
            "hermes": {
                "present": hermes_cli is not None,
                "resolved_path": hermes_cli,
                "version": _run_version([hermes_cli, "--version"]) if hermes_cli else None,
            },
            "cua_driver": {
                "command": driver_name,
                "present": driver_path is not None,
                "resolved_path": driver_path,
                "version": _run_version([driver_path, "--version"]) if driver_path else None,
            },
            "windows_bridge": {
                "powershell_exe": shutil.which("powershell.exe", path=SAFE_PATH) is not None,
                "cmd_exe": shutil.which("cmd.exe", path=SAFE_PATH) is not None,
            },
        },
        "guardrails": {
            "fixed_commands_only": True,
            "gui_actions": False,
            "screenshots": False,
            "window_or_tab_enumeration": False,
            "credentials_accessed": False,
            "software_installation": False,
            "configuration_changes": False,
            "service_changes": False,
            "microsoft365_interaction": False,
        },
    }
    return json.dumps(result, indent=2)


def _doctor_env(hermes_root: Path, driver_path: str | None) -> dict[str, str]:
    env = {
        "PATH": SAFE_PATH,
        "HOME": str(hermes_root.parent),
        "HERMES_HOME": str(hermes_root),
        "HERMES_CUA_DRIVER_CMD": driver_path or "cua-driver",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    for key in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_SESSION_TYPE", "WSL_DISTRO_NAME", "WSL_INTEROP"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def computer_use_doctor(
    timeout: int = 15,
    *,
    agent_root: Path | None = None,
    hermes_root: Path | None = None,
) -> str:
    """Run only the fixed Hermes computer-use doctor command, read-only."""
    bounded_timeout = max(1, min(int(timeout), 60))
    agent_root = (agent_root or DEFAULT_AGENT_ROOT).resolve(strict=False)
    hermes_root = (hermes_root or DEFAULT_HERMES_ROOT).resolve(strict=False)
    hermes_cli = _resolve_binary("hermes", DEFAULT_HERMES_CLI)
    driver_path = _resolve_binary("cua-driver")
    base = {
        "success": False,
        "capability": "computer_use",
        "mode": "read_only_host_doctor",
        "timeout_seconds": bounded_timeout,
        "command": [hermes_cli or "hermes", "computer-use", "doctor"],
        "guardrails": {
            "fixed_commands_only": True,
            "gui_actions": False,
            "screenshots": False,
            "window_or_tab_enumeration": False,
            "credentials_accessed": False,
            "software_installation": False,
            "configuration_changes": False,
            "service_changes": False,
            "microsoft365_interaction": False,
        },
    }
    if hermes_cli is None:
        base.update({"status": "BLOCKED", "returncode": 127, "output": "Hermes CLI was not found."})
        return json.dumps(base, indent=2)
    try:
        completed = subprocess.run(
            [hermes_cli, "computer-use", "doctor"],
            cwd=str(agent_root) if agent_root.is_dir() else None,
            env=_doctor_env(hermes_root, driver_path),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=bounded_timeout,
            check=False,
        )
        stdout = _bounded(completed.stdout)
        stderr = _bounded(completed.stderr)
        base.update(
            {
                "success": completed.returncode == 0,
                "status": "PASS" if completed.returncode == 0 else "WARN",
                "returncode": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "cua_driver_present": driver_path is not None,
                "cua_driver_path": driver_path,
            }
        )
    except subprocess.TimeoutExpired as exc:
        base.update(
            {
                "status": "TIMEOUT",
                "returncode": 124,
                "stdout": _bounded(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                "stderr": _bounded(exc.stderr or "") if isinstance(exc.stderr, str) else "",
            }
        )
    except OSError as exc:
        base.update({"status": "BLOCKED", "returncode": 127, "output": _bounded(str(exc))})
    return json.dumps(base, indent=2)
