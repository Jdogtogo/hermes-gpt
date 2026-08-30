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
TARGET_VM_NAME = "hermes-exec"
TARGET_VM_IP = "172.29.176.132"
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


def _run_fixed_probe(argv: list[str], timeout: int = 10) -> dict[str, Any]:
    try:
        env = {"PATH": SAFE_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        runtime_dir = f"/run/user/{os.getuid()}"
        if Path(runtime_dir).is_dir():
            env["XDG_RUNTIME_DIR"] = runtime_dir
            bus = Path(runtime_dir) / "bus"
            if bus.exists():
                env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
        completed = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        return {
            "attempted": True,
            "returncode": completed.returncode,
            "stdout": _bounded((completed.stdout or "").strip()),
            "stderr": _bounded((completed.stderr or "").strip()),
        }
    except subprocess.TimeoutExpired:
        return {"attempted": True, "returncode": 124, "stdout": "", "stderr": "probe timed out"}
    except OSError as exc:
        return {"attempted": True, "returncode": 127, "stdout": "", "stderr": _bounded(str(exc))}


def _target_network_status() -> dict[str, Any]:
    ip_path = _resolve_binary("ip")
    powershell = _resolve_binary("powershell.exe")
    route = _run_fixed_probe([ip_path, "route", "get", TARGET_VM_IP]) if ip_path else {
        "attempted": False, "returncode": 127, "stdout": "", "stderr": "ip command unavailable"
    }
    if powershell:
        vm = _run_fixed_probe([
            powershell, "-NoProfile", "-NonInteractive", "-Command",
            "$vm=Get-VM -Name 'hermes-exec' -ErrorAction Stop; "
            "$ips=(Get-VMNetworkAdapter -VM $vm).IPAddresses; "
            "[pscustomobject]@{Name=$vm.Name;State=[string]$vm.State;IPAddresses=($ips -join ',')} | ConvertTo-Json -Compress",
        ])
        tcp22 = _run_fixed_probe([
            powershell, "-NoProfile", "-NonInteractive", "-Command",
            "$r=Test-NetConnection -ComputerName 172.29.176.132 -Port 22 -WarningAction SilentlyContinue; "
            "[pscustomobject]@{RemoteAddress=[string]$r.RemoteAddress;TcpTestSucceeded=[bool]$r.TcpTestSucceeded;InterfaceAlias=[string]$r.InterfaceAlias;SourceAddress=[string]$r.SourceAddress} | ConvertTo-Json -Compress",
        ])
    else:
        vm = {"attempted": False, "returncode": 127, "stdout": "", "stderr": "powershell.exe unavailable"}
        tcp22 = dict(vm)
    return {
        "target_vm_name": TARGET_VM_NAME,
        "expected_ip": TARGET_VM_IP,
        "wsl_route": route,
        "hyper_v_vm": vm,
        "windows_tcp_22": tcp22,
    }


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


TARGET_RUNTIME_PORTS = (4000, 7677, 7680, 7690, 8642, 8644, 8787, 8789, 8888, 9119, 11434, 20241)


def _filter_lines(text: str, needles: tuple[str, ...]) -> list[str]:
    return [line for line in (text or "").splitlines() if any(needle.casefold() in line.casefold() for needle in needles)]


def _safe_cron_inventory(hermes_root: Path) -> dict[str, Any]:
    candidates = [
        hermes_root / "profiles" / "default" / "cron" / "jobs.json",
        hermes_root / "cron" / "jobs.json",
    ]
    registries: list[dict[str, Any]] = []
    for path in candidates:
        item: dict[str, Any] = {"path": str(path), "exists": path.is_file()}
        if path.is_file():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                jobs = loaded.get("jobs", []) if isinstance(loaded, dict) else loaded
                jobs = jobs if isinstance(jobs, list) else []
                item["jobs_count"] = len(jobs)
                item["jobs"] = [
                    {
                        "id": job.get("id") or job.get("name"),
                        "name": job.get("name"),
                        "enabled": job.get("enabled"),
                        "schedule": job.get("schedule") or job.get("cron"),
                    }
                    for job in jobs
                    if isinstance(job, dict)
                ]
            except (OSError, json.JSONDecodeError) as exc:
                item["error"] = type(exc).__name__
        registries.append(item)
    return {"registries": registries}


def _proc_socket_owners() -> dict[str, list[dict[str, Any]]]:
    """Map target listening TCP ports to same-host process names via /proc only."""
    inode_ports: dict[str, int] = {}
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        try:
            lines = table.read_text(encoding="utf-8", errors="replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            try:
                port = int(fields[1].split(":", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            if port in TARGET_RUNTIME_PORTS:
                inode_ports[fields[9]] = port

    owners: dict[str, list[dict[str, Any]]] = {str(port): [] for port in TARGET_RUNTIME_PORTS}
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        try:
            comm = (proc_dir / "comm").read_text(encoding="utf-8", errors="replace").strip()
            uid = (proc_dir / "status").read_text(encoding="utf-8", errors="replace").split("Uid:", 1)[1].splitlines()[0].split()[0]
            fd_dir = proc_dir / "fd"
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if not (target.startswith("socket:[") and target.endswith("]")):
                    continue
                inode = target[8:-1]
                port = inode_ports.get(inode)
                if port is None:
                    continue
                item = {"pid": int(proc_dir.name), "comm": comm, "uid": int(uid)}
                bucket = owners[str(port)]
                if item not in bucket:
                    bucket.append(item)
        except (OSError, IndexError, ValueError):
            continue
    return {port: items for port, items in owners.items() if items}


def _runtime_inventory(hermes_root: Path) -> dict[str, Any]:
    ss_path = _resolve_binary("ss")
    lsof_path = _resolve_binary("lsof")
    fuser_path = _resolve_binary("fuser")
    systemctl_path = _resolve_binary("systemctl")
    docker_path = _resolve_binary("docker")
    tailscale_path = _resolve_binary("tailscale")

    ss_probe = _run_fixed_probe([ss_path, "-ltnp"]) if ss_path else {"attempted": False, "returncode": 127, "stdout": "", "stderr": "ss unavailable"}
    port_needles = tuple(f":{port}" for port in TARGET_RUNTIME_PORTS)
    listeners = _filter_lines(ss_probe.get("stdout", ""), port_needles)
    lsof_probe = _run_fixed_probe([lsof_path, "-nP", "-iTCP", "-sTCP:LISTEN"]) if lsof_path else {"attempted": False, "returncode": 127, "stdout": "", "stderr": "lsof unavailable"}
    lsof_matches = _filter_lines(lsof_probe.get("stdout", ""), port_needles)
    fuser_map: dict[str, Any] = {}
    if fuser_path:
        for port in TARGET_RUNTIME_PORTS:
            probe = _run_fixed_probe([fuser_path, "-n", "tcp", str(port)])
            if probe.get("returncode") == 0 and (probe.get("stdout", "").strip() or probe.get("stderr", "").strip()):
                fuser_map[str(port)] = {
                    "stdout": probe.get("stdout", "").strip(),
                    "stderr": probe.get("stderr", "").strip(),
                }

    services_probe = _run_fixed_probe([systemctl_path, "--user", "list-units", "--type=service", "--all", "--no-pager", "--plain"]) if systemctl_path else {"attempted": False, "returncode": 127, "stdout": "", "stderr": "systemctl unavailable"}
    timers_probe = _run_fixed_probe([systemctl_path, "--user", "list-timers", "--all", "--no-pager", "--plain"]) if systemctl_path else {"attempted": False, "returncode": 127, "stdout": "", "stderr": "systemctl unavailable"}
    relevant_services = _filter_lines(services_probe.get("stdout", ""), ("hermes", "cloudflared", "tailscale", "docker", "ollama"))
    relevant_timers = [line for line in timers_probe.get("stdout", "").splitlines() if line.strip()]

    docker_probe = _run_fixed_probe([docker_path, "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"] ) if docker_path else {"attempted": False, "returncode": 127, "stdout": "", "stderr": "docker unavailable"}

    tailscale_status = _run_fixed_probe([tailscale_path, "status", "--json"]) if tailscale_path else {"attempted": False, "returncode": 127, "stdout": "", "stderr": "tailscale unavailable"}
    tailscale_ip = _run_fixed_probe([tailscale_path, "ip", "-4"]) if tailscale_path else {"attempted": False, "returncode": 127, "stdout": "", "stderr": "tailscale unavailable"}

    curl_path = _resolve_binary("curl")
    http_fingerprints: dict[str, Any] = {}
    if curl_path:
        fixed_urls = {
            "8642": "http://127.0.0.1:8642/",
            "8644": "http://127.0.0.1:8644/",
            "8789": "http://127.0.0.1:8789/",
            "9119": "http://127.0.0.1:9119/",
            "20241": "http://127.0.0.1:20241/metrics",
        }
        for label, url in fixed_urls.items():
            probe = _run_fixed_probe([curl_path, "-sS", "--max-time", "2", "-D", "-", "-o", "-", url], timeout=3)
            raw = probe.get("stdout", "") or ""
            header_text, _, body = raw.partition("\r\n\r\n") if "\r\n\r\n" in raw else raw.partition("\n\n")
            headers: dict[str, str] = {}
            header_lines = header_text.splitlines()
            status_line = header_lines[0] if header_lines else ""
            for line in header_lines[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    if key.strip().casefold() in {"server", "content-type"}:
                        headers[key.strip().casefold()] = value.strip()
            title = None
            lower_body = body.casefold()
            start = lower_body.find("<title>")
            end = lower_body.find("</title>", start + 7) if start >= 0 else -1
            if start >= 0 and end > start:
                title = body[start + 7:end].strip()[:200]
            http_fingerprints[label] = {
                "returncode": probe.get("returncode"),
                "status": status_line,
                "server": headers.get("server"),
                "content_type": headers.get("content-type"),
                "title": title,
                "cloudflared_metrics": "cloudflared_" in body and "build_info" in body,
                "stderr": _bounded((probe.get("stderr", "") or "")[:500]),
            }

        for label in ("8642", "8644", "8789"):
            health_summary: dict[str, Any] = {}
            for path in ("/health", "/status", "/api/health"):
                probe = _run_fixed_probe([curl_path, "-sS", "--max-time", "2", f"http://127.0.0.1:{label}{path}"], timeout=3)
                body = (probe.get("stdout", "") or "").strip()
                item: dict[str, Any] = {"returncode": probe.get("returncode")}
                if body.startswith("{"):
                    try:
                        payload = json.loads(body)
                        if isinstance(payload, dict):
                            for key in ("service", "name", "status", "version", "ok"):
                                value = payload.get(key)
                                if isinstance(value, (str, int, float, bool)) or value is None:
                                    item[key] = value
                    except json.JSONDecodeError:
                        pass
                health_summary[path] = item
            http_fingerprints[label]["health"] = health_summary
    tailscale_safe: dict[str, Any] = {
        "available": tailscale_path is not None,
        "ipv4": tailscale_ip.get("stdout", "").strip(),
        "status_returncode": tailscale_status.get("returncode"),
    }
    if tailscale_status.get("returncode") == 0:
        try:
            payload = json.loads(tailscale_status.get("stdout", "") or "{}")
            self_node = payload.get("Self") if isinstance(payload, dict) else None
            if isinstance(self_node, dict):
                tailscale_safe["self"] = {
                    "host_name": self_node.get("HostName"),
                    "dns_name": self_node.get("DNSName"),
                    "tailscale_ips": self_node.get("TailscaleIPs"),
                    "online": self_node.get("Online"),
                    "active": self_node.get("Active"),
                }
            if isinstance(payload, dict):
                tailscale_safe["backend_state"] = payload.get("BackendState")
        except json.JSONDecodeError:
            tailscale_safe["parse_error"] = True

    return {
        "listeners": {
            "target_ports": list(TARGET_RUNTIME_PORTS),
            "matches": listeners,
            "probe_returncode": ss_probe.get("returncode"),
            "lsof_matches": lsof_matches,
            "lsof_returncode": lsof_probe.get("returncode"),
            "fuser": fuser_map,
            "proc_owners": _proc_socket_owners(),
        },
        "systemd": {
            "relevant_services": relevant_services,
            "timers": relevant_timers,
            "services_returncode": services_probe.get("returncode"),
            "timers_returncode": timers_probe.get("returncode"),
        },
        "docker": {
            "available": docker_path is not None,
            "returncode": docker_probe.get("returncode"),
            "containers": [line for line in docker_probe.get("stdout", "").splitlines() if line.strip()],
            "stderr": docker_probe.get("stderr", ""),
        },
        "http_fingerprints": http_fingerprints,
        "cron": _safe_cron_inventory(hermes_root),
        "tailscale": tailscale_safe,
        "guardrails": {
            "fixed_commands_only": True,
            "arbitrary_command_input": False,
            "credentials_accessed": False,
            "configuration_changes": False,
            "service_changes": False,
            "network_changes": False,
        },
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
        "target_network": _target_network_status(),
        "runtime_inventory": _runtime_inventory(hermes_root),
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
