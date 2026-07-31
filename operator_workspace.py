"""Workspace, gateway, git, and owner-mode tools for hermes-gpt.

Tools:
- ``hermes_gateway_status``        : read_only  — gateway / ticker / adapter health
- ``hermes_gateway_restart``       : workspace  — fixed-argv gateway restart
- ``hermes_operator_service_restart``: workspace — exact, delayed ChatGPT operator restart
- ``hermes_workspace_read``        : read_only  — read file with operator path policy
- ``hermes_workspace_patch``       : workspace  — find-and-replace within an allowed path
- ``hermes_workspace_write_file``  : workspace  — write file within an allowed path
- ``hermes_workspace_run_test``    : workspace  — conservative compatibility test/lint runner
- ``hermes_workspace_exec``        : workspace  — argv-only developer commands in a Docker workspace sandbox
- ``hermes_git_status``            : read_only  — git status in a workdir
- ``hermes_git_diff``              : read_only  — git diff in a workdir
- ``hermes_workspace_git_commit``  : workspace  — narrow, session-gated commit of an explicit file list
- ``hermes_owner_run_command``     : owner      — arbitrary command (with catastrophic blocks)
- ``hermes_owner_patch``           : owner      — arbitrary file patch (still denies secret paths)
- ``hermes_owner_write_file``      : owner      — arbitrary file write (still denies secret paths)

Safety rules:
- No shell=True anywhere. Ever.
- Workspace path tools require path under allowed_paths AND not denied.
- Owner tools require explicit owner ack AND direct mode AND dry_run=false.
- Owner tools still deny secret paths (no secret override in this PR).
- Workspace run_test keeps its conservative compatibility allowlist.
- Workspace exec accepts structured argv only, never invokes a shell, rejects
  direct shell/destructive/downloader commands and dangerous Git mutations,
  and runs inside an air-gapped Docker container with only the approved
  workspace mounted read-write.
- Operator-service restart accepts no unit or command input and requires the
  maintenance template's immutable services:restart grant for the exact unit.
- Owner run_command blocks obvious catastrophic patterns: rm -rf /, del /s,
  format, powershell -EncodedCommand, curl|bash, wget|bash, git push --force,
  git add -A, anything touching .env/vault/token/ssh paths.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import time
from pathlib import Path
from typing import Any, Optional

import operator_policy as op


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(tmp, path)


def _backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    bak = path.with_name(f"{path.name}.bak.{ts}")
    try:
        shutil.copy2(path, bak)
        return bak
    except OSError:
        return None


def _split_command_argv(command: str) -> list[str]:
    """Split a command string into argv without invoking a shell.

    On Windows, shlex with posix=False preserves surrounding quote characters.
    That makes a quoted single argument like "45 5 * * *" arrive downstream as
    a literal string that still includes the quotes. Strip only matching outer
    quotes after parsing so cron expressions and paths with spaces survive as
    single argv tokens, without changing unquoted Windows paths.
    """
    argv = shlex.split(command, posix=(os.name != "nt"))
    if os.name == "nt":
        cleaned: list[str] = []
        for arg in argv:
            if len(arg) >= 2 and arg[0] == arg[-1] and arg[0] in {"'", '"'}:
                cleaned.append(arg[1:-1])
            else:
                cleaned.append(arg)
        return cleaned
    return argv


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


def _gateway_pid_path(profile_home: Path) -> Path:
    return profile_home / "gateway.pid"


def _gateway_state_path(profile_home: Path) -> Path:
    return profile_home / "gateway_state.json"


def _systemd_default_gateway_status(runner=None) -> dict[str, Any] | None:
    """Return authoritative default-gateway service state when systemd is available.

    None means the probe is unsupported or failed, so callers must retain
    the portable PID-file fallback.
    """
    if os.name == "nt":
        return None
    run_fn = runner or op.run_argv
    try:
        rc, stdout, _stderr = run_fn(
            [
                "systemctl",
                "--user",
                "show",
                "hermes-gateway.service",
                "--property=ActiveState,SubState,MainPID",
            ],
            timeout=10,
            workdir=None,
        )
    except Exception:
        return None
    if rc != 0:
        return None

    values: dict[str, str] = {}
    for line in stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value

    active_state = values.get("ActiveState")
    sub_state = values.get("SubState")
    if active_state is None:
        return None
    try:
        main_pid = int(values.get("MainPID", "0"))
    except ValueError:
        main_pid = 0

    return {
        "running": active_state == "active" and sub_state == "running",
        "pid": main_pid if main_pid > 0 else None,
        "active_state": active_state,
        "sub_state": sub_state,
        "unit": "hermes-gateway.service",
    }


def hermes_gateway_status(
    profile: str = "default",
    hermes_root: Path | None = None,
    prefer_systemd: bool = False,
) -> str:
    try:
        policy = op.OperatorPolicy()
        policy.require_profile(profile, hermes_root)
        profile_home = op.resolve_profile_home(profile, hermes_root)

        pid_path = _gateway_pid_path(profile_home)
        state_path = _gateway_state_path(profile_home)
        pid = None
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                pid = None
        running = False
        status_source = "pid_file" if pid is not None else "unavailable"
        if pid is not None:
            try:
                import psutil  # type: ignore

                running = psutil.pid_exists(pid)
            except ImportError:
                # Fall back to OS kill 0 probe.
                try:
                    os.kill(pid, 0)
                    running = True
                except (OSError, ProcessLookupError):
                    running = False
                except Exception:
                    running = False

        # The default Linux installation is supervised by a user systemd unit.
        # Prefer that authoritative service state over a stale/missing PID file.
        systemd_status = None
        if profile == "default" and prefer_systemd:
            systemd_status = _systemd_default_gateway_status()
            if systemd_status is not None:
                running = bool(systemd_status["running"])
                pid = systemd_status["pid"]
                status_source = "systemd"

        state: dict[str, Any] = {}
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                state = {}

        # Cron ticker heartbeat.
        cron_dir = profile_home / "cron"
        ticker_heartbeat = None
        hb_path = cron_dir / "ticker_heartbeat"
        if hb_path.exists():
            try:
                ticker_heartbeat = hb_path.stat().st_mtime
            except OSError:
                ticker_heartbeat = None

        # Adapter / telegram / discord connection info: surface only
        # connected/unconnected booleans, no tokens.
        adapters_summary: list[dict[str, Any]] = []
        for key in ("telegram", "discord", "slack", "signal", "whatsapp", "api_server"):
            entry = state.get(key)
            if isinstance(entry, dict):
                adapters_summary.append(
                    {
                        "name": key,
                        "connected": bool(entry.get("connected", False)),
                    }
                )

        result = {
            "success": True,
            "profile": profile,
            "gateway_pid": pid,
            "gateway_running": running,
            "gateway_status_source": status_source,
            "ticker_heartbeat_mtime": ticker_heartbeat,
            "adapters": adapters_summary,
        }
        if systemd_status is not None:
            result["systemd_unit"] = systemd_status["unit"]
            result["systemd_active_state"] = systemd_status["active_state"]
            result["systemd_sub_state"] = systemd_status["sub_state"]
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="gateway",
                code="GATEWAY_STATUS_ERROR",
                suggested_action="Check gateway.pid, gateway_state.json, and profile name.",
            ),
            indent=2,
        )


def _hermes_argv(profile: str, sub: list[str]) -> list[str]:
    if profile == "default":
        return ["hermes", *sub]
    return ["hermes", "-p", profile, *sub]


def _gateway_restart_argv(profile: str) -> list[str]:
    return _hermes_argv(profile, ["gateway", "restart"])


def _hermes_gateway_restart_raw(
    profile: str = "default",
    runner=None,
) -> tuple[int, str, str]:
    """Execute the raw gateway restart argv. Returns (rc, stdout, stderr).

    No policy checks; callers must gate mutation themselves.
    """
    run_fn = runner or op.run_argv
    return run_fn(_gateway_restart_argv(profile), timeout=120, workdir=None)


def hermes_gateway_restart(
    profile: str = "default",
    dry_run: bool = True,
    hermes_root: Path | None = None,
    runner=None,
) -> str:
    try:
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        policy.require_profile(profile, hermes_root)
        argv = _gateway_restart_argv(profile)

        if policy.effective_dry_run(dry_run):
            plan = {
                "would_restart": True,
                "argv": argv,
                "shell": False,
                "profile": profile,
            }
            op.audit_record(
                tool="hermes_gateway_restart",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run plan",
                profile=profile,
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        rc, out, err = _hermes_gateway_restart_raw(profile, runner=runner)
        result = {
            "success": rc == 0,
            "dry_run": False,
            "returncode": rc,
            "stdout": op.redact_output(out),
            "stderr": op.redact_output(err),
            "note": (
                "If hermes does not support 'gateway restart', this command "
                "may have failed. Try 'hermes gateway stop' + 'hermes gateway start' "
                "manually."
            ),
        }
        op.audit_record(
            tool="hermes_gateway_restart",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=rc == 0,
            changed=True,
            summary=f"rc={rc}",
            profile=profile,
            error=op.redact_output(err) if rc != 0 else "",
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_gateway_restart",
            level="unknown",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            error=str(exc),
            profile=profile,
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="gateway",
                code="GATEWAY_RESTART_ERROR",
                suggested_action="Check Hermes CLI availability, profile, and operator level/apply mode.",
            ),
            indent=2,
        )


# ---------------------------------------------------------------------------
# Narrow operator-service restart
# ---------------------------------------------------------------------------


_OPERATOR_SERVICE_UNIT = "hermes-gpt-chatgpt-operator.service"
_OPERATOR_SERVICE_RESTART_TEMPLATE = "hermes-gpt-operator-maintenance"
_OPERATOR_SERVICE_RESTART_DELAY_SECONDS = 3


def _operator_service_restart_argv(
    *,
    systemd_run_binary: str,
    systemctl_binary: str,
    schedule_unit: str,
) -> list[str]:
    return [
        systemd_run_binary,
        "--user",
        f"--unit={schedule_unit}",
        f"--on-active={_OPERATOR_SERVICE_RESTART_DELAY_SECONDS}s",
        "--collect",
        systemctl_binary,
        "--user",
        "restart",
        _OPERATOR_SERVICE_UNIT,
    ]


def hermes_operator_service_restart(
    dry_run: bool = True,
    runner=None,
    systemd_run_binary: str | None = None,
    systemctl_binary: str | None = None,
) -> str:
    """Queue an exact, delayed restart of the ChatGPT operator service."""

    try:
        # Single authoritative policy-resolution path: OperatorPolicy() derives
        # its entire session authority (level, apply_mode, verbs, service_units,
        # AND policy_template) from one resolve_effective_authority() snapshot.
        # Every gate condition below reads that same object; the tool never
        # performs a second, independently resolved lookup that could disagree
        # with the authority actually being enforced.
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        if policy.session_status != "active" or policy.session_id is None:
            state = policy.session_status or "unknown"
            raise PermissionError(
                "Operator service restart requires an active, approved Operator "
                f"Session (current session state: {state!r})."
            )
        if policy.policy_template != _OPERATOR_SERVICE_RESTART_TEMPLATE:
            raise PermissionError(
                "Operator service restart requires the "
                f"{_OPERATOR_SERVICE_RESTART_TEMPLATE!r} policy template "
                f"(active session template: {policy.policy_template!r})."
            )
        policy.require_verb("services", "restart")
        if _OPERATOR_SERVICE_UNIT not in set(policy.service_units):
            raise PermissionError(
                f"Service unit {_OPERATOR_SERVICE_UNIT!r} is not granted by this Operator Session."
            )

        schedule_unit = (
            f"hermes-gpt-operator-restart-{os.getpid()}-{time.time_ns()}"
        )
        selected_systemd_run = (
            systemd_run_binary or shutil.which("systemd-run") or "systemd-run"
        )
        selected_systemctl = (
            systemctl_binary or shutil.which("systemctl") or "systemctl"
        )
        argv = _operator_service_restart_argv(
            systemd_run_binary=selected_systemd_run,
            systemctl_binary=selected_systemctl,
            schedule_unit=schedule_unit,
        )

        if policy.effective_dry_run(dry_run):
            plan = {
                "would_schedule_restart": True,
                "service_unit": _OPERATOR_SERVICE_UNIT,
                "delay_seconds": _OPERATOR_SERVICE_RESTART_DELAY_SECONDS,
                "argv": argv,
                "shell": False,
            }
            op.audit_record(
                tool="hermes_operator_service_restart",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run operator service restart plan",
                extra={
                    "service_unit": _OPERATOR_SERVICE_UNIT,
                    "delay_seconds": _OPERATOR_SERVICE_RESTART_DELAY_SECONDS,
                },
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        if systemd_run_binary is None and shutil.which("systemd-run") is None:
            raise RuntimeError("systemd-run is required to schedule the operator service restart.")
        if systemctl_binary is None and shutil.which("systemctl") is None:
            raise RuntimeError("systemctl is required to restart the operator service.")

        run_fn = runner or op.run_argv
        rc, stdout, stderr = run_fn(argv, timeout=30, workdir=None)
        result = {
            "success": rc == 0,
            "dry_run": False,
            "scheduled": rc == 0,
            "service_unit": _OPERATOR_SERVICE_UNIT,
            "delay_seconds": _OPERATOR_SERVICE_RESTART_DELAY_SECONDS,
            "returncode": rc,
            "stdout": op.redact_output(stdout),
            "stderr": op.redact_output(stderr),
            "note": (
                "The operator connector will briefly disconnect when the delayed "
                "restart runs; reconnect and continue with the same approved session."
            ),
        }
        op.audit_record(
            tool="hermes_operator_service_restart",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=rc == 0,
            changed=rc == 0,
            summary=f"scheduled operator service restart rc={rc}",
            error=op.redact_output(stderr) if rc != 0 else "",
            extra={
                "service_unit": _OPERATOR_SERVICE_UNIT,
                "delay_seconds": _OPERATOR_SERVICE_RESTART_DELAY_SECONDS,
                "schedule_unit": schedule_unit,
            },
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_operator_service_restart",
            level="unknown",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            changed=False,
            error=str(exc),
            extra={"service_unit": _OPERATOR_SERVICE_UNIT},
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="operator",
                code="OPERATOR_SERVICE_RESTART_ERROR",
                suggested_action=(
                    "Use an active hermes-gpt-operator-maintenance session whose "
                    "immutable policy grants services:restart for the exact operator unit."
                ),
            ),
            indent=2,
        )


# ---------------------------------------------------------------------------
# Narrow approval-web service restart
# ---------------------------------------------------------------------------


_APPROVAL_WEB_SERVICE_UNIT = "hermes-gpt-approval-web.service"
_APPROVAL_WEB_RESTART_TEMPLATE = "hermes-approval-web-maintenance"
_APPROVAL_WEB_RESTART_DELAY_SECONDS = 3


def _approval_web_service_restart_argv(
    *,
    systemd_run_binary: str,
    systemctl_binary: str,
    schedule_unit: str,
) -> list[str]:
    return [
        systemd_run_binary,
        "--user",
        f"--unit={schedule_unit}",
        f"--on-active={_APPROVAL_WEB_RESTART_DELAY_SECONDS}s",
        "--collect",
        systemctl_binary,
        "--user",
        "restart",
        _APPROVAL_WEB_SERVICE_UNIT,
    ]


def hermes_approval_web_service_restart(
    dry_run: bool = True,
    runner=None,
    systemd_run_binary: str | None = None,
    systemctl_binary: str | None = None,
) -> str:
    """Queue an exact, delayed restart of the localhost approval web service."""

    try:
        # Single authoritative policy-resolution path: OperatorPolicy() derives
        # its entire session authority (level, apply_mode, verbs, service_units,
        # AND policy_template) from one resolve_effective_authority() snapshot.
        # Every gate condition below reads that same object; the tool never
        # performs a second, independently resolved lookup that could disagree
        # with the authority actually being enforced.
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        if policy.session_status != "active" or policy.session_id is None:
            state = policy.session_status or "unknown"
            raise PermissionError(
                "Approval web service restart requires an active, approved Operator "
                f"Session (current session state: {state!r})."
            )
        if policy.policy_template != _APPROVAL_WEB_RESTART_TEMPLATE:
            raise PermissionError(
                "Approval web service restart requires the "
                f"{_APPROVAL_WEB_RESTART_TEMPLATE!r} policy template "
                f"(active session template: {policy.policy_template!r})."
            )
        policy.require_verb("services", "restart")
        if _APPROVAL_WEB_SERVICE_UNIT not in set(policy.service_units):
            raise PermissionError(
                f"Service unit {_APPROVAL_WEB_SERVICE_UNIT!r} is not granted by this Operator Session."
            )

        schedule_unit = (
            f"hermes-gpt-approval-web-restart-{os.getpid()}-{time.time_ns()}"
        )
        selected_systemd_run = (
            systemd_run_binary or shutil.which("systemd-run") or "systemd-run"
        )
        selected_systemctl = (
            systemctl_binary or shutil.which("systemctl") or "systemctl"
        )
        argv = _approval_web_service_restart_argv(
            systemd_run_binary=selected_systemd_run,
            systemctl_binary=selected_systemctl,
            schedule_unit=schedule_unit,
        )

        if policy.effective_dry_run(dry_run):
            plan = {
                "would_schedule_restart": True,
                "service_unit": _APPROVAL_WEB_SERVICE_UNIT,
                "delay_seconds": _APPROVAL_WEB_RESTART_DELAY_SECONDS,
                "argv": argv,
                "shell": False,
            }
            op.audit_record(
                tool="hermes_approval_web_service_restart",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run approval web service restart plan",
                extra={
                    "service_unit": _APPROVAL_WEB_SERVICE_UNIT,
                    "delay_seconds": _APPROVAL_WEB_RESTART_DELAY_SECONDS,
                },
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        if systemd_run_binary is None and shutil.which("systemd-run") is None:
            raise RuntimeError("systemd-run is required to schedule the approval web service restart.")
        if systemctl_binary is None and shutil.which("systemctl") is None:
            raise RuntimeError("systemctl is required to restart the approval web service.")

        run_fn = runner or op.run_argv
        rc, stdout, stderr = run_fn(argv, timeout=30, workdir=None)
        result = {
            "success": rc == 0,
            "dry_run": False,
            "scheduled": rc == 0,
            "service_unit": _APPROVAL_WEB_SERVICE_UNIT,
            "delay_seconds": _APPROVAL_WEB_RESTART_DELAY_SECONDS,
            "returncode": rc,
            "stdout": op.redact_output(stdout),
            "stderr": op.redact_output(stderr),
            "note": "The localhost approval service will briefly restart; pending approvals remain stored.",
        }
        op.audit_record(
            tool="hermes_approval_web_service_restart",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=rc == 0,
            changed=rc == 0,
            summary=f"scheduled approval web service restart rc={rc}",
            error=op.redact_output(stderr) if rc != 0 else "",
            extra={
                "service_unit": _APPROVAL_WEB_SERVICE_UNIT,
                "delay_seconds": _APPROVAL_WEB_RESTART_DELAY_SECONDS,
                "schedule_unit": schedule_unit,
            },
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_approval_web_service_restart",
            level="unknown",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            changed=False,
            error=str(exc),
            extra={"service_unit": _APPROVAL_WEB_SERVICE_UNIT},
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="operator",
                code="APPROVAL_WEB_SERVICE_RESTART_ERROR",
                suggested_action=(
                    "Use an active hermes-approval-web-maintenance session whose immutable "
                    "policy grants services:restart for the exact approval web unit."
                ),
            ),
            indent=2,
        )


# ---------------------------------------------------------------------------
# Workspace read / patch / write_file / run_test
# ---------------------------------------------------------------------------


def hermes_workspace_read(
    path: str,
    offset: int = 1,
    limit: int = 500,
) -> str:
    """Read a file. Read-only but applies operator path policy (deny secrets)."""
    try:
        policy = op.OperatorPolicy()
        policy.require_read_path(path)
        p = op._normalize_path(path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        text = p.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines(keepends=True)
        start = max(1, int(offset)) - 1
        end = start + max(1, int(limit))
        chunk = "".join(lines[start:end])
        result = {
            "success": True,
            "path": str(p),
            "offset": start + 1,
            "limit": end - start,
            "total_lines": len(lines),
            "content": chunk,
        }
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="workspace",
                code="WORKSPACE_READ_ERROR",
                suggested_action="Check path, allowed_paths, denied-path policy, and that the file exists.",
            ),
            indent=2,
        )


def hermes_workspace_patch(
    path: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
    dry_run: bool = True,
) -> str:
    try:
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        policy.require_workspace_path(path)
        if not old_string:
            raise ValueError("old_string is required.")
        if new_string is None:
            raise ValueError("new_string is required.")

        p = op._normalize_path(path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        content = p.read_text(encoding="utf-8", errors="replace")
        if old_string not in content:
            raise ValueError("old_string not found in file.")
        if not replace_all and content.count(old_string) > 1:
            raise ValueError(
                "old_string matches multiple locations. Provide more context "
                "or set replace_all=True."
            )
        if replace_all:
            new_content = content.replace(old_string, new_string)
            match_count = content.count(old_string)
        else:
            new_content = content.replace(old_string, new_string, 1)
            match_count = 1

        if policy.effective_dry_run(dry_run):
            plan = {
                "would_patch": True,
                "path": str(p),
                "match_count": match_count,
                "diff": op.unified_diff(content, new_content, label=p.name),
            }
            op.audit_record(
                tool="hermes_workspace_patch",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run plan",
                path=str(p),
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        backup = _backup_file(p)
        _atomic_write_text(p, new_content)
        result = {
            "success": True,
            "dry_run": False,
            "path": str(p),
            "match_count": match_count,
            "backup": str(backup) if backup else None,
        }
        op.audit_record(
            tool="hermes_workspace_patch",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary=f"patched {p.name} ({match_count} replacement(s))",
            path=str(p),
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_workspace_patch",
            level="unknown",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            error=str(exc),
            path=path,
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="workspace",
                code="WORKSPACE_PATCH_ERROR",
                suggested_action="Check path, allowed_paths, old_string/new_string, and operator level/apply mode.",
            ),
            indent=2,
        )


def hermes_workspace_write_file(
    path: str,
    content: str,
    dry_run: bool = True,
) -> str:
    try:
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        policy.require_workspace_path(path)
        if content is None:
            raise ValueError("content is required.")

        p = op._normalize_path(path)
        if policy.effective_dry_run(dry_run):
            plan = {
                "would_write": True,
                "path": str(p),
                "exists": p.exists(),
                "content_len": len(content),
            }
            op.audit_record(
                tool="hermes_workspace_write_file",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run plan",
                path=str(p),
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        backup = _backup_file(p) if p.exists() else None
        _atomic_write_text(p, content)
        result = {
            "success": True,
            "dry_run": False,
            "path": str(p),
            "backup": str(backup) if backup else None,
        }
        op.audit_record(
            tool="hermes_workspace_write_file",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary=f"wrote {p.name}",
            path=str(p),
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_workspace_write_file",
            level="unknown",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            error=str(exc),
            path=path,
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="workspace",
                code="WORKSPACE_WRITE_ERROR",
                suggested_action="Check path, allowed_paths, denied-path policy, and operator level/apply mode.",
            ),
            indent=2,
        )


# Allowlist for run_test. Each entry is a tuple of (argv_prefix, max_args).
# The prefix must match exactly; the rest is bounded.
_TEST_COMMAND_ALLOWLIST: tuple[tuple[tuple[str, ...], int], ...] = (
    (("pytest",), 8),
    (("python", "-m", "pytest"), 8),
    (("python3", "-m", "pytest"), 8),
    (("npm", "test"), 4),
    (("npm", "run", "test"), 4),
    (("npm", "run", "lint"), 4),
    (("ruff", "check"), 4),
    (("mypy",), 4),
    (("git", "status"), 4),
    (("git", "diff"), 4),
)

_WINDOWS_POWERSHELL_FALLBACK = Path(
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
)
_WINDOWS_PYTHON313 = Path(
    "/mnt/c/Users/jfroh/AppData/Local/Programs/Python/Python313/python.exe"
)

# Substrings that mark a command as dangerous and must be refused.
_DANGEROUS_PATTERNS: tuple[str, ...] = (
    "rm ",
    "del ",
    "format ",
    "powershell -c",
    "powershell.exe -c",
    "pwsh -c",
    "pwsh.exe -c",
    "curl ",
    "wget ",
    "bash -c",
    "cmd /c",
    "git add",
    "git commit",
    "git push",
    "|",
    ">",
    "<",
    ";",
    "&",
    "EncodedCommand",
    "||",
    "&&",
    "`",
    "$(",
)


def _is_repository_local_script_command(
    argv: list[str], workdir: str | None
) -> tuple[bool, str]:
    """Allow direct execution of a repository-local Python or Node script.

    The command is still executed as fixed argv with ``shell=False``. The script
    must resolve inside the supplied working directory, exist as a regular file,
    and use an expected extension. Interpreter code flags such as ``-c`` are
    deliberately not accepted.
    """
    if len(argv) < 2 or argv[0] not in {"python", "python3", "windows-python313", "node"}:
        return (False, "")
    if not workdir:
        return (False, "Repository-local script execution requires workdir.")

    expected_suffixes = {
        "python": {".py"},
        "python3": {".py"},
        "windows-python313": {".py"},
        "node": {".js", ".mjs", ".cjs"},
    }
    script_arg = argv[1]
    if script_arg.startswith("-"):
        return (False, "Interpreter flags are not allowed for repository-local script execution.")
    if len(argv[2:]) > 8:
        return (False, "Too many arguments for repository-local script execution.")

    root = Path(workdir).expanduser().resolve(strict=False)
    script = Path(script_arg).expanduser()
    if not script.is_absolute():
        script = root / script
    script = script.resolve(strict=False)
    try:
        script.relative_to(root)
    except ValueError:
        return (False, "Script path must remain inside workdir.")
    if script.suffix.lower() not in expected_suffixes[argv[0]]:
        return (False, f"Unsupported script type for {argv[0]}.")
    if not script.is_file():
        return (False, "Repository-local script does not exist.")
    return (True, "")


def _is_repository_local_powershell_script_command(
    argv: list[str], workdir: str | None
) -> tuple[bool, str]:
    """Allow a repository-local PowerShell script through fixed host argv.

    Only ``powershell.exe -NoProfile -File <script.ps1>`` is accepted. The
    script must resolve inside ``workdir`` and no command-string flags are
    permitted, so this does not introduce a general PowerShell surface.
    """
    if not argv or argv[0].lower() != "powershell.exe":
        return (False, "")
    if not workdir:
        return (False, "Repository-local PowerShell execution requires workdir.")
    if len(argv) < 4 or argv[1:3] != ["-NoProfile", "-File"]:
        return (
            False,
            "PowerShell must use exactly -NoProfile -File with a repository-local script.",
        )
    if len(argv[4:]) > 8:
        return (False, "Too many arguments for repository-local PowerShell execution.")

    root = Path(workdir).expanduser().resolve(strict=False)
    script = Path(argv[3]).expanduser()
    if not script.is_absolute():
        script = root / script
    script = script.resolve(strict=False)
    try:
        script.relative_to(root)
    except ValueError:
        return (False, "PowerShell script path must remain inside workdir.")
    if script.suffix.lower() != ".ps1":
        return (False, "Unsupported PowerShell script type.")
    if not script.is_file():
        return (False, "Repository-local PowerShell script does not exist.")
    return (True, "")


def _resolve_test_argv(argv: list[str]) -> list[str]:
    """Resolve fixed host executables after the command has passed validation."""
    if not argv:
        return []
    if argv[0] == "windows-python313":
        if not _WINDOWS_PYTHON313.is_file():
            raise FileNotFoundError(
                f"Windows Python 3.13 executable was not found at {_WINDOWS_PYTHON313}"
            )
        return [str(_WINDOWS_PYTHON313), *argv[1:]]
    if argv[0].lower() != "powershell.exe":
        return list(argv)
    resolved = shutil.which(argv[0])
    if resolved:
        return [resolved, *argv[1:]]
    if _WINDOWS_POWERSHELL_FALLBACK.is_file():
        return [str(_WINDOWS_POWERSHELL_FALLBACK), *argv[1:]]
    raise FileNotFoundError(
        "Windows PowerShell executable was not found on PATH or at "
        f"{_WINDOWS_POWERSHELL_FALLBACK}"
    )


def _is_allowed_test_command(
    argv: list[str], workdir: str | None = None
) -> tuple[bool, str]:
    """Check whether argv matches the test/lint allowlist."""
    if not argv:
        return (False, "Empty command.")
    cmd = " ".join(argv)
    # Reject dangerous substrings first.
    for needle in _DANGEROUS_PATTERNS:
        if needle in cmd:
            return (False, f"Command contains forbidden substring {needle!r}.")
    for prefix, max_extra in _TEST_COMMAND_ALLOWLIST:
        if len(argv) >= len(prefix) and tuple(argv[: len(prefix)]) == prefix:
            extra = argv[len(prefix) :]
            if len(extra) > max_extra:
                return (False, f"Too many arguments for {prefix!r}.")
            return (True, "")

    powershell_allowed, powershell_reason = _is_repository_local_powershell_script_command(
        argv, workdir
    )
    if powershell_allowed or powershell_reason:
        return (powershell_allowed, powershell_reason)

    local_script_allowed, local_script_reason = _is_repository_local_script_command(argv, workdir)
    if local_script_allowed or local_script_reason:
        return (local_script_allowed, local_script_reason)
    return (False, "Command not in the test/lint allowlist.")


def hermes_workspace_run_test(
    command: str,
    workdir: str | None = None,
    timeout: int = 120,
    dry_run: bool = True,
    runner=None,
) -> str:
    try:
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        if not command or not command.strip():
            raise ValueError("command is required.")

        # Parse with shlex so we never invoke a shell.
        try:
            argv = _split_command_argv(command)
        except ValueError as exc:
            raise PermissionError(
                "Command not in the test/lint allowlist: could not parse safely."
            ) from exc

        allowed, reason = _is_allowed_test_command(argv, workdir=workdir)
        if not allowed:
            raise PermissionError(reason)
        execution_argv = _resolve_test_argv(argv)

        # workdir policy: must be under an allowed_path if any are set.
        if workdir:
            if policy.allowed_paths and not op.path_under_allowed(workdir, policy.allowed_paths):
                raise PermissionError(
                    f"workdir {workdir!r} is not under any allowed path."
                )

        if policy.effective_dry_run(dry_run):
            plan = {
                "would_run": True,
                "argv": execution_argv,
                "requested_argv": argv,
                "shell": False,
                "workdir": workdir,
                "timeout": max(1, min(int(timeout), 600)),
            }
            op.audit_record(
                tool="hermes_workspace_run_test",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run plan",
                path=workdir or "",
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        run_fn = runner or op.run_argv
        rc, out, err = run_fn(execution_argv, timeout=timeout, workdir=workdir)
        result = {
            "success": rc == 0,
            "dry_run": False,
            "returncode": rc,
            "argv": execution_argv,
            "requested_argv": argv,
            "stdout": op.redact_output(out),
            "stderr": op.redact_output(err),
        }
        op.audit_record(
            tool="hermes_workspace_run_test",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=rc == 0,
            changed=False,  # test runs are not file mutations
            summary=f"rc={rc} argv={argv}",
            path=workdir or "",
            error=op.redact_output(err) if rc != 0 else "",
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_workspace_run_test",
            level="unknown",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            error=str(exc),
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="workspace",
                code="WORKSPACE_RUN_TEST_ERROR",
                suggested_action="Check command allowlist, workdir, and operator level/apply mode.",
            ),
            indent=2,
        )


# ---------------------------------------------------------------------------
# General workspace command execution
# ---------------------------------------------------------------------------

WORKSPACE_EXEC_IMAGE_ENV = "HERMES_GPT_WORKSPACE_EXEC_IMAGE"
_WORKSPACE_EXEC_DEFAULT_IMAGE = "hermes-gpt-workspace-exec:python3.11-nodejs20"
_WORKSPACE_EXEC_MAX_ARGS = 128
_WORKSPACE_EXEC_MAX_ARG_LENGTH = 4096
_WORKSPACE_EXEC_BLOCKED_COMMANDS: frozenset[str] = frozenset(
    {
        "bash",
        "sh",
        "dash",
        "zsh",
        "fish",
        "ksh",
        "csh",
        "tcsh",
        "cmd",
        "powershell",
        "pwsh",
        "curl",
        "wget",
        "ftp",
        "telnet",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "ssh",
        "scp",
        "sftp",
        "rm",
        "rmdir",
        "del",
        "erase",
        "format",
        "shred",
        "wipefs",
        "dd",
        "unlink",
        "truncate",
        "sudo",
        "su",
        "doas",
        "docker",
        "podman",
        "nerdctl",
        "base64",
        "certutil",
        "xargs",
        "env",
        "timeout",
        "nice",
        "nohup",
        "setsid",
        "stdbuf",
        "chroot",
        "unshare",
        "nsenter",
        "ionice",
        "taskset",
        "watch",
        "script",
        "busybox",
        "toybox",
    }
)
_WORKSPACE_EXEC_BLOCKED_GIT_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "add",
        "am",
        "apply",
        "bisect",
        "branch",
        "checkout",
        "cherry-pick",
        "clean",
        "clone",
        "commit",
        "config",
        "fetch",
        "filter-branch",
        "gc",
        "init",
        "merge",
        "mv",
        "notes",
        "pull",
        "push",
        "rebase",
        "remote",
        "reset",
        "restore",
        "revert",
        "rm",
        "stash",
        "submodule",
        "switch",
        "tag",
        "update-index",
        "update-ref",
        "worktree",
    }
)
_WORKSPACE_EXEC_INLINE_CODE_FLAG_FAMILIES: tuple[
    tuple[tuple[str, ...], frozenset[str], tuple[str, ...]], ...
] = (
    (("python", "pypy"), frozenset({"-c", "--command"}), ("-c", "--command=")),
    (("node", "nodejs"), frozenset({"-e", "--eval", "-p", "--print"}), ("-e", "-p", "--eval=", "--print=")),
    (("ruby",), frozenset({"-e"}), ("-e",)),
    (("perl",), frozenset({"-e", "-E"}), ("-e", "-E")),
    (("php",), frozenset({"-r"}), ("-r",)),
    (("lua",), frozenset({"-e"}), ("-e",)),
    (("rscript",), frozenset({"-e", "--expression"}), ("-e", "--expression=")),
)
_WORKSPACE_EXEC_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
_WORKSPACE_EXEC_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _workspace_exec_command_name(value: str) -> str:
    name = Path(value).name.lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _workspace_exec_root(policy: op.OperatorPolicy, workdir: Path) -> Path:
    roots = policy.writable_roots or policy.allowed_paths
    candidates: list[Path] = []
    for raw_root in roots:
        root = Path(raw_root).expanduser().resolve(strict=False)
        if op.path_under_allowed(workdir, [root]):
            candidates.append(root)
    if not candidates:
        raise PermissionError("workdir is not under an approved writable workspace root.")
    root = max(candidates, key=lambda item: len(item.parts))
    policy.require_read_path(root)
    policy.require_write_path(root)
    if not root.is_dir():
        raise NotADirectoryError("Approved workspace root is not a directory.")
    return root


def _workspace_exec_container_path(workspace_root: Path, path: Path) -> str:
    relative = path.relative_to(workspace_root)
    if relative == Path("."):
        return "/workspace"
    return f"/workspace/{relative.as_posix()}"


def _workspace_exec_looks_like_path(value: str, workdir: Path) -> bool:
    if not value:
        return False
    if value in {".", ".."} or value.startswith(("./", "../", ".\\", "..\\", "~")):
        return True
    if "/" in value or "\\" in value:
        return True
    try:
        return (workdir / value).exists()
    except OSError:
        return False


def _workspace_exec_translate_path_value(
    value: str,
    *,
    workspace_root: Path,
    workdir: Path,
    policy: op.OperatorPolicy,
) -> str:
    normalized = value.replace("\\", "/")
    if ".." in [part for part in normalized.split("/") if part]:
        raise PermissionError("Path traversal is not allowed in workspace command arguments.")
    if _WORKSPACE_EXEC_WINDOWS_ABSOLUTE_RE.match(value):
        raise PermissionError("Windows absolute paths are not allowed in workspace command arguments.")

    raw_path = Path(value).expanduser()
    absolute_input = raw_path.is_absolute()
    candidate = raw_path if absolute_input else workdir / raw_path
    resolved = candidate.resolve(strict=False)
    if not op.path_under_allowed(resolved, [workspace_root]):
        raise PermissionError("Command path arguments must remain inside the approved workspace.")
    if policy.denies_path(resolved):
        raise PermissionError("Command path argument is denied by the operator path policy.")
    if absolute_input:
        return _workspace_exec_container_path(workspace_root, resolved)
    return normalized


def _workspace_exec_translate_arg(
    arg: str,
    *,
    workspace_root: Path,
    workdir: Path,
    policy: op.OperatorPolicy,
) -> str:
    if arg.startswith("-") and "=" in arg:
        option, value = arg.split("=", 1)
        if _workspace_exec_looks_like_path(value, workdir):
            translated = _workspace_exec_translate_path_value(
                value,
                workspace_root=workspace_root,
                workdir=workdir,
                policy=policy,
            )
            return f"{option}={translated}"
        return arg
    if _workspace_exec_looks_like_path(arg, workdir):
        return _workspace_exec_translate_path_value(
            arg,
            workspace_root=workspace_root,
            workdir=workdir,
            policy=policy,
        )
    return arg


def _workspace_exec_has_inline_code_flag(command: str, args: list[str]) -> bool:
    for command_prefixes, exact_flags, attached_prefixes in _WORKSPACE_EXEC_INLINE_CODE_FLAG_FAMILIES:
        if not any(command.startswith(prefix) for prefix in command_prefixes):
            continue
        for arg in args:
            if arg in exact_flags or any(arg.startswith(prefix) for prefix in attached_prefixes):
                return True
    return False


def _workspace_exec_git_metadata_path(workspace_root: Path, workdir: Path) -> Path | None:
    current = workdir
    while True:
        candidate = current / ".git"
        if candidate.exists() or candidate.is_symlink():
            return candidate
        if current == workspace_root:
            return None
        current = current.parent


def _workspace_exec_validate_git_metadata(workspace_root: Path, workdir: Path) -> None:
    metadata = _workspace_exec_git_metadata_path(workspace_root, workdir)
    if metadata is None or metadata.is_dir():
        return
    if not metadata.is_file():
        raise PermissionError("Git metadata must be a directory inside the approved workspace.")
    try:
        first_line = metadata.read_text(encoding="utf-8").splitlines()[0].strip()
    except (OSError, UnicodeError, IndexError) as exc:
        raise PermissionError("Could not validate Git metadata inside the approved workspace.") from exc
    prefix = "gitdir:"
    if not first_line.lower().startswith(prefix):
        raise PermissionError("Unsupported .git indirection file.")
    raw_target = first_line[len(prefix):].strip()
    target = Path(raw_target).expanduser()
    if target.is_absolute():
        raise PermissionError(
            "Linked Git worktrees with absolute external metadata are not supported by confined workspace execution."
        )
    resolved_target = (metadata.parent / target).resolve(strict=False)
    if not op.path_under_allowed(resolved_target, [workspace_root]):
        raise PermissionError(
            "Linked Git worktree metadata escapes the approved workspace; use the dedicated Git tools instead."
        )


def _workspace_exec_git_subcommand(argv: list[str]) -> str:
    index = 1
    options_with_values = {"-C", "--git-dir", "--work-tree", "--namespace"}
    while index < len(argv):
        arg = argv[index]
        if arg in {"-c", "--config-env"} or arg.startswith(("-c=", "--config-env=")):
            raise PermissionError("Git configuration injection is not allowed.")
        if arg in options_with_values:
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        return arg.lower()
    return ""


def _validate_workspace_exec_argv(
    argv: list[str],
    *,
    workspace_root: Path,
    workdir: Path,
    policy: op.OperatorPolicy,
) -> list[str]:
    if not isinstance(argv, list) or not argv:
        raise ValueError("argv must be a non-empty list of strings.")
    if len(argv) > _WORKSPACE_EXEC_MAX_ARGS:
        raise ValueError(f"argv may contain at most {_WORKSPACE_EXEC_MAX_ARGS} arguments.")

    cleaned: list[str] = []
    for raw_arg in argv:
        if not isinstance(raw_arg, str) or not raw_arg:
            raise ValueError("Every argv element must be a non-empty string.")
        if len(raw_arg) > _WORKSPACE_EXEC_MAX_ARG_LENGTH:
            raise ValueError("Command argument exceeds the maximum supported length.")
        if any(char in raw_arg for char in ("\x00", "\n", "\r")):
            raise PermissionError("Control characters are not allowed in command arguments.")
        if any(char in raw_arg for char in (";", "&", "|", ">", "<", "`")) or "$(" in raw_arg:
            raise PermissionError("Shell metacharacters and command substitution are not allowed.")
        lower_arg = raw_arg.lower()
        if lower_arg in {"-enc", "/enc", "-encodedcommand", "/encodedcommand"} or "encodedcommand" in lower_arg:
            raise PermissionError("Encoded command forms are not allowed.")
        if re.search(r"(?i)(?:token|secret|password|passwd|api[_-]?key)\s*=", raw_arg):
            raise PermissionError("Secret-bearing command arguments are not allowed.")
        cleaned.append(raw_arg)

    command = _workspace_exec_command_name(cleaned[0])
    if not command or cleaned[0].startswith("-"):
        raise PermissionError("A concrete executable name is required.")
    if command in _WORKSPACE_EXEC_BLOCKED_COMMANDS or command.startswith("mkfs"):
        raise PermissionError(f"Direct execution of {command!r} is blocked.")

    if _workspace_exec_has_inline_code_flag(command, cleaned[1:]):
        raise PermissionError(f"Inline code execution flags are not allowed for {command!r}.")
    if command.startswith(("python", "pypy")) and len(cleaned) > 1 and cleaned[1] == "-":
        raise PermissionError("Python code from standard input is not allowed.")

    if command == "git":
        _workspace_exec_validate_git_metadata(workspace_root, workdir)
        subcommand = _workspace_exec_git_subcommand(cleaned)
        if not subcommand:
            raise PermissionError("A Git subcommand is required.")
        if subcommand in _WORKSPACE_EXEC_BLOCKED_GIT_SUBCOMMANDS:
            raise PermissionError(
                f"Git subcommand {subcommand!r} is mutating or network-capable and is blocked."
            )

    return [
        _workspace_exec_translate_arg(
            arg,
            workspace_root=workspace_root,
            workdir=workdir,
            policy=policy,
        )
        for arg in cleaned
    ]


def _workspace_exec_should_mask(path: Path, policy: op.OperatorPolicy) -> bool:
    name = path.name.lower()
    if name in op.DEFAULT_DENIED_BASENAMES or name.startswith(".env."):
        return True
    if name in op.DEFAULT_DENIED_DIR_NAMES:
        return True
    for denied_root in policy.denied_paths:
        if op.path_under_allowed(path, [denied_root]):
            return True
    return False


_WORKSPACE_EXEC_SECRET_DISCOVERY_TIMEOUT_SECONDS = 20


def _workspace_exec_secret_pathspecs() -> list[str]:
    names = sorted(op.DEFAULT_DENIED_BASENAMES | op.DEFAULT_DENIED_DIR_NAMES)
    patterns: set[str] = {
        ":(glob).env.*",
        ":(glob)**/.env.*",
    }
    for name in names:
        patterns.update(
            {
                f":(glob){name}",
                f":(glob)**/{name}",
                f":(glob){name}/**",
                f":(glob)**/{name}/**",
            }
        )
    return sorted(patterns)


def _workspace_exec_git_secret_candidates(
    workspace_root: Path,
    *,
    runner=None,
) -> list[Path] | None:
    """Use Git index-aware traversal to find mask candidates quickly.

    Returns None when the fast path is unavailable or fails, causing the
    caller to fall back to the conservative filesystem walk. Linked worktrees
    and repositories containing submodules retain the walk because their
    external or nested metadata needs the more conservative treatment.
    """

    if not (workspace_root / ".git").is_dir():
        return None
    if (workspace_root / ".gitmodules").exists():
        return None

    run_fn = runner or op.run_argv
    pathspecs = _workspace_exec_secret_pathspecs()
    modes = (
        ("--cached", "--others", "--exclude-standard"),
        ("--others", "--ignored", "--exclude-standard"),
    )
    found: set[Path] = set()
    for mode in modes:
        argv = ["git", "ls-files", "-z", *mode, "--", *pathspecs]
        try:
            rc, stdout, _ = run_fn(
                argv,
                timeout=_WORKSPACE_EXEC_SECRET_DISCOVERY_TIMEOUT_SECONDS,
                workdir=str(workspace_root),
            )
        except Exception:
            return None
        if rc != 0:
            return None
        for raw_path in stdout.split("\x00"):
            if not raw_path:
                continue
            relative = Path(raw_path)
            if relative.is_absolute() or ".." in relative.parts:
                continue
            candidate = workspace_root / relative
            if candidate.exists() or candidate.is_symlink():
                found.add(candidate)
    return sorted(found, key=lambda item: item.as_posix())


def _workspace_exec_mask_target(
    candidate: Path,
    *,
    workspace_root: Path,
    policy: op.OperatorPolicy,
) -> Path | None:
    try:
        relative = candidate.relative_to(workspace_root)
    except ValueError:
        return None
    current = workspace_root
    for part in relative.parts:
        current = current / part
        if _workspace_exec_should_mask(current, policy):
            return current
    return None


def _workspace_exec_mount_args(
    targets: set[Path],
    *,
    workspace_root: Path,
) -> tuple[list[str], int]:
    docker_args: list[str] = []
    for target in sorted(targets, key=lambda item: item.as_posix()):
        destination = _workspace_exec_container_path(workspace_root, target)
        if target.is_dir() and not target.is_symlink():
            docker_args.extend(
                ["--mount", f"type=tmpfs,destination={destination},tmpfs-mode=0000"]
            )
        else:
            docker_args.extend(
                [
                    "--mount",
                    f"type=bind,source=/dev/null,destination={destination},readonly",
                ]
            )
    return docker_args, len(targets)


def _workspace_exec_denied_mounts(
    workspace_root: Path,
    policy: op.OperatorPolicy,
    *,
    discovery_runner=None,
) -> tuple[list[str], int]:
    targets: set[Path] = set()

    for denied_root in policy.denied_paths:
        denied = Path(denied_root).expanduser().resolve(strict=False)
        if denied.exists() and op.path_under_allowed(denied, [workspace_root]):
            targets.add(denied)

    git_candidates = _workspace_exec_git_secret_candidates(
        workspace_root,
        runner=discovery_runner,
    )
    if git_candidates is not None:
        for candidate in git_candidates:
            target = _workspace_exec_mask_target(
                candidate,
                workspace_root=workspace_root,
                policy=policy,
            )
            if target is not None:
                targets.add(target)
        return _workspace_exec_mount_args(targets, workspace_root=workspace_root)

    for current, dirnames, filenames in os.walk(workspace_root, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in dirnames:
            candidate = current_path / dirname
            if _workspace_exec_should_mask(candidate, policy):
                targets.add(candidate)
            else:
                kept_dirs.append(dirname)
        dirnames[:] = kept_dirs
        for filename in filenames:
            candidate = current_path / filename
            if _workspace_exec_should_mask(candidate, policy):
                targets.add(candidate)
    return _workspace_exec_mount_args(targets, workspace_root=workspace_root)


def _workspace_exec_image(image: str | None = None) -> str:
    selected = (image or os.environ.get(WORKSPACE_EXEC_IMAGE_ENV) or _WORKSPACE_EXEC_DEFAULT_IMAGE).strip()
    if not _WORKSPACE_EXEC_IMAGE_RE.fullmatch(selected):
        raise ValueError("Workspace execution image contains unsupported characters.")
    return selected


def _workspace_exec_docker_argv(
    command_argv: list[str],
    *,
    workspace_root: Path,
    workdir: Path,
    policy: op.OperatorPolicy,
    docker_binary: str,
    image: str,
) -> tuple[list[str], int]:
    container_workdir = _workspace_exec_container_path(workspace_root, workdir)
    denied_mounts, denied_count = _workspace_exec_denied_mounts(workspace_root, policy)
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    gid = os.getgid() if hasattr(os, "getgid") else 1000
    docker_argv = [
        docker_binary,
        "run",
        "--rm",
        "--init",
        "--pull=never",
        "--read-only",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=256",
        "--user",
        f"{uid}:{gid}",
        "--mount",
        f"type=bind,source={workspace_root},destination=/workspace",
        "--workdir",
        container_workdir,
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=512m",
        "--env",
        "HOME=/tmp/hermes-home",
        "--env",
        "XDG_CACHE_HOME=/tmp/cache",
        "--env",
        "PIP_CACHE_DIR=/tmp/pip-cache",
        "--env",
        "NPM_CONFIG_CACHE=/tmp/npm-cache",
        "--env",
        "CARGO_HOME=/tmp/cargo-home",
        "--env",
        "GOCACHE=/tmp/go-cache",
        *denied_mounts,
        "--entrypoint",
        command_argv[0],
        image,
        *command_argv[1:],
    ]
    return docker_argv, denied_count


def _workspace_exec_redacted_argv(argv: list[str]) -> list[str]:
    return [op.redact_output(arg) for arg in argv]


def hermes_workspace_exec(
    argv: list[str],
    workdir: str,
    timeout: int = 300,
    dry_run: bool = True,
    runner=None,
    docker_binary: str | None = None,
    image: str | None = None,
) -> str:
    """Execute structured argv in a Docker-confined approved workspace.

    The host subprocess is always the Docker CLI launched through
    ``subprocess.run(..., shell=False)``. The requested developer command is
    passed to the container runtime as argv, not through a shell. The container
    has a read-only root filesystem, no network, no Linux capabilities, no
    host credentials/environment, and only the approved workspace mounted
    read-write.
    """
    policy: op.OperatorPolicy | None = None
    started = time.monotonic()
    safe_argv: list[str] = []
    resolved_workdir: Path | None = None
    capped_timeout = max(1, min(int(timeout), 600))
    try:
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        if policy.session_id is None:
            raise PermissionError("An active approved Operator Session is required.")
        policy.require_verb("tests", "run")
        if not workdir:
            raise ValueError("workdir is required.")
        resolved_workdir = Path(workdir).expanduser().resolve(strict=True)
        if not resolved_workdir.is_dir():
            raise NotADirectoryError("workdir must be an existing directory.")
        policy.require_read_path(resolved_workdir)
        policy.require_write_path(resolved_workdir)
        workspace_root = _workspace_exec_root(policy, resolved_workdir)
        safe_argv = _validate_workspace_exec_argv(
            argv,
            workspace_root=workspace_root,
            workdir=resolved_workdir,
            policy=policy,
        )
        selected_image = _workspace_exec_image(image)
        selected_docker = docker_binary or shutil.which("docker")
        if not selected_docker:
            raise RuntimeError("Docker is required for confined workspace execution.")
        docker_argv, masked_path_count = _workspace_exec_docker_argv(
            safe_argv,
            workspace_root=workspace_root,
            workdir=resolved_workdir,
            policy=policy,
            docker_binary=selected_docker,
            image=selected_image,
        )
        redacted_argv = _workspace_exec_redacted_argv(argv)

        if policy.effective_dry_run(dry_run):
            duration_ms = int((time.monotonic() - started) * 1000)
            plan = {
                "would_run": True,
                "argv": redacted_argv,
                "workdir": str(resolved_workdir),
                "workspace_root": str(workspace_root),
                "timeout": capped_timeout,
                "shell": False,
                "backend": "docker",
                "image": selected_image,
                "network": "none",
                "masked_path_count": masked_path_count,
            }
            op.audit_record(
                tool="hermes_workspace_exec",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run confined workspace command plan",
                path=str(resolved_workdir),
                extra={
                    "argv": redacted_argv,
                    "workdir": str(resolved_workdir),
                    "timeout_seconds": capped_timeout,
                    "exit_code": None,
                    "duration_ms": duration_ms,
                    "stdout": "",
                    "stderr": "",
                    "backend": "docker",
                    "image": selected_image,
                    "network": "none",
                    "masked_path_count": masked_path_count,
                },
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        run_fn = runner or op.run_argv
        rc, stdout, stderr = run_fn(
            docker_argv,
            timeout=capped_timeout,
            workdir=None,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        redacted_stdout = op.redact_output(stdout)
        redacted_stderr = op.redact_output(stderr)
        result = {
            "success": rc == 0,
            "dry_run": False,
            "returncode": rc,
            "argv": redacted_argv,
            "workdir": str(resolved_workdir),
            "timeout": capped_timeout,
            "duration_ms": duration_ms,
            "backend": "docker",
            "image": selected_image,
            "network": "none",
            "stdout": redacted_stdout,
            "stderr": redacted_stderr,
        }
        op.audit_record(
            tool="hermes_workspace_exec",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=rc == 0,
            changed=False,
            summary=f"rc={rc} confined argv={redacted_argv}",
            path=str(resolved_workdir),
            error=redacted_stderr if rc != 0 else "",
            extra={
                "argv": redacted_argv,
                "workdir": str(resolved_workdir),
                "timeout_seconds": capped_timeout,
                "exit_code": rc,
                "duration_ms": duration_ms,
                "stdout": redacted_stdout,
                "stderr": redacted_stderr,
                "backend": "docker",
                "image": selected_image,
                "network": "none",
                "masked_path_count": masked_path_count,
                "workspace_mutation_possible": True,
            },
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        op.audit_record(
            tool="hermes_workspace_exec",
            level=policy.level if policy is not None else "unknown",
            apply_mode=policy.apply_mode if policy is not None else "unknown",
            dry_run=dry_run,
            success=False,
            changed=False,
            error=str(exc),
            path=str(resolved_workdir) if resolved_workdir is not None else workdir,
            extra={
                "argv": _workspace_exec_redacted_argv(argv) if isinstance(argv, list) else [],
                "workdir": str(resolved_workdir) if resolved_workdir is not None else str(workdir or ""),
                "timeout_seconds": capped_timeout,
                "exit_code": None,
                "duration_ms": duration_ms,
                "stdout": "",
                "stderr": op.redact_output(str(exc)),
                "backend": "docker",
            },
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="workspace",
                code="WORKSPACE_EXEC_ERROR",
                suggested_action=(
                    "Use structured argv, an approved workspace workdir, a non-shell command, "
                    "and ensure the configured Docker image is already available."
                ),
            ),
            indent=2,
        )


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------


def _git(argv: list[str], workdir: str, runner=None) -> tuple[int, str, str]:
    run_fn = runner or op.run_argv
    return run_fn(["git", *argv], timeout=60, workdir=workdir)


def hermes_git_status(workdir: str, runner=None) -> str:
    try:
        policy = op.OperatorPolicy()
        if not workdir:
            raise ValueError("workdir is required.")
        policy.require_read_path(workdir)
        rc, out, err = _git(["status", "--porcelain=v1"], workdir, runner=runner)
        result = {
            "success": rc == 0,
            "workdir": workdir,
            "stdout": op.redact_output(out),
            "stderr": op.redact_output(err),
        }
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="workspace",
                code="GIT_STATUS_ERROR",
                suggested_action="Check workdir, allowed_paths, and git availability.",
            ),
            indent=2,
        )


def hermes_git_diff(
    workdir: str,
    pathspec: str | None = None,
    stat: bool = False,
    runner=None,
) -> str:
    try:
        policy = op.OperatorPolicy()
        if not workdir:
            raise ValueError("workdir is required.")
        policy.require_read_path(workdir)
        argv: list[str] = ["diff"]
        if stat:
            argv.append("--stat")
        if pathspec:
            argv.append("--")
            argv.append(pathspec)
        rc, out, err = _git(argv, workdir, runner=runner)
        result = {
            "success": rc == 0,
            "workdir": workdir,
            "stdout": op.redact_output(out),
            "stderr": op.redact_output(err),
        }
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="workspace",
                code="GIT_DIFF_ERROR",
                suggested_action="Check workdir, allowed_paths, pathspec, and git availability.",
            ),
            indent=2,
        )


def hermes_workspace_git_commit(
    workdir: str,
    expected_branch: str,
    expected_baseline: str,
    allowed_files: list[str],
    message: str,
    dry_run: bool = True,
    runner=None,
) -> str:
    """Create exactly one normal commit of an explicitly approved file list.

    Requires an active Operator Session granting the ``git:commit`` verb.
    Never pushes, amends, resets, cleans, stashes, or changes branches.
    Refuses if the worktree has any tracked, staged, renamed, or deleted file
    outside ``allowed_files``. Unrelated untracked files are left untouched and
    do not block an otherwise explicit path-scoped commit. Also refuses if the
    branch or baseline commit does not match what was expected, or if ``workdir``
    is not the repository's own toplevel.
    """
    try:
        policy = op.OperatorPolicy()
        if not workdir:
            raise ValueError("workdir is required.")
        if not policy.session_id:
            raise PermissionError("hermes_workspace_git_commit requires an active Operator Session.")
        policy.require_write_path(workdir)
        policy.require_verb("git", "commit")
        if not allowed_files:
            raise ValueError("allowed_files must list at least one path.")
        if not message or not message.strip():
            raise ValueError("message is required.")

        root_rc, root_out, _ = _git(["rev-parse", "--show-toplevel"], workdir, runner=runner)
        if root_rc != 0:
            raise PermissionError("workdir is not inside a Git repository.")
        actual_root = str(Path(root_out.strip()).resolve())
        if actual_root != str(Path(workdir).expanduser().resolve()):
            raise PermissionError(
                f"workdir must be the repository toplevel; got {workdir!r}, repository root is {actual_root!r}."
            )

        branch_rc, branch_out, _ = _git(["branch", "--show-current"], workdir, runner=runner)
        actual_branch = branch_out.strip()
        if branch_rc != 0 or actual_branch != expected_branch:
            raise PermissionError(
                f"Branch mismatch: expected {expected_branch!r}, found {actual_branch!r}."
            )
        # expected_branch above is only a caller-supplied consistency check
        # (does the repo's branch match what ChatGPT claimed). The session's own
        # branch restriction is enforced independently here, so a branch-scoped
        # session can never commit to a branch outside its template's grant.
        policy.require_branch(actual_branch)

        head_rc, head_out, _ = _git(["rev-parse", "HEAD"], workdir, runner=runner)
        actual_head = head_out.strip()
        if head_rc != 0 or actual_head != expected_baseline:
            raise PermissionError(
                f"Baseline mismatch: expected {expected_baseline!r}, found {actual_head!r}."
            )

        status_rc, status_out, _ = _git(["status", "--porcelain=v1"], workdir, runner=runner)
        if status_rc != 0:
            raise PermissionError("Could not read git status.")
        dirty_entries: list[tuple[str, str]] = []
        for line in status_out.splitlines():
            if not line.strip():
                continue
            # Porcelain v1: "XY path" (or "XY orig -> path" for renames).
            status = line[:2]
            entry = line[3:].strip()
            if " -> " in entry:
                entry = entry.split(" -> ", 1)[1]
            dirty_entries.append((status, entry))

        allowed_set = set(allowed_files)
        # A path-scoped commit is safe in the presence of unrelated untracked
        # files because the tool stages and commits only explicit allowed paths.
        # Any out-of-scope tracked/index change still fails closed, including
        # staged additions, modifications, deletions, and renames.
        out_of_scope = [
            path
            for status, path in dirty_entries
            if path not in allowed_set and status != "??"
        ]
        if out_of_scope:
            raise PermissionError(
                f"Refusing to commit: unapproved tracked or staged files present: {out_of_scope!r}."
            )
        dirty_files = [path for _status, path in dirty_entries]
        to_stage = [f for f in allowed_files if f in dirty_files]
        if not to_stage:
            raise PermissionError("None of allowed_files are actually modified or untracked.")

        for f in to_stage:
            if op.is_denied_path(Path(workdir) / f):
                raise PermissionError(f"Path {f!r} is denied by the operator path safety policy.")

        if policy.effective_dry_run(dry_run):
            plan = {"would_commit": True, "branch": actual_branch, "baseline": actual_head, "files": to_stage}
            op.audit_record(
                tool="hermes_workspace_git_commit",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                summary="dry-run commit plan",
                path=workdir,
                extra={"files": ",".join(to_stage)},
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        for f in to_stage:
            add_rc, _, add_err = _git(["add", "--", f], workdir, runner=runner)
            if add_rc != 0:
                raise PermissionError(f"Failed to stage {f!r}: {op.redact_output(add_err)}")

        commit_rc, commit_out, commit_err = _git(
            ["commit", "-m", message, "--"] + to_stage, workdir, runner=runner
        )
        if commit_rc != 0:
            raise PermissionError(f"Commit failed: {op.redact_output(commit_err)}")

        hash_rc, hash_out, _ = _git(["rev-parse", "HEAD"], workdir, runner=runner)
        commit_hash = hash_out.strip() if hash_rc == 0 else ""
        final_status_rc, final_status_out, _ = _git(["status", "--porcelain=v1"], workdir, runner=runner)

        result = {
            "success": True,
            "commit_hash": commit_hash,
            "branch": actual_branch,
            "files": to_stage,
            "status": op.redact_output(final_status_out) if final_status_rc == 0 else "",
        }
        op.audit_record(
            tool="hermes_workspace_git_commit",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary=f"committed {commit_hash} with {len(to_stage)} file(s)",
            path=workdir,
            extra={"files": ",".join(to_stage), "commit_hash": commit_hash},
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_workspace_git_commit",
            level="unknown",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            error=str(exc),
            path=workdir,
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="workspace",
                code="WORKSPACE_GIT_COMMIT_ERROR",
                suggested_action="Check branch, baseline commit, allowed_files, and the git:commit session verb.",
            ),
            indent=2,
        )


# ---------------------------------------------------------------------------
# Owner Mode
# ---------------------------------------------------------------------------

# Catastrophic command patterns that even Owner Mode refuses.
_CATASTROPHIC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-rf\s+/(\s|$)"),
    re.compile(r"\brm\s+-rf\s+/\*"),
    re.compile(r"(?i)\bdel\s+/s\b"),
    re.compile(r"(?i)\bformat\b"),
    re.compile(r"(?i)powershell.*-EncodedCommand"),
    re.compile(r"(?i)\b(curl|wget)\b[^|]*\|\s*(bash|sh)"),
    re.compile(r"(?i)\bgit\s+push\b.*--force"),
    re.compile(r"(?i)\bgit\s+push\b.*\s-f\b"),
    re.compile(r"(?i)\bgit\s+add\s+-A\b"),
    re.compile(r"(?i)\bgit\s+add\s+\.\s*$"),
)


def _command_touches_secrets(command: str) -> bool:
    """Heuristic: does the command mention secret/vault/token/.env/ssh paths?"""
    lower = command.lower()
    needles = (
        ".env",
        "vault",
        "mcp-tokens",
        "auth.json",
        ".ssh",
        "id_rsa",
        "id_ed25519",
        "authorized_keys",
        ".aws",
        ".gnupg",
        ".kube",
        "webhook_subscriptions.json",
        "oauth",
        "token",
        "secret",
        "credential",
        "cookie",
        "password",
    )
    return any(n in lower for n in needles)


def hermes_owner_run_command(
    command: str,
    timeout: int = 120,
    workdir: str | None = None,
    dry_run: bool = True,
    runner=None,
) -> str:
    try:
        policy = op.OperatorPolicy()
        policy.require_owner(dry_run)
        if not command or not command.strip():
            raise ValueError("command is required.")

        # Catastrophic pattern block.
        for pattern in _CATASTROPHIC_PATTERNS:
            if pattern.search(command):
                raise PermissionError(
                    f"Command blocked by catastrophic-pattern guard: {command!r}"
                )
        if _command_touches_secrets(command):
            raise PermissionError(
                "Command touches secret-like paths (.env / vault / token / ssh). "
                "Owner Mode does not permit secret access. Edit the file directly "
                "on a trusted shell."
            )

        try:
            argv = _split_command_argv(command)
        except ValueError as exc:
            raise ValueError(f"Could not parse command: {exc}") from exc
        if not argv:
            raise ValueError("Empty command after parse.")

        if policy.effective_dry_run(dry_run):
            plan = {
                "would_run": True,
                "argv": argv,
                "shell": False,
                "workdir": workdir,
                "timeout": max(1, min(int(timeout), 600)),
                "owner_mode": True,
            }
            op.audit_record(
                tool="hermes_owner_run_command",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run plan",
                extra={"argv": argv, "workdir": workdir or ""},
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        run_fn = runner or op.run_argv
        rc, out, err = run_fn(argv, timeout=timeout, workdir=workdir)
        result = {
            "success": rc == 0,
            "dry_run": False,
            "owner_mode": True,
            "returncode": rc,
            "argv": argv,
            "stdout": op.redact_output(out),
            "stderr": op.redact_output(err),
        }
        op.audit_record(
            tool="hermes_owner_run_command",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=rc == 0,
            changed=True,
            summary=f"rc={rc} argv={argv}",
            error=op.redact_output(err) if rc != 0 else "",
            extra={"workdir": workdir or ""},
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_owner_run_command",
            level="owner",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            error=str(exc),
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="owner",
                code="OWNER_RUN_COMMAND_ERROR",
                suggested_action="Check owner acknowledgement, command safety, and operator level/apply mode.",
            ),
            indent=2,
        )


def hermes_owner_patch(
    path: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
    dry_run: bool = True,
) -> str:
    try:
        policy = op.OperatorPolicy()
        policy.require_owner(dry_run)
        if not old_string:
            raise ValueError("old_string is required.")
        if new_string is None:
            raise ValueError("new_string is required.")

        # Owner mode still denies secret paths.
        if op.is_denied_path(path):
            raise PermissionError(
                f"Path {path!r} is denied by the operator path safety policy "
                "(secret / credential / vault / token / .env). Owner Mode "
                "does not override this in the current release."
            )

        p = op._normalize_path(path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        content = p.read_text(encoding="utf-8", errors="replace")
        if old_string not in content:
            raise ValueError("old_string not found in file.")
        if not replace_all and content.count(old_string) > 1:
            raise ValueError(
                "old_string matches multiple locations. Provide more context "
                "or set replace_all=True."
            )
        if replace_all:
            new_content = content.replace(old_string, new_string)
            match_count = content.count(old_string)
        else:
            new_content = content.replace(old_string, new_string, 1)
            match_count = 1

        if policy.effective_dry_run(dry_run):
            plan = {
                "would_patch": True,
                "path": str(p),
                "match_count": match_count,
                "diff": op.unified_diff(content, new_content, label=p.name),
                "owner_mode": True,
            }
            op.audit_record(
                tool="hermes_owner_patch",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run plan",
                path=str(p),
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        backup = _backup_file(p)
        _atomic_write_text(p, new_content)
        result = {
            "success": True,
            "dry_run": False,
            "owner_mode": True,
            "path": str(p),
            "match_count": match_count,
            "backup": str(backup) if backup else None,
        }
        op.audit_record(
            tool="hermes_owner_patch",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary=f"owner patched {p.name}",
            path=str(p),
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_owner_patch",
            level="owner",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            error=str(exc),
            path=path,
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="owner",
                code="OWNER_PATCH_ERROR",
                suggested_action="Check owner acknowledgement, path, old_string/new_string, and operator level/apply mode.",
            ),
            indent=2,
        )


def hermes_owner_write_file(
    path: str,
    content: str,
    dry_run: bool = True,
) -> str:
    try:
        policy = op.OperatorPolicy()
        policy.require_owner(dry_run)
        if content is None:
            raise ValueError("content is required.")
        if op.is_denied_path(path):
            raise PermissionError(
                f"Path {path!r} is denied by the operator path safety policy "
                "(secret / credential / vault / token / .env). Owner Mode "
                "does not override this in the current release."
            )

        p = op._normalize_path(path)
        if policy.effective_dry_run(dry_run):
            plan = {
                "would_write": True,
                "path": str(p),
                "exists": p.exists(),
                "content_len": len(content),
                "owner_mode": True,
            }
            op.audit_record(
                tool="hermes_owner_write_file",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="dry-run plan",
                path=str(p),
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        backup = _backup_file(p) if p.exists() else None
        _atomic_write_text(p, content)
        result = {
            "success": True,
            "dry_run": False,
            "owner_mode": True,
            "path": str(p),
            "backup": str(backup) if backup else None,
        }
        op.audit_record(
            tool="hermes_owner_write_file",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary=f"owner wrote {p.name}",
            path=str(p),
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_owner_write_file",
            level="owner",
            apply_mode="unknown",
            dry_run=dry_run,
            success=False,
            error=str(exc),
            path=path,
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="owner",
                code="OWNER_WRITE_ERROR",
                suggested_action="Check owner acknowledgement, path, denied-path policy, and operator level/apply mode.",
            ),
            indent=2,
        )
