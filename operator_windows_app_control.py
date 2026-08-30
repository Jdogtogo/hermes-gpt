from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import operator_policy as op


_CLAUDE_RESTART_TEMPLATE = "hermes-claude-desktop-restart"
_POWERSHELL_CANDIDATES = (
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
    "powershell.exe",
)

# Fixed script: no caller-supplied process name, executable path, command, or arguments.
# It only restarts an already-running Claude.exe, reuses that exact path, and
# verifies that a different Claude PID is running afterward.
_CLAUDE_RESTART_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$before = @(Get-Process -Name 'Claude' -ErrorAction Stop)
if ($before.Count -lt 1) { throw 'Claude Desktop is not running.' }
$primary = $before | Where-Object { $_.Path -and ([IO.Path]::GetFileName($_.Path) -ieq 'Claude.exe') } | Select-Object -First 1
if (-not $primary) { throw 'Could not resolve the running Claude.exe path.' }
$exe = $primary.Path
if ([IO.Path]::GetFileName($exe) -ine 'Claude.exe') { throw 'Resolved executable is not Claude.exe.' }
$oldPids = @($before | Select-Object -ExpandProperty Id)
$before | Stop-Process -Force
$deadline = (Get-Date).AddSeconds(10)
do {
  Start-Sleep -Milliseconds 250
  $remaining = @(Get-Process -Name 'Claude' -ErrorAction SilentlyContinue | Where-Object { $oldPids -contains $_.Id })
} while ($remaining.Count -gt 0 -and (Get-Date) -lt $deadline)
if ($remaining.Count -gt 0) { throw 'Existing Claude process did not stop within 10 seconds.' }
$started = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds 2
$after = @(Get-Process -Name 'Claude' -ErrorAction SilentlyContinue)
$new = $after | Where-Object { $oldPids -notcontains $_.Id } | Select-Object -First 1
if (-not $new) { throw 'Claude Desktop did not restart with a new process.' }
[ordered]@{
  success = $true
  application = 'Claude Desktop'
  previous_pids = $oldPids
  new_pid = $new.Id
  executable = $exe
  verified_running = $true
} | ConvertTo-Json -Compress
""".strip()


def _powershell_binary() -> str | None:
    for candidate in _POWERSHELL_CANDIDATES:
        if candidate.startswith("/"):
            path = Path(candidate)
            if path.is_file():
                return str(path)
        else:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
    return None


def _restart_argv(powershell_binary: str) -> list[str]:
    return [powershell_binary, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _CLAUDE_RESTART_SCRIPT]


def hermes_claude_desktop_restart(dry_run: bool = True, *, runner=None, powershell_binary: str | None = None) -> str:
    """Restart only the already-running Windows Claude Desktop application."""
    try:
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        if policy.session_status != "active" or policy.session_id is None:
            state = policy.session_status or "unknown"
            raise PermissionError(f"Claude Desktop restart requires an active, approved Operator Session (current session state: {state!r}).")
        if policy.policy_template != _CLAUDE_RESTART_TEMPLATE:
            raise PermissionError(
                "Claude Desktop restart requires the "
                f"{_CLAUDE_RESTART_TEMPLATE!r} policy template (active session template: {policy.policy_template!r})."
            )
        policy.require_verb("applications", "restart")

        selected_powershell = powershell_binary or _powershell_binary()
        if not selected_powershell:
            raise RuntimeError("Windows PowerShell bridge is unavailable from this Hermes host.")
        argv = _restart_argv(selected_powershell)

        if policy.effective_dry_run(dry_run):
            plan: dict[str, Any] = {
                "would_restart": True,
                "application": "Claude Desktop",
                "process_name": "Claude",
                "requires_already_running_process": True,
                "reuses_resolved_executable_path": True,
                "verifies_new_pid": True,
                "caller_supplied_command_or_path": False,
                "shell": False,
            }
            op.audit_record(tool="hermes_claude_desktop_restart", level=policy.level, apply_mode=policy.apply_mode, dry_run=True, success=True, changed=False, summary="dry-run fixed Claude Desktop restart plan")
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        run_fn = runner or op.run_argv
        rc, stdout, stderr = run_fn(argv, timeout=30, workdir=None)
        parsed: dict[str, Any] = {}
        if rc == 0:
            try:
                parsed = json.loads((stdout or "").strip())
            except json.JSONDecodeError:
                rc = 1
                stderr = "Claude restart returned malformed verification evidence."
        success = rc == 0 and bool(parsed.get("verified_running")) and bool(parsed.get("new_pid"))
        result = {
            "success": success,
            "dry_run": False,
            "application": "Claude Desktop",
            "returncode": rc,
            "verified_running": bool(parsed.get("verified_running")) if parsed else False,
            "previous_pids": parsed.get("previous_pids", []) if parsed else [],
            "new_pid": parsed.get("new_pid") if parsed else None,
            "executable": op.redact_output(str(parsed.get("executable", ""))) if parsed else "",
            "stderr": op.redact_output(stderr) if not success else "",
        }
        op.audit_record(tool="hermes_claude_desktop_restart", level=policy.level, apply_mode=policy.apply_mode, dry_run=False, success=success, changed=success, summary=("Claude Desktop restarted and verified" if success else f"Claude Desktop restart failed rc={rc}"))
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(tool="hermes_claude_desktop_restart", level="unknown", apply_mode="unknown", dry_run=dry_run, success=False, error=str(exc))
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="windows_app_control",
                code="CLAUDE_DESKTOP_RESTART_ERROR",
                suggested_action="Use the dedicated approved Claude Desktop restart Operator Session, ensure Claude Desktop is already running, and verify the Windows bridge is available.",
            ),
            indent=2,
        )
