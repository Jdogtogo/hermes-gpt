"""Durable, workspace-confined Hermes task delegation for ChatGPT operator mode.

The delegation surface intentionally does not expose Hermes' unrestricted
terminal toolset. Apply tasks receive only Hermes' file and todo toolsets and
remain confined to the approved workspace through HERMES_FILE_READ_SAFE_ROOT.
Tests and commits remain separate, policy-gated operator actions.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import uuid
from typing import Any

import yaml

import operator_policy as op

HERMES_BIN = str(Path.home() / ".local" / "bin" / "hermes")
FILE_READ_SAFE_ROOT_ENV = "HERMES_FILE_READ_SAFE_ROOT"
MAX_PROMPT_BYTES = 65536
MAX_OUTPUT_CHARS = 20000
MAX_TIMEOUT_SECONDS = 3600
MAX_TURNS = 100
TERMINAL_STATES = frozenset({"completed", "failed", "cancelled"})
_TASKS_ROOT = Path(__file__).resolve().parent / "logs" / "delegated_tasks"
_LOCK = threading.RLock()
_PROCESSES: dict[str, subprocess.Popen[str]] = {}


def _now() -> int:
    return int(time.time())


def _task_path(task_id: str) -> Path:
    if not task_id.startswith("dt_") or not task_id[3:].replace("-", "").isalnum():
        raise ValueError("Invalid delegated task id.")
    return _TASKS_ROOT / f"{task_id}.json"


def _atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _load(task_id: str) -> dict[str, Any]:
    path = _task_path(task_id)
    if not path.is_file():
        raise FileNotFoundError(f"Delegated task not found: {task_id}")
    return json.loads(path.read_text(encoding="utf-8"))


def _save(task: dict[str, Any]) -> None:
    task["updated_at"] = _now()
    _atomic_write(_task_path(str(task["task_id"])), task)


def _prepare_runtime_home(task: dict[str, Any]) -> Path:
    """Create a writable, isolated Hermes home for one delegated process.

    The operator service runs with ``ProtectHome=read-only``. A child Hermes
    process therefore cannot write its normal ``~/.hermes/logs/agent.log``.
    Materialising only the selected profile's model configuration and a
    read-only ``.env`` link keeps logging/state inside the operator worktree
    while preserving the configured inference provider without loading the
    owner's plugins, MCP servers, memory, or unrelated profile state.
    """
    runtime_home = _TASKS_ROOT / "runtime" / str(task["task_id"])
    runtime_home.mkdir(parents=True, exist_ok=True)

    hermes_root = Path.home() / ".hermes"
    profile_home = op.resolve_profile_home(str(task.get("profile", "default")), hermes_root)
    config_path = profile_home / "config.yaml"
    if not config_path.is_file():
        raise FileNotFoundError(f"Hermes profile config not found: {config_path}")

    loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    model_config = loaded.get("model")
    if not isinstance(model_config, dict) or not model_config:
        raise ValueError(f"Hermes profile has no usable model configuration: {config_path}")

    # Keep the runtime profile deliberately minimal. Credentials remain in the
    # profile .env and are linked read-only below rather than copied into task
    # records or output.
    runtime_config = {
        "model": model_config,
        "display": {"interface": "cli"},
    }
    (runtime_home / "config.yaml").write_text(
        yaml.safe_dump(runtime_config, sort_keys=False), encoding="utf-8"
    )

    source_env = profile_home / ".env"
    runtime_env = runtime_home / ".env"
    if source_env.is_file():
        if runtime_env.exists() or runtime_env.is_symlink():
            runtime_env.unlink()
        runtime_env.symlink_to(source_env)
    return runtime_home


def _safe_text(value: str) -> str:
    redacted = op.redact_output(value or "")
    if len(redacted) <= MAX_OUTPUT_CHARS:
        return redacted
    return redacted[:MAX_OUTPUT_CHARS] + f"\n... [truncated {len(redacted)-MAX_OUTPUT_CHARS} chars]"


def _resolve_workdir(workdir: str) -> Path:
    candidate = Path(workdir).expanduser()
    if not candidate.is_absolute():
        raise ValueError("workdir must be an absolute path.")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise NotADirectoryError(str(resolved))
    return resolved


def _build_argv(*, prompt: str, mode: str, profile: str, workdir: Path, max_turns: int, allow_web: bool) -> list[str]:
    # The selected profile is materialised into a task-specific HERMES_HOME by
    # _prepare_runtime_home(). Passing --profile here would make Hermes append a
    # second profiles/<name> layer beneath that isolated runtime directory.
    argv = [HERMES_BIN]
    argv.extend(["chat", "-Q", "--source", "tool", "--max-turns", str(max_turns)])
    if mode == "apply":
        toolsets = ["file", "todo"]
        prefix = (
            "Execute the task only inside the supplied working directory. "
            "You may edit files with the file tool, but terminal, shell, service, "
            "network, skill, credential, and git operations are unavailable. "
            "Do not claim tests or commits were run. Report files changed and "
            "the exact verification still required by the controller."
        )
    else:
        toolsets = ["file_read_only"]
        prefix = (
            "Inspect only inside the supplied working directory. Do not modify "
            "files, configuration, services, external systems, or persistent state."
        )
        if allow_web:
            toolsets.append("web")
    argv.extend(["-t", ",".join(toolsets)])
    effective = f"{prefix}\n\nAllowed working directory: {workdir}\n\nTask:\n{prompt}"
    argv.extend(["-q", effective])
    return argv


def _audit(task: dict[str, Any], *, success: bool, summary: str, error: str = "") -> None:
    op.audit_record(
        tool="hermes_delegate_task",
        level=str(task.get("authority", {}).get("level", "read_only")),
        apply_mode=str(task.get("authority", {}).get("apply_mode", "unknown")),
        dry_run=False,
        success=success,
        changed=task.get("mode") == "apply" and success,
        summary=summary,
        error=error,
        profile=str(task.get("profile", "default")),
        prompt=None,
        extra={
            "task_id": task.get("task_id"),
            "status": task.get("status"),
            "mode": task.get("mode"),
            "workdir": task.get("workdir"),
            "session_id": task.get("authority", {}).get("session_id"),
            "prompt_sha256": task.get("prompt_sha256"),
        },
    )


def _worker(task_id: str) -> None:
    with _LOCK:
        task = _load(task_id)
        if task["status"] == "cancel_requested":
            task["status"] = "cancelled"
            task["finished_at"] = _now()
            _save(task)
            return
        task["status"] = "running"
        task["started_at"] = _now()
        _save(task)

    env = os.environ.copy()
    env[FILE_READ_SAFE_ROOT_ENV] = task["workdir"]
    runtime_home: Path | None = None
    try:
        runtime_home = _prepare_runtime_home(task)
        env["HERMES_HOME"] = str(runtime_home)
        process = subprocess.Popen(
            task["argv"],
            cwd=task["workdir"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        with _LOCK:
            _PROCESSES[task_id] = process
            task = _load(task_id)
            task["pid"] = process.pid
            _save(task)
        try:
            stdout, stderr = process.communicate(timeout=int(task["timeout"]))
            rc = int(process.returncode or 0)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            rc = 124
        with _LOCK:
            task = _load(task_id)
            cancelled = task["status"] == "cancel_requested"
            task["returncode"] = rc
            task["stdout"] = _safe_text(stdout)
            task["stderr"] = _safe_text(stderr)
            task["finished_at"] = _now()
            task["pid"] = None
            if cancelled:
                task["status"] = "cancelled"
            elif rc == 0:
                task["status"] = "completed"
            else:
                task["status"] = "failed"
            _save(task)
            _audit(task, success=task["status"] == "completed", summary=f"delegated task {task['status']} rc={rc}", error=task["stderr"][:500] if rc else "")
    except Exception as exc:
        with _LOCK:
            task = _load(task_id)
            task["status"] = "failed"
            task["finished_at"] = _now()
            task["pid"] = None
            task["stderr"] = _safe_text(str(exc))
            _save(task)
            _audit(task, success=False, summary="delegated task launch failed", error=str(exc))
    finally:
        if runtime_home is not None:
            runtime_env = runtime_home / ".env"
            try:
                if runtime_env.is_symlink():
                    runtime_env.unlink()
            except OSError:
                pass
        with _LOCK:
            _PROCESSES.pop(task_id, None)


def hermes_delegate_task(
    prompt: str,
    workdir: str,
    mode: str = "apply",
    profile: str = "default",
    max_turns: int = 30,
    timeout: int = 1800,
    allow_web: bool = False,
) -> str:
    """Queue a durable Hermes task and return immediately with its task id."""
    try:
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt is required.")
        encoded = prompt.encode("utf-8")
        if len(encoded) > MAX_PROMPT_BYTES:
            raise ValueError(f"prompt exceeds {MAX_PROMPT_BYTES} bytes.")
        normalized_mode = str(mode).strip().lower()
        if normalized_mode not in {"plan", "read_only", "apply"}:
            raise ValueError("mode must be plan, read_only, or apply.")
        turns = int(max_turns)
        seconds = int(timeout)
        if not 1 <= turns <= MAX_TURNS:
            raise ValueError(f"max_turns must be between 1 and {MAX_TURNS}.")
        if not 1 <= seconds <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds.")
        if normalized_mode == "apply" and allow_web:
            raise PermissionError("allow_web is disabled for apply delegation.")

        policy = op.OperatorPolicy()
        policy.require_enabled()
        canonical_profile = op.validate_profile_name(profile)
        policy.require_profile(canonical_profile, Path.home() / ".hermes")
        resolved = _resolve_workdir(workdir)
        policy.require_read_path(resolved)
        if normalized_mode == "apply":
            policy.require_level("workspace")
            policy.require_mutation(dry_run=False)
            policy.require_write_path(resolved)
            policy.require_verb("filesystem", "edit")

        task_id = "dt_" + uuid.uuid4().hex
        argv = _build_argv(prompt=prompt, mode=normalized_mode, profile=canonical_profile, workdir=resolved, max_turns=turns, allow_web=bool(allow_web))
        task: dict[str, Any] = {
            "task_id": task_id,
            "status": "queued",
            "mode": normalized_mode,
            "profile": canonical_profile,
            "workdir": str(resolved),
            "max_turns": turns,
            "timeout": seconds,
            "allow_web": bool(allow_web),
            "prompt_sha256": hashlib.sha256(encoded).hexdigest(),
            "prompt_bytes": len(encoded),
            "argv": argv,
            "created_at": _now(),
            "updated_at": _now(),
            "started_at": None,
            "finished_at": None,
            "pid": None,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "messages": [],
            "authority": {
                "session_id": policy.session_id,
                "snapshot_hash": policy.snapshot_hash,
                "expires_at": policy.expires_at,
                "level": policy.level,
                "apply_mode": policy.apply_mode,
            },
        }
        with _LOCK:
            _save(task)
        thread = threading.Thread(target=_worker, args=(task_id,), daemon=True, name=f"hermes-delegate-{task_id[-8:]}")
        thread.start()
        _audit(task, success=True, summary="delegated task queued")
        return json.dumps({"success": True, "task_id": task_id, "status": "queued", "mode": normalized_mode, "workdir": str(resolved)}, indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATE_TASK_ERROR", suggested_action="Use an approved workspace, active Operator Session, allowed profile, and bounded task settings."), indent=2)


def hermes_delegated_task_status(task_id: str) -> str:
    try:
        with _LOCK:
            task = _load(task_id)
        keys = ("task_id", "status", "mode", "profile", "workdir", "created_at", "updated_at", "started_at", "finished_at", "pid", "returncode", "prompt_sha256", "authority")
        return json.dumps({"success": True, **{key: task.get(key) for key in keys}}, indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATED_TASK_STATUS_ERROR", suggested_action="Check the delegated task id."), indent=2)


def hermes_delegated_task_result(task_id: str) -> str:
    try:
        with _LOCK:
            task = _load(task_id)
        if task["status"] not in TERMINAL_STATES:
            return json.dumps({"success": True, "task_id": task_id, "status": task["status"], "ready": False}, indent=2)
        return json.dumps({"success": task["status"] == "completed", "task_id": task_id, "status": task["status"], "ready": True, "returncode": task["returncode"], "stdout": task["stdout"], "stderr": task["stderr"], "messages": task["messages"]}, indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATED_TASK_RESULT_ERROR", suggested_action="Check the delegated task id."), indent=2)


def hermes_delegated_task_message(task_id: str, message: str) -> str:
    """Attach durable operator guidance for review or a later continuation."""
    try:
        if not isinstance(message, str) or not message.strip():
            raise ValueError("message is required.")
        if len(message.encode("utf-8")) > 8192:
            raise ValueError("message exceeds 8192 bytes.")
        with _LOCK:
            task = _load(task_id)
            task["messages"].append({"created_at": _now(), "message": message.strip()})
            _save(task)
        return json.dumps({"success": True, "task_id": task_id, "status": task["status"], "message_count": len(task["messages"]), "note": "Message recorded durably. Running one-shot Hermes processes cannot consume it until a continuation task is submitted."}, indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATED_TASK_MESSAGE_ERROR", suggested_action="Check the task id and message size."), indent=2)


def hermes_delegated_task_cancel(task_id: str) -> str:
    try:
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        policy.require_mutation(dry_run=False)
        with _LOCK:
            task = _load(task_id)
            if task["status"] in TERMINAL_STATES:
                return json.dumps({"success": True, "task_id": task_id, "status": task["status"], "changed": False}, indent=2)
            task["status"] = "cancel_requested"
            _save(task)
            process = _PROCESSES.get(task_id)
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        return json.dumps({"success": True, "task_id": task_id, "status": "cancel_requested", "changed": True}, indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATED_TASK_CANCEL_ERROR", suggested_action="Use an active workspace Operator Session and check the task id."), indent=2)
