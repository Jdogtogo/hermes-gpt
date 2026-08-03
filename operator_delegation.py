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
import sqlite3
import subprocess
import threading
import time
import uuid
from typing import Any

import yaml

import operator_policy as op
import operator_antigravity as op_antigravity
import operator_antigravity_tax as op_antigravity_tax

HERMES_BIN = str(Path.home() / ".local" / "bin" / "hermes")
FILE_READ_SAFE_ROOT_ENV = "HERMES_FILE_READ_SAFE_ROOT"
MAX_PROMPT_BYTES = 65536
MAX_OUTPUT_CHARS = 20000
MAX_TIMEOUT_SECONDS = 3600
MAX_TOTAL_TASK_WINDOW_SECONDS = 28800
MAX_CONTINUATIONS = 8
MAX_TURNS = 100
AUTHORITY_POLL_SECONDS = 2
TASK_SCHEMA_VERSION = 3
LONG_HORIZON_STOP_CONDITIONS = frozenset({
    "completion",
    "material_scope_change",
    "unsafe_action",
    "repeated_failure",
    "authority_expiry",
})
SLICE_STATUS_PREFIX = "HERMES_SLICE_STATUS:"
FINAL_ANSWER_BEGIN = "---BEGIN_HERMES_FINAL_ANSWER---"
FINAL_ANSWER_END = "---END_HERMES_FINAL_ANSWER---"
ADAPTER_NAME = "hermes-profile-delegation"
TERMINAL_STATES = frozenset({"completed", "incomplete", "failed", "timed_out", "cancelled", "blocked"})
RESUMABLE_STATES = frozenset({"incomplete", "failed", "timed_out", "blocked"})
NON_TERMINAL_STATES = frozenset({"queued", "starting", "running", "checkpointed", "awaiting_continuation", "resuming", "cancel_requested"})
LEGAL_TRANSITIONS = {
    "queued": {"starting", "cancel_requested", "cancelled", "blocked"},
    "starting": {"running", "failed", "blocked", "cancelled"},
    "running": {"checkpointed", "completed", "incomplete", "failed", "timed_out", "blocked", "cancel_requested", "cancelled"},
    "checkpointed": {"running", "awaiting_continuation", "completed", "incomplete", "failed", "timed_out", "blocked", "cancel_requested", "cancelled"},
    "awaiting_continuation": {"resuming", "cancelled", "blocked"},
    "resuming": {"running", "failed", "blocked", "cancelled"},
    "cancel_requested": {"cancelled"},
}
_TASKS_ROOT = Path(__file__).resolve().parent / "logs" / "delegated_tasks"
MISSION_CONTROL_DB_ENV = "HERMES_GPT_DELEGATION_MISSION_CONTROL_DB"
_LOCK = threading.RLock()
_PROCESSES: dict[str, subprocess.Popen[str]] = {}

ANTIGRAVITY_REVIEW_PROFILE = "antigravity-operator"
ANTIGRAVITY_REVIEW_MARKERS = (
    "operator-regression-independent-review",
    "supervised-host-agy",
    op_antigravity.TARGET_COMMIT,
    str(op_antigravity.PACKET_PATH),
)
ANTIGRAVITY_TAX_REVIEW_MARKERS = (
    "Independent Projections Calculator completion review",
    "Projections Calculator",
    "Tax Calculator",
    *op_antigravity_tax.TARGET_COMMITS,
)


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


def _transition(task: dict[str, Any], new_status: str, *, reason: str | None = None) -> None:
    old_status = str(task.get("status") or "")
    if old_status and old_status != new_status:
        allowed = LEGAL_TRANSITIONS.get(old_status, set())
        if old_status in TERMINAL_STATES:
            raise ValueError(f"Cannot transition terminal delegated task from {old_status!r} to {new_status!r}.")
        if new_status not in allowed and new_status not in TERMINAL_STATES:
            raise ValueError(f"Illegal delegated task transition {old_status!r} -> {new_status!r}.")
    task["status"] = new_status
    task.setdefault("events", []).append(
        {
            "at": _now(),
            "from": old_status or None,
            "to": new_status,
            "reason": reason or "",
        }
    )


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


def _legacy_token_candidate(value: str) -> bool:
    """Return true only for a narrow machine-token shaped legacy answer."""
    candidate = value.strip()
    if not candidate or len(candidate) > 256 or not candidate[0].isalnum():
        return False
    allowed_punctuation = "_.:-"
    return any("A" <= char <= "Z" for char in candidate) and all(
        ("A" <= char <= "Z") or char.isdigit() or char in allowed_punctuation
        for char in candidate
    )


def _final_answer_noise_line(value: str) -> bool:
    stripped = value.strip()
    lowered = stripped.lower()
    if not stripped:
        return True
    if stripped.upper().startswith(SLICE_STATUS_PREFIX):
        return True
    if lowered.startswith("session_id:"):
        return True
    if "tirith security scanner" in lowered:
        return True
    if stripped.startswith("⚠"):
        return True
    if "reasoning" in lowered and any(char in stripped for char in "┌─┐"):
        return True
    if lowered.startswith("... [truncated"):
        return True
    return False


def _extract_final_answer(stdout: str, stderr: str = "") -> tuple[str | None, str]:
    """Extract a caller-facing answer while retaining raw output separately.

    New workers are instructed to wrap their final response in deterministic
    delimiters. Legacy output receives only a narrow fallback: a machine-token
    shaped terminal line, or a single non-diagnostic line. Ambiguous transcripts
    fail closed instead of presenting reasoning or diagnostics as a final answer.
    """
    streams = (stdout or "", stderr or "")
    saw_structured_marker = False
    for stream in streams:
        if FINAL_ANSWER_BEGIN in stream or FINAL_ANSWER_END in stream:
            saw_structured_marker = True
        end_index = stream.rfind(FINAL_ANSWER_END)
        if end_index < 0:
            continue
        start_index = stream.rfind(FINAL_ANSWER_BEGIN, 0, end_index)
        if start_index < 0:
            continue
        answer = stream[start_index + len(FINAL_ANSWER_BEGIN):end_index].strip()
        if not answer:
            return None, "structured_empty"
        return _safe_text(answer), "structured_delimiters"

    if saw_structured_marker:
        return None, "structured_incomplete"

    meaningful = [
        line.strip()
        for line in (stdout or "").splitlines()
        if not _final_answer_noise_line(line)
    ]
    if not meaningful:
        return None, "not_found"

    candidate = meaningful[-1]
    if _legacy_token_candidate(candidate):
        return _safe_text(candidate), "legacy_terminal_token"
    if len(meaningful) == 1:
        return _safe_text(candidate), "legacy_single_line"
    return None, "unstructured_ambiguous"


def _workspace_snapshot(root: Path) -> dict[str, tuple[int, int]]:
    """Return bounded file metadata used to prove apply-task changes."""
    snapshot: dict[str, tuple[int, int]] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in {".git", "logs"}:
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        snapshot[str(rel)] = (int(stat.st_size), int(stat.st_mtime_ns))
        if len(snapshot) >= 10000:
            break
    return snapshot


def _changed_files(before: dict[str, tuple[int, int]], after: dict[str, tuple[int, int]]) -> list[str]:
    return sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))


def _git_context(workdir: Path) -> dict[str, str | None]:
    context = {"root": None, "branch": None, "baseline": None}
    commands = {
        "root": ["git", "-C", str(workdir), "rev-parse", "--show-toplevel"],
        "branch": ["git", "-C", str(workdir), "branch", "--show-current"],
        "baseline": ["git", "-C", str(workdir), "rev-parse", "HEAD"],
    }
    for key, argv in commands.items():
        try:
            result = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            continue
        if result.returncode == 0:
            value = result.stdout.strip()
            context[key] = value or None
    return context


def _prompt_fingerprint(prompt: str) -> str:
    normalized = " ".join(str(prompt).split())
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()


def _normalize_long_horizon(
    *,
    timeout: int | None,
    worker_slice_timeout: int | None,
    total_task_window: int | None,
    maximum_continuations: int,
    resume_from_checkpoint: bool,
    stop_on: list[str] | None,
    authority_expires_at: int | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    """Validate and materialise the bounded parent task envelope."""
    alias_seconds = int(1800 if timeout is None else timeout)
    if worker_slice_timeout is None:
        slice_seconds = alias_seconds
    else:
        slice_seconds = int(worker_slice_timeout)
        if timeout not in (None, 1800, slice_seconds):
            raise ValueError("timeout conflicts with worker_slice_timeout.")
    if not 1 <= slice_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"worker_slice_timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds."
        )

    total_seconds = slice_seconds if total_task_window is None else int(total_task_window)
    if not 1 <= total_seconds <= MAX_TOTAL_TASK_WINDOW_SECONDS:
        raise ValueError(
            f"total_task_window must be between 1 and {MAX_TOTAL_TASK_WINDOW_SECONDS} seconds."
        )
    if total_seconds < slice_seconds:
        raise ValueError("total_task_window cannot be shorter than worker_slice_timeout.")

    continuations = int(maximum_continuations)
    if not 0 <= continuations <= MAX_CONTINUATIONS:
        raise ValueError(f"maximum_continuations must be between 0 and {MAX_CONTINUATIONS}.")
    if not isinstance(resume_from_checkpoint, bool):
        raise ValueError("resume_from_checkpoint must be a boolean.")

    supplied_stop = [] if stop_on is None else [str(value).strip() for value in stop_on]
    stop_set = {value for value in supplied_stop if value}
    unknown = stop_set - LONG_HORIZON_STOP_CONDITIONS
    if unknown:
        raise ValueError(f"Unknown stop_on condition(s): {', '.join(sorted(unknown))}.")

    automatic = bool(resume_from_checkpoint or continuations or total_seconds > slice_seconds)
    if automatic:
        if not resume_from_checkpoint:
            raise ValueError("resume_from_checkpoint must be true for automatic long-horizon delegation.")
        if continuations < 1:
            raise ValueError("maximum_continuations must be at least 1 for automatic long-horizon delegation.")
        if stop_set != LONG_HORIZON_STOP_CONDITIONS:
            missing = LONG_HORIZON_STOP_CONDITIONS - stop_set
            raise ValueError(
                "Automatic long-horizon delegation requires all governed stop_on conditions"
                + (f": {', '.join(sorted(missing))}." if missing else ".")
            )

    started_at = int(_now() if now is None else now)
    deadline = started_at + total_seconds
    if authority_expires_at is not None and deadline > int(authority_expires_at):
        raise PermissionError("total_task_window exceeds the active Operator Session authority expiry.")

    return {
        "enabled": automatic,
        "total_task_window": total_seconds,
        "worker_slice_timeout": slice_seconds,
        "maximum_continuations": continuations,
        "resume_from_checkpoint": resume_from_checkpoint,
        "stop_on": sorted(stop_set),
        "envelope_started_at": started_at,
        "envelope_deadline": deadline,
        "root_task_id": None,
        "continuation_count": 0,
        "consecutive_failure_count": 0,
        "previous_failure_signature": None,
        "latest_task_id": None,
        "final_stop_reason": None,
    }


def _slice_control_status(stdout: str, stderr: str = "") -> str | None:
    for line in reversed(f"{stdout}\n{stderr}".splitlines()):
        stripped = line.strip()
        if stripped.upper().startswith(SLICE_STATUS_PREFIX):
            return stripped.split(":", 1)[1].strip().upper()
    return None


def _latest_task_for(task: dict[str, Any]) -> dict[str, Any]:
    logical_work_id = task.get("logical_work_id")
    if not logical_work_id:
        return task
    matches = [candidate for candidate in _iter_tasks() if candidate.get("logical_work_id") == logical_work_id]
    if not matches:
        return task
    return max(
        matches,
        key=lambda candidate: (
            int(candidate.get("continuation_sequence") or 0),
            int(candidate.get("created_at") or 0),
        ),
    )


def _chain_cancelled(task: dict[str, Any]) -> bool:
    logical_work_id = task.get("logical_work_id")
    if not logical_work_id:
        return bool(task.get("chain_cancelled"))
    return any(
        bool(candidate.get("chain_cancelled"))
        for candidate in _iter_tasks()
        if candidate.get("logical_work_id") == logical_work_id
    )


def _failure_signature(task: dict[str, Any]) -> str:
    payload = {
        "status": task.get("status"),
        "failure_category": task.get("failure_category"),
        "provider_error_category": task.get("provider_error_category"),
        "outcome_reason": task.get("outcome_reason"),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _antigravity_route(
    *,
    profile: str,
    workdir: Path,
    prompt: str,
) -> str | None:
    if profile != ANTIGRAVITY_REVIEW_PROFILE:
        return None
    resolved = workdir.resolve(strict=False)
    if (
        resolved == op_antigravity.CANONICAL_WORKTREE
        and any(marker in prompt for marker in ANTIGRAVITY_REVIEW_MARKERS)
    ):
        return "operator_regression"
    if (
        resolved == op_antigravity_tax.TAX_CALCULATOR_ROOT
        and all(commit in prompt for commit in op_antigravity_tax.TARGET_COMMITS)
        and any(marker in prompt for marker in ANTIGRAVITY_TAX_REVIEW_MARKERS[:3])
    ):
        return "tax_calculator"
    return None


def _is_fixed_antigravity_review_request(
    *,
    profile: str,
    workdir: Path,
    prompt: str,
) -> bool:
    return _antigravity_route(profile=profile, workdir=workdir, prompt=prompt) == "operator_regression"


def _logical_work_id(
    *,
    prompt: str,
    profile: str,
    mode: str,
    workdir: Path,
    execution_contract: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    git = _git_context(workdir)
    fingerprint = {
        "profile": profile,
        "mode": mode,
        "workdir": str(workdir),
        "prompt_sha256": _prompt_fingerprint(prompt),
        "git_root": git.get("root"),
        "git_branch": git.get("branch"),
        "git_baseline": git.get("baseline"),
        "execution_contract": execution_contract or {},
    }
    encoded = json.dumps(fingerprint, sort_keys=True, separators=(",", ":"))
    return "lw_" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:32], fingerprint


def _iter_tasks() -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    if not _TASKS_ROOT.exists():
        return tasks
    for path in _TASKS_ROOT.glob("dt_*.json"):
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(loaded, dict):
            tasks.append(loaded)
    return tasks


def _find_existing_logical_work(logical_work_id: str) -> dict[str, Any] | None:
    matches = [
        task for task in _iter_tasks()
        if task.get("logical_work_id") == logical_work_id
    ]
    if not matches:
        return None
    return sorted(matches, key=lambda task: int(task.get("created_at") or 0), reverse=True)[0]


def _checkpoint_path(task: dict[str, Any], checkpoint_id: str) -> Path:
    logical_work_id = str(task.get("logical_work_id") or "unknown")
    return _TASKS_ROOT / "checkpoints" / logical_work_id / f"{checkpoint_id}.json"


def _write_checkpoint(task: dict[str, Any], *, reason: str) -> str:
    sequence = int(task.get("checkpoint_sequence") or 0) + 1
    checkpoint_id = "cp_" + hashlib.sha256(
        f"{task.get('logical_work_id')}:{task.get('task_id')}:{sequence}:{task.get('status')}:{_now()}".encode("utf-8")
    ).hexdigest()[:20]
    payload = {
        "schema_version": TASK_SCHEMA_VERSION,
        "checkpoint_id": checkpoint_id,
        "logical_work_id": task.get("logical_work_id"),
        "task_id": task.get("task_id"),
        "attempt_id": task.get("attempt_id"),
        "interaction_id": task.get("interaction_id"),
        "continuation_sequence": task.get("continuation_sequence", 0),
        "root_task_id": task.get("root_task_id") or task.get("task_id"),
        "long_horizon": task.get("long_horizon", {}),
        "state": task.get("status"),
        "reason": reason,
        "profile": task.get("profile"),
        "adapter": task.get("adapter"),
        "model": task.get("model"),
        "workdir": task.get("workdir"),
        "git": task.get("git"),
        "changed_files": task.get("changed_files", []),
        "returncode": task.get("returncode"),
        "outcome_reason": task.get("outcome_reason", ""),
        "failure_category": task.get("failure_category"),
        "provider_error_category": task.get("provider_error_category"),
        "retry_count": task.get("retry_count", 0),
        "created_at": _now(),
        "updated_at": task.get("updated_at"),
        "safe_stdout_excerpt": str(task.get("stdout") or "")[-2000:],
        "safe_stderr_excerpt": str(task.get("stderr") or "")[-2000:],
        "resume_instructions": (
            "Use hermes_delegated_task_continue with unchanged scope and active authority. "
            "Reconcile repository state before continuing; do not replay completed changes."
        ),
    }
    path = _checkpoint_path(task, checkpoint_id)
    _atomic_write(path, payload)
    task["checkpoint_sequence"] = sequence
    task["checkpoint_ref"] = str(path)
    return str(path)


def _mission_control_db_path() -> Path | None:
    configured = os.environ.get(MISSION_CONTROL_DB_ENV)
    if configured:
        path = Path(configured).expanduser()
        return path if path.is_file() else None
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    path = Path.home() / ".hermes" / "kanban.db"
    return path if path.is_file() else None


def _mission_status(task_status: str) -> str:
    if task_status == "completed":
        return "Completed"
    if task_status == "cancelled":
        return "Cancelled"
    if task_status in TERMINAL_STATES:
        return "On Hold"
    return "In Progress"


def _record_mission_control(task: dict[str, Any], *, event: str) -> None:
    db_path = _mission_control_db_path()
    if db_path is None:
        return
    try:
        now = _now()
        logical_work_id = str(task.get("logical_work_id") or task.get("task_id"))
        title = f"Delegated Hermes task {logical_work_id}"
        result = json.dumps(
            {
                "task_id": task.get("task_id"),
                "status": task.get("status"),
                "profile": task.get("profile"),
                "checkpoint_ref": task.get("checkpoint_ref"),
                "outcome_reason": task.get("outcome_reason", ""),
            },
            sort_keys=True,
        )
        with sqlite3.connect(db_path, timeout=10) as connection:
            connection.execute(
                """
                INSERT INTO tasks(id, title, body, assignee, status, priority, created_by,
                                  created_at, workspace_kind, workspace_path, result,
                                  idempotency_key, session_id)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?, 'delegated', ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    assignee=excluded.assignee,
                    status=excluded.status,
                    workspace_path=excluded.workspace_path,
                    result=excluded.result,
                    idempotency_key=excluded.idempotency_key,
                    session_id=excluded.session_id
                """,
                (
                    logical_work_id,
                    title,
                    "Hermes delegated execution worker record. Prompt content is intentionally not stored.",
                    task.get("profile"),
                    _mission_status(str(task.get("status") or "")),
                    ADAPTER_NAME,
                    now,
                    task.get("workdir"),
                    result,
                    logical_work_id,
                    task.get("authority", {}).get("session_id"),
                ),
            )
            connection.execute(
                "INSERT INTO task_events(task_id, run_id, kind, payload, created_at) VALUES (?, NULL, ?, ?, ?)",
                (
                    logical_work_id,
                    f"delegated_task.{event}",
                    json.dumps(
                        {
                            "task_id": task.get("task_id"),
                            "attempt_id": task.get("attempt_id"),
                            "interaction_id": task.get("interaction_id"),
                            "status": task.get("status"),
                            "checkpoint_ref": task.get("checkpoint_ref"),
                        },
                        sort_keys=True,
                    ),
                    now,
                ),
            )
    except Exception:
        return


def _classify_failure(*, rc: int, stdout: str, stderr: str, status: str, reason: str) -> tuple[str | None, str | None]:
    combined = f"{stdout}\n{stderr}".lower()
    if status == "timed_out":
        return "timeout", None
    if status == "blocked":
        return "permission", None
    if "provider resolver returned an empty api key" in combined:
        return "provider_configuration", "missing_api_key"
    if "model returned empty content" in combined or "empty-response" in reason:
        return "model_failure", "empty_response"
    if "fallback" in combined:
        return "model_failure", "fallback_response"
    if rc != 0:
        return "process_failure", None
    if status == "incomplete":
        return "evidence_failure", None
    return None, None


def _assess_outcome(*, task: dict[str, Any], rc: int, stdout: str, stderr: str, changed_files: list[str]) -> tuple[str, str]:
    """Classify substantive completion instead of trusting process exit alone."""
    if rc == 124:
        return "timed_out", "delegated attempt exceeded its bounded execution timeout"
    long_horizon = task.get("long_horizon") or {}
    if long_horizon.get("enabled"):
        control = _slice_control_status(stdout, stderr)
        if control == "COMPLETE":
            return "completed", "long-horizon worker declared the logical task complete"
        if control == "CONTINUE":
            return "incomplete", "long-horizon worker requested continuation from checkpoint"
        if control == "BLOCKED_MATERIAL_SCOPE_CHANGE":
            long_horizon["final_stop_reason"] = "material_scope_change"
            task["long_horizon"] = long_horizon
            return "blocked", "worker detected a material scope change requiring renewed approval"
        if control == "BLOCKED_UNSAFE_ACTION":
            long_horizon["final_stop_reason"] = "unsafe_action"
            task["long_horizon"] = long_horizon
            return "blocked", "worker detected an unsafe action and stopped"
        if control == "FAILED":
            return "failed", "long-horizon worker declared the slice failed"
        if control is not None:
            return "failed", f"unrecognised long-horizon slice control status: {control}"
    if rc != 0:
        return "failed", f"process exited with return code {rc}"
    combined = f"{stdout}\n{stderr}".strip()
    lowered = combined.lower()
    if not combined:
        return "incomplete", "process exited cleanly but produced no output"
    incomplete_markers = (
        "no reply: the model returned empty content",
        "model returned empty content",
        "try `continue`, switch model/provider",
    )
    if any(marker in lowered for marker in incomplete_markers):
        return "incomplete", "model produced an explicit empty-response/fallback failure"
    if task.get("mode") == "apply" and not changed_files:
        return "incomplete", "apply task produced no workspace changes"
    return "completed", "substantive output and required workspace evidence were produced"


def _capture_authority_envelope(
    policy: op.OperatorPolicy,
    *,
    profile: str,
    workdir: Path,
    mode: str,
    allow_web: bool,
    max_turns: int,
    timeout: int,
) -> dict[str, Any]:
    """Capture the immutable, non-secret authority contract for one task."""
    return {
        "session_id": policy.session_id,
        "snapshot_hash": policy.snapshot_hash,
        "expires_at": policy.expires_at,
        "level": policy.level,
        "apply_mode": policy.apply_mode,
        "readable_roots": [str(path) for path in policy.readable_roots],
        "writable_roots": [str(path) for path in policy.writable_roots],
        "verbs": {key: list(value) for key, value in policy.verbs.items()},
        "allowed_profiles": list(policy.allowed_profiles),
        "profile": profile,
        "workdir": str(workdir),
        "mode": mode,
        "allow_web": bool(allow_web),
        "max_turns": int(max_turns),
        "timeout": int(timeout),
        "evidence_required": mode == "apply",
        "evidence": ["changed_files", "substantive_output"] if mode == "apply" else ["substantive_output"],
    }


def _require_task_authority(task: dict[str, Any]) -> None:
    """Fail closed when current authority no longer matches the task envelope."""
    authority = task.get("authority") or {}
    policy = op.OperatorPolicy()
    policy.require_enabled()
    if policy.session_id != authority.get("session_id"):
        raise PermissionError("originating Operator Session is no longer active")
    if policy.snapshot_hash != authority.get("snapshot_hash"):
        raise PermissionError("Operator Session authority snapshot changed")
    expires_at = int(authority.get("expires_at") or 0)
    if not expires_at or _now() >= expires_at:
        raise PermissionError("originating Operator Session expired")
    profile = str(authority.get("profile") or task.get("profile") or "default")
    workdir = _resolve_workdir(str(authority.get("workdir") or task.get("workdir") or ""))
    mode = str(authority.get("mode") or task.get("mode") or "read_only")
    policy.require_profile(profile, Path.home() / ".hermes")
    policy.require_read_path(workdir)
    if mode == "apply":
        policy.require_level("workspace")
        policy.require_mutation(dry_run=False)
        policy.require_write_path(workdir)
        policy.require_verb("filesystem", "edit")


def _resolve_workdir(workdir: str) -> Path:
    candidate = Path(workdir).expanduser()
    if not candidate.is_absolute():
        raise ValueError("workdir must be an absolute path.")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise NotADirectoryError(str(resolved))
    return resolved


def _build_argv(
    *,
    prompt: str,
    mode: str,
    profile: str,
    workdir: Path,
    max_turns: int,
    allow_web: bool,
    long_horizon: dict[str, Any] | None = None,
) -> list[str]:
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
    prefix += (
        "\nPlace only the final response intended for the caller between these exact delimiter lines:\n"
        f"{FINAL_ANSWER_BEGIN}\n"
        "<final response>\n"
        f"{FINAL_ANSWER_END}\n"
        "Keep reasoning, diagnostics, warnings, tool transcripts, and control lines outside the delimiters. "
        "Always emit both delimiters, even when the final response is one line."
    )
    if long_horizon and long_horizon.get("enabled"):
        prefix += (
            "\nThis is one bounded slice of a durable long-horizon task. Reconcile the latest "
            "checkpoint and current repository state before acting. Never replay completed work "
            "or expand the approved scope. End the response with exactly one control line: "
            "HERMES_SLICE_STATUS: COMPLETE, CONTINUE, BLOCKED_MATERIAL_SCOPE_CHANGE, "
            "BLOCKED_UNSAFE_ACTION, or FAILED. Use CONTINUE only when useful in-scope work remains."
        )
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


def _record_long_horizon_stop(task: dict[str, Any], reason: str) -> None:
    long_horizon = dict(task.get("long_horizon") or {})
    if not long_horizon.get("enabled"):
        return
    long_horizon["final_stop_reason"] = reason
    long_horizon["latest_task_id"] = task.get("task_id")
    task["long_horizon"] = long_horizon
    _save(task)
    _record_mission_control(task, event="final_stop")


def _schedule_automatic_continuation(task_id: str) -> None:
    """Continue one logical task without exceeding its authority or hard envelope."""
    with _LOCK:
        task = _load(task_id)
        long_horizon = dict(task.get("long_horizon") or {})
        if not long_horizon.get("enabled") or not long_horizon.get("resume_from_checkpoint"):
            return
        long_horizon["latest_task_id"] = task_id
        task["long_horizon"] = long_horizon

        if _chain_cancelled(task) or task.get("status") == "cancelled":
            _record_long_horizon_stop(task, "cancelled")
            return
        if long_horizon.get("final_stop_reason"):
            _record_long_horizon_stop(task, str(long_horizon["final_stop_reason"]))
            return
        if task.get("status") == "completed":
            _record_long_horizon_stop(task, "completion")
            return
        if task.get("status") == "blocked":
            reason = "authority_expiry" if task.get("failure_category") == "permission" else "blocked"
            _record_long_horizon_stop(task, reason)
            return

        now = _now()
        deadline = int(long_horizon.get("envelope_deadline") or 0)
        if not deadline or now >= deadline:
            _record_long_horizon_stop(task, "envelope_deadline")
            return
        continuation_count = int(long_horizon.get("continuation_count") or 0)
        maximum = int(long_horizon.get("maximum_continuations") or 0)
        if continuation_count >= maximum:
            _record_long_horizon_stop(task, "continuation_limit")
            return
        if task.get("status") not in RESUMABLE_STATES:
            _record_long_horizon_stop(task, "terminal_failure")
            return

        explicit_continue = "requested continuation from checkpoint" in str(task.get("outcome_reason") or "")
        progress_made = bool(task.get("changed_files")) or explicit_continue or (
            task.get("status") == "timed_out" and bool(str(task.get("stdout") or "").strip())
        )
        if task.get("status") in {"failed", "incomplete"} and not progress_made:
            signature = _failure_signature(task)
            previous_signature = long_horizon.get("previous_failure_signature")
            count = int(long_horizon.get("consecutive_failure_count") or 0)
            count = count + 1 if previous_signature == signature else 1
            long_horizon["previous_failure_signature"] = signature
            long_horizon["consecutive_failure_count"] = count
            task["long_horizon"] = long_horizon
            if count >= 2:
                _record_long_horizon_stop(task, "repeated_failure")
                return
        else:
            long_horizon["previous_failure_signature"] = None
            long_horizon["consecutive_failure_count"] = 0
            task["long_horizon"] = long_horizon

        try:
            _require_task_authority(task)
        except Exception:
            _record_long_horizon_stop(task, "authority_expiry")
            return

        authority_expires_at = int((task.get("authority") or {}).get("expires_at") or 0)
        remaining = min(deadline - now, authority_expires_at - now)
        if remaining <= 0:
            _record_long_horizon_stop(task, "authority_expiry")
            return
        next_timeout = min(int(long_horizon.get("worker_slice_timeout") or MAX_TIMEOUT_SECONDS), remaining)
        _save(task)

    guidance = (
        "Automatically resume the same approved logical task from the latest durable checkpoint. "
        "Reconcile current repository state first, preserve the exact approved scope, do not replay "
        "completed operations, and continue only the remaining work."
    )
    result = json.loads(
        hermes_delegated_task_continue(
            task_id,
            guidance,
            timeout=next_timeout,
            _automatic=True,
        )
    )
    if not result.get("success"):
        with _LOCK:
            current = _load(task_id)
            _record_long_horizon_stop(current, "continuation_queue_failed")


def _worker(task_id: str) -> None:
    with _LOCK:
        task = _load(task_id)
        if task["status"] == "cancel_requested":
            _transition(task, "cancelled", reason="cancelled before start")
            task["finished_at"] = _now()
            _write_checkpoint(task, reason="cancelled before start")
            _save(task)
            _record_mission_control(task, event="cancelled")
            return
        _transition(task, "starting", reason="worker thread accepted task")
        task["started_at"] = _now()
        _write_checkpoint(task, reason="starting delegated attempt")
        _save(task)
        _record_mission_control(task, event="starting")

    env = os.environ.copy()
    env[FILE_READ_SAFE_ROOT_ENV] = task["workdir"]
    runtime_home: Path | None = None
    before_snapshot = _workspace_snapshot(Path(task["workdir"])) if task.get("mode") == "apply" else {}
    authority_failure = ""
    try:
        _require_task_authority(task)
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
            _transition(task, "running", reason="provider process started")
            task["pid"] = process.pid
            _write_checkpoint(task, reason="provider process started")
            _save(task)
            _record_mission_control(task, event="running")
        deadline = time.monotonic() + int(task["timeout"])
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                os.killpg(process.pid, signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=10)
                rc = 124
                break
            try:
                stdout, stderr = process.communicate(timeout=min(AUTHORITY_POLL_SECONDS, remaining))
                rc = int(process.returncode or 0)
                break
            except subprocess.TimeoutExpired:
                try:
                    _require_task_authority(task)
                except Exception as exc:
                    authority_failure = str(exc)
                    os.killpg(process.pid, signal.SIGTERM)
                    stdout, stderr = process.communicate(timeout=10)
                    rc = 125
                    break
        with _LOCK:
            task = _load(task_id)
            cancelled = task["status"] == "cancel_requested"
            task["returncode"] = rc
            task["stdout"] = _safe_text(stdout)
            task["stderr"] = _safe_text(stderr)
            task["finished_at"] = _now()
            task["pid"] = None
            after_snapshot = _workspace_snapshot(Path(task["workdir"])) if task.get("mode") == "apply" else {}
            changed_files = _changed_files(before_snapshot, after_snapshot) if task.get("mode") == "apply" else []
            task["changed_files"] = changed_files
            if cancelled:
                _transition(task, "cancelled", reason="task cancellation was requested")
                task["outcome_reason"] = "task cancellation was requested"
            elif authority_failure:
                _transition(task, "blocked", reason="task authority was withdrawn")
                task["outcome_reason"] = f"task authority was withdrawn: {authority_failure}"
            else:
                status, reason = _assess_outcome(
                    task=task,
                    rc=rc,
                    stdout=stdout,
                    stderr=stderr,
                    changed_files=changed_files,
                )
                _transition(task, status, reason=reason)
                task["outcome_reason"] = reason
            task["failure_category"], task["provider_error_category"] = _classify_failure(
                rc=rc,
                stdout=stdout,
                stderr=stderr,
                status=str(task["status"]),
                reason=str(task.get("outcome_reason") or ""),
            )
            _write_checkpoint(task, reason=str(task.get("outcome_reason") or task["status"]))
            _save(task)
            _record_mission_control(task, event=str(task["status"]))
            audit_error = task["stderr"][:500] if task["status"] != "completed" else ""
            _audit(
                task,
                success=task["status"] == "completed",
                summary=f"delegated task {task['status']} rc={rc}: {task.get('outcome_reason', '')}",
                error=audit_error,
            )
    except Exception as exc:
        with _LOCK:
            task = _load(task_id)
            if task.get("status") not in TERMINAL_STATES:
                _transition(task, "failed", reason="delegated task launch failed")
            task["finished_at"] = _now()
            task["pid"] = None
            task["stderr"] = _safe_text(str(exc))
            task["failure_category"] = "adapter_failure"
            _write_checkpoint(task, reason="delegated task launch failed")
            _save(task)
            _record_mission_control(task, event="failed")
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
    try:
        _schedule_automatic_continuation(task_id)
    except Exception as exc:
        with _LOCK:
            try:
                task = _load(task_id)
                if (task.get("long_horizon") or {}).get("enabled"):
                    task["stderr"] = _safe_text(f"{task.get('stderr', '')}\nautomatic continuation error: {exc}")
                    _record_long_horizon_stop(task, "continuation_scheduler_failure")
            except Exception:
                pass


def hermes_delegate_task_forecast(
    workdir: str,
    mode: str = "apply",
    profile: str = "default",
    max_turns: int = 30,
    timeout: int | None = 1800,
    allow_web: bool = False,
    total_task_window: int | None = None,
    worker_slice_timeout: int | None = None,
    maximum_continuations: int = 0,
    resume_from_checkpoint: bool = False,
    stop_on: list[str] | None = None,
) -> str:
    """Return the exact authority contract for a proposed task without queuing it."""
    required: dict[str, Any] = {
        "level": "workspace" if str(mode).strip().lower() == "apply" else "read_only",
        "verbs": {"filesystem": ["edit"]} if str(mode).strip().lower() == "apply" else {},
        "workdir": workdir,
        "mode": str(mode).strip().lower(),
        "profile": profile,
        "allow_web": bool(allow_web),
        "max_turns": max_turns,
        "timeout": timeout,
        "total_task_window": total_task_window,
        "worker_slice_timeout": worker_slice_timeout,
        "maximum_continuations": maximum_continuations,
        "resume_from_checkpoint": resume_from_checkpoint,
        "stop_on": stop_on,
        "evidence": ["changed_files", "substantive_output"] if str(mode).strip().lower() == "apply" else ["substantive_output"],
    }
    try:
        normalized_mode = str(mode).strip().lower()
        if normalized_mode not in {"plan", "read_only", "apply"}:
            raise ValueError("mode must be plan, read_only, or apply.")
        turns = int(max_turns)
        if not 1 <= turns <= MAX_TURNS:
            raise ValueError(f"max_turns must be between 1 and {MAX_TURNS}.")
        if normalized_mode == "apply" and allow_web:
            raise PermissionError("allow_web is disabled for apply delegation.")

        policy = op.OperatorPolicy()
        policy.require_enabled()
        long_horizon = _normalize_long_horizon(
            timeout=timeout,
            worker_slice_timeout=worker_slice_timeout,
            total_task_window=total_task_window,
            maximum_continuations=maximum_continuations,
            resume_from_checkpoint=resume_from_checkpoint,
            stop_on=stop_on,
            authority_expires_at=policy.expires_at,
        )
        if long_horizon["enabled"] and not policy.session_id:
            raise PermissionError("Automatic long-horizon delegation requires an approved Operator Session.")
        seconds = int(long_horizon["worker_slice_timeout"])
        required.update(
            {
                "timeout": seconds,
                "worker_slice_timeout": seconds,
                "total_task_window": long_horizon["total_task_window"],
                "maximum_continuations": long_horizon["maximum_continuations"],
                "resume_from_checkpoint": long_horizon["resume_from_checkpoint"],
                "stop_on": long_horizon["stop_on"],
                "envelope_deadline": long_horizon["envelope_deadline"],
            }
        )

        canonical_profile = op.validate_profile_name(profile)
        resolved = _resolve_workdir(workdir)
        route = _antigravity_route(
            profile=canonical_profile,
            workdir=resolved,
            prompt=(
                " ".join(ANTIGRAVITY_REVIEW_MARKERS)
                if resolved == op_antigravity.CANONICAL_WORKTREE
                else "Independent Projections Calculator completion review "
                + " ".join(op_antigravity_tax.TARGET_COMMITS)
            ),
        )
        if route == "operator_regression":
            if long_horizon["enabled"]:
                raise PermissionError("The fixed supervised Antigravity review runner does not support generic long-horizon envelopes.")
            required["runner"] = "supervised-host-agy"
            return json.dumps(
                {
                    "success": True,
                    "granted": True,
                    "required": required,
                    "route": "supervised-host-agy",
                    "tool": "hermes_antigravity_review_start",
                    "target_commit": op_antigravity.TARGET_COMMIT,
                    "workdir": str(op_antigravity.CANONICAL_WORKTREE),
                    "packet": str(op_antigravity.PACKET_PATH),
                },
                indent=2,
            )
        if route == "tax_calculator":
            if normalized_mode not in {"plan", "read_only"}:
                raise PermissionError("The fixed Tax Calculator Antigravity review is read-only.")
            preview = json.loads(op_antigravity_tax.start(dry_run=True))
            if not preview.get("success"):
                raise PermissionError(str(preview.get("error") or "Tax Calculator Antigravity preflight denied."))
            required.update(
                {
                    "level": "workspace",
                    "runner": "supervised-host-agy-tax-review",
                    "policy_template": op_antigravity_tax.REQUIRED_TEMPLATE,
                    "total_task_window": op_antigravity_tax.OUTER_TIMEOUT_SECONDS,
                    "worker_slice_timeout": 3600,
                    "maximum_continuations": 8,
                    "resume_from_checkpoint": True,
                    "stop_on": [
                        "completion",
                        "material_scope_change",
                        "unsafe_action",
                        "repeated_failure",
                        "authority_expiry",
                    ],
                }
            )
            return json.dumps(
                {
                    "success": True,
                    "granted": True,
                    "required": required,
                    "route": "supervised-host-agy-tax-review",
                    "tool": "hermes_delegate_task",
                    "target_commits": list(op_antigravity_tax.TARGET_COMMITS),
                    "workdir": str(op_antigravity_tax.TAX_CALCULATOR_ROOT),
                    "report": str(op_antigravity_tax.REPORT_PATH),
                    "envelope": str(op_antigravity_tax.ENVELOPE_PATH),
                },
                indent=2,
            )
        policy.require_profile(canonical_profile, Path.home() / ".hermes")
        policy.require_read_path(resolved)
        if normalized_mode == "apply":
            policy.require_level("workspace")
            policy.require_mutation(dry_run=False)
            policy.require_write_path(resolved)
            policy.require_verb("filesystem", "edit")
        envelope = _capture_authority_envelope(
            policy,
            profile=canonical_profile,
            workdir=resolved,
            mode=normalized_mode,
            allow_web=bool(allow_web),
            max_turns=turns,
            timeout=seconds,
        )
        envelope["long_horizon"] = long_horizon
        return json.dumps(
            {"success": True, "granted": True, "required": required, "authority": envelope},
            indent=2,
        )
    except Exception as exc:
        error = op.error_from_exception(
            exc,
            layer="operator",
            code="DELEGATE_TASK_FORECAST_DENIED",
            suggested_action="Request an Operator Session whose roots, profile, verbs, mode, and expiry cover the proposed task.",
        )
        return json.dumps({"success": True, "granted": False, "required": required, "denial": error}, indent=2)


def hermes_delegate_task(
    prompt: str,
    workdir: str,
    mode: str = "apply",
    profile: str = "default",
    max_turns: int = 30,
    timeout: int | None = 1800,
    allow_web: bool = False,
    total_task_window: int | None = None,
    worker_slice_timeout: int | None = None,
    maximum_continuations: int = 0,
    resume_from_checkpoint: bool = False,
    stop_on: list[str] | None = None,
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
        if not 1 <= turns <= MAX_TURNS:
            raise ValueError(f"max_turns must be between 1 and {MAX_TURNS}.")
        if normalized_mode == "apply" and allow_web:
            raise PermissionError("allow_web is disabled for apply delegation.")

        policy = op.OperatorPolicy()
        policy.require_enabled()
        long_horizon = _normalize_long_horizon(
            timeout=timeout,
            worker_slice_timeout=worker_slice_timeout,
            total_task_window=total_task_window,
            maximum_continuations=maximum_continuations,
            resume_from_checkpoint=resume_from_checkpoint,
            stop_on=stop_on,
            authority_expires_at=policy.expires_at,
        )
        if long_horizon["enabled"] and not policy.session_id:
            raise PermissionError("Automatic long-horizon delegation requires an approved Operator Session.")
        seconds = int(long_horizon["worker_slice_timeout"])

        canonical_profile = op.validate_profile_name(profile)
        resolved = _resolve_workdir(workdir)
        route = _antigravity_route(
            profile=canonical_profile,
            workdir=resolved,
            prompt=prompt,
        )
        if route == "operator_regression":
            if long_horizon["enabled"]:
                raise PermissionError("The fixed supervised Antigravity review runner does not support generic long-horizon envelopes.")
            started = json.loads(op_antigravity.hermes_antigravity_review_start(dry_run=False))
            started.update(
                {
                    "routed_from": "hermes_delegate_task",
                    "route": "supervised-host-agy",
                    "worker_kind": "official-antigravity-host-runner",
                    "profile": canonical_profile,
                    "workdir": str(resolved),
                }
            )
            return json.dumps(started, indent=2, sort_keys=True)
        if route == "tax_calculator":
            if normalized_mode not in {"plan", "read_only"}:
                raise PermissionError("The fixed Tax Calculator Antigravity review is read-only.")
            if allow_web:
                raise PermissionError("allow_web is not accepted for the fixed Tax Calculator Antigravity review.")
            started = json.loads(op_antigravity_tax.start(dry_run=False))
            started.update(
                {
                    "routed_from": "hermes_delegate_task",
                    "route": "supervised-host-agy-tax-review",
                    "worker_kind": "official-antigravity-host-runner",
                    "profile": canonical_profile,
                    "workdir": str(resolved),
                    "total_task_window": op_antigravity_tax.OUTER_TIMEOUT_SECONDS,
                    "worker_slice_timeout": 3600,
                    "maximum_continuations": 8,
                    "resume_from_checkpoint": True,
                    "stop_on": [
                        "completion",
                        "material_scope_change",
                        "unsafe_action",
                        "repeated_failure",
                        "authority_expiry",
                    ],
                }
            )
            return json.dumps(started, indent=2, sort_keys=True)
        policy.require_profile(canonical_profile, Path.home() / ".hermes")
        policy.require_read_path(resolved)
        if normalized_mode == "apply":
            policy.require_level("workspace")
            policy.require_mutation(dry_run=False)
            policy.require_write_path(resolved)
            policy.require_verb("filesystem", "edit")

        logical_work_id, work_fingerprint = _logical_work_id(
            prompt=prompt,
            profile=canonical_profile,
            mode=normalized_mode,
            workdir=resolved,
            execution_contract={
                "total_task_window": long_horizon["total_task_window"],
                "worker_slice_timeout": long_horizon["worker_slice_timeout"],
                "maximum_continuations": long_horizon["maximum_continuations"],
                "resume_from_checkpoint": long_horizon["resume_from_checkpoint"],
                "stop_on": long_horizon["stop_on"],
            },
        )
        with _LOCK:
            existing = _find_existing_logical_work(logical_work_id)
        if existing is not None:
            existing = _latest_task_for(existing)
            existing_status = str(existing.get("status") or "unknown")
            existing_long_horizon = existing.get("long_horizon") or {}
            duplicate_result = {
                "success": True,
                "duplicate": True,
                "logical_work_id": logical_work_id,
                "task_id": existing.get("task_id"),
                "root_task_id": existing.get("root_task_id") or existing.get("task_id"),
                "latest_task_id": existing.get("task_id"),
                "status": existing_status,
                "mode": existing.get("mode"),
                "workdir": existing.get("workdir"),
                "resolution": "existing_task_returned",
                "resumable": existing_status in RESUMABLE_STATES,
                "checkpoint_ref": existing.get("checkpoint_ref"),
                "continuation_count": existing_long_horizon.get("continuation_count", 0),
                "final_stop_reason": existing_long_horizon.get("final_stop_reason"),
            }
            if existing_status == "completed":
                duplicate_result["resolution"] = "already_completed"
            elif existing_status in RESUMABLE_STATES:
                duplicate_result["resolution"] = "duplicate_rejected_resumable_checkpoint_available"
            elif existing_status in TERMINAL_STATES:
                duplicate_result["resolution"] = "duplicate_rejected_terminal_nonresumable"
            return json.dumps(duplicate_result, indent=2)

        task_id = "dt_" + uuid.uuid4().hex
        attempt_id = "da_" + uuid.uuid4().hex
        interaction_id = "di_" + uuid.uuid4().hex
        long_horizon["root_task_id"] = task_id
        long_horizon["latest_task_id"] = task_id
        argv = _build_argv(
            prompt=prompt,
            mode=normalized_mode,
            profile=canonical_profile,
            workdir=resolved,
            max_turns=turns,
            allow_web=bool(allow_web),
            long_horizon=long_horizon,
        )
        authority = _capture_authority_envelope(
            policy,
            profile=canonical_profile,
            workdir=resolved,
            mode=normalized_mode,
            allow_web=bool(allow_web),
            max_turns=turns,
            timeout=seconds,
        )
        authority["long_horizon"] = long_horizon
        task: dict[str, Any] = {
            "schema_version": TASK_SCHEMA_VERSION,
            "adapter": ADAPTER_NAME,
            "worker_kind": "antigravity-profile-worker" if canonical_profile == "antigravity-operator" else "hermes-profile-worker",
            "logical_work_id": logical_work_id,
            "root_task_id": task_id,
            "task_id": task_id,
            "attempt_id": attempt_id,
            "interaction_id": interaction_id,
            "continuation_sequence": 0,
            "status": "queued",
            "mode": normalized_mode,
            "profile": canonical_profile,
            "workdir": str(resolved),
            "git": work_fingerprint,
            "max_turns": turns,
            "timeout": seconds,
            "allow_web": bool(allow_web),
            "prompt_sha256": hashlib.sha256(encoded).hexdigest(),
            "work_fingerprint": work_fingerprint,
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
            "changed_files": [],
            "outcome_reason": "",
            "failure_category": None,
            "provider_error_category": None,
            "retry_count": 0,
            "checkpoint_sequence": 0,
            "checkpoint_ref": None,
            "events": [],
            "chain_cancelled": False,
            "long_horizon": long_horizon,
            "authority": authority,
        }
        _transition(task, "queued", reason="delegated task queued")
        with _LOCK:
            _write_checkpoint(task, reason="delegated task queued")
            _save(task)
        _record_mission_control(task, event="queued")
        thread = threading.Thread(target=_worker, args=(task_id,), daemon=True, name=f"hermes-delegate-{task_id[-8:]}")
        thread.start()
        _audit(task, success=True, summary="delegated task queued")
        return json.dumps(
            {
                "success": True,
                "logical_work_id": logical_work_id,
                "root_task_id": task_id,
                "task_id": task_id,
                "latest_task_id": task_id,
                "attempt_id": attempt_id,
                "interaction_id": interaction_id,
                "status": "queued",
                "mode": normalized_mode,
                "workdir": str(resolved),
                "continuation_count": 0,
                "maximum_continuations": long_horizon["maximum_continuations"],
                "envelope_deadline": long_horizon["envelope_deadline"],
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATE_TASK_ERROR", suggested_action="Use an approved workspace, active Operator Session, allowed profile, and bounded task settings."), indent=2)


def hermes_delegated_task_status(task_id: str) -> str:
    try:
        if str(task_id).startswith(op_antigravity_tax.TASK_ID_PREFIX):
            return op_antigravity_tax.status(task_id)
        with _LOCK:
            requested = _load(task_id)
            task = _latest_task_for(requested)
        long_horizon = task.get("long_horizon") or {}
        keys = (
            "schema_version", "adapter", "worker_kind", "logical_work_id",
            "task_id", "attempt_id", "interaction_id", "continuation_sequence",
            "status", "mode", "profile", "workdir", "created_at", "updated_at",
            "started_at", "finished_at", "pid", "returncode", "prompt_sha256",
            "changed_files", "outcome_reason", "failure_category",
            "provider_error_category", "retry_count", "checkpoint_ref",
            "checkpoint_sequence", "authority",
        )
        payload = {"success": True, **{key: task.get(key) for key in keys}}
        payload.update(
            {
                "requested_task_id": task_id,
                "root_task_id": task.get("root_task_id") or requested.get("root_task_id") or requested.get("task_id"),
                "latest_task_id": task.get("task_id"),
                "latest_status": task.get("status"),
                "continuation_count": long_horizon.get("continuation_count", task.get("continuation_sequence", 0)),
                "maximum_continuations": long_horizon.get("maximum_continuations", 0),
                "envelope_deadline": long_horizon.get("envelope_deadline"),
                "final_stop_reason": long_horizon.get("final_stop_reason"),
                "long_horizon": long_horizon,
            }
        )
        return json.dumps(payload, indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATED_TASK_STATUS_ERROR", suggested_action="Check the delegated task id."), indent=2)


def hermes_delegated_task_result(task_id: str) -> str:
    try:
        if str(task_id).startswith(op_antigravity_tax.TASK_ID_PREFIX):
            return op_antigravity_tax.result(task_id)
        with _LOCK:
            requested = _load(task_id)
            task = _latest_task_for(requested)
        long_horizon = task.get("long_horizon") or {}
        if task["status"] not in TERMINAL_STATES:
            if not long_horizon:
                return json.dumps(
                    {"success": True, "task_id": task_id, "status": task["status"], "ready": False},
                    indent=2,
                )
            return json.dumps(
                {
                    "success": True,
                    "task_id": task_id,
                    "root_task_id": task.get("root_task_id") or requested.get("root_task_id") or requested.get("task_id"),
                    "latest_task_id": task.get("task_id"),
                    "status": task["status"],
                    "ready": False,
                    "continuation_count": long_horizon.get("continuation_count", task.get("continuation_sequence", 0)),
                    "maximum_continuations": long_horizon.get("maximum_continuations", 0),
                    "envelope_deadline": long_horizon.get("envelope_deadline"),
                    "final_stop_reason": long_horizon.get("final_stop_reason"),
                },
                indent=2,
            )
        final_answer, final_answer_extraction_status = _extract_final_answer(
            str(task.get("stdout") or ""),
            str(task.get("stderr") or ""),
        )
        return json.dumps({
            "success": task["status"] == "completed",
            "logical_work_id": task.get("logical_work_id"),
            "task_id": task_id,
            "result_task_id": task.get("task_id"),
            "root_task_id": task.get("root_task_id") or requested.get("root_task_id") or requested.get("task_id"),
            "latest_task_id": task.get("task_id"),
            "attempt_id": task.get("attempt_id"),
            "interaction_id": task.get("interaction_id"),
            "continuation_sequence": task.get("continuation_sequence", 0),
            "continuation_count": long_horizon.get("continuation_count", task.get("continuation_sequence", 0)),
            "maximum_continuations": long_horizon.get("maximum_continuations", 0),
            "envelope_deadline": long_horizon.get("envelope_deadline"),
            "final_stop_reason": long_horizon.get("final_stop_reason"),
            "status": task["status"],
            "ready": True,
            "returncode": task.get("returncode"),
            "final_answer": final_answer,
            "final_answer_extraction_status": final_answer_extraction_status,
            "stdout": task.get("stdout", ""),
            "stderr": task.get("stderr", ""),
            "messages": task.get("messages", []),
            "changed_files": task.get("changed_files", []),
            "outcome_reason": task.get("outcome_reason", ""),
            "failure_category": task.get("failure_category"),
            "provider_error_category": task.get("provider_error_category"),
            "checkpoint_ref": task.get("checkpoint_ref"),
            "resumable": task["status"] in RESUMABLE_STATES and not bool(long_horizon.get("final_stop_reason")),
            "authority": task.get("authority", {}),
            "long_horizon": long_horizon,
        }, indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATED_TASK_RESULT_ERROR", suggested_action="Check the delegated task id."), indent=2)


def hermes_delegated_task_message(task_id: str, message: str) -> str:
    """Attach durable operator guidance for review or a later continuation."""
    try:
        if str(task_id).startswith(op_antigravity_tax.TASK_ID_PREFIX):
            raise PermissionError("The fixed Tax Calculator Antigravity review does not accept mid-run messages.")
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


def hermes_delegated_task_continue(
    task_id: str,
    prompt: str,
    max_turns: int | None = None,
    timeout: int | None = None,
    _automatic: bool = False,
) -> str:
    """Queue a continuation from the latest durable checkpoint."""
    try:
        if str(task_id).startswith(op_antigravity_tax.TASK_ID_PREFIX):
            raise PermissionError("The fixed Tax Calculator Antigravity review owns its bounded host execution and cannot be manually continued.")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("continuation prompt is required.")
        if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise ValueError(f"continuation prompt exceeds {MAX_PROMPT_BYTES} bytes.")
        with _LOCK:
            requested = _load(task_id)
            previous = _latest_task_for(requested)
        previous_id = str(previous.get("task_id") or task_id)
        previous_status = str(previous.get("status") or "")
        if previous_status not in RESUMABLE_STATES:
            raise PermissionError(f"Task {previous_id!r} is not in a resumable state.")
        if _chain_cancelled(previous):
            raise PermissionError("The delegated task chain has been cancelled.")
        _require_task_authority(previous)

        long_horizon = dict(previous.get("long_horizon") or {})
        if _automatic:
            if not long_horizon.get("enabled") or not long_horizon.get("resume_from_checkpoint"):
                raise PermissionError("Automatic continuation is not enabled for this task.")
            if long_horizon.get("final_stop_reason"):
                raise PermissionError("The long-horizon envelope has already reached a governed stop condition.")
            if int(long_horizon.get("continuation_count") or 0) >= int(long_horizon.get("maximum_continuations") or 0):
                raise PermissionError("The long-horizon continuation limit has been reached.")

        mode = str(previous.get("mode") or "read_only")
        profile = str(previous.get("profile") or "default")
        workdir = _resolve_workdir(str(previous.get("workdir") or ""))
        turns = int(max_turns if max_turns is not None else previous.get("max_turns") or 30)
        seconds = int(timeout if timeout is not None else previous.get("timeout") or 1800)
        if not 1 <= turns <= MAX_TURNS:
            raise ValueError(f"max_turns must be between 1 and {MAX_TURNS}.")
        if not 1 <= seconds <= MAX_TIMEOUT_SECONDS:
            raise ValueError(f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds.")
        continuation_sequence = int(previous.get("continuation_sequence") or 0) + 1
        continuation_id = "dc_" + uuid.uuid4().hex
        continuation_prompt = (
            f"Continue delegated task {previous_id} from checkpoint {previous.get('checkpoint_ref') or '<none>'}.\n"
            "First reconcile current repository state against the checkpoint and preserve the exact approved scope. "
            "Do not replay completed operations. Continue only remaining work.\n\n"
            f"Continuation guidance:\n{prompt.strip()}"
        )
        encoded = continuation_prompt.encode("utf-8")
        new_task_id = "dt_" + uuid.uuid4().hex
        attempt_id = "da_" + uuid.uuid4().hex
        interaction_id = "di_" + uuid.uuid4().hex
        root_task_id = str(previous.get("root_task_id") or previous_id)
        if long_horizon:
            long_horizon["root_task_id"] = root_task_id
            long_horizon["continuation_count"] = int(long_horizon.get("continuation_count") or 0) + 1
            long_horizon["latest_task_id"] = new_task_id
            long_horizon["final_stop_reason"] = None
        argv = _build_argv(
            prompt=continuation_prompt,
            mode=mode,
            profile=profile,
            workdir=workdir,
            max_turns=turns,
            allow_web=bool(previous.get("allow_web", False)),
            long_horizon=long_horizon,
        )
        authority = json.loads(json.dumps(previous.get("authority", {})))
        authority["timeout"] = seconds
        if long_horizon:
            authority["long_horizon"] = long_horizon
        task: dict[str, Any] = {
            "schema_version": TASK_SCHEMA_VERSION,
            "adapter": ADAPTER_NAME,
            "worker_kind": previous.get("worker_kind") or ("antigravity-profile-worker" if profile == "antigravity-operator" else "hermes-profile-worker"),
            "logical_work_id": previous.get("logical_work_id") or task_id,
            "root_task_id": root_task_id,
            "task_id": new_task_id,
            "attempt_id": attempt_id,
            "interaction_id": interaction_id,
            "continuation_id": continuation_id,
            "continuation_sequence": continuation_sequence,
            "previous_task_id": previous_id,
            "previous_checkpoint_ref": previous.get("checkpoint_ref"),
            "status": "queued",
            "mode": mode,
            "profile": profile,
            "workdir": str(workdir),
            "git": _git_context(workdir),
            "max_turns": turns,
            "timeout": seconds,
            "allow_web": bool(previous.get("allow_web", False)),
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
            "changed_files": [],
            "outcome_reason": "",
            "failure_category": None,
            "provider_error_category": None,
            "retry_count": int(previous.get("retry_count") or 0),
            "checkpoint_sequence": 0,
            "checkpoint_ref": None,
            "events": [],
            "chain_cancelled": False,
            "long_horizon": long_horizon,
            "authority": authority,
        }
        _transition(task, "queued", reason="automatic continuation queued" if _automatic else "continuation queued")
        with _LOCK:
            _write_checkpoint(task, reason="automatic continuation queued" if _automatic else "continuation queued")
            _save(task)
        _record_mission_control(task, event="automatic_continuation_queued" if _automatic else "continuation_queued")
        thread = threading.Thread(target=_worker, args=(new_task_id,), daemon=True, name=f"hermes-delegate-{new_task_id[-8:]}")
        thread.start()
        _audit(task, success=True, summary=f"delegated task continuation queued from {previous_id}")
        return json.dumps(
            {
                "success": True,
                "logical_work_id": task.get("logical_work_id"),
                "root_task_id": root_task_id,
                "task_id": new_task_id,
                "latest_task_id": new_task_id,
                "previous_task_id": previous_id,
                "attempt_id": attempt_id,
                "interaction_id": interaction_id,
                "continuation_id": continuation_id,
                "continuation_sequence": continuation_sequence,
                "continuation_count": long_horizon.get("continuation_count", continuation_sequence),
                "automatic": _automatic,
                "status": "queued",
                "mode": mode,
                "workdir": str(workdir),
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATED_TASK_CONTINUE_ERROR", suggested_action="Check task state, checkpoint, active authority, and continuation prompt."), indent=2)


def hermes_delegated_task_cancel(task_id: str) -> str:
    try:
        if str(task_id).startswith(op_antigravity_tax.TASK_ID_PREFIX):
            return op_antigravity_tax.cancel(task_id, dry_run=False)
        policy = op.OperatorPolicy()
        policy.require_level("workspace")
        policy.require_mutation(dry_run=False)
        changed = False
        affected: list[dict[str, Any]] = []
        with _LOCK:
            requested = _load(task_id)
            logical_work_id = requested.get("logical_work_id")
            chain = [
                candidate
                for candidate in _iter_tasks()
                if logical_work_id and candidate.get("logical_work_id") == logical_work_id
            ] or [requested]
            for task in chain:
                if not task.get("chain_cancelled"):
                    changed = True
                task["chain_cancelled"] = True
                long_horizon = dict(task.get("long_horizon") or {})
                if long_horizon.get("enabled"):
                    long_horizon["final_stop_reason"] = "cancelled"
                    task["long_horizon"] = long_horizon
                status = str(task.get("status") or "")
                if status not in TERMINAL_STATES and status != "cancel_requested":
                    allowed = LEGAL_TRANSITIONS.get(status, set())
                    target = "cancel_requested" if "cancel_requested" in allowed else "cancelled"
                    _transition(task, target, reason="operator requested chain cancellation")
                    changed = True
                _write_checkpoint(task, reason="operator requested chain cancellation")
                _save(task)
                process = _PROCESSES.get(str(task.get("task_id")))
                if process is not None and process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    changed = True
                affected.append(task)
        for task in affected:
            _record_mission_control(task, event="cancel_requested")
        latest = _latest_task_for(requested)
        return json.dumps(
            {
                "success": True,
                "task_id": task_id,
                "root_task_id": latest.get("root_task_id") or requested.get("root_task_id") or requested.get("task_id"),
                "latest_task_id": latest.get("task_id"),
                "status": latest.get("status"),
                "changed": changed,
                "chain_cancelled": True,
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="operator", code="DELEGATED_TASK_CANCEL_ERROR", suggested_action="Use an active workspace Operator Session and check the task id."), indent=2)
