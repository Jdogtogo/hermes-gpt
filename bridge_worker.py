"""Local worker for the asynchronous Hermes file bridge."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

import operator_agent
import operator_bridge as bridge
import operator_policy as op_policy


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _save_state(root: Path, state: dict[str, Any]) -> None:
    state = dict(state)
    state["version"] = 1
    state["updated_at"] = _now()
    bridge._atomic_write(
        root / "state.json",
        json.dumps(state, indent=2, sort_keys=True) + "\n",
    )


def _section_body(text: str, heading: str, *, last: bool = False) -> str:
    start = text.rfind(heading) if last else text.find(heading)
    if start < 0:
        return ""
    metadata_start = text.find("\n\n", start + len(heading))
    if metadata_start < 0:
        return ""
    metadata_end = text.find("\n\n", metadata_start + 2)
    if metadata_end < 0:
        return ""
    body_start = metadata_end + 2
    next_heading = text.find("\n### ", body_start)
    body_end = len(text) if next_heading < 0 else next_heading
    return text[body_start:body_end].strip()


def _build_prompt(root: Path, command_id: str, status: str) -> str:
    text = (root / "bridge.md").read_text(encoding="utf-8")
    if not text.startswith(bridge.COMMAND_HEADING):
        raise ValueError("bridge.md does not begin with COMMAND_FROM_CHATGPT.")
    if f"command_id: {command_id}" not in text:
        raise ValueError("bridge.md command_id does not match state.json.")
    command = _section_body(text, bridge.COMMAND_HEADING)
    if not command:
        raise ValueError("bridge.md command section is malformed or empty.")
    if status != "adjudicated":
        return command

    escalation = _section_body(text, bridge.ADJUDICATION_HEADING, last=True)
    verdict = _section_body(text, bridge.VERDICT_HEADING, last=True)
    if not verdict:
        raise ValueError("Adjudicated state has no ADJUDICATION_FROM_CHATGPT section.")
    return (
        f"{command}\n\n"
        f"Previous execution escalation:\n{escalation or '(no details recorded)'}\n\n"
        f"Binding adjudication from ChatGPT:\n{verdict}"
    )


def _archive(
    root: Path,
    command_id: str,
    attempt: int,
    status: str,
    content: str,
) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = root / "archive" / f"{command_id}.attempt-{attempt}.{stamp}.{status}.md"
    bridge._atomic_write(path, content)
    return path


def _try_lock(root: Path) -> TextIO | None:
    path = root / "worker.lock"
    handle = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    handle.seek(0)
    handle.truncate()
    handle.write(f"pid={os.getpid()} timestamp={_now()}\n")
    handle.flush()
    return handle


def _release_lock(handle: TextIO) -> None:
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _safe_error(exc: Exception) -> str:
    return op_policy.redact_output(str(exc))[:2000]


def _write_outcome(
    *,
    root: Path,
    state: dict[str, Any],
    command_id: str,
    result: dict[str, Any],
    succeeded: bool,
) -> dict[str, Any]:
    heading = bridge.SUCCESS_HEADING if succeeded else bridge.ADJUDICATION_HEADING
    status = "success" if succeeded else "adjudication_required"
    attempt = int(state.get("attempt") or 1)
    result_body = json.dumps(result, indent=2, sort_keys=True)
    mailbox = root / "bridge.md"
    if mailbox.exists():
        current = mailbox.read_text(encoding="utf-8")
    else:
        fallback_workdir = Path(str(state.get("workdir") or root)).expanduser()
        current = bridge._command_section(
            command_id,
            fallback_workdir,
            "(original command content unavailable during worker recovery)",
        )
    final_content = current.rstrip() + "\n\n" + bridge._section(heading, command_id, result_body)
    bridge._atomic_write(root / "bridge.md", final_content)
    archive_path = _archive(root, command_id, attempt, status, final_content)
    state.update(
        {
            "status": status,
            "completed_at": _now(),
            "archive_path": str(archive_path),
            "result_success": succeeded,
        }
    )
    _save_state(root, state)
    return {
        "success": True,
        "executed": True,
        "command_id": command_id,
        "status": status,
        "attempt": attempt,
    }


def _recover_stale_running(
    *,
    root: Path,
    state: dict[str, Any],
    timeout: int,
) -> dict[str, Any] | None:
    if state.get("status") != "running":
        return None
    claimed_at = _parse_time(state.get("claimed_at"))
    age = None if claimed_at is None else (datetime.now(timezone.utc) - claimed_at).total_seconds()
    if age is not None and age <= timeout + 60:
        return {
            "success": True,
            "executed": False,
            "status": "running",
            "command_id": state.get("command_id"),
        }

    command_id = bridge._valid_id(str(state.get("command_id") or ""))
    result = {
        "success": False,
        "code": "WORKER_RESTART_RECOVERY",
        "error": (
            "The previous worker stopped while this command was marked running. "
            "The command was not automatically re-run because it may already have mutated state."
        ),
        "claimed_at": state.get("claimed_at"),
        "detected_at": _now(),
    }
    recovered = _write_outcome(
        root=root,
        state=state,
        command_id=command_id,
        result=result,
        succeeded=False,
    )
    recovered["recovered_stale_run"] = True
    return recovered


def worker_once(
    *,
    root: str | None = None,
    default_workdir: str | None = None,
    profile: str = "default",
    max_turns: int = 30,
    timeout: int = 600,
) -> dict[str, Any]:
    bridge_root = bridge._root(root)
    bridge._guard(bridge_root, write=True)
    bridge._layout(bridge_root)
    lock = _try_lock(bridge_root)
    if lock is None:
        return {"success": True, "executed": False, "status": "worker_busy"}

    try:
        state = bridge._load_state(bridge_root)
        recovered = _recover_stale_running(root=bridge_root, state=state, timeout=timeout)
        if recovered is not None:
            return recovered

        initial_status = str(state.get("status") or "idle")
        if initial_status not in {"queued", "adjudicated"}:
            return {
                "success": True,
                "executed": False,
                "status": initial_status,
            }

        command_id = bridge._valid_id(str(state.get("command_id") or ""))
        state["status"] = "running"
        state["claimed_at"] = _now()
        state["attempt"] = int(state.get("attempt") or 0) + 1
        _save_state(bridge_root, state)

        workdir = str(state.get("workdir") or default_workdir or "").strip()
        prompt = ""
        try:
            if not workdir:
                raise ValueError("No workdir is recorded for this command.")
            prompt = _build_prompt(bridge_root, command_id, initial_status)
            raw = operator_agent.hermes_agent_run(
                prompt=prompt,
                mode="apply",
                profile=profile,
                workdir=workdir,
                max_turns=max_turns,
                timeout=timeout,
                allow_web=False,
                apply=True,
                transport="stdio",
                hermes_root=Path.home() / ".hermes",
            )
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError("Hermes Agent returned a non-object result.")
        except Exception as exc:
            result = {
                "success": False,
                "code": "WORKER_EXECUTION_EXCEPTION",
                "error": _safe_error(exc),
            }

        succeeded = bool(result.get("success"))
        outcome = _write_outcome(
            root=bridge_root,
            state=state,
            command_id=command_id,
            result=result,
            succeeded=succeeded,
        )
        policy = op_policy.OperatorPolicy()
        op_policy.audit_record(
            tool="hermes_file_bridge_worker",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=succeeded,
            changed=succeeded,
            summary=f"bridge worker completed with status {outcome['status']}",
            path=workdir,
            prompt=prompt,
            extra={
                "command_id": command_id,
                "attempt": outcome["attempt"],
                "status": outcome["status"],
            },
        )
        return outcome
    finally:
        _release_lock(lock)


def main() -> None:
    parser = argparse.ArgumentParser(description="Process Hermes file-bridge commands locally.")
    parser.add_argument("--root", default=str(bridge.DEFAULT_BRIDGE_ROOT))
    parser.add_argument("--default-workdir", default="")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--max-turns", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    kwargs = {
        "root": args.root,
        "default_workdir": args.default_workdir or None,
        "profile": args.profile,
        "max_turns": args.max_turns,
        "timeout": args.timeout,
    }
    if args.once:
        print(json.dumps(worker_once(**kwargs), indent=2))
        return

    delay = max(0.5, min(args.interval, 60.0))
    while True:
        try:
            worker_once(**kwargs)
        except Exception as exc:
            print(json.dumps({"success": False, "error": _safe_error(exc)}), flush=True)
        time.sleep(delay)


if __name__ == "__main__":
    main()
