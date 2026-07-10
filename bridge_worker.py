"""Local worker for the asynchronous Hermes file bridge."""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import operator_agent
import operator_bridge as bridge
import operator_policy as op_policy


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_state(root: Path) -> dict[str, Any]:
    return json.loads((root / "state.json").read_text(encoding="utf-8"))


def _save_state(root: Path, state: dict[str, Any]) -> None:
    state = dict(state)
    state["version"] = 1
    state["updated_at"] = _now()
    bridge._atomic_write(root / "state.json", json.dumps(state, indent=2, sort_keys=True) + "\n")


def _extract_command(root: Path, command_id: str) -> str:
    text = (root / "bridge.md").read_text(encoding="utf-8")
    if not text.startswith(bridge.COMMAND_HEADING):
        raise ValueError("bridge.md does not begin with COMMAND_FROM_CHATGPT.")
    if f"command_id: {command_id}" not in text:
        raise ValueError("bridge.md command_id does not match state.json.")
    parts = text.split("\n\n", 2)
    if len(parts) < 3:
        raise ValueError("bridge.md command section is malformed.")
    return parts[2].strip()


def _archive(root: Path, command_id: str, status: str, content: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = root / "archive" / f"{command_id}.{stamp}.{status}.md"
    bridge._atomic_write(path, content)
    return path


def worker_once(
    *,
    root: str | None = None,
    workdir: str,
    profile: str = "default",
    max_turns: int = 30,
    timeout: int = 600,
) -> dict[str, Any]:
    bridge_root = bridge._root(root)
    bridge._guard(bridge_root, write=True)
    bridge._layout(bridge_root)
    state = bridge._load_state(bridge_root)
    if state.get("status") not in {"queued", "adjudicated"}:
        return {"success": True, "executed": False, "status": state.get("status", "idle")}

    command_id = bridge._valid_id(str(state.get("command_id") or ""))
    command = _extract_command(bridge_root, command_id)
    state["status"] = "running"
    state["claimed_at"] = _now()
    state["attempt"] = int(state.get("attempt") or 0) + 1
    _save_state(bridge_root, state)

    raw = operator_agent.hermes_agent_run(
        prompt=command,
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
    succeeded = bool(result.get("success"))
    if succeeded:
        heading = bridge.SUCCESS_HEADING
        status = "success"
    else:
        heading = bridge.ADJUDICATION_HEADING
        status = "adjudication_required"

    result_body = json.dumps(result, indent=2, sort_keys=True)
    current = (bridge_root / "bridge.md").read_text(encoding="utf-8")
    final_content = current.rstrip() + "\n\n" + bridge._section(heading, command_id, result_body)
    bridge._atomic_write(bridge_root / "bridge.md", final_content)
    archive_path = _archive(bridge_root, command_id, status, final_content)
    state.update(
        {
            "status": status,
            "completed_at": _now(),
            "archive_path": str(archive_path),
            "result_success": succeeded,
        }
    )
    _save_state(bridge_root, state)
    return {"success": True, "executed": True, "command_id": command_id, "status": status}


def main() -> None:
    parser = argparse.ArgumentParser(description="Process Hermes file-bridge commands locally.")
    parser.add_argument("--root", default=str(bridge.DEFAULT_BRIDGE_ROOT))
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--max-turns", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    if args.once:
        print(json.dumps(worker_once(root=args.root, workdir=args.workdir, profile=args.profile, max_turns=args.max_turns, timeout=args.timeout), indent=2))
        return

    delay = max(0.5, min(args.interval, 60.0))
    while True:
        worker_once(root=args.root, workdir=args.workdir, profile=args.profile, max_turns=args.max_turns, timeout=args.timeout)
        time.sleep(delay)


if __name__ == "__main__":
    main()
