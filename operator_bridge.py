"""Narrow asynchronous file mailbox for ChatGPT and Hermes."""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import operator_policy as op_policy

BRIDGE_ROOT_ENV = "HERMES_GPT_BRIDGE_ROOT"
DEFAULT_BRIDGE_ROOT = Path.home() / ".hermes" / "bridge"
COMMAND_HEADING = "### COMMAND_FROM_CHATGPT"
SUCCESS_HEADING = "### EXECUTION_SUCCESS"
ADJUDICATION_HEADING = "### REQUEST_FOR_ADJUDICATION"
VERDICT_HEADING = "### ADJUDICATION_FROM_CHATGPT"
MAX_COMMAND_CHARS = 100_000
MAX_READ_CHARS = 200_000
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _root(value: str | None = None) -> Path:
    raw = Path(value).expanduser() if value else Path(os.environ.get(BRIDGE_ROOT_ENV, DEFAULT_BRIDGE_ROOT)).expanduser()
    return raw.resolve()


def _guard(root: Path, *, write: bool) -> op_policy.OperatorPolicy:
    policy = op_policy.OperatorPolicy()
    policy.require_level("workspace" if write else "read_only")
    if op_policy.is_denied_path(root):
        raise PermissionError("Bridge root is denied by operator path policy.")
    if not op_policy.path_under_allowed(root, policy.allowed_paths):
        raise PermissionError("Bridge root is not under HERMES_GPT_OPERATOR_ALLOWED_PATHS.")
    if write:
        policy.require_mutation(False)
    return policy


def _layout(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "archive").mkdir(exist_ok=True)
    (root / "logs").mkdir(exist_ok=True)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _load_state(root: Path) -> dict[str, Any]:
    path = root / "state.json"
    if not path.exists():
        return {"version": 1, "status": "idle", "command_id": None, "updated_at": _now()}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("state.json must contain a JSON object.")
    return value


def _save_state(root: Path, state: dict[str, Any]) -> None:
    value = dict(state)
    value["version"] = 1
    value["updated_at"] = _now()
    _atomic_write(root / "state.json", json.dumps(value, indent=2, sort_keys=True) + "\n")


def _valid_id(value: str) -> str:
    result = (value or "").strip()
    if not _ID_RE.fullmatch(result):
        raise ValueError("Invalid command_id.")
    return result


def _section(heading: str, command_id: str, body: str) -> str:
    return f"{heading}\n\ncommand_id: {command_id}\ntimestamp: {_now()}\n\n{body.rstrip()}\n"


def _response(**values: Any) -> str:
    return json.dumps(values, indent=2, sort_keys=True)


def bridge_status(root: str | None = None) -> str:
    try:
        bridge_root = _root(root)
        _guard(bridge_root, write=False)
        state = _load_state(bridge_root)
        path = bridge_root / "bridge.md"
        return _response(success=True, root=str(bridge_root), bridge_exists=path.exists(), state=state)
    except Exception as exc:
        return _response(success=False, error=str(exc))


def bridge_read(root: str | None = None, max_chars: int = MAX_READ_CHARS) -> str:
    try:
        bridge_root = _root(root)
        _guard(bridge_root, write=False)
        path = bridge_root / "bridge.md"
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        limit = max(1, min(int(max_chars), MAX_READ_CHARS))
        return _response(success=True, path=str(path), content=text[:limit], truncated=len(text) > limit)
    except Exception as exc:
        return _response(success=False, error=str(exc))


def bridge_submit_command(command: str, command_id: str = "", root: str | None = None) -> str:
    try:
        bridge_root = _root(root)
        _guard(bridge_root, write=True)
        _layout(bridge_root)
        body = (command or "").strip()
        if not body:
            raise ValueError("command cannot be empty.")
        if len(body) > MAX_COMMAND_CHARS:
            raise ValueError("command is too large.")
        cid = _valid_id(command_id or uuid.uuid4().hex)
        state = _load_state(bridge_root)
        if state.get("status") in {"queued", "claimed", "running", "adjudicated"}:
            raise RuntimeError("Bridge already has an active command.")
        if state.get("command_id") == cid or list((bridge_root / "archive").glob(f"{cid}.*")):
            raise RuntimeError("command_id has already been used.")
        _atomic_write(bridge_root / "bridge.md", _section(COMMAND_HEADING, cid, body))
        _save_state(bridge_root, {"status": "queued", "command_id": cid, "created_at": _now(), "attempt": 0})
        return _response(success=True, command_id=cid, status="queued")
    except Exception as exc:
        return _response(success=False, error=str(exc))


def bridge_read_result(command_id: str = "", root: str | None = None) -> str:
    try:
        bridge_root = _root(root)
        _guard(bridge_root, write=False)
        state = _load_state(bridge_root)
        cid = _valid_id(command_id) if command_id else state.get("command_id")
        if not cid:
            return _response(success=True, status="idle", command_id=None, content="")
        if state.get("command_id") == cid:
            path = bridge_root / "bridge.md"
            content = path.read_text(encoding="utf-8") if path.exists() else ""
            return _response(success=True, status=state.get("status"), command_id=cid, content=content, state=state)
        matches = sorted((bridge_root / "archive").glob(f"{cid}.*.md"))
        if not matches:
            raise FileNotFoundError("No result for command_id.")
        return _response(success=True, status="archived", command_id=cid, content=matches[-1].read_text(encoding="utf-8"))
    except Exception as exc:
        return _response(success=False, error=str(exc))


def bridge_write_adjudication(command_id: str, verdict: str, root: str | None = None) -> str:
    try:
        bridge_root = _root(root)
        _guard(bridge_root, write=True)
        cid = _valid_id(command_id)
        body = (verdict or "").strip()
        if not body:
            raise ValueError("verdict cannot be empty.")
        state = _load_state(bridge_root)
        if state.get("command_id") != cid or state.get("status") != "adjudication_required":
            raise RuntimeError("Current command is not awaiting adjudication.")
        path = bridge_root / "bridge.md"
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        _atomic_write(path, existing.rstrip() + "\n\n" + _section(VERDICT_HEADING, cid, body))
        state["status"] = "adjudicated"
        state["adjudicated_at"] = _now()
        _save_state(bridge_root, state)
        return _response(success=True, command_id=cid, status="adjudicated")
    except Exception as exc:
        return _response(success=False, error=str(exc))
