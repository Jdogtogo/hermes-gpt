from __future__ import annotations

import json
from pathlib import Path

import pytest

import operator_bridge as bridge
import operator_policy as op


@pytest.fixture
def bridge_root(tmp_path: Path, monkeypatch):
    root = tmp_path / "bridge"
    (root / "workspace").mkdir(parents=True)
    monkeypatch.setenv(op.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "workspace")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "direct")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PATHS_ENV, str(root))
    monkeypatch.setenv(bridge.BRIDGE_ROOT_ENV, str(root))
    op.set_audit_log_override(tmp_path / "audit.jsonl")
    yield root
    op.set_audit_log_override(None)


def parsed(value: str):
    return json.loads(value)


def submit(root: Path, command: str, command_id: str):
    return parsed(
        bridge.bridge_submit_command(
            command,
            workdir=str(root / "workspace"),
            command_id=command_id,
        )
    )


def test_submit_creates_atomic_mailbox_and_state(bridge_root):
    out = submit(bridge_root, "Do the bounded task.", "cmd-1")
    assert out["success"] is True
    assert out["status"] == "queued"
    assert out["workdir"] == str((bridge_root / "workspace").resolve())
    text = (bridge_root / "bridge.md").read_text(encoding="utf-8")
    state = json.loads((bridge_root / "state.json").read_text(encoding="utf-8"))
    assert text.startswith(bridge.COMMAND_HEADING)
    assert "command_id: cmd-1" in text
    assert f"workdir: {(bridge_root / 'workspace').resolve()}" in text
    assert state["command_id"] == "cmd-1"
    assert state["status"] == "queued"
    assert state["workdir"] == str((bridge_root / "workspace").resolve())
    assert not list(bridge_root.glob(".bridge.md.*"))


def test_submit_refuses_duplicate_or_active_command(bridge_root):
    assert submit(bridge_root, "one", "cmd-1")["success"] is True
    second = submit(bridge_root, "two", "cmd-2")
    assert second["success"] is False
    assert "active" in second["error"].lower()


def test_submit_refuses_while_adjudication_is_required(bridge_root):
    assert submit(bridge_root, "one", "cmd-1")["success"] is True
    state_path = bridge_root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["status"] = "adjudication_required"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    second = submit(bridge_root, "two", "cmd-2")
    assert second["success"] is False
    assert "active" in second["error"].lower()


def test_submit_refuses_invalid_id_empty_command_and_bad_workdir(bridge_root, tmp_path):
    workdir = str(bridge_root / "workspace")
    assert parsed(bridge.bridge_submit_command("", workdir=workdir, command_id="cmd-1"))["success"] is False
    assert parsed(bridge.bridge_submit_command("task", workdir=workdir, command_id="../bad"))["success"] is False
    assert parsed(bridge.bridge_submit_command("task", workdir="relative/path", command_id="cmd-1"))["success"] is False
    outside = tmp_path / "outside"
    outside.mkdir()
    refused = parsed(bridge.bridge_submit_command("task", workdir=str(outside), command_id="cmd-1"))
    assert refused["success"] is False
    assert "not under" in refused["error"].lower()


def test_read_and_status(bridge_root):
    submit(bridge_root, "task body", "cmd-1")
    status = parsed(bridge.bridge_status())
    read = parsed(bridge.bridge_read())
    assert status["success"] is True
    assert status["state"]["status"] == "queued"
    assert read["success"] is True
    assert "task body" in read["content"]


def test_adjudication_requires_matching_waiting_state(bridge_root):
    submit(bridge_root, "task", "cmd-1")
    refused = parsed(bridge.bridge_write_adjudication("cmd-1", "Proceed using option B."))
    assert refused["success"] is False

    state = json.loads((bridge_root / "state.json").read_text(encoding="utf-8"))
    state["status"] = "adjudication_required"
    (bridge_root / "state.json").write_text(json.dumps(state), encoding="utf-8")

    accepted = parsed(bridge.bridge_write_adjudication("cmd-1", "Proceed using option B."))
    assert accepted["success"] is True
    assert accepted["status"] == "adjudicated"
    text = (bridge_root / "bridge.md").read_text(encoding="utf-8")
    assert bridge.VERDICT_HEADING in text
    assert "Proceed using option B." in text


def test_outside_allowed_root_is_refused(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    workdir = allowed / "workspace"
    workdir.mkdir()
    monkeypatch.setenv(op.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "workspace")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "direct")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PATHS_ENV, str(allowed))
    out = parsed(
        bridge.bridge_submit_command(
            "task",
            workdir=str(workdir),
            command_id="cmd-1",
            root=str(outside),
        )
    )
    assert out["success"] is False
    assert "not under" in out["error"].lower()


def test_read_result_returns_current_mailbox(bridge_root):
    submit(bridge_root, "task", "cmd-1")
    out = parsed(bridge.bridge_read_result("cmd-1"))
    assert out["success"] is True
    assert out["status"] == "queued"
    assert bridge.COMMAND_HEADING in out["content"]
