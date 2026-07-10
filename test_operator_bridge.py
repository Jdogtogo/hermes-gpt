from __future__ import annotations

import json
from pathlib import Path

import pytest

import operator_bridge as bridge
import operator_policy as op


@pytest.fixture
def bridge_root(tmp_path: Path, monkeypatch):
    root = tmp_path / "bridge"
    monkeypatch.setenv(op.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "workspace")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "direct")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PATHS_ENV, str(root))
    monkeypatch.setenv(bridge.BRIDGE_ROOT_ENV, str(root))
    return root


def parsed(value: str):
    return json.loads(value)


def test_submit_creates_atomic_mailbox_and_state(bridge_root):
    out = parsed(bridge.bridge_submit_command("Do the bounded task.", command_id="cmd-1"))
    assert out["success"] is True
    assert out["status"] == "queued"
    text = (bridge_root / "bridge.md").read_text(encoding="utf-8")
    state = json.loads((bridge_root / "state.json").read_text(encoding="utf-8"))
    assert text.startswith(bridge.COMMAND_HEADING)
    assert "command_id: cmd-1" in text
    assert state["command_id"] == "cmd-1"
    assert state["status"] == "queued"
    assert not list(bridge_root.glob(".bridge.md.*"))


def test_submit_refuses_duplicate_or_active_command(bridge_root):
    assert parsed(bridge.bridge_submit_command("one", command_id="cmd-1"))["success"] is True
    second = parsed(bridge.bridge_submit_command("two", command_id="cmd-2"))
    assert second["success"] is False
    assert "active" in second["error"].lower()


def test_submit_refuses_invalid_id_and_empty_command(bridge_root):
    assert parsed(bridge.bridge_submit_command("", command_id="cmd-1"))["success"] is False
    assert parsed(bridge.bridge_submit_command("task", command_id="../bad"))["success"] is False


def test_read_and_status(bridge_root):
    bridge.bridge_submit_command("task body", command_id="cmd-1")
    status = parsed(bridge.bridge_status())
    read = parsed(bridge.bridge_read())
    assert status["success"] is True
    assert status["state"]["status"] == "queued"
    assert read["success"] is True
    assert "task body" in read["content"]


def test_adjudication_requires_matching_waiting_state(bridge_root):
    bridge.bridge_submit_command("task", command_id="cmd-1")
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
    outside = tmp_path / "outside"
    monkeypatch.setenv(op.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "workspace")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "direct")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PATHS_ENV, str(allowed))
    out = parsed(bridge.bridge_submit_command("task", command_id="cmd-1", root=str(outside)))
    assert out["success"] is False
    assert "not under" in out["error"].lower()


def test_read_result_returns_current_mailbox(bridge_root):
    bridge.bridge_submit_command("task", command_id="cmd-1")
    out = parsed(bridge.bridge_read_result("cmd-1"))
    assert out["success"] is True
    assert out["status"] == "queued"
    assert bridge.COMMAND_HEADING in out["content"]
