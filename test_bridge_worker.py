from __future__ import annotations

import json
from pathlib import Path

import bridge_worker
import operator_bridge as bridge
import operator_policy as op


def test_worker_success_and_duplicate_prevention(tmp_path: Path, monkeypatch):
    root = tmp_path / "bridge"
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    monkeypatch.setenv(op.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "owner")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "direct")
    monkeypatch.setenv(op.OWNER_ACK_ENV, op.OWNER_ACK_REQUIRED_VALUE)
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PROFILES_ENV, "default")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PATHS_ENV, f"{root},{workdir}")
    monkeypatch.setenv(bridge.BRIDGE_ROOT_ENV, str(root))

    submitted = json.loads(bridge.bridge_submit_command("Perform the task.", command_id="cmd-1"))
    assert submitted["success"] is True

    def fake_run(**kwargs):
        assert kwargs["transport"] == "stdio"
        assert kwargs["mode"] == "apply"
        assert kwargs["apply"] is True
        assert kwargs["workdir"] == str(workdir)
        return json.dumps({"success": True, "returncode": 0, "stdout": "done", "stderr": ""})

    monkeypatch.setattr(bridge_worker.operator_agent, "hermes_agent_run", fake_run)
    result = bridge_worker.worker_once(root=str(root), workdir=str(workdir))
    assert result["success"] is True
    assert result["status"] == "success"
    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
    assert state["status"] == "success"
    assert list((root / "archive").glob("cmd-1.*.success.md"))
    assert bridge.SUCCESS_HEADING in (root / "bridge.md").read_text(encoding="utf-8")

    second = bridge_worker.worker_once(root=str(root), workdir=str(workdir))
    assert second["executed"] is False


def test_worker_routes_failure_to_adjudication(tmp_path: Path, monkeypatch):
    root = tmp_path / "bridge"
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    monkeypatch.setenv(op.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "owner")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "direct")
    monkeypatch.setenv(op.OWNER_ACK_ENV, op.OWNER_ACK_REQUIRED_VALUE)
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PROFILES_ENV, "default")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PATHS_ENV, f"{root},{workdir}")
    monkeypatch.setenv(bridge.BRIDGE_ROOT_ENV, str(root))
    bridge.bridge_submit_command("Perform the task.", command_id="cmd-2")
    monkeypatch.setattr(
        bridge_worker.operator_agent,
        "hermes_agent_run",
        lambda **kwargs: json.dumps({"success": False, "error": "blocked"}),
    )
    result = bridge_worker.worker_once(root=str(root), workdir=str(workdir))
    assert result["status"] == "adjudication_required"
    assert bridge.ADJUDICATION_HEADING in (root / "bridge.md").read_text(encoding="utf-8")
