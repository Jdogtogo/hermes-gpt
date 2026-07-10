from __future__ import annotations

import fcntl
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import bridge_worker
import operator_bridge as bridge
import operator_policy as op


@pytest.fixture
def worker_env(tmp_path: Path, monkeypatch):
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
    op.set_audit_log_override(tmp_path / "audit.jsonl")
    yield root, workdir
    op.set_audit_log_override(None)


def submit(root: Path, workdir: Path, command_id: str = "cmd-1"):
    return json.loads(
        bridge.bridge_submit_command(
            "Perform the task.",
            workdir=str(workdir),
            command_id=command_id,
        )
    )


def test_worker_success_and_duplicate_prevention(worker_env, monkeypatch):
    root, workdir = worker_env
    assert submit(root, workdir)["success"] is True

    def fake_run(**kwargs):
        assert kwargs["transport"] == "stdio"
        assert kwargs["mode"] == "apply"
        assert kwargs["apply"] is True
        assert kwargs["workdir"] == str(workdir)
        assert kwargs["prompt"] == "Perform the task."
        return json.dumps(
            {"success": True, "returncode": 0, "stdout": "done", "stderr": ""}
        )

    monkeypatch.setattr(bridge_worker.operator_agent, "hermes_agent_run", fake_run)
    result = bridge_worker.worker_once(root=str(root))
    assert result["success"] is True
    assert result["status"] == "success"
    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
    assert state["status"] == "success"
    assert list((root / "archive").glob("cmd-1.attempt-1.*.success.md"))
    assert bridge.SUCCESS_HEADING in (root / "bridge.md").read_text(encoding="utf-8")

    second = bridge_worker.worker_once(root=str(root))
    assert second["executed"] is False


def test_worker_routes_failure_to_adjudication(worker_env, monkeypatch):
    root, workdir = worker_env
    assert submit(root, workdir, "cmd-2")["success"] is True
    monkeypatch.setattr(
        bridge_worker.operator_agent,
        "hermes_agent_run",
        lambda **kwargs: json.dumps({"success": False, "error": "blocked"}),
    )
    result = bridge_worker.worker_once(root=str(root))
    assert result["status"] == "adjudication_required"
    assert bridge.ADJUDICATION_HEADING in (root / "bridge.md").read_text(encoding="utf-8")


def test_worker_exception_becomes_adjudication_not_stuck_running(worker_env, monkeypatch):
    root, workdir = worker_env
    assert submit(root, workdir, "cmd-exception")["success"] is True

    def explode(**kwargs):
        raise RuntimeError("simulated execution crash")

    monkeypatch.setattr(bridge_worker.operator_agent, "hermes_agent_run", explode)
    result = bridge_worker.worker_once(root=str(root))
    assert result["status"] == "adjudication_required"
    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
    assert state["status"] == "adjudication_required"
    assert "WORKER_EXECUTION_EXCEPTION" in (root / "bridge.md").read_text(encoding="utf-8")


def test_worker_recovers_stale_running_without_reexecuting(worker_env, monkeypatch):
    root, workdir = worker_env
    assert submit(root, workdir, "cmd-stale")["success"] is True
    state_path = root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["status"] = "running"
    state["attempt"] = 1
    state["claimed_at"] = (datetime.now(timezone.utc) - timedelta(seconds=700)).isoformat()
    state_path.write_text(json.dumps(state), encoding="utf-8")

    called = False

    def should_not_run(**kwargs):
        nonlocal called
        called = True
        return json.dumps({"success": True})

    monkeypatch.setattr(bridge_worker.operator_agent, "hermes_agent_run", should_not_run)
    result = bridge_worker.worker_once(root=str(root), timeout=600)
    assert result["status"] == "adjudication_required"
    assert result["recovered_stale_run"] is True
    assert called is False


def test_worker_lock_prevents_concurrent_execution(worker_env):
    root, workdir = worker_env
    assert submit(root, workdir, "cmd-lock")["success"] is True
    bridge._layout(root)
    handle = (root / "worker.lock").open("a+", encoding="utf-8")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        result = bridge_worker.worker_once(root=str(root))
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()
    assert result == {"success": True, "executed": False, "status": "worker_busy"}


def test_adjudicated_retry_includes_binding_verdict(worker_env, monkeypatch):
    root, workdir = worker_env
    assert submit(root, workdir, "cmd-adjudicated")["success"] is True
    state_path = root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["status"] = "adjudication_required"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    accepted = json.loads(
        bridge.bridge_write_adjudication(
            "cmd-adjudicated",
            "Use the safe fallback and do not modify configuration.",
        )
    )
    assert accepted["success"] is True

    captured = {}

    def fake_run(**kwargs):
        captured["prompt"] = kwargs["prompt"]
        return json.dumps({"success": True, "returncode": 0})

    monkeypatch.setattr(bridge_worker.operator_agent, "hermes_agent_run", fake_run)
    result = bridge_worker.worker_once(root=str(root))
    assert result["status"] == "success"
    assert "Binding adjudication from ChatGPT" in captured["prompt"]
    assert "Use the safe fallback" in captured["prompt"]


def test_missing_mailbox_escalates_instead_of_looping_queued(worker_env, monkeypatch):
    root, workdir = worker_env
    assert submit(root, workdir, "cmd-missing-mailbox")["success"] is True
    (root / "bridge.md").unlink()

    called = False

    def should_not_run(**kwargs):
        nonlocal called
        called = True
        return json.dumps({"success": True})

    monkeypatch.setattr(bridge_worker.operator_agent, "hermes_agent_run", should_not_run)
    result = bridge_worker.worker_once(root=str(root))
    assert result["status"] == "adjudication_required"
    assert called is False
    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
    assert state["status"] == "adjudication_required"
    text = (root / "bridge.md").read_text(encoding="utf-8")
    assert "WORKER_EXECUTION_EXCEPTION" in text
    assert "original command content unavailable" in text
