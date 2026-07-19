from __future__ import annotations

import json
from pathlib import Path

import operator_delegation as delegation


class FakePolicy:
    enabled = True
    level = "workspace"
    apply_mode = "direct"
    session_id = "ops_test"
    snapshot_hash = "snapshot"
    expires_at = 9999999999

    def require_enabled(self):
        return None

    def require_profile(self, profile, hermes_root):
        return None

    def require_read_path(self, path):
        return None

    def require_write_path(self, path):
        return None

    def require_level(self, level):
        assert level == "workspace"

    def require_mutation(self, dry_run):
        assert dry_run is False

    def require_verb(self, resource, verb):
        assert (resource, verb) == ("filesystem", "edit")


def test_apply_delegation_is_durable_and_excludes_terminal_web_and_skills(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(delegation.threading.Thread, "start", lambda self: None)

    result = json.loads(
        delegation.hermes_delegate_task(
            prompt="Edit the requested file.",
            workdir=str(tmp_path),
            mode="apply",
            timeout=120,
        )
    )

    assert result["success"] is True
    task = delegation._load(result["task_id"])
    tool_arg = task["argv"][task["argv"].index("-t") + 1]
    assert tool_arg == "file,todo"
    assert "terminal" not in task["argv"]
    assert "web" not in tool_arg
    assert "skills" not in tool_arg
    assert task["authority"]["session_id"] == "ops_test"
    assert task["prompt_sha256"]
    assert task["prompt_bytes"] == len("Edit the requested file.".encode("utf-8"))


def test_apply_delegation_rejects_web_before_launch(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    result = json.loads(
        delegation.hermes_delegate_task(
            prompt="Do work.",
            workdir=str(tmp_path),
            mode="apply",
            allow_web=True,
        )
    )
    assert result["success"] is False
    assert result["code"] == "DELEGATE_TASK_ERROR"
    assert not (tmp_path / "tasks").exists()


def test_status_result_message_and_cancel_lifecycle(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    task_id = "dt_" + "a" * 32
    task = {
        "task_id": task_id,
        "status": "queued",
        "mode": "apply",
        "profile": "default",
        "workdir": str(tmp_path),
        "created_at": 1,
        "updated_at": 1,
        "started_at": None,
        "finished_at": None,
        "pid": None,
        "returncode": None,
        "prompt_sha256": "abc",
        "stdout": "",
        "stderr": "",
        "messages": [],
        "authority": {"session_id": "ops_test", "level": "workspace", "apply_mode": "direct"},
    }
    delegation._save(task)

    status = json.loads(delegation.hermes_delegated_task_status(task_id))
    assert status["status"] == "queued"
    pending = json.loads(delegation.hermes_delegated_task_result(task_id))
    assert pending == {"success": True, "task_id": task_id, "status": "queued", "ready": False}

    message = json.loads(delegation.hermes_delegated_task_message(task_id, "Focus on the existing architecture."))
    assert message["message_count"] == 1

    cancelled = json.loads(delegation.hermes_delegated_task_cancel(task_id))
    assert cancelled["changed"] is True
    assert delegation._load(task_id)["status"] == "cancel_requested"


def test_result_redacts_and_returns_terminal_output(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    task_id = "dt_" + "b" * 32
    delegation._save({
        "task_id": task_id,
        "status": "completed",
        "returncode": 0,
        "stdout": "done",
        "stderr": "",
        "messages": [],
    })
    result = json.loads(delegation.hermes_delegated_task_result(task_id))
    assert result["success"] is True
    assert result["ready"] is True
    assert result["stdout"] == "done"
