from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import operator_delegation as delegation


class FakePolicy:
    enabled = True
    level = "workspace"
    apply_mode = "direct"
    session_id = "ops_test"
    snapshot_hash = "snapshot"
    expires_at = 9999999999
    readable_roots = []
    writable_roots = []
    verbs = {"filesystem": ["edit"]}
    allowed_profiles = ["default"]

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
    assert task["authority"]["snapshot_hash"] == "snapshot"
    assert task["authority"]["workdir"] == str(tmp_path)
    assert task["authority"]["mode"] == "apply"
    assert task["authority"]["evidence_required"] is True
    assert task["authority"]["evidence"] == ["changed_files", "substantive_output"]
    assert task["schema_version"] == delegation.TASK_SCHEMA_VERSION
    assert task["adapter"] == delegation.ADAPTER_NAME
    assert task["logical_work_id"].startswith("lw_")
    assert task["attempt_id"].startswith("da_")
    assert task["interaction_id"].startswith("di_")
    assert task["checkpoint_ref"]
    assert task["prompt_sha256"]
    assert task["prompt_bytes"] == len("Edit the requested file.".encode("utf-8"))


def test_prepare_runtime_home_is_writable_and_profile_minimal(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    profile_home = tmp_path / "profile"
    profile_home.mkdir()
    (profile_home / "config.yaml").write_text(
        "model:\n  provider: openrouter\n  default: test/model\nplugins:\n  enabled:\n    - chronos\n",
        encoding="utf-8",
    )
    (profile_home / ".env").write_text("OPENROUTER_API_KEY=secret\n", encoding="utf-8")
    monkeypatch.setattr(
        delegation.op,
        "resolve_profile_home",
        lambda profile, hermes_root: profile_home,
    )

    runtime_home = delegation._prepare_runtime_home(
        {"task_id": "dt_" + "c" * 32, "profile": "default"}
    )

    loaded = delegation.yaml.safe_load(
        (runtime_home / "config.yaml").read_text(encoding="utf-8")
    )
    assert loaded == {
        "model": {"provider": "openrouter", "default": "test/model"},
        "display": {"interface": "cli"},
    }
    assert (runtime_home / ".env").is_symlink()
    assert (runtime_home / "logs").parent == runtime_home
    (runtime_home / "logs").mkdir()
    (runtime_home / "logs" / "agent.log").write_text("ok\n", encoding="utf-8")


def test_delegate_task_forecast_reports_granted_authority(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)

    result = json.loads(
        delegation.hermes_delegate_task_forecast(
            workdir=str(tmp_path),
            mode="apply",
            timeout=120,
        )
    )

    assert result["success"] is True
    assert result["granted"] is True
    assert result["required"]["verbs"] == {"filesystem": ["edit"]}
    assert result["authority"]["session_id"] == "ops_test"
    assert result["authority"]["evidence_required"] is True


def test_antigravity_review_forecast_selects_host_runner(monkeypatch):
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)

    result = json.loads(
        delegation.hermes_delegate_task_forecast(
            workdir=str(delegation.op_antigravity.CANONICAL_WORKTREE),
            mode="read_only",
            profile="antigravity-operator",
        )
    )

    assert result["success"] is True
    assert result["route"] == "supervised-host-agy"
    assert result["tool"] == "hermes_antigravity_review_start"
    assert result["target_commit"] == delegation.op_antigravity.TARGET_COMMIT


def test_antigravity_review_delegation_routes_to_host_runner(monkeypatch):
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(
        delegation.op_antigravity,
        "hermes_antigravity_review_start",
        lambda dry_run: json.dumps({"success": True, "dry_run": dry_run, "job_id": "agr_test"}),
    )

    result = json.loads(
        delegation.hermes_delegate_task(
            prompt=(
                "Run operator-regression-independent-review with supervised-host-agy "
                f"for {delegation.op_antigravity.TARGET_COMMIT}."
            ),
            workdir=str(delegation.op_antigravity.CANONICAL_WORKTREE),
            mode="read_only",
            profile="antigravity-operator",
        )
    )

    assert result["success"] is True
    assert result["route"] == "supervised-host-agy"
    assert result["worker_kind"] == "official-antigravity-host-runner"
    assert result["routed_from"] == "hermes_delegate_task"
    assert result["dry_run"] is False


def test_tax_calculator_antigravity_forecast_selects_fixed_host_runner(monkeypatch):
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(
        delegation,
        "_resolve_workdir",
        lambda _value: delegation.op_antigravity_tax.TAX_CALCULATOR_ROOT,
    )
    monkeypatch.setattr(
        delegation.op_antigravity_tax,
        "start",
        lambda dry_run: json.dumps({"success": True, "dry_run": dry_run}),
    )

    result = json.loads(
        delegation.hermes_delegate_task_forecast(
            workdir=str(delegation.op_antigravity_tax.TAX_CALCULATOR_ROOT),
            mode="read_only",
            profile="antigravity-operator",
        )
    )

    assert result["success"] is True
    assert result["granted"] is True
    assert result["route"] == "supervised-host-agy-tax-review"
    assert result["required"]["policy_template"] == delegation.op_antigravity_tax.REQUIRED_TEMPLATE
    assert result["required"]["total_task_window"] == 8 * 60 * 60
    assert result["required"]["worker_slice_timeout"] == 60 * 60
    assert result["required"]["maximum_continuations"] == 8
    assert result["target_commits"] == list(delegation.op_antigravity_tax.TARGET_COMMITS)


def test_tax_calculator_antigravity_delegation_and_lifecycle_route_to_fixed_runner(monkeypatch):
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(
        delegation,
        "_resolve_workdir",
        lambda _value: delegation.op_antigravity_tax.TAX_CALCULATOR_ROOT,
    )
    task_id = delegation.op_antigravity_tax.TASK_ID_PREFIX + "a" * 20
    monkeypatch.setattr(
        delegation.op_antigravity_tax,
        "start",
        lambda dry_run: json.dumps({"success": True, "dry_run": dry_run, "task_id": task_id, "status": "queued"}),
    )
    monkeypatch.setattr(
        delegation.op_antigravity_tax,
        "status",
        lambda value: json.dumps({"success": True, "task_id": value, "status": "running"}),
    )
    monkeypatch.setattr(
        delegation.op_antigravity_tax,
        "result",
        lambda value: json.dumps({"success": True, "task_id": value, "status": "completed", "ready": True}),
    )
    monkeypatch.setattr(
        delegation.op_antigravity_tax,
        "cancel",
        lambda value, dry_run: json.dumps({"success": True, "task_id": value, "dry_run": dry_run, "status": "cancel_requested"}),
    )

    result = json.loads(
        delegation.hermes_delegate_task(
            prompt=(
                "Independent Projections Calculator completion review for commits "
                + " ".join(delegation.op_antigravity_tax.TARGET_COMMITS)
            ),
            workdir=str(delegation.op_antigravity_tax.TAX_CALCULATOR_ROOT),
            mode="read_only",
            profile="antigravity-operator",
        )
    )

    assert result["success"] is True
    assert result["route"] == "supervised-host-agy-tax-review"
    assert result["worker_kind"] == "official-antigravity-host-runner"
    assert result["total_task_window"] == 8 * 60 * 60
    assert json.loads(delegation.hermes_delegated_task_status(task_id))["status"] == "running"
    assert json.loads(delegation.hermes_delegated_task_result(task_id))["ready"] is True
    assert json.loads(delegation.hermes_delegated_task_cancel(task_id))["status"] == "cancel_requested"


def test_delegate_task_forecast_reports_denial_without_queuing(monkeypatch, tmp_path):
    result = json.loads(
        delegation.hermes_delegate_task_forecast(
            workdir=str(tmp_path),
            mode="apply",
            allow_web=True,
        )
    )

    assert result["success"] is True
    assert result["granted"] is False
    assert result["denial"]["code"] == "DELEGATE_TASK_FORECAST_DENIED"


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
        "events": [],
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


def test_assess_outcome_marks_empty_model_response_incomplete(tmp_path):
    task = {"mode": "apply"}
    status, reason = delegation._assess_outcome(
        task=task,
        rc=0,
        stdout="No reply: the model returned empty content after retries.",
        stderr="",
        changed_files=["changed.txt"],
    )
    assert status == "incomplete"
    assert "empty-response" in reason


def test_assess_outcome_marks_timeout_distinct_from_failure(tmp_path):
    status, reason = delegation._assess_outcome(
        task={"mode": "apply"},
        rc=124,
        stdout="partial",
        stderr="",
        changed_files=[],
    )
    assert status == "timed_out"
    assert "timeout" in reason


def test_assess_outcome_requires_apply_change_evidence(tmp_path):
    task = {"mode": "apply"}
    status, reason = delegation._assess_outcome(
        task=task,
        rc=0,
        stdout="I inspected the workspace.",
        stderr="",
        changed_files=[],
    )
    assert status == "incomplete"
    assert "no workspace changes" in reason


def test_assess_outcome_completes_with_output_and_change_evidence(tmp_path):
    task = {"mode": "apply"}
    status, reason = delegation._assess_outcome(
        task=task,
        rc=0,
        stdout="Updated the requested project record.",
        stderr="",
        changed_files=["project.md"],
    )
    assert status == "completed"
    assert "substantive output" in reason


def test_duplicate_logical_work_returns_existing_task(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(delegation.threading.Thread, "start", lambda self: None)

    first = json.loads(
        delegation.hermes_delegate_task(
            prompt="Edit the requested file.",
            workdir=str(tmp_path),
            mode="apply",
            timeout=120,
        )
    )
    second = json.loads(
        delegation.hermes_delegate_task(
            prompt="Edit   the requested file.",
            workdir=str(tmp_path),
            mode="apply",
            timeout=120,
        )
    )

    assert first["success"] is True
    assert second["duplicate"] is True
    assert second["task_id"] == first["task_id"]
    assert second["logical_work_id"] == first["logical_work_id"]
    assert second["resolution"] == "existing_task_returned"


def test_checkpoint_written_for_resumable_task(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    task = {
        "schema_version": delegation.TASK_SCHEMA_VERSION,
        "logical_work_id": "lw_test",
        "task_id": "dt_" + "d" * 32,
        "attempt_id": "da_" + "a" * 32,
        "interaction_id": "di_" + "i" * 32,
        "continuation_sequence": 0,
        "status": "incomplete",
        "profile": "default",
        "adapter": delegation.ADAPTER_NAME,
        "workdir": str(tmp_path),
        "changed_files": [],
        "returncode": 0,
        "outcome_reason": "model produced an explicit empty-response/fallback failure",
        "stdout": "No reply: the model returned empty content after retries.",
        "stderr": "",
        "retry_count": 0,
        "updated_at": 1,
    }

    path = Path(delegation._write_checkpoint(task, reason="empty response"))
    loaded = json.loads(path.read_text(encoding="utf-8"))

    assert loaded["logical_work_id"] == "lw_test"
    assert loaded["state"] == "incomplete"
    assert loaded["checkpoint_id"].startswith("cp_")
    assert "resume_instructions" in loaded
    assert task["checkpoint_ref"] == str(path)


def test_continuation_links_to_previous_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(delegation.threading.Thread, "start", lambda self: None)
    previous_id = "dt_" + "e" * 32
    previous = {
        "schema_version": delegation.TASK_SCHEMA_VERSION,
        "adapter": delegation.ADAPTER_NAME,
        "worker_kind": "hermes-profile-worker",
        "logical_work_id": "lw_resume",
        "task_id": previous_id,
        "attempt_id": "da_old",
        "interaction_id": "di_old",
        "continuation_sequence": 0,
        "status": "incomplete",
        "mode": "apply",
        "profile": "default",
        "workdir": str(tmp_path),
        "max_turns": 2,
        "timeout": 60,
        "allow_web": False,
        "created_at": 1,
        "updated_at": 1,
        "messages": [],
        "checkpoint_ref": str(tmp_path / "checkpoint.json"),
        "authority": {
            "session_id": "ops_test",
            "snapshot_hash": "snapshot",
            "expires_at": 9999999999,
            "profile": "default",
            "workdir": str(tmp_path),
            "mode": "apply",
        },
    }
    delegation._save(previous)

    result = json.loads(
        delegation.hermes_delegated_task_continue(
            previous_id,
            "Continue only the remaining work.",
        )
    )
    new_task = delegation._load(result["task_id"])

    assert result["success"] is True
    assert result["previous_task_id"] == previous_id
    assert result["logical_work_id"] == "lw_resume"
    assert new_task["previous_checkpoint_ref"] == previous["checkpoint_ref"]
    assert new_task["continuation_sequence"] == 1
    assert new_task["interaction_id"] != previous["interaction_id"]


def test_mission_control_upsert_is_idempotent(monkeypatch, tmp_path):
    db = tmp_path / "kanban.db"
    with sqlite3.connect(db) as connection:
        connection.executescript(
            """
            CREATE TABLE tasks (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                body TEXT,
                assignee TEXT,
                status TEXT NOT NULL,
                priority INTEGER DEFAULT 0,
                created_by TEXT,
                created_at INTEGER NOT NULL,
                workspace_kind TEXT NOT NULL DEFAULT 'scratch',
                workspace_path TEXT,
                result TEXT,
                idempotency_key TEXT,
                session_id TEXT
            );
            CREATE TABLE task_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                run_id INTEGER,
                kind TEXT NOT NULL,
                payload TEXT,
                created_at INTEGER NOT NULL
            );
            """
        )
    monkeypatch.setenv(delegation.MISSION_CONTROL_DB_ENV, str(db))
    task = {
        "logical_work_id": "lw_mc",
        "task_id": "dt_mc",
        "attempt_id": "da_mc",
        "interaction_id": "di_mc",
        "status": "running",
        "profile": "antigravity-operator",
        "workdir": str(tmp_path),
        "checkpoint_ref": None,
        "outcome_reason": "",
        "authority": {"session_id": "ops_test"},
    }

    delegation._record_mission_control(task, event="running")
    task["status"] = "completed"
    task["checkpoint_ref"] = "checkpoint"
    delegation._record_mission_control(task, event="completed")

    with sqlite3.connect(db) as connection:
        task_count = connection.execute("SELECT count(*) FROM tasks").fetchone()[0]
        event_count = connection.execute("SELECT count(*) FROM task_events").fetchone()[0]
        status = connection.execute("SELECT status FROM tasks WHERE id='lw_mc'").fetchone()[0]

    assert task_count == 1
    assert event_count == 2
    assert status == "Completed"


def test_require_task_authority_rejects_snapshot_replacement(monkeypatch, tmp_path):
    class ReplacedPolicy(FakePolicy):
        snapshot_hash = "replacement"

    monkeypatch.setattr(delegation.op, "OperatorPolicy", ReplacedPolicy)
    task = {
        "profile": "default",
        "workdir": str(tmp_path),
        "mode": "apply",
        "authority": {
            "session_id": "ops_test",
            "snapshot_hash": "snapshot",
            "expires_at": 9999999999,
            "profile": "default",
            "workdir": str(tmp_path),
            "mode": "apply",
        },
    }

    try:
        delegation._require_task_authority(task)
    except PermissionError as exc:
        assert "snapshot changed" in str(exc)
    else:
        raise AssertionError("snapshot replacement should invalidate delegated authority")


def test_require_task_authority_rejects_expired_envelope(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation, "_now", lambda: 100)
    task = {
        "profile": "default",
        "workdir": str(tmp_path),
        "mode": "apply",
        "authority": {
            "session_id": "ops_test",
            "snapshot_hash": "snapshot",
            "expires_at": 99,
            "profile": "default",
            "workdir": str(tmp_path),
            "mode": "apply",
        },
    }

    try:
        delegation._require_task_authority(task)
    except PermissionError as exc:
        assert "expired" in str(exc)
    else:
        raise AssertionError("expired delegated authority should be rejected")


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
    assert result["final_answer"] == "done"
    assert result["final_answer_extraction_status"] == "legacy_single_line"
    assert "stderr" in result
    assert "messages" in result
    assert "changed_files" in result


def test_extract_final_answer_legacy_token_after_diagnostics_and_reasoning():
    stdout = (
        "⚠ tirith security scanner enabled but not available — command scanning will use pattern matching only\n"
        "┌─ Reasoning ─────────────────────────────┐\n"
        "The file contains Result: PASS. I must return the requested token.\n"
        "HERMES_CONNECTOR_DELEGATION_OK\n"
    )

    answer, status = delegation._extract_final_answer(stdout)

    assert answer == "HERMES_CONNECTOR_DELEGATION_OK"
    assert status == "legacy_terminal_token"


def test_extract_final_answer_prefers_structured_multiline_block():
    stdout = (
        "diagnostic before response\n"
        f"{delegation.FINAL_ANSWER_BEGIN}\n"
        "First line\nSecond line\n"
        f"{delegation.FINAL_ANSWER_END}\n"
        "HERMES_SLICE_STATUS: COMPLETE\n"
    )

    answer, status = delegation._extract_final_answer(stdout)

    assert answer == "First line\nSecond line"
    assert status == "structured_delimiters"


def test_extract_final_answer_fails_closed_for_incomplete_structured_block():
    stdout = (
        f"{delegation.FINAL_ANSWER_BEGIN}\n"
        "partial answer without closing delimiter\n"
        "HERMES_CONNECTOR_DELEGATION_OK\n"
    )

    answer, status = delegation._extract_final_answer(stdout)

    assert answer is None
    assert status == "structured_incomplete"


def test_extract_final_answer_fails_closed_for_ambiguous_legacy_transcript():
    stdout = "I inspected the file.\nI think the final response should confirm success.\n"

    answer, status = delegation._extract_final_answer(stdout)

    assert answer is None
    assert status == "unstructured_ambiguous"


def test_extract_final_answer_returns_not_found_for_diagnostics_only():
    stdout = (
        "⚠ tirith security scanner enabled but not available\n"
        "┌─ Reasoning ─────────────────────────────┐\n"
        "HERMES_SLICE_STATUS: FAILED\n"
    )

    answer, status = delegation._extract_final_answer(stdout)

    assert answer is None
    assert status == "not_found"


def test_extract_final_answer_preserves_redaction(monkeypatch):
    monkeypatch.setattr(
        delegation.op,
        "redact_output",
        lambda value: value.replace("secret-value", "[REDACTED]"),
    )
    stdout = (
        f"{delegation.FINAL_ANSWER_BEGIN}\n"
        "Result contains secret-value\n"
        f"{delegation.FINAL_ANSWER_END}\n"
    )

    answer, status = delegation._extract_final_answer(stdout)

    assert answer == "Result contains [REDACTED]"
    assert status == "structured_delimiters"


def test_build_argv_requires_structured_final_answer_delimiters(tmp_path):
    argv = delegation._build_argv(
        prompt="Return a result.",
        mode="read_only",
        profile="default",
        workdir=tmp_path,
        max_turns=10,
        allow_web=False,
    )
    effective_prompt = argv[argv.index("-q") + 1]

    assert delegation.FINAL_ANSWER_BEGIN in effective_prompt
    assert delegation.FINAL_ANSWER_END in effective_prompt
    assert "Keep reasoning, diagnostics, warnings" in effective_prompt


ALL_LONG_HORIZON_STOPS = sorted(delegation.LONG_HORIZON_STOP_CONDITIONS)


def _long_horizon_task(tmp_path: Path, *, status: str = "timed_out") -> dict:
    task_id = "dt_" + "h" * 32
    return {
        "schema_version": delegation.TASK_SCHEMA_VERSION,
        "adapter": delegation.ADAPTER_NAME,
        "worker_kind": "hermes-profile-worker",
        "logical_work_id": "lw_long_horizon",
        "root_task_id": task_id,
        "task_id": task_id,
        "attempt_id": "da_long",
        "interaction_id": "di_long",
        "continuation_sequence": 0,
        "status": status,
        "mode": "apply",
        "profile": "default",
        "workdir": str(tmp_path),
        "max_turns": 30,
        "timeout": 3600,
        "allow_web": False,
        "created_at": 1,
        "updated_at": 1,
        "started_at": 1,
        "finished_at": 2,
        "pid": None,
        "returncode": 124 if status == "timed_out" else 1,
        "stdout": "partial progress" if status == "timed_out" else "",
        "stderr": "",
        "messages": [],
        "changed_files": [],
        "outcome_reason": "delegated attempt exceeded its bounded execution timeout" if status == "timed_out" else "process failed",
        "failure_category": "timeout" if status == "timed_out" else "process_failure",
        "provider_error_category": None,
        "retry_count": 0,
        "checkpoint_sequence": 1,
        "checkpoint_ref": str(tmp_path / "checkpoint.json"),
        "events": [],
        "chain_cancelled": False,
        "long_horizon": {
            "enabled": True,
            "total_task_window": 28800,
            "worker_slice_timeout": 3600,
            "maximum_continuations": 8,
            "resume_from_checkpoint": True,
            "stop_on": ALL_LONG_HORIZON_STOPS,
            "envelope_started_at": 1,
            "envelope_deadline": 9999999999,
            "root_task_id": task_id,
            "continuation_count": 0,
            "consecutive_failure_count": 0,
            "previous_failure_signature": None,
            "latest_task_id": task_id,
            "final_stop_reason": None,
        },
        "authority": {
            "session_id": "ops_test",
            "snapshot_hash": "snapshot",
            "expires_at": 9999999999,
            "profile": "default",
            "workdir": str(tmp_path),
            "mode": "apply",
        },
    }


def test_long_horizon_accepts_eight_hour_envelope(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(delegation, "_now", lambda: 100)

    result = json.loads(
        delegation.hermes_delegate_task_forecast(
            workdir=str(tmp_path),
            mode="apply",
            timeout=1800,
            worker_slice_timeout=3600,
            total_task_window=28800,
            maximum_continuations=8,
            resume_from_checkpoint=True,
            stop_on=ALL_LONG_HORIZON_STOPS,
        )
    )

    assert result["granted"] is True
    assert result["required"]["total_task_window"] == 28800
    assert result["required"]["worker_slice_timeout"] == 3600
    assert result["required"]["maximum_continuations"] == 8
    assert result["authority"]["long_horizon"]["envelope_deadline"] == 28900


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"worker_slice_timeout": 3601}, "worker_slice_timeout"),
        ({"total_task_window": 28801}, "total_task_window"),
        ({"maximum_continuations": 9}, "maximum_continuations"),
        ({"timeout": 120, "worker_slice_timeout": 60}, "conflicts"),
        (
            {
                "total_task_window": 7200,
                "worker_slice_timeout": 3600,
                "maximum_continuations": 1,
                "resume_from_checkpoint": True,
                "stop_on": ALL_LONG_HORIZON_STOPS[:-1],
            },
            "requires all governed",
        ),
        (
            {
                "total_task_window": 7200,
                "worker_slice_timeout": 3600,
                "maximum_continuations": 1,
                "resume_from_checkpoint": True,
                "stop_on": ALL_LONG_HORIZON_STOPS + ["forever"],
            },
            "Unknown stop_on",
        ),
    ],
)
def test_long_horizon_rejects_invalid_bounds(kwargs, message):
    with pytest.raises(ValueError, match=message):
        delegation._normalize_long_horizon(
            timeout=kwargs.pop("timeout", 1800),
            worker_slice_timeout=kwargs.pop("worker_slice_timeout", None),
            total_task_window=kwargs.pop("total_task_window", None),
            maximum_continuations=kwargs.pop("maximum_continuations", 0),
            resume_from_checkpoint=kwargs.pop("resume_from_checkpoint", False),
            stop_on=kwargs.pop("stop_on", None),
            authority_expires_at=9999999999,
            now=100,
        )


def test_long_horizon_rejects_window_beyond_authority_expiry():
    with pytest.raises(PermissionError, match="authority expiry"):
        delegation._normalize_long_horizon(
            timeout=1800,
            worker_slice_timeout=3600,
            total_task_window=28800,
            maximum_continuations=8,
            resume_from_checkpoint=True,
            stop_on=ALL_LONG_HORIZON_STOPS,
            authority_expires_at=200,
            now=100,
        )


@pytest.mark.parametrize(
    ("marker", "expected_status", "expected_stop"),
    [
        ("COMPLETE", "completed", None),
        ("CONTINUE", "incomplete", None),
        ("BLOCKED_MATERIAL_SCOPE_CHANGE", "blocked", "material_scope_change"),
        ("BLOCKED_UNSAFE_ACTION", "blocked", "unsafe_action"),
        ("FAILED", "failed", None),
    ],
)
def test_long_horizon_slice_control_protocol(marker, expected_status, expected_stop):
    task = {"mode": "apply", "long_horizon": {"enabled": True, "final_stop_reason": None}}
    status, _ = delegation._assess_outcome(
        task=task,
        rc=0,
        stdout=f"work summary\nHERMES_SLICE_STATUS: {marker}",
        stderr="",
        changed_files=["changed.txt"],
    )
    assert status == expected_status
    assert task["long_horizon"].get("final_stop_reason") == expected_stop


def test_timeout_remains_resumable_even_if_output_contains_complete_marker():
    task = {"mode": "apply", "long_horizon": {"enabled": True}}
    status, _ = delegation._assess_outcome(
        task=task,
        rc=124,
        stdout="HERMES_SLICE_STATUS: COMPLETE",
        stderr="",
        changed_files=["changed.txt"],
    )
    assert status == "timed_out"


def test_scheduler_auto_continues_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    task = _long_horizon_task(tmp_path, status="timed_out")
    delegation._save(task)
    calls = []

    def fake_continue(task_id, prompt, max_turns=None, timeout=None, _automatic=False):
        calls.append((task_id, prompt, timeout, _automatic))
        return json.dumps({"success": True, "task_id": "dt_child"})

    monkeypatch.setattr(delegation, "hermes_delegated_task_continue", fake_continue)
    delegation._schedule_automatic_continuation(task["task_id"])

    assert len(calls) == 1
    assert calls[0][0] == task["task_id"]
    assert calls[0][2] == 3600
    assert calls[0][3] is True


def test_scheduler_auto_continues_explicit_continue(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    task = _long_horizon_task(tmp_path, status="incomplete")
    task["outcome_reason"] = "long-horizon worker requested continuation from checkpoint"
    task["failure_category"] = "evidence_failure"
    delegation._save(task)
    calls = []
    monkeypatch.setattr(
        delegation,
        "hermes_delegated_task_continue",
        lambda *args, **kwargs: calls.append((args, kwargs)) or json.dumps({"success": True}),
    )

    delegation._schedule_automatic_continuation(task["task_id"])

    assert calls
    assert calls[0][1]["_automatic"] is True


def test_scheduler_stops_on_completion(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    task = _long_horizon_task(tmp_path, status="completed")
    task["returncode"] = 0
    delegation._save(task)
    monkeypatch.setattr(
        delegation,
        "hermes_delegated_task_continue",
        lambda *args, **kwargs: pytest.fail("completion must not continue"),
    )

    delegation._schedule_automatic_continuation(task["task_id"])

    assert delegation._load(task["task_id"])["long_horizon"]["final_stop_reason"] == "completion"


def test_scheduler_stops_on_repeated_identical_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    task = _long_horizon_task(tmp_path, status="failed")
    signature = delegation._failure_signature(task)
    task["long_horizon"]["previous_failure_signature"] = signature
    task["long_horizon"]["consecutive_failure_count"] = 1
    delegation._save(task)
    monkeypatch.setattr(
        delegation,
        "hermes_delegated_task_continue",
        lambda *args, **kwargs: pytest.fail("repeated failure must stop"),
    )

    delegation._schedule_automatic_continuation(task["task_id"])

    assert delegation._load(task["task_id"])["long_horizon"]["final_stop_reason"] == "repeated_failure"


@pytest.mark.parametrize(
    ("mutator", "expected_reason"),
    [
        (lambda task: task["long_horizon"].update({"envelope_deadline": 100}), "envelope_deadline"),
        (lambda task: task["long_horizon"].update({"continuation_count": 8}), "continuation_limit"),
        (lambda task: task.update({"chain_cancelled": True}), "cancelled"),
    ],
)
def test_scheduler_stops_on_hard_envelope_conditions(monkeypatch, tmp_path, mutator, expected_reason):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation, "_now", lambda: 100)
    task = _long_horizon_task(tmp_path, status="timed_out")
    mutator(task)
    delegation._save(task)
    monkeypatch.setattr(
        delegation,
        "hermes_delegated_task_continue",
        lambda *args, **kwargs: pytest.fail("hard stop must not continue"),
    )

    delegation._schedule_automatic_continuation(task["task_id"])

    assert delegation._load(task["task_id"])["long_horizon"]["final_stop_reason"] == expected_reason


def test_scheduler_stops_when_authority_is_withdrawn(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    task = _long_horizon_task(tmp_path, status="timed_out")
    delegation._save(task)
    monkeypatch.setattr(
        delegation,
        "_require_task_authority",
        lambda task: (_ for _ in ()).throw(PermissionError("expired")),
    )

    delegation._schedule_automatic_continuation(task["task_id"])

    assert delegation._load(task["task_id"])["long_horizon"]["final_stop_reason"] == "authority_expiry"


def test_automatic_continuation_preserves_root_and_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.threading.Thread, "start", lambda self: None)
    previous = _long_horizon_task(tmp_path, status="timed_out")
    delegation._save(previous)

    result = json.loads(
        delegation.hermes_delegated_task_continue(
            previous["task_id"],
            "Continue remaining work.",
            timeout=60,
            _automatic=True,
        )
    )
    child = delegation._load(result["task_id"])

    assert result["success"] is True
    assert result["automatic"] is True
    assert child["root_task_id"] == previous["task_id"]
    assert child["previous_task_id"] == previous["task_id"]
    assert child["previous_checkpoint_ref"] == previous["checkpoint_ref"]
    assert child["long_horizon"]["continuation_count"] == 1
    assert child["long_horizon"]["latest_task_id"] == child["task_id"]
    assert "HERMES_SLICE_STATUS" in child["argv"][-1]


def test_root_status_and_result_resolve_latest_child(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    root = _long_horizon_task(tmp_path, status="timed_out")
    child_id = "dt_" + "c" * 32
    child = dict(root)
    child.update(
        {
            "task_id": child_id,
            "attempt_id": "da_child",
            "interaction_id": "di_child",
            "continuation_sequence": 1,
            "status": "completed",
            "returncode": 0,
            "stdout": "final result",
            "outcome_reason": "complete",
            "created_at": 2,
            "updated_at": 2,
        }
    )
    child["long_horizon"] = dict(root["long_horizon"])
    child["long_horizon"].update(
        {"continuation_count": 1, "latest_task_id": child_id, "final_stop_reason": "completion"}
    )
    delegation._save(root)
    delegation._save(child)

    status = json.loads(delegation.hermes_delegated_task_status(root["task_id"]))
    result = json.loads(delegation.hermes_delegated_task_result(root["task_id"]))

    assert status["requested_task_id"] == root["task_id"]
    assert status["latest_task_id"] == child_id
    assert status["status"] == "completed"
    assert result["result_task_id"] == child_id
    assert result["stdout"] == "final result"
    assert result["continuation_count"] == 1
    assert result["final_stop_reason"] == "completion"


def test_chain_cancel_handles_awaiting_continuation_state(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    task = _long_horizon_task(tmp_path, status="awaiting_continuation")
    delegation._save(task)

    result = json.loads(delegation.hermes_delegated_task_cancel(task["task_id"]))

    assert result["success"] is True
    assert result["chain_cancelled"] is True
    assert delegation._load(task["task_id"])["status"] == "cancelled"
