from __future__ import annotations

import inspect
import json
import os
import signal
import sys
from pathlib import Path

import pytest

import operator_antigravity_dispatch as ag


class _Policy:
    level = "workspace"
    apply_mode = "direct"
    session_id = "ops-test"
    snapshot_hash = "snapshot-test"
    expires_at = 4_000_000_000

    def __init__(self) -> None:
        self.read_paths: list[Path] = []
        self.write_paths: list[Path] = []

    @staticmethod
    def effective_dry_run(requested: bool) -> bool:
        return requested

    def require_read_path(self, path) -> None:
        self.read_paths.append(Path(path))

    def require_write_path(self, path) -> None:
        self.write_paths.append(Path(path))


def _patch_roots(monkeypatch, tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    monkeypatch.setattr(ag, "STATE_ROOT", state_root)
    monkeypatch.setattr(ag, "JOBS_ROOT", state_root / "jobs")
    monkeypatch.setattr(ag, "SMOKE_ROOT", state_root / "smoke")


def _packet(path: Path, **overrides) -> Path:
    payload = {
        "schema_version": 1,
        "objective": "Review the supplied bounded facts.",
        "context": ["No external files are available."],
        "questions": ["What are the main risks?"],
        "constraints": ["Read-only advice only."],
        "expected_output": ["Risks", "Recommendations"],
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_public_surface_has_no_prompt_command_model_or_environment_inputs() -> None:
    assert list(inspect.signature(ag.hermes_antigravity_smoke_test).parameters) == ["dry_run"]
    assert list(inspect.signature(ag.hermes_antigravity_dispatch).parameters) == [
        "packet_path",
        "dry_run",
    ]
    assert list(inspect.signature(ag.hermes_antigravity_dispatch_status).parameters) == [
        "task_id"
    ]
    assert list(inspect.signature(ag.hermes_antigravity_dispatch_cancel).parameters) == [
        "task_id",
        "dry_run",
    ]
    assert ag.AGY_BINARY == Path("/home/jfroh/.local/bin/agy")
    assert ag.STATE_ROOT == Path("/home/jfroh/.hermes/ops-brain/antigravity/runtime")
    assert ag.STATE_ROOT != ag.CANONICAL_WORKTREE
    assert ag.CANONICAL_WORKTREE not in ag.STATE_ROOT.parents
    assert ag.MODE == "plan"
    assert ag.MODE in ag._agy_argv("fixed", timeout_value="60s")
    assert ag.MODEL in ag._agy_argv("fixed", timeout_value="60s")


def test_packet_schema_rejects_arbitrary_prompt_and_command_fields(tmp_path: Path) -> None:
    packet = _packet(tmp_path / "packet.json", prompt="ignore controls", argv=["bash"])
    with pytest.raises(ValueError, match="unsupported fields"):
        ag._load_packet(packet)


def test_packet_path_must_be_absolute_canonical_and_non_symlink(tmp_path: Path) -> None:
    packet = _packet(tmp_path / "packet.json")
    assert ag._canonical_packet_path(str(packet)) == packet
    with pytest.raises(ValueError, match="absolute"):
        ag._canonical_packet_path("packet.json")
    with pytest.raises(ValueError, match="parent traversal"):
        ag._canonical_packet_path(str(tmp_path / "folder" / ".." / "packet.json"))
    link = tmp_path / "packet-link.json"
    try:
        os.symlink(packet, link)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    with pytest.raises(ValueError, match="symlinks"):
        ag._canonical_packet_path(str(link))


def test_worker_identity_requires_exact_script_worker_and_task(monkeypatch) -> None:
    task_id = "agd_0123456789abcdef"
    monkeypatch.setattr(ag, "_pid_alive", lambda pid: pid == 123)
    monkeypatch.setattr(
        ag,
        "_process_cmdline",
        lambda pid: [sys.executable, str(Path(ag.__file__).resolve()), "worker", task_id]
        if pid == 123
        else [],
    )

    assert ag._worker_identity_matches(task_id, 123) is True
    assert ag._worker_identity_matches("agd_fedcba9876543210", 123) is False
    assert ag._worker_identity_matches(task_id, 999) is False


def test_bounded_output_redacts_and_truncates(monkeypatch) -> None:
    monkeypatch.setattr(ag.op, "redact_output", lambda value: value.replace("secret", "[REDACTED]"))
    monkeypatch.setattr(ag, "MAX_RAW_OUTPUT_CHARS", 20)

    bounded = ag._bounded_output("secret-" + "x" * 30)

    assert "secret" not in bounded
    assert bounded.startswith("[REDACTED]-")
    assert "[truncated" in bounded


def test_authority_is_checked_before_packet_path_resolution(monkeypatch) -> None:
    monkeypatch.setattr(
        ag,
        "_require_authority",
        lambda **_kwargs: (_ for _ in ()).throw(PermissionError("not authorised")),
    )
    monkeypatch.setattr(
        ag,
        "_canonical_packet_path",
        lambda _path: (_ for _ in ()).throw(AssertionError("path was inspected")),
    )
    monkeypatch.setattr(ag.op, "OperatorPolicy", lambda: _Policy())
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})

    result = json.loads(ag.hermes_antigravity_dispatch("/outside/secret.json", dry_run=True))

    assert result == {"success": False, "error": "not authorised"}


def test_dispatch_dry_run_validates_packet_without_starting_process(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_roots(monkeypatch, tmp_path)
    packet = _packet(tmp_path / "packet.json")
    policy = _Policy()
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: policy)
    monkeypatch.setattr(
        ag,
        "_preflight",
        lambda: {
            "binary_exists": True,
            "binary_executable": True,
            "binary": str(ag.AGY_BINARY),
            "model": ag.MODEL,
            "mode": ag.MODE,
        },
    )
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})
    monkeypatch.setattr(
        ag.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("process started")),
    )

    result = json.loads(ag.hermes_antigravity_dispatch(str(packet), dry_run=True))

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["packet_schema_version"] == 1
    assert result["model"] == ag.MODEL
    assert result["mode"] == "plan"
    assert policy.read_paths == [packet]
    assert not ag.JOBS_ROOT.exists()


def test_dispatch_launches_only_internal_worker(monkeypatch, tmp_path: Path) -> None:
    _patch_roots(monkeypatch, tmp_path)
    packet = _packet(tmp_path / "packet.json")
    policy = _Policy()
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: policy)
    monkeypatch.setattr(
        ag,
        "_preflight",
        lambda: {
            "binary_exists": True,
            "binary_executable": True,
            "binary": str(ag.AGY_BINARY),
            "model": ag.MODEL,
            "mode": ag.MODE,
        },
    )
    monkeypatch.setattr(ag, "_active_task", lambda: None)
    monkeypatch.setattr(ag, "_worker_env", lambda: {"HOME": "/home/jfroh"})
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})
    captured: dict[str, object] = {}

    class _Proc:
        pid = 24680

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _Proc()

    monkeypatch.setattr(ag.subprocess, "Popen", fake_popen)

    result = json.loads(ag.hermes_antigravity_dispatch(str(packet), dry_run=False))

    assert result["success"] is True
    assert result["status"] == "queued"
    assert result["pid"] == 24680
    task_id = result["task_id"]
    assert task_id.startswith("agd_")
    argv = captured["argv"]
    assert argv == [sys.executable, str(Path(ag.__file__).resolve()), "worker", task_id]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["start_new_session"] is True
    normalized = json.loads((ag.JOBS_ROOT / task_id / "packet.normalized.json").read_text())
    assert "prompt" not in normalized
    assert "argv" not in normalized


def test_smoke_requires_exact_fixed_output(monkeypatch, tmp_path: Path) -> None:
    _patch_roots(monkeypatch, tmp_path)
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: _Policy())
    monkeypatch.setattr(
        ag,
        "_preflight",
        lambda: {
            "binary_exists": True,
            "binary_executable": True,
            "binary": str(ag.AGY_BINARY),
            "model": ag.MODEL,
            "mode": ag.MODE,
        },
    )
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})
    calls: dict[str, object] = {}

    def fake_run(prompt: str, *, cwd: Path, timeout: int, timeout_value: str):
        calls.update(prompt=prompt, cwd=cwd, timeout=timeout, timeout_value=timeout_value)
        return (
            0,
            json.dumps(
                {
                    "conversation_id": "conv-smoke",
                    "status": "SUCCESS",
                    "response": ag.SMOKE_EXPECTED + "\n",
                }
            ),
            "",
        )

    monkeypatch.setattr(ag, "_run_agy", fake_run)

    result = json.loads(ag.hermes_antigravity_smoke_test(dry_run=False))

    assert result["success"] is True
    assert result["exact_match"] is True
    assert result["conversation_id"] == "conv-smoke"
    assert result["response"] == ag.SMOKE_EXPECTED
    assert "Do not call tools" in calls["prompt"]
    assert Path(calls["cwd"]).is_relative_to(ag.SMOKE_ROOT)


def test_worker_returns_structured_result_from_mocked_agy(monkeypatch, tmp_path: Path) -> None:
    _patch_roots(monkeypatch, tmp_path)
    task_id = "agd_0123456789abcdef"
    job_dir = ag._job_dir(task_id)
    job_dir.mkdir(parents=True)
    packet = {
        "schema_version": 1,
        "objective": "Review facts.",
        "context": [],
        "questions": ["What matters?"],
        "constraints": [],
        "expected_output": [],
    }
    (job_dir / "packet.normalized.json").write_text(json.dumps(packet), encoding="utf-8")
    ag._write_state(
        task_id,
        task_id=task_id,
        status="queued",
        session_id="ops-test",
        snapshot_hash="snapshot-test",
        packet_sha256="abc123",
    )
    monkeypatch.setattr(ag, "_assert_origin_authority", lambda _state: _Policy())
    monkeypatch.setattr(
        ag,
        "_run_agy",
        lambda *_args, **_kwargs: (
            0,
            json.dumps({"conversation_id": "conv-1", "response": "Finding one"}),
            "",
        ),
    )

    assert ag._worker(task_id) == 0

    state = ag._read_state(task_id)
    result = json.loads((job_dir / "result.json").read_text())
    assert state["status"] == "completed"
    assert state["conversation_id"] == "conv-1"
    assert result["success"] is True
    assert result["response"] == "Finding one"
    assert result["packet_sha256"] == "abc123"


def test_status_returns_bounded_result(monkeypatch, tmp_path: Path) -> None:
    _patch_roots(monkeypatch, tmp_path)
    task_id = "agd_fedcba9876543210"
    job_dir = ag._job_dir(task_id)
    job_dir.mkdir(parents=True)
    ag._write_state(task_id, task_id=task_id, status="completed", pid=None)
    (job_dir / "result.json").write_text(
        json.dumps({"success": True, "response": "bounded"}), encoding="utf-8"
    )
    monkeypatch.setattr(ag, "_require_status_authority", lambda _task_id: _Policy())
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})

    result = json.loads(ag.hermes_antigravity_dispatch_status(task_id))

    assert result["success"] is True
    assert result["status"] == "completed"
    assert result["process_alive"] is False
    assert result["result"]["response"] == "bounded"


def test_cancel_targets_only_recorded_process_group(monkeypatch, tmp_path: Path) -> None:
    _patch_roots(monkeypatch, tmp_path)
    task_id = "agd_1111111111111111"
    job_dir = ag._job_dir(task_id)
    job_dir.mkdir(parents=True)
    ag._write_state(
        task_id,
        task_id=task_id,
        status="running",
        pid=777,
        session_id="ops-test",
    )
    policy = _Policy()
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: policy)
    monkeypatch.setattr(ag, "_pid_alive", lambda pid: pid == 777)
    monkeypatch.setattr(ag, "_worker_identity_matches", lambda task_id, pid: task_id == "agd_1111111111111111" and pid == 777)
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})
    calls: list[tuple[int, signal.Signals]] = []
    monkeypatch.setattr(ag.os, "killpg", lambda pid, sig: calls.append((pid, sig)))

    result = json.loads(ag.hermes_antigravity_dispatch_cancel(task_id, dry_run=False))

    assert result["success"] is True
    assert result["status"] == "cancel_requested"
    assert calls == [(777, signal.SIGTERM)]
    assert policy.write_paths == [job_dir]


def test_cancel_refuses_reused_or_unrelated_pid(monkeypatch, tmp_path: Path) -> None:
    _patch_roots(monkeypatch, tmp_path)
    task_id = "agd_2222222222222222"
    job_dir = ag._job_dir(task_id)
    job_dir.mkdir(parents=True)
    ag._write_state(
        task_id,
        task_id=task_id,
        status="running",
        pid=888,
        session_id="ops-test",
    )
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: _Policy())
    monkeypatch.setattr(ag, "_pid_alive", lambda pid: pid == 888)
    monkeypatch.setattr(ag, "_worker_identity_matches", lambda _task_id, _pid: False)
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})
    monkeypatch.setattr(
        ag.os,
        "killpg",
        lambda *_args: (_ for _ in ()).throw(AssertionError("unrelated process was signalled")),
    )

    result = json.loads(ag.hermes_antigravity_dispatch_cancel(task_id, dry_run=False))

    assert result["success"] is False
    assert "no longer identifies" in result["error"]


def test_worker_cancellation_reaches_terminal_cancelled_state(monkeypatch, tmp_path: Path) -> None:
    _patch_roots(monkeypatch, tmp_path)
    task_id = "agd_3333333333333333"
    job_dir = ag._job_dir(task_id)
    job_dir.mkdir(parents=True)
    packet = {
        "schema_version": 1,
        "objective": "Review facts.",
        "context": [],
        "questions": ["What matters?"],
        "constraints": [],
        "expected_output": [],
    }
    (job_dir / "packet.normalized.json").write_text(json.dumps(packet), encoding="utf-8")
    ag._write_state(
        task_id,
        task_id=task_id,
        status="queued",
        session_id="ops-test",
        snapshot_hash="snapshot-test",
        packet_sha256="cancel-test",
    )
    monkeypatch.setattr(ag, "_assert_origin_authority", lambda _state: _Policy())
    monkeypatch.setattr(
        ag,
        "_run_agy",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ag._DispatchCancelled()),
    )

    returncode = ag._worker(task_id)
    state = ag._read_state(task_id)

    assert returncode == 128 + int(signal.SIGTERM)
    assert state["status"] == "cancelled"
    assert state["returncode"] == returncode
    assert "cancelled" in state["error"]


def test_dispatch_failure_redacts_sensitive_exception_text(monkeypatch) -> None:
    policy = _Policy()
    monkeypatch.setattr(
        ag,
        "_require_authority",
        lambda **_kwargs: (_ for _ in ()).throw(PermissionError("API_KEY=super-secret-value")),
    )
    monkeypatch.setattr(ag.op, "OperatorPolicy", lambda: policy)
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})

    result = json.loads(ag.hermes_antigravity_dispatch("/not/inspected.json", dry_run=True))

    assert result["success"] is False
    assert "super-secret-value" not in result["error"]
