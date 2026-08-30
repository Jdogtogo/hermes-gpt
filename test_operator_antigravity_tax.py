from __future__ import annotations

import inspect
import io
import json
import os
import stat
import sys
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import operator_antigravity_tax as ag


class _Policy:
    level = "workspace"
    apply_mode = "direct"
    policy_template = ag.REQUIRED_TEMPLATE
    session_id = "ops-tax-test"
    snapshot_hash = "snapshot-tax-test"
    expires_at = int(time.time()) + 36000

    @staticmethod
    def effective_dry_run(requested: bool) -> bool:
        return requested

    @staticmethod
    def require_level(_level: str) -> None:
        return None

    @staticmethod
    def require_verb(_resource: str, _verb: str) -> None:
        return None

    @staticmethod
    def require_read_path(_path: Path) -> None:
        return None

    @staticmethod
    def require_write_path(_path: Path) -> None:
        return None

    @staticmethod
    def require_mutation(_dry_run: bool) -> None:
        return None


def _patch_paths(monkeypatch, tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    runs_dir = state_dir / "runs"
    tax_root = tmp_path / "Tax Calculator"
    tax_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ag, "STATE_DIR", state_dir)
    monkeypatch.setattr(ag, "STATE_PATH", state_dir / "state.json")
    monkeypatch.setattr(ag, "LAUNCH_LOG_PATH", state_dir / "launcher.log")
    monkeypatch.setattr(ag, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(ag, "REPORT_PATH", tmp_path / "evidence" / "review.md")
    monkeypatch.setattr(ag, "ENVELOPE_PATH", tmp_path / "evidence" / "review.yaml")
    monkeypatch.setattr(ag, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(ag, "TAX_CALCULATOR_ROOT", tax_root)


def _final_response() -> str:
    markdown = (
        f"{ag._MARKDOWN_START}\n# Independent review\n"
        "Verdict: ACCEPT\nNo blocking findings.\n"
        f"{ag._MARKDOWN_END}\n"
    )
    yaml_text = (
        f"{ag._YAML_START}\n"
        "schema_version: 1\nreview:\n"
        "  target_commits:\n"
        "    - HEAD\n"
        "  verdict: ACCEPT\n"
        "  blocking_findings: 0\n"
        "  non_blocking_findings: 0\n"
        "  supplied_tests_passed: true\n"
        "  reported_audit_reproduced: true\n"
        "  source_modified: false\n"
        "  credentials_accessed: false\n"
        "  services_restarted: false\n"
        f"{ag._YAML_END}\n"
    )
    return json.dumps(
        {
            "conversation_id": "conversation-tax-test",
            "response": markdown + yaml_text + "HERMES_SLICE_STATUS: COMPLETE\n",
        }
    )


def test_fixed_surface_and_long_horizon_contract() -> None:
    assert list(inspect.signature(ag.start).parameters) == ["dry_run"]
    assert ag.TAX_CALCULATOR_ROOT == Path("/mnt/c/Dev/Tax Calculator")
    assert ag.TARGET_COMMITS == ("HEAD",)
    assert ag.TARGET_RANGE == "HEAD^..HEAD"
    assert ag.OUTER_TIMEOUT_SECONDS == 8 * 60 * 60
    assert ag.WORKER_SLICE_TIMEOUT_SECONDS == 60 * 60
    assert ag.MAXIMUM_CONTINUATIONS == 8
    assert ag.STOP_ON == (
        "completion",
        "material_scope_change",
        "unsafe_action",
        "repeated_failure",
        "authority_expiry",
    )


def test_require_authority_rejects_wrong_template(monkeypatch) -> None:
    wrong = SimpleNamespace(
        policy_template="hermes-gpt-operator-maintenance",
        require_level=lambda _value: None,
        require_verb=lambda _resource, _verb: None,
        require_read_path=lambda _path: None,
        require_write_path=lambda _path: None,
        require_mutation=lambda _dry_run: None,
    )
    monkeypatch.setattr(ag.op, "OperatorPolicy", lambda: wrong)
    try:
        ag._require_authority(mutate=False)
    except PermissionError as exc:
        assert ag.REQUIRED_TEMPLATE in str(exc)
    else:
        raise AssertionError("wrong policy template was accepted")


def test_worker_env_preserves_only_session_pointer(monkeypatch) -> None:
    monkeypatch.setenv("HERMES_GPT_OPERATOR_SESSION_ROOT", "/tmp/session-root")
    monkeypatch.setenv("HERMES_GPT_OPERATOR_SESSION_ID", "ops-test")
    monkeypatch.setenv("EXAMPLE_API_KEY", "secret")
    env = ag._worker_env()
    assert env["HERMES_GPT_OPERATOR_SESSION_ROOT"] == "/tmp/session-root"
    assert env["HERMES_GPT_OPERATOR_SESSION_ID"] == "ops-test"
    assert "EXAMPLE_API_KEY" not in env
    child_env = ag._sanitized_env()
    assert "HERMES_GPT_OPERATOR_SESSION_ROOT" not in child_env
    assert "HERMES_GPT_OPERATOR_SESSION_ID" not in child_env


def test_start_dry_run_returns_fixed_contract(monkeypatch, tmp_path: Path) -> None:
    _patch_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: _Policy())
    monkeypatch.setattr(
        ag,
        "_preflight",
        lambda: {commit: f"full-{commit}" for commit in ag.TARGET_COMMITS},
    )
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})

    result = json.loads(ag.start(dry_run=True))

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["route"] == "supervised-host-agy-tax-review"
    assert result["total_task_window"] == 8 * 60 * 60
    assert result["worker_slice_timeout"] == 60 * 60
    assert result["maximum_continuations"] == 8
    assert result["resume_from_checkpoint"] is True
    assert result["stop_on"] == list(ag.STOP_ON)


def test_start_launches_only_internal_worker(monkeypatch, tmp_path: Path) -> None:
    _patch_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: _Policy())
    monkeypatch.setattr(
        ag,
        "_preflight",
        lambda: {commit: f"full-{commit}" for commit in ag.TARGET_COMMITS},
    )
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})
    monkeypatch.setattr(ag, "_worker_env", lambda: {"HOME": "/home/jfroh"})
    captured: dict[str, object] = {}

    class _Proc:
        pid = 43210

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _Proc()

    monkeypatch.setattr(ag.subprocess, "Popen", fake_popen)
    result = json.loads(ag.start(dry_run=False))

    assert result["success"] is True
    assert result["pid"] == 43210
    argv = captured["argv"]
    assert argv[0] == sys.executable
    assert argv[1] == str(Path(ag.__file__).resolve())
    assert argv[2] == "worker"
    assert argv[3].startswith(ag.TASK_ID_PREFIX)
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["start_new_session"] is True


def test_settings_permissions_are_scoped_and_restored(monkeypatch, tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    original = b'{"theme":"dark"}\n'
    settings.write_bytes(original)
    os.chmod(settings, 0o640)
    monkeypatch.setattr(ag, "SETTINGS_PATH", settings)

    saved, mode, data = ag._load_settings()
    path_a = tmp_path / "repo"
    path_b = tmp_path / "inputs"
    ag._install_read_permissions([path_a, path_b], data, mode)
    updated = json.loads(settings.read_text(encoding="utf-8"))
    assert updated["permissions"]["allow"] == [
        f"read_file({path_a})",
        f"read_file({path_b})",
    ]
    assert stat.S_IMODE(settings.stat().st_mode) == 0o640

    ag._restore_settings(saved, mode)
    assert settings.read_bytes() == original
    assert stat.S_IMODE(settings.stat().st_mode) == 0o640


def test_existing_non_executable_output_file_is_writable(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text("{}\n", encoding="utf-8")
    os.chmod(settings, 0o600)

    assert not os.access(settings, os.X_OK)
    assert ag._output_path_is_writable(settings) is True
    assert ag._output_path_is_writable(tmp_path / "new" / "review.yaml") is True


def test_preflight_accepts_dirty_live_worktree_because_review_uses_snapshot(
    monkeypatch, tmp_path: Path
) -> None:
    _patch_paths(monkeypatch, tmp_path)
    agy = tmp_path / "agy"
    agy.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(agy, 0o700)
    monkeypatch.setattr(ag, "AGY_BINARY", agy)
    monkeypatch.setattr(
        ag.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name=ag.HOST_USER),
    )
    monkeypatch.setattr(ag.os, "getuid", lambda: 1000)
    calls: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        if argv[:3] == ["git", "rev-parse", "--verify"]:
            short = argv[3].split("^")[0]
            return 0, f"full-{short}\n", ""
        if argv[:2] == ["git", "status"]:
            raise AssertionError("preflight must not inspect or reject unrelated worktree changes")
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(ag, "_run", fake_run)

    resolved = ag._preflight()

    assert resolved == {commit: f"full-{commit}" for commit in ag.TARGET_COMMITS}
    assert len(calls) == len(ag.TARGET_COMMITS)


def test_changed_test_discovery_uses_resolved_commit_range_and_snapshot(
    monkeypatch, tmp_path: Path
) -> None:
    review_root = tmp_path / "approved-commit-snapshot"
    review_root.mkdir()
    (review_root / "test_changed.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    resolved = {commit: f"full-{commit}" for commit in ag.TARGET_COMMITS}
    captured: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["cwd"] = kwargs["cwd"]
        return 0, "test_changed.py\n", ""

    monkeypatch.setattr(ag, "_run", fake_run)

    commands = ag._collect_changed_test_commands(review_root, resolved)

    assert captured["argv"] == [
        "git",
        "diff",
        "--name-only",
        f"full-{ag.TARGET_COMMITS[0]}^..full-{ag.TARGET_COMMITS[-1]}",
    ]
    assert captured["cwd"] == ag.TAX_CALCULATOR_ROOT
    assert ["pytest", "-q", "-p", "no:cacheprovider", "test_changed.py"] in commands


def test_snapshot_archive_extracts_regular_files_and_rejects_links(tmp_path: Path) -> None:
    regular = io.BytesIO()
    with tarfile.open(fileobj=regular, mode="w:") as archive:
        payload = b"approved source\n"
        member = tarfile.TarInfo("src/example.txt")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    destination = tmp_path / "snapshot"
    ag._extract_snapshot_archive(regular.getvalue(), destination)
    assert (destination / "src" / "example.txt").read_bytes() == b"approved source\n"

    unsafe = io.BytesIO()
    with tarfile.open(fileobj=unsafe, mode="w:") as archive:
        member = tarfile.TarInfo("src/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        archive.addfile(member)

    with pytest.raises(RuntimeError, match="Unsupported review snapshot archive entry type"):
        ag._extract_snapshot_archive(unsafe.getvalue(), tmp_path / "unsafe-snapshot")

    sensitive = io.BytesIO()
    with tarfile.open(fileobj=sensitive, mode="w:") as archive:
        payload = b"secret\n"
        member = tarfile.TarInfo("config/.env.production")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    with pytest.raises(RuntimeError, match="Sensitive path is not permitted"):
        ag._extract_snapshot_archive(sensitive.getvalue(), tmp_path / "sensitive-snapshot")


def test_prompt_and_control_status_support_checkpoints(tmp_path: Path) -> None:
    checkpoint = tmp_path / "slice-01.txt"
    prompt = ag._build_prompt(
        1,
        [checkpoint],
        tmp_path / "inputs",
        tmp_path / "approved-commit-snapshot",
    )
    assert "bounded review slice 2" in prompt
    assert str(checkpoint) in prompt
    assert "HERMES_SLICE_STATUS: CONTINUE" in prompt
    assert "BLOCKED_MATERIAL_SCOPE_CHANGE" in prompt
    assert ag._slice_control_status(
        json.dumps({"response": "checkpoint\nHERMES_SLICE_STATUS: CONTINUE\n"})
    ) == "CONTINUE"
    assert ag._slice_control_status(_final_response()) == "COMPLETE"


def test_worker_continues_from_checkpoint_then_completes(monkeypatch, tmp_path: Path) -> None:
    _patch_paths(monkeypatch, tmp_path)
    task_id = ag.TASK_ID_PREFIX + "a" * 20
    run_dir = ag.RUNS_DIR / task_id
    input_dir = run_dir / "review-input"
    run_dir.mkdir(parents=True, exist_ok=True)
    started = int(time.time())
    ag._write_state(
        task_id=task_id,
        status="queued",
        session_id=_Policy.session_id,
        snapshot_hash=_Policy.snapshot_hash,
        envelope_deadline=started + 7200,
        continuation_count=0,
        maximum_continuations=ag.MAXIMUM_CONTINUATIONS,
        run_dir=str(run_dir),
        input_dir=str(input_dir),
    )
    monkeypatch.setattr(ag, "_assert_authority", lambda *_args: _Policy())
    monkeypatch.setattr(
        ag,
        "_preflight",
        lambda: {commit: f"full-{commit}" for commit in ag.TARGET_COMMITS},
    )

    monkeypatch.setattr(
        ag,
        "_create_review_snapshot",
        lambda _resolved, destination, **_kwargs: destination.mkdir(parents=True, exist_ok=True),
    )

    def fake_collect(_resolved, target_input_dir, _review_root, **_kwargs):
        target_input_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(ag, "_collect_review_inputs", fake_collect)
    monkeypatch.setattr(ag, "_load_settings", lambda: (None, None, {}))
    monkeypatch.setattr(ag, "_install_read_permissions", lambda *_args: None)
    monkeypatch.setattr(ag, "_restore_settings", lambda *_args: None)
    responses = iter(
        [
            (
                0,
                json.dumps(
                    {
                        "response": (
                            "---BEGIN_CHECKPOINT---\ncriteria 1-5 complete\n"
                            "---END_CHECKPOINT---\nHERMES_SLICE_STATUS: CONTINUE\n"
                        )
                    }
                ),
                "",
            ),
            (0, _final_response(), ""),
        ]
    )
    monkeypatch.setattr(ag, "_run_agy_slice", lambda **_kwargs: next(responses))

    assert ag._worker(task_id) == 0
    state = ag._read_state()
    assert state["status"] == "completed"
    assert state["final_stop_reason"] == "completion"
    assert state["continuation_count"] == 1
    assert state["verdict"] == "ACCEPT"
    assert ag.REPORT_PATH.is_file()
    assert ag.ENVELOPE_PATH.is_file()
    assert (input_dir / "checkpoints" / "slice-01.txt").is_file()


def test_worker_stops_after_repeated_identical_failure(monkeypatch, tmp_path: Path) -> None:
    _patch_paths(monkeypatch, tmp_path)
    task_id = ag.TASK_ID_PREFIX + "b" * 20
    run_dir = ag.RUNS_DIR / task_id
    input_dir = run_dir / "review-input"
    run_dir.mkdir(parents=True, exist_ok=True)
    started = int(time.time())
    ag._write_state(
        task_id=task_id,
        status="queued",
        session_id=_Policy.session_id,
        snapshot_hash=_Policy.snapshot_hash,
        envelope_deadline=started + 7200,
        continuation_count=0,
        maximum_continuations=ag.MAXIMUM_CONTINUATIONS,
        run_dir=str(run_dir),
        input_dir=str(input_dir),
    )
    monkeypatch.setattr(ag, "_assert_authority", lambda *_args: _Policy())
    monkeypatch.setattr(
        ag,
        "_preflight",
        lambda: {commit: f"full-{commit}" for commit in ag.TARGET_COMMITS},
    )
    monkeypatch.setattr(
        ag,
        "_create_review_snapshot",
        lambda _resolved, destination, **_kwargs: destination.mkdir(parents=True, exist_ok=True),
    )
    monkeypatch.setattr(
        ag,
        "_collect_review_inputs",
        lambda _resolved, target_input_dir, _review_root, **_kwargs: target_input_dir.mkdir(
            parents=True, exist_ok=True
        ),
    )
    monkeypatch.setattr(ag, "_load_settings", lambda: (None, None, {}))
    monkeypatch.setattr(ag, "_install_read_permissions", lambda *_args: None)
    monkeypatch.setattr(ag, "_restore_settings", lambda *_args: None)
    monkeypatch.setattr(ag, "_run_agy_slice", lambda **_kwargs: (1, "", "same provider failure"))

    assert ag._worker(task_id) == 1
    state = ag._read_state()
    assert state["status"] == "failed"
    assert state["final_stop_reason"] == "repeated_failure"
    assert state["continuation_count"] == 1


def test_extract_and_validate_final_artifacts() -> None:
    markdown, yaml_text, conversation_id = ag._extract_artifacts(_final_response())
    assert "Verdict: ACCEPT" in markdown
    assert "verdict: ACCEPT" in yaml_text
    assert conversation_id == "conversation-tax-test"
    assert ag._validate_artifacts(markdown, yaml_text) == "ACCEPT"


def test_cancel_terminates_child_but_preserves_supervisor_for_cleanup(monkeypatch, tmp_path: Path) -> None:
    _patch_paths(monkeypatch, tmp_path)
    task_id = ag.TASK_ID_PREFIX + "c" * 20
    ag._write_state(task_id=task_id, status="running", pid=11111, agy_pid=22222)
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: _Policy())
    monkeypatch.setattr(ag, "_pid_alive", lambda pid: pid in {11111, 22222})
    terminated: list[int] = []
    monkeypatch.setattr(ag, "_terminate_process_group", lambda pid: terminated.append(pid))

    result = json.loads(ag.cancel(task_id, dry_run=False))

    assert result["success"] is True
    assert result["status"] == "cancel_requested"
    assert terminated == [22222]
    assert ag._read_state()["status"] == "cancel_requested"
