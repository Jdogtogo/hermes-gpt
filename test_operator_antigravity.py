from __future__ import annotations

import inspect
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import operator_antigravity as ag


class _Policy:
    level = "workspace"
    apply_mode = "direct"
    session_id = "ops-test"
    snapshot_hash = "snapshot-test"

    @staticmethod
    def effective_dry_run(requested: bool) -> bool:
        return requested


def _patch_state_paths(monkeypatch, tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    monkeypatch.setattr(ag, "STATE_DIR", state_dir)
    monkeypatch.setattr(ag, "STATE_PATH", state_dir / "state.json")
    monkeypatch.setattr(ag, "LAUNCH_LOG_PATH", state_dir / "launcher.log")


def test_start_surface_accepts_no_arbitrary_job_inputs() -> None:
    signature = inspect.signature(ag.hermes_antigravity_review_start)
    assert list(signature.parameters) == ["dry_run"]
    assert ag.AGY_BINARY == Path("/home/jfroh/.local/bin/agy")
    assert ag.CANONICAL_WORKTREE == Path(
        "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"
    )
    assert ag.TARGET_COMMIT == "d37757895fb1cc835ffe28da288b90c98ff3c612"


def test_start_dry_run_returns_fixed_contract(monkeypatch, tmp_path: Path) -> None:
    _patch_state_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: _Policy())
    monkeypatch.setattr(
        ag,
        "_dry_run_validation",
        lambda: {
            "target_commit_exists": True,
            "detached_review_worktree_created": True,
            "launcher_validation_succeeded": True,
            "review_launched": False,
            "model_execution": False,
        },
    )
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})

    result = json.loads(ag.hermes_antigravity_review_start(dry_run=True))

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["binary"] == str(ag.AGY_BINARY)
    assert result["target_commit"] == ag.TARGET_COMMIT
    assert result["fixed_test_count"] == 4
    assert result["target_commit_exists"] is True
    assert result["detached_review_worktree_created"] is True
    assert result["launcher_validation_succeeded"] is True
    assert result["review_launched"] is False
    assert result["model_execution"] is False


def test_dry_run_validation_preflights_worktree_and_removes_it(monkeypatch, tmp_path: Path) -> None:
    calls: list[tuple[str, Path | None]] = []
    review_dir = tmp_path / "review"

    monkeypatch.setattr(ag, "_preflight", lambda: calls.append(("preflight", None)))

    def fake_create(job_id: str) -> Path:
        assert job_id.startswith("dryrun-")
        calls.append(("create", None))
        return review_dir

    def fake_remove(path: Path | None) -> None:
        calls.append(("remove", path))

    monkeypatch.setattr(ag, "_create_detached_worktree", fake_create)
    monkeypatch.setattr(ag, "_remove_detached_worktree", fake_remove)

    result = ag._dry_run_validation()

    assert result == {
        "target_commit_exists": True,
        "detached_review_worktree_created": True,
        "launcher_validation_succeeded": True,
        "review_launched": False,
        "model_execution": False,
    }
    assert calls == [("preflight", None), ("create", None), ("remove", review_dir)]


def test_detached_review_worktree_stays_under_authorised_root(monkeypatch, tmp_path: Path) -> None:
    canonical = tmp_path / "canonical"
    review_root = canonical / "logs" / "antigravity-review" / "worktrees"
    canonical.mkdir()
    monkeypatch.setattr(ag, "CANONICAL_WORKTREE", canonical)
    monkeypatch.setattr(ag, "REVIEW_ROOT", review_root)

    captured: dict[str, object] = {}

    def fake_run(argv, *, cwd: Path, timeout: int):
        captured["argv"] = argv
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        return 0, "", ""

    monkeypatch.setattr(ag, "_run", fake_run)

    review_dir = ag._create_detached_worktree("dryrun-test")

    assert review_root.is_dir()
    assert review_dir == review_root / f"{ag.REVIEW_PREFIX}dryrun-test"
    assert review_dir.is_relative_to(canonical)
    assert captured["cwd"] == canonical
    assert captured["argv"] == [
        "git",
        "worktree",
        "add",
        "--detach",
        str(review_dir),
        ag.TARGET_COMMIT,
    ]
    assert captured["timeout"] == 120


def test_start_launches_only_internal_worker(monkeypatch, tmp_path: Path) -> None:
    _patch_state_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(ag, "_require_authority", lambda **_kwargs: _Policy())
    monkeypatch.setattr(ag.op, "audit_record", lambda **_kwargs: {})
    monkeypatch.setattr(ag, "_sanitized_env", lambda: {"HOME": "/home/jfroh"})

    captured: dict[str, object] = {}

    class _Proc:
        pid = 43210

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _Proc()

    monkeypatch.setattr(ag.subprocess, "Popen", fake_popen)

    result = json.loads(ag.hermes_antigravity_review_start(dry_run=False))

    assert result["success"] is True
    assert result["pid"] == 43210
    argv = captured["argv"]
    assert isinstance(argv, list)
    assert argv[0] == sys.executable
    assert argv[1] == str(Path(ag.__file__).resolve())
    assert argv[2] == "worker"
    assert argv[3].startswith("agr_")
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["start_new_session"] is True


def test_settings_permission_is_scoped_and_exactly_restored(monkeypatch, tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    original = b'{"theme":"dark"}\n'
    settings.write_bytes(original)
    os.chmod(settings, 0o640)
    monkeypatch.setattr(ag, "SETTINGS_PATH", settings)

    saved, mode, data = ag._load_settings()
    review_dir = tmp_path / "review"
    ag._install_read_permission(review_dir, data, mode)

    updated = json.loads(settings.read_text(encoding="utf-8"))
    assert updated["permissions"]["allow"] == [f"read_file({review_dir})"]
    assert stat.S_IMODE(settings.stat().st_mode) == 0o640

    ag._restore_settings(saved, mode)
    assert settings.read_bytes() == original
    assert stat.S_IMODE(settings.stat().st_mode) == 0o640


def test_read_permission_temporarily_suspends_only_conflicting_ask_rules(
    monkeypatch, tmp_path: Path
) -> None:
    settings = tmp_path / "settings.json"
    original = (
        '{\n'
        '  "permissions": {\n'
        '    "allow": ["read_url(example.com)"],\n'
        '    "ask": ["read_file(*)", "command(*)"],\n'
        '    "deny": ["write_file(.git/)"]\n'
        '  }\n'
        '}\n'
    ).encode("utf-8")
    settings.write_bytes(original)
    monkeypatch.setattr(ag, "SETTINGS_PATH", settings)

    saved, mode, data = ag._load_settings()
    review_dir = tmp_path / "review"
    ag._install_read_permission(review_dir, data, mode)

    updated = json.loads(settings.read_text(encoding="utf-8"))
    assert updated["permissions"]["allow"] == [
        "read_url(example.com)",
        f"read_file({review_dir})",
    ]
    assert updated["permissions"]["ask"] == ["command(*)"]
    assert updated["permissions"]["deny"] == ["write_file(.git/)"]

    ag._restore_settings(saved, mode)
    assert settings.read_bytes() == original


def test_read_permission_refuses_to_override_read_deny(monkeypatch, tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps({"permissions": {"deny": ["read_file(*)"]}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(ag, "SETTINGS_PATH", settings)

    _saved, mode, data = ag._load_settings()
    try:
        ag._install_read_permission(tmp_path / "review", data, mode)
    except RuntimeError as exc:
        assert "refusing to weaken" in str(exc)
    else:
        raise AssertionError("read_file deny rule was overridden")


def test_settings_created_for_job_is_removed_after_restore(monkeypatch, tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    monkeypatch.setattr(ag, "SETTINGS_PATH", settings)
    saved, mode, data = ag._load_settings()
    ag._install_read_permission(tmp_path / "review", data, mode)
    assert settings.exists()
    ag._restore_settings(saved, mode)
    assert not settings.exists()


def test_fixed_operator_suite_expands_without_shell_glob(tmp_path: Path) -> None:
    (tmp_path / "test_operator_z.py").write_text("", encoding="utf-8")
    (tmp_path / "test_operator_a.py").write_text("", encoding="utf-8")
    commands = ag._fixed_test_commands(tmp_path)
    assert commands[0][-1] == "test_operator_session_requests.py"
    assert commands[1][-1] == "test_operator_service_sandbox.py"
    assert commands[2][-2:] == ["test_operator_a.py", "test_operator_z.py"]
    assert commands[3] == ["pytest", "-q"]


def test_extract_artifacts_from_json_response() -> None:
    markdown = (
        f"{ag._MARKDOWN_START}\n# Review\nTarget {ag.TARGET_COMMIT}\n"
        f"Final verdict: PASS\n{ag._MARKDOWN_END}"
    )
    envelope = (
        f"{ag._YAML_START}\nschema_version: 1\nreview:\n"
        f"  target_commit: {ag.TARGET_COMMIT}\n"
        "  verdict: PASS\n"
        "  blocking_findings: 0\n"
        "  non_blocking_findings: 0\n"
        "  targeted_tests_passed: true\n"
        "  operator_suite_passed: true\n"
        "  full_suite_passed: true\n"
        "  source_modified: false\n"
        "  credentials_accessed: false\n"
        f"  services_restarted: false\n{ag._YAML_END}"
    )
    raw = json.dumps(
        {
            "conversation_id": "conversation-test",
            "response": markdown + "\n" + envelope,
        }
    )

    md, yaml_text, conversation_id = ag._extract_artifacts(raw)

    assert "Final verdict: PASS" in md
    assert "verdict: PASS" in yaml_text
    assert conversation_id == "conversation-test"
    assert ag._validate_artifacts(md, yaml_text) == "PASS"


def test_extract_artifacts_accepts_yaml_start_as_bounded_markdown_end() -> None:
    raw = json.dumps(
        {
            "conversation_id": "conversation-fallback",
            "response": (
                f"{ag._MARKDOWN_START}\n# Review\nTarget {ag.TARGET_COMMIT}\n"
                "Final verdict: PASS\n"
                f"{ag._YAML_START}\n"
                "schema_version: 1\nreview:\n"
                f"  target_commit: {ag.TARGET_COMMIT}\n"
                "  verdict: PASS\n"
                "  blocking_findings: 0\n"
                "  non_blocking_findings: 0\n"
                "  targeted_tests_passed: true\n"
                "  operator_suite_passed: true\n"
                "  full_suite_passed: true\n"
                "  source_modified: false\n"
                "  credentials_accessed: false\n"
                "  services_restarted: false\n"
                f"{ag._YAML_END}\n"
            ),
        }
    )

    md, yaml_text, conversation_id = ag._extract_artifacts(raw)

    assert "Final verdict: PASS" in md
    assert ag._YAML_START not in md
    assert "verdict: PASS" in yaml_text
    assert conversation_id == "conversation-fallback"
    assert ag._validate_artifacts(md, yaml_text) == "PASS"


def test_require_authority_rejects_wrong_template(monkeypatch) -> None:
    policy = SimpleNamespace(
        policy_template="hermes-overnight-maintenance",
        require_level=lambda _level: None,
        require_verb=lambda _resource, _verb: None,
        require_mutation=lambda _dry_run: None,
    )
    monkeypatch.setattr(ag.op, "OperatorPolicy", lambda: policy)

    try:
        ag._require_authority(mutate=False)
    except PermissionError as exc:
        assert ag.REQUIRED_TEMPLATE in str(exc)
    else:
        raise AssertionError("wrong policy template was accepted")
