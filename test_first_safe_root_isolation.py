"""Offline regression checks for FIRST_SAFE coexisting with a live default profile.

No production Hermes files, credentials or network services are accessed.
"""
from __future__ import annotations

import ast
import stat
from pathlib import Path

import pytest

import first_safe_provision_worker as provision_worker
import operator_first_safe_provision as provision
import operator_hermes_exec_model as acceptance


def _snapshot_function(program: str, root_paths: tuple[Path, ...]):
    """Run only the embedded metadata helper against temporary fixture files."""
    tree = ast.parse(program)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "root_state_snapshot"
    )
    unit = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))

    def fail(message, **_details):
        raise ValueError(message)

    scope = {"ROOT_STATE_PATHS": root_paths, "stat": stat, "fail": fail}
    exec(compile(unit, "<metadata-only-root-snapshot>", "exec"), scope)
    return scope["root_state_snapshot"]


@pytest.mark.parametrize("program", [provision_worker.REMOTE_PROGRAM, acceptance.REMOTE_PROGRAM])
def test_existing_root_files_are_allowed_without_reading_their_contents(tmp_path, monkeypatch, program):
    paths = tuple(tmp_path / name for name in ("config.yaml", ".env", "auth.json", "nous_auth.json"))
    for path in paths:
        path.write_text("fixture secret: never read", encoding="utf-8")
    snapshot = _snapshot_function(program, paths)
    with monkeypatch.context() as patcher:
        def forbidden_read(*_args, **_kwargs):
            raise AssertionError("root credential contents must not be read")
        patcher.setattr(Path, "read_text", forbidden_read)
        patcher.setattr(Path, "read_bytes", forbidden_read)
        initial = snapshot()
        assert initial == snapshot()
    paths[1].write_text("fixture secret: changed and still never read", encoding="utf-8")
    assert snapshot() != initial


@pytest.mark.parametrize("program", [provision_worker.REMOTE_PROGRAM, acceptance.REMOTE_PROGRAM])
def test_root_snapshot_detects_absence_and_rejects_symlinks(tmp_path, program):
    path = tmp_path / "config.yaml"
    snapshot = _snapshot_function(program, (path,))
    assert snapshot()[str(path)] is None
    path.symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError, match="regular file"):
        snapshot()
    path.unlink()
    path.write_text("model: isolated", encoding="utf-8")
    assert snapshot()[str(path)] is not None


def test_provisioning_guard_precedes_quarantine_and_checks_after_write():
    program = provision_worker.REMOTE_PROGRAM
    assert program.index("root_before=root_state_snapshot()") < program.index("os.rename(PROFILE_AUTH,destination)")
    assert program.index("pinned Hermes profile home binding unverified") < program.index("CONFIG.write_text(CONFIG_TEXT")
    assert program.index("root_state_snapshot()!=root_before") > program.index("CONFIG.write_text(CONFIG_TEXT")
    assert "ROOT_ENV.read_text" not in program and "ROOT_AUTH.read_bytes" not in program
    assert provision.fixed_plan()["root_provider_state_policy"].startswith("allow existing default-profile files")
    source = provision_worker.execute.__code__.co_consts
    assert "root_provider_state_unchanged" in provision_worker.REMOTE_PROGRAM
    assert "profile_home_binding_verified" in provision_worker.REMOTE_PROGRAM
    assert source


def test_acceptance_checks_pinned_resolver_and_root_integrity_around_model_calls():
    program = acceptance.REMOTE_PROGRAM
    assert program.index("root_before=root_state_snapshot()") < program.index("selected,reason,catalog_price=select_model()")
    assert program.index("pinned Hermes profile home binding unverified") < program.index("selected,reason,catalog_price=select_model()")
    assert program.index("root_state_snapshot()!=root_before") > program.index("calls.append(call_and_evidence")
    assert '"HERMES_HOME": str(PROFILE_HOME)' in program
    assert '"root_provider_state_unchanged":True' in program
    assert '"profile_home_binding_verified":True' in program
    assert acceptance.fixed_plan()["root_provider_state_unchanged_required"] is True
    assert acceptance.fixed_plan()["profile_home_binding_required"] is True
