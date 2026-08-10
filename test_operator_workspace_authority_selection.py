from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import operator_workspace as workspace


def _under(path: str | Path, roots: list[Path]) -> bool:
    candidate = Path(path).resolve()
    for root in roots:
        try:
            candidate.relative_to(Path(root).resolve())
            return True
        except ValueError:
            continue
    return False


class _FakePolicy:
    registry = {}

    def __init__(self, *, authority_preference="effective", standing_authority_id=None):
        key = standing_authority_id if authority_preference == "standing" else "effective"
        data = dict(self.registry[key])
        self.session_id = key
        self.session_status = "standing" if authority_preference == "standing" else "task_bound"
        self.path_authority_source = (
            "standing_policy_snapshot" if authority_preference == "standing" else "session_snapshot"
        )
        self.readable_roots = [Path(p) for p in data.get("readable", [])]
        self.writable_roots = [Path(p) for p in data.get("writable", [])]
        self.allowed_paths = [*self.writable_roots]
        self.verbs = data.get("verbs", {})
        self.egress_hosts = data.get("egress_hosts", [])
        self.git_remotes = data.get("git_remotes", [])
        self.service_units = data.get("service_units", [])
        self.allowed_profiles = data.get("allowed_profiles", ["default"])
        self.level = data.get("level", "workspace")
        self.apply_mode = "direct"

    def require_read_path(self, path):
        if not _under(path, self.readable_roots):
            raise PermissionError("read not covered")

    def require_write_path(self, path):
        if not _under(path, self.writable_roots):
            raise PermissionError("write not covered")

    def require_workspace_path(self, path):
        self.require_write_path(path)

    def require_level(self, level):
        if level != self.level:
            raise PermissionError("level not covered")

    def require_branch(self, branch):
        return None

    def require_verb(self, resource, verb):
        if verb not in self.verbs.get(resource, []):
            raise PermissionError("verb not covered")

    def require_mutation(self, dry_run):
        return None

    def effective_dry_run(self, dry_run):
        return bool(dry_run)


def _install(monkeypatch, registry, standing_ids):
    _FakePolicy.registry = registry
    monkeypatch.setattr(workspace.op, "OperatorPolicy", _FakePolicy)
    monkeypatch.setattr(
        workspace.op_standing,
        "list_standing_authorities",
        lambda: [SimpleNamespace(authority_id=value) for value in standing_ids],
    )


def test_direct_workspace_read_reuses_independent_standing_authority(monkeypatch, tmp_path):
    task_root = tmp_path / "task"
    board_root = tmp_path / "board"
    task_root.mkdir()
    board_root.mkdir()
    target = board_root / "board.json"
    target.write_text('{"ok": true}\n', encoding="utf-8")

    _install(
        monkeypatch,
        {
            "effective": {"readable": [task_root], "writable": [task_root]},
            "sa_board": {"readable": [board_root], "writable": [board_root]},
        },
        ["sa_board"],
    )

    result = json.loads(workspace.hermes_workspace_read(str(target)))
    assert result["success"] is True
    assert '"ok": true' in result["content"]


def test_direct_workspace_selector_prefers_narrower_complete_authority(monkeypatch, tmp_path):
    broad = tmp_path
    narrow = tmp_path / "narrow"
    narrow.mkdir()
    target = narrow / "file.txt"
    target.write_text("proof\n", encoding="utf-8")

    _install(
        monkeypatch,
        {
            "effective": {
                "readable": [broad],
                "writable": [broad],
                "verbs": {"filesystem": ["read", "edit"], "tests": ["run"]},
                "service_units": ["example.service"],
            },
            "sa_narrow": {
                "readable": [narrow],
                "writable": [],
                "verbs": {"filesystem": ["read"]},
            },
        },
        ["sa_narrow"],
    )

    selected = workspace._select_workspace_operation_policy(
        lambda candidate: candidate.require_read_path(target)
    )
    assert selected.session_id == "sa_narrow"


def test_direct_workspace_selector_never_unions_partial_authorities(monkeypatch, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    target = root / "file.txt"
    target.write_text("proof\n", encoding="utf-8")

    _install(
        monkeypatch,
        {
            "effective": {"readable": [], "writable": []},
            "sa_read": {"readable": [root], "writable": []},
            "sa_write": {"readable": [], "writable": [root]},
        },
        ["sa_read", "sa_write"],
    )

    def require_both(candidate):
        candidate.require_read_path(target)
        candidate.require_write_path(target)

    with pytest.raises(PermissionError):
        workspace._select_workspace_operation_policy(require_both)
