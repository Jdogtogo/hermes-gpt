from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

import operator_delegation as delegation
import operator_routing as routing


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


class NoWebPolicy(FakePolicy):
    def require_verb(self, resource, verb):
        if resource == "network" and verb == "web":
            raise PermissionError("Delegated web authority is not granted.")
        return super().require_verb(resource, verb)


class WebPolicy(FakePolicy):
    verbs = {"filesystem": ["edit"], "network": ["web"]}

    def require_verb(self, resource, verb):
        assert (resource, verb) in {("filesystem", "edit"), ("network", "web")}


def _multi_authority_policy_class(registry):
    class MultiAuthorityPolicy:
        enabled = True
        level = "workspace"
        apply_mode = "direct"
        snapshot_hash = "snapshot"
        expires_at = None
        path_authority_source = "standing_policy_snapshot"
        profile_allowlist_source = "standing_policy_snapshot"
        session_allowed_profiles = ["default"]
        process_allowed_profiles = ["default"]
        owner_mode_ready = False
        mutation_allowed = True
        policy_template = "test-standing"
        session_status = "standing"
        session_failure_reason = None
        pointed_session_id = None
        session_approved_at = 1
        denied_paths = []
        allowed_branches = None

        def __init__(self, *, authority_preference="effective", standing_authority_id=None):
            key = standing_authority_id if authority_preference == "standing" else "effective"
            if key is None:
                key = "active"
            data = registry[key]
            self.session_id = data["session_id"]
            self.readable_roots = [Path(p) for p in data.get("readable_roots", [])]
            self.writable_roots = [Path(p) for p in data.get("writable_roots", [])]
            self.allowed_paths = sorted(
                {*self.readable_roots, *self.writable_roots}, key=lambda p: str(p)
            )
            self.verbs = data.get("verbs", {"filesystem": ["edit"]})
            self.allowed_profiles = data.get("allowed_profiles", ["default"])
            self.egress_hosts = data.get("egress_hosts", [])
            self.git_remotes = data.get("git_remotes", [])
            self.service_units = data.get("service_units", [])
            self.path_authority_source = data.get(
                "path_authority_source", "standing_policy_snapshot"
            )
            self.expires_at = data.get("expires_at")

        @staticmethod
        def _under(path, roots):
            resolved = Path(path).resolve(strict=False)
            for root in roots:
                try:
                    resolved.relative_to(Path(root).resolve(strict=False))
                    return True
                except ValueError:
                    pass
            return False

        def require_enabled(self):
            return None

        def require_profile(self, profile, hermes_root):
            if profile not in self.allowed_profiles and "*" not in self.allowed_profiles:
                raise PermissionError("profile denied")

        def require_read_path(self, path):
            if not self._under(path, self.readable_roots):
                raise PermissionError("read path denied")

        def require_write_path(self, path):
            if not self._under(path, self.writable_roots):
                raise PermissionError("write path denied")

        def require_level(self, level):
            if level != "workspace":
                raise PermissionError("level denied")

        def require_mutation(self, dry_run):
            if dry_run or self.apply_mode != "direct":
                raise PermissionError("mutation denied")

        def require_verb(self, resource, verb):
            if verb not in self.verbs.get(resource, []):
                raise PermissionError(f"verb denied: {resource}:{verb}")

    return MultiAuthorityPolicy


def test_multi_standing_resolver_selects_narrowest_complete_authority(monkeypatch, tmp_path):
    workdir = tmp_path / "maintenance" / "specific"
    workdir.mkdir(parents=True)
    registry = {
        "sa_broad": {
            "session_id": "sa_broad",
            "readable_roots": [tmp_path],
            "writable_roots": [tmp_path],
            "verbs": {"filesystem": ["read", "edit"], "git": ["commit"]},
            "allowed_profiles": ["default", "backend-eng"],
        },
        "sa_narrow": {
            "session_id": "sa_narrow",
            "readable_roots": [workdir],
            "writable_roots": [workdir],
            "verbs": {"filesystem": ["edit"]},
            "allowed_profiles": ["default"],
        },
        "active": {
            "session_id": "sa_broad",
            "readable_roots": [tmp_path],
            "writable_roots": [tmp_path],
            "verbs": {"filesystem": ["read", "edit"], "git": ["commit"]},
            "allowed_profiles": ["default", "backend-eng"],
        },
        "effective": {
            "session_id": "ops_session",
            "readable_roots": [tmp_path],
            "writable_roots": [tmp_path],
            "verbs": {"filesystem": ["edit"], "services": ["restart"]},
            "allowed_profiles": ["default"],
            "path_authority_source": "session_snapshot",
            "expires_at": 9999999999,
        },
    }
    policy_cls = _multi_authority_policy_class(registry)
    monkeypatch.setattr(delegation.op, "OperatorPolicy", policy_cls)
    monkeypatch.setattr(
        delegation.op_standing,
        "list_standing_authorities",
        lambda: [
            type("Authority", (), {"authority_id": "sa_broad"})(),
            type("Authority", (), {"authority_id": "sa_narrow"})(),
        ],
    )

    selected = delegation._select_delegation_policy(
        profile="default", workdir=workdir, mode="apply", allow_web=False
    )

    assert selected.session_id == "sa_narrow"
    assert selected.path_authority_source == "standing_policy_snapshot"


def test_multi_standing_resolver_never_composes_partial_grants(monkeypatch, tmp_path):
    workdir = tmp_path / "maintenance"
    workdir.mkdir()
    registry = {
        "sa_read": {
            "session_id": "sa_read",
            "readable_roots": [workdir],
            "writable_roots": [],
            "verbs": {"filesystem": ["read"]},
        },
        "sa_write": {
            "session_id": "sa_write",
            "readable_roots": [],
            "writable_roots": [workdir],
            "verbs": {"filesystem": ["edit"]},
        },
        "active": {
            "session_id": "sa_read",
            "readable_roots": [workdir],
            "writable_roots": [],
            "verbs": {"filesystem": ["read"]},
        },
        "effective": {
            "session_id": "ops_insufficient",
            "readable_roots": [],
            "writable_roots": [],
            "verbs": {},
            "path_authority_source": "session_snapshot",
            "expires_at": 9999999999,
        },
    }
    policy_cls = _multi_authority_policy_class(registry)
    monkeypatch.setattr(delegation.op, "OperatorPolicy", policy_cls)
    monkeypatch.setattr(
        delegation.op_standing,
        "list_standing_authorities",
        lambda: [
            type("Authority", (), {"authority_id": "sa_read"})(),
            type("Authority", (), {"authority_id": "sa_write"})(),
        ],
    )

    with pytest.raises(PermissionError, match="not composable"):
        delegation._select_delegation_policy(
            profile="default", workdir=workdir, mode="apply", allow_web=False
        )


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
    hermes_root = tmp_path / "hermes"
    hermes_root.mkdir()
    (hermes_root / "config.yaml").write_text("model:\n  provider: openrouter\n", encoding="utf-8")
    monkeypatch.setattr(delegation, "HERMES_ROOT", hermes_root)
    _pin_control(monkeypatch, tmp_path, include_qualified_routes=False)
    profile_home = tmp_path / "profile"
    profile_home.mkdir()
    (profile_home / "config.yaml").write_text(
        f"model:\n  provider: openrouter\n  default: {_OPENROUTER_MODEL}\nplugins:\n  enabled:\n    - chronos\n",
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
    # No eligible alternates are configured, so no fallback chain is emitted and
    # the runtime profile stays minimal: no plugins, MCP servers or memory.
    assert loaded == {
        "model": {
            "provider": "openrouter",
            "model": _OPENROUTER_MODEL,
            "default": _OPENROUTER_MODEL,
        },
        "display": {"interface": "cli"},
    }
    assert "plugins" not in loaded
    assert (runtime_home / ".env").is_symlink()
    assert (runtime_home / "logs").parent == runtime_home
    (runtime_home / "logs").mkdir()
    (runtime_home / "logs" / "agent.log").write_text("ok\n", encoding="utf-8")


def test_prepare_ephemeral_nous_shared_dir_is_private_and_nous_only(monkeypatch, tmp_path):
    private_dir = tmp_path / "nous-shared"
    private_dir.mkdir()
    monkeypatch.setattr(
        delegation.tempfile,
        "mkdtemp",
        lambda prefix: str(private_dir),
    )
    nous_route = delegation.routing.RouteCandidate(
        provider="nous",
        model="tencent/hy3:free",
    )

    selected = delegation._prepare_ephemeral_nous_shared_dir(
        nous_route,
        "dt_test",
    )

    assert selected == private_dir
    assert selected.stat().st_mode & 0o777 == 0o700
    assert list(selected.iterdir()) == []

    non_nous = delegation.routing.RouteCandidate(
        provider="nvidia",
        model="test/model",
    )
    assert delegation._prepare_ephemeral_nous_shared_dir(
        non_nous,
        "dt_test",
    ) is None


def test_select_structurally_runnable_route_skips_nous_for_default_profile(monkeypatch, tmp_path):
    hermes_root = tmp_path / "hermes"
    hermes_root.mkdir()
    monkeypatch.setattr(delegation, "HERMES_ROOT", hermes_root)
    nous = delegation.routing.RouteCandidate(provider="nous", model="tencent/hy3:free")
    nvidia = delegation.routing.RouteCandidate(provider="nvidia", model="test/model")
    resolved = delegation.routing.ResolvedRouting(primary=nous, alternates=[nvidia])

    selected, skipped = delegation._select_structurally_runnable_route(resolved, hermes_root)

    assert selected == nvidia
    assert skipped == [
        {
            "route": nous.to_audit_dict(),
            "reason": "Nous delegation requires a named Hermes profile home",
        }
    ]


def test_prepare_nous_profile_runtime_home_uses_exact_selected_profile(monkeypatch, tmp_path):
    hermes_root = tmp_path / "hermes"
    profile_home = hermes_root / "profiles" / "hy3-free-test"
    profile_home.mkdir(parents=True)
    (profile_home / "config.yaml").write_text(
        "model:\n  provider: nous\n  model: tencent/hy3:free\n",
        encoding="utf-8",
    )
    auth_path = profile_home / delegation.AUTH_FILENAME
    auth_path.write_text(
        json.dumps(
            {
                "providers": {
                    "nous": {
                        "access_token": "access",
                        "refresh_token": "refresh",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    before = auth_path.read_text(encoding="utf-8")
    monkeypatch.setattr(delegation, "HERMES_ROOT", hermes_root)
    route = delegation.routing.RouteCandidate(provider="nous", model="tencent/hy3:free")

    selected = delegation._prepare_nous_profile_runtime_home(route, profile_home)

    assert selected == profile_home.resolve(strict=False)
    assert auth_path.read_text(encoding="utf-8") == before


def test_prepare_nous_profile_runtime_home_rejects_global_or_external_home(monkeypatch, tmp_path):
    hermes_root = tmp_path / "hermes"
    hermes_root.mkdir()
    external = tmp_path / "external-profile"
    external.mkdir()
    (external / "config.yaml").write_text(
        "model:\n  provider: nous\n  model: tencent/hy3:free\n",
        encoding="utf-8",
    )
    (external / delegation.AUTH_FILENAME).write_text(
        json.dumps({"providers": {"nous": {"access_token": "access"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(delegation, "HERMES_ROOT", hermes_root)
    route = delegation.routing.RouteCandidate(provider="nous", model="tencent/hy3:free")

    with pytest.raises(RuntimeError, match="named Hermes profile home"):
        delegation._prepare_nous_profile_runtime_home(route, external)


def test_prepare_nous_profile_runtime_home_requires_matching_model_and_auth(monkeypatch, tmp_path):
    hermes_root = tmp_path / "hermes"
    profile_home = hermes_root / "profiles" / "hy3-free-test"
    profile_home.mkdir(parents=True)
    monkeypatch.setattr(delegation, "HERMES_ROOT", hermes_root)
    route = delegation.routing.RouteCandidate(provider="nous", model="tencent/hy3:free")

    (profile_home / "config.yaml").write_text(
        "model:\n  provider: nous\n  model: tencent/hy3\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="model does not match"):
        delegation._prepare_nous_profile_runtime_home(route, profile_home)

    (profile_home / "config.yaml").write_text(
        "model:\n  provider: nous\n  model: tencent/hy3:free\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="no usable local auth state"):
        delegation._prepare_nous_profile_runtime_home(route, profile_home)


def test_prepare_nous_profile_runtime_home_is_nous_only(tmp_path):
    route = delegation.routing.RouteCandidate(provider="nvidia", model="test/model")
    assert delegation._prepare_nous_profile_runtime_home(
        route,
        tmp_path / "profile",
    ) is None


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


def test_read_only_forecast_requires_explicit_web_authority(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation.op, "OperatorPolicy", NoWebPolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)

    result = json.loads(
        delegation.hermes_delegate_task_forecast(
            workdir=str(tmp_path),
            mode="plan",
            profile="default",
            allow_web=True,
            timeout=60,
            total_task_window=60,
            worker_slice_timeout=60,
        )
    )

    assert result["success"] is True
    assert result["granted"] is False
    assert "web authority" in result["denial"]["error"].lower()


def test_read_only_delegation_requires_explicit_web_authority_before_launch(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", NoWebPolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)

    result = json.loads(
        delegation.hermes_delegate_task(
            prompt="Inspect the repository.",
            workdir=str(tmp_path),
            mode="plan",
            profile="default",
            allow_web=True,
            timeout=60,
            total_task_window=60,
            worker_slice_timeout=60,
        )
    )

    assert result["success"] is False
    assert not (tmp_path / "tasks").exists()


def test_read_only_delegation_allows_web_with_explicit_web_authority(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation.op, "OperatorPolicy", WebPolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(delegation.threading.Thread, "start", lambda self: None)

    result = json.loads(
        delegation.hermes_delegate_task(
            prompt="Inspect the repository.",
            workdir=str(tmp_path),
            mode="plan",
            profile="default",
            allow_web=True,
            timeout=60,
            total_task_window=60,
            worker_slice_timeout=60,
        )
    )

    assert result["success"] is True
    task = delegation._load(result["task_id"])
    tool_arg = task["argv"][task["argv"].index("-t") + 1]
    assert tool_arg == "file_read_only,web"
    assert task["authority"]["allow_web"] is True


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


@pytest.mark.parametrize(
    ("worker_status", "expected_status"),
    [
        ("queued", "In Progress"),
        ("running", "In Progress"),
        ("completed", "In Review"),
        ("cancelled", "Cancelled"),
        ("failed", "On Hold"),
        ("blocked", "On Hold"),
        ("incomplete", "On Hold"),
    ],
)
def test_mission_status_maps_worker_lifecycle(worker_status, expected_status):
    assert delegation._mission_status(worker_status) == expected_status


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
        row = connection.execute(
            "SELECT status, result FROM tasks WHERE id='lw_mc'"
        ).fetchone()
        status, result_json = row[0], row[1]

    assert task_count == 1
    assert event_count == 2
    assert status == "In Review"
    result_payload = json.loads(result_json)
    assert result_payload["task_id"] == "dt_mc"


def test_mission_control_review_acceptance_requires_lease_and_completes_canonical_task(monkeypatch, tmp_path):
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
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(
        delegation.op_lease,
        "verify_lease_token",
        lambda token: {
            "success": token == "lease-secret",
            "error": None if token == "lease-secret" else "INVALID_LEASE_TOKEN",
            "owner": "mission-control-test",
            "lease_id": "lease-test",
        },
    )
    task = {
        "logical_work_id": "lw_review",
        "task_id": "dt_review",
        "attempt_id": "da_review",
        "interaction_id": "di_review",
        "status": "completed",
        "profile": "default",
        "workdir": str(tmp_path),
        "checkpoint_ref": "checkpoint-review",
        "outcome_reason": "complete",
        "returncode": 0,
        "stdout": "REVIEW_OK",
        "stderr": "",
        "messages": [],
        "changed_files": [],
        "authority": {"session_id": "ops_test"},
    }
    delegation._save(task)
    delegation._record_mission_control(task, event="completed")

    accepted = json.loads(
        delegation.hermes_delegated_task_message(
            "dt_review",
            delegation.MISSION_CONTROL_REVIEW_ACCEPT_PREFIX
            + "lease-secret:independent runtime acceptance passed",
        )
    )
    persisted = delegation._load("dt_review")
    replay = json.loads(
        delegation.hermes_delegated_task_message(
            "dt_review",
            delegation.MISSION_CONTROL_REVIEW_ACCEPT_PREFIX
            + "lease-secret:independent runtime acceptance passed",
        )
    )
    envelope = json.loads(delegation.hermes_delegated_task_result("dt_review"))

    with sqlite3.connect(db) as connection:
        status, result_json = connection.execute(
            "SELECT status, result FROM tasks WHERE id='lw_review'"
        ).fetchone()
        event_count = connection.execute(
            "SELECT count(*) FROM task_events WHERE task_id='lw_review'"
        ).fetchone()[0]

    assert accepted["success"] is True
    assert accepted["mission_control_status"] == "Completed"
    assert accepted["mission_control_persisted"] is True
    assert accepted["already_reviewed"] is False
    assert replay["mission_control_persisted"] is True
    assert replay["already_reviewed"] is True
    assert persisted["review_status"] == "accepted"
    assert persisted["messages"] == []
    assert "lease-secret" not in json.dumps(persisted)
    assert status == "Completed"
    assert json.loads(result_json)["review_status"] == "accepted"
    assert event_count == 2
    assert envelope["review_status"] == "accepted"
    assert envelope["review_summary"] == "independent runtime acceptance passed"
    assert envelope["mission_control_status"] == "Completed"
    assert envelope["mission_control_persisted"] is True
    assert delegation._mission_status("completed", "accepted") == "Completed"


def test_mission_control_review_acceptance_rejects_invalid_lease(monkeypatch, tmp_path):
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(
        delegation.op_lease,
        "verify_lease_token",
        lambda token: {"success": False, "error": "INVALID_LEASE_TOKEN"},
    )
    task = {
        "logical_work_id": "lw_review_bad",
        "task_id": "dt_reviewbad",
        "status": "completed",
        "messages": [],
        "stdout": "REVIEW_OK",
        "stderr": "",
    }
    delegation._save(task)

    rejected = json.loads(
        delegation.hermes_delegated_task_message(
            "dt_reviewbad",
            delegation.MISSION_CONTROL_REVIEW_ACCEPT_PREFIX + "bad-token:review passed",
        )
    )
    persisted = delegation._load("dt_reviewbad")

    assert rejected["success"] is False
    assert "review_status" not in persisted
    assert persisted["messages"] == []
    assert "bad-token" not in json.dumps(persisted)


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


def test_require_task_authority_accepts_active_standing_authority_without_expiry(monkeypatch, tmp_path):
    captured = {}

    class StandingPolicy(FakePolicy):
        session_status = "standing"
        session_id = "sa_test"
        expires_at = None

        def __init__(self, *, authority_preference="effective", standing_authority_id=None):
            captured["authority_preference"] = authority_preference
            captured["standing_authority_id"] = standing_authority_id

    monkeypatch.setattr(delegation.op, "OperatorPolicy", StandingPolicy)
    task = {
        "profile": "default",
        "workdir": str(tmp_path),
        "mode": "apply",
        "authority": {
            "authority_kind": "standing",
            "session_id": "sa_test",
            "snapshot_hash": "snapshot",
            "expires_at": None,
            "profile": "default",
            "workdir": str(tmp_path),
            "mode": "apply",
        },
    }

    delegation._require_task_authority(task)
    assert captured == {
        "authority_preference": "standing",
        "standing_authority_id": "sa_test",
    }


def test_require_task_authority_rejects_inactive_standing_authority(monkeypatch, tmp_path):
    class InactiveStandingPolicy(FakePolicy):
        session_status = "read_only"
        session_id = "sa_test"
        expires_at = None

    monkeypatch.setattr(delegation.op, "OperatorPolicy", InactiveStandingPolicy)
    task = {
        "profile": "default",
        "workdir": str(tmp_path),
        "mode": "apply",
        "authority": {
            "authority_kind": "standing",
            "session_id": "sa_test",
            "snapshot_hash": "snapshot",
            "expires_at": None,
            "profile": "default",
            "workdir": str(tmp_path),
            "mode": "apply",
        },
    }

    with pytest.raises(PermissionError, match="standing authority is no longer active"):
        delegation._require_task_authority(task)


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
    assert result["evidence_envelope_version"] == 1
    assert result["final_answer"] == "done"
    assert result["final_summary"] == "done"
    assert result["final_answer_extraction_status"] == "legacy_single_line"
    assert result["raw_output_included"] is False
    assert result["raw_output_available"] is True
    assert result["message_count"] == 0
    assert "stdout" not in result
    assert "stderr" not in result
    assert "messages" not in result
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


def test_forecast_ignores_diagnostic_expiry_without_active_session(monkeypatch, tmp_path):
    class StandingReadOnlyPolicy(FakePolicy):
        level = "read_only"
        apply_mode = "dry_run"
        session_id = None
        snapshot_hash = None
        expires_at = 200
        readable_roots = [tmp_path]
        writable_roots = []
        verbs = {"filesystem": ["read"]}

        def require_level(self, level):
            assert level == "read_only"

    monkeypatch.setattr(delegation.op, "OperatorPolicy", StandingReadOnlyPolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(delegation, "_now", lambda: 1000)

    result = json.loads(
        delegation.hermes_delegate_task_forecast(
            workdir=str(tmp_path),
            mode="plan",
            timeout=600,
            total_task_window=600,
        )
    )

    assert result["granted"] is True
    assert result["authority"]["session_id"] is None
    assert result["authority"]["long_horizon"]["envelope_deadline"] == 1600


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
    assert result["final_answer"] == "final result"
    assert result["raw_output_included"] is False
    assert "stdout" not in result
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


# ---------------------------------------------------------------------------
# Delegated runtime fallback inheritance and bounded cross-provider recovery
# ---------------------------------------------------------------------------

_NVIDIA_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
_OPENROUTER_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"


def _pin_control(monkeypatch, tmp_path, **overrides):
    """Write and select a bounded routing control surface for one test."""
    raw = json.loads(routing.DEFAULT_ROUTING_CONTROL_PATH.read_text(encoding="utf-8"))
    raw.update(overrides)
    path = tmp_path / "routing_control.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setenv(routing.ROUTING_CONTROL_ENV, str(path))
    return path


def _routing_workspace(monkeypatch, tmp_path, *, fallbacks=None):
    """Hermetic profile/global config plus the shipped routing control."""
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    hermes_root = tmp_path / "hermes"
    hermes_root.mkdir(parents=True, exist_ok=True)
    chain = [{"provider": "nvidia", "model": _NVIDIA_MODEL}] if fallbacks is None else fallbacks
    (hermes_root / "config.yaml").write_text(
        delegation.yaml.safe_dump(
            {
                "model": {"provider": "openrouter", "model": _OPENROUTER_MODEL},
                "fallback_providers": chain,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    (hermes_root / ".env").write_text("OPENROUTER_API_KEY=secret\n", encoding="utf-8")
    monkeypatch.setattr(delegation, "HERMES_ROOT", hermes_root)
    monkeypatch.setattr(
        delegation.op, "resolve_profile_home", lambda profile, root: hermes_root
    )
    return hermes_root


def _queued_task(monkeypatch, tmp_path, workdir, *, profile="default"):
    monkeypatch.setattr(delegation.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(delegation.op, "validate_profile_name", lambda value: value)
    monkeypatch.setattr(delegation.threading.Thread, "start", lambda self: None)
    monkeypatch.setattr(delegation, "_require_task_authority", lambda task: None)
    result = json.loads(
        delegation.hermes_delegate_task(
            prompt="Apply the requested bounded change.",
            workdir=str(workdir),
            mode="apply",
            profile=profile,
            timeout=120,
        )
    )
    assert result["success"] is True, result
    return result["task_id"]


def test_runtime_materialisation_preserves_the_resolved_fallback_chain(monkeypatch, tmp_path):
    """The root-cause fix: fallback_providers must survive materialisation."""
    _routing_workspace(monkeypatch, tmp_path)

    runtime_home = delegation._prepare_runtime_home(
        {"task_id": "dt_" + "a" * 32, "profile": "default", "timeout": 120}
    )

    loaded = delegation.yaml.safe_load(
        (runtime_home / "config.yaml").read_text(encoding="utf-8")
    )
    assert loaded["model"]["provider"] == "openrouter"
    assert loaded["model"]["model"] == _OPENROUTER_MODEL
    assert loaded["fallback_providers"][0] == {"provider": "nvidia", "model": _NVIDIA_MODEL}
    assert len(loaded["fallback_providers"]) == 3
    assert all(item["provider"] != "ollama" for item in loaded["fallback_providers"])

    audit = json.loads((runtime_home / "routing.json").read_text(encoding="utf-8"))
    assert audit["primary"]["lane"] == "openrouter"
    # NVIDIA direct leads the canonical order; the bounded live policy now
    # materialises up to three qualified free Agent alternates.
    assert audit["alternates"][0]["lane"] == "nvidia"
    assert audit["materialised_fallback_providers"][0] == {
        "provider": "nvidia",
        "model": _NVIDIA_MODEL,
    }
    assert len(audit["materialised_fallback_providers"]) == 3
    assert all(item["provider"] != "ollama" for item in audit["materialised_fallback_providers"])
    assert audit["free_only"] is True
    assert audit["max_alternate_attempts"] == 3
    assert audit["provider_order"] == list(routing.CANONICAL_PROVIDER_ORDER)
    assert audit["deadline_seconds"] == 120


def test_runtime_materialisation_preserves_explicit_empty_fallback_barrier(monkeypatch, tmp_path):
    _routing_workspace(monkeypatch, tmp_path, fallbacks=[])

    runtime_home = delegation._prepare_runtime_home(
        {"task_id": "dt_" + "f" * 32, "profile": "default", "timeout": 120}
    )

    loaded = delegation.yaml.safe_load(
        (runtime_home / "config.yaml").read_text(encoding="utf-8")
    )
    assert loaded["model"]["provider"] == "openrouter"
    assert loaded["fallback_providers"] == []

    audit = json.loads((runtime_home / "routing.json").read_text(encoding="utf-8"))
    assert audit["fallbacks_disabled"] is True
    assert audit["alternates"] == []
    assert audit["materialised_fallback_providers"] == []
    assert audit["max_alternate_attempts"] == 0


def test_direct_only_ollama_is_excluded_while_nous_remains_agent_available(monkeypatch, tmp_path):
    _routing_workspace(
        monkeypatch,
        tmp_path,
        fallbacks=[
            {"provider": "ollama", "model": "qwen2.5:7b-instruct"},
            {"provider": "nous", "model": "tencent/hy3:free"},
            {"provider": "nvidia", "model": _NVIDIA_MODEL},
        ],
    )

    runtime_home = delegation._prepare_runtime_home(
        {"task_id": "dt_" + "b" * 32, "profile": "default", "timeout": 60}
    )
    audit = json.loads((runtime_home / "routing.json").read_text(encoding="utf-8"))

    lanes = {item["lane"] for item in audit["alternates"]}
    assert "ollama" not in lanes
    assert "nous" in lanes
    control = routing.load_routing_control().control_for("ollama")
    assert control.direct_inference_models == ("qwen2.5:7b-instruct",)
    assert control.agent_qualified_models == ()


def test_worker_uses_selected_nous_profile_and_keeps_file_root_confined(monkeypatch, tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    hermes_root = _routing_workspace(monkeypatch, tmp_path, fallbacks=[])
    profile_home = hermes_root / "profiles" / "hy3-free-test"
    profile_home.mkdir(parents=True)
    (profile_home / "config.yaml").write_text(
        delegation.yaml.safe_dump(
            {
                "model": {"provider": "nous", "model": "tencent/hy3:free"},
                "fallback_providers": [],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    auth_path = profile_home / delegation.AUTH_FILENAME
    auth_path.write_text(
        json.dumps(
            {
                "providers": {
                    "nous": {
                        "access_token": "access",
                        "refresh_token": "refresh",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    before_auth = auth_path.read_text(encoding="utf-8")
    monkeypatch.setattr(
        delegation.op,
        "resolve_profile_home",
        lambda profile, root: profile_home if profile == "hy3-free-test" else hermes_root,
    )
    task_id = _queued_task(
        monkeypatch,
        tmp_path,
        workdir,
        profile="hy3-free-test",
    )
    shared_dir = tmp_path / "ephemeral-shared"
    shared_dir.mkdir()
    monkeypatch.setattr(
        delegation.tempfile,
        "mkdtemp",
        lambda prefix: str(shared_dir),
    )

    observed: dict[str, str] = {}

    def fake_run(task_id_arg, task, env):
        observed.update(
            {
                "HERMES_HOME": env["HERMES_HOME"],
                "FILE_ROOT": env[delegation.FILE_READ_SAFE_ROOT_ENV],
                "SHARED_AUTH_DIR": env[delegation.SHARED_AUTH_DIR_ENV],
            }
        )
        selected_shared = Path(env[delegation.SHARED_AUTH_DIR_ENV])
        assert selected_shared == shared_dir
        assert selected_shared.stat().st_mode & 0o777 == 0o700
        assert list(selected_shared.iterdir()) == []
        assert not selected_shared.is_relative_to(workdir)
        (workdir / "applied.txt").write_text("done\n", encoding="utf-8")
        return (
            0,
            f"{delegation.FINAL_ANSWER_BEGIN}\nApplied.\n{delegation.FINAL_ANSWER_END}",
            "",
            "",
        )

    monkeypatch.setattr(delegation, "_run_worker_process", fake_run)
    monkeypatch.setattr(delegation, "_schedule_automatic_continuation", lambda tid: None)

    delegation._worker(task_id)

    assert delegation._load(task_id)["status"] == "completed"
    assert Path(observed["HERMES_HOME"]) == profile_home.resolve(strict=False)
    assert Path(observed["FILE_ROOT"]) == workdir
    assert Path(observed["SHARED_AUTH_DIR"]) == shared_dir
    assert not shared_dir.exists()
    assert auth_path.read_text(encoding="utf-8") == before_auth


def test_completed_task_metadata_does_not_reclassify_historical_fallback_text():
    failure_category, provider_error_category = delegation._classify_failure(
        rc=0,
        stdout="Historical evidence recorded provider_error_category=fallback_response.",
        stderr="",
        status="completed",
        reason="substantive output and required workspace evidence were produced",
    )
    assert failure_category is None
    assert provider_error_category is None


def test_provider_attempt_start_clears_previous_attempt_outcome(monkeypatch, tmp_path):
    """A recovered alternate must not expose the predecessor's terminal fields."""
    monkeypatch.setattr(delegation, "_TASKS_ROOT", tmp_path / "tasks")
    monkeypatch.setattr(delegation, "_write_checkpoint", lambda *args, **kwargs: None)
    monkeypatch.setattr(delegation, "_record_mission_control", lambda *args, **kwargs: None)
    workdir = tmp_path / "work"
    workdir.mkdir()
    task_id = "dt_" + "a" * 32
    task = {
        "task_id": task_id,
        "status": "running",
        "argv": ["fake-worker"],
        "workdir": str(workdir),
        "timeout": 30,
        "pid": None,
        "returncode": 0,
        "stdout": "previous attempt output",
        "stderr": "previous attempt stderr",
        "outcome_reason": "previous attempt failed",
        "failure_category": "evidence_failure",
        "provider_error_category": "rate_limit",
        "events": [],
    }
    delegation._save(task)
    observed = {}

    class FakeProcess:
        pid = 4242
        returncode = 0

        def communicate(self, timeout=None):
            current = delegation._load(task_id)
            observed.update(
                {
                    "status": current["status"],
                    "pid": current["pid"],
                    "returncode": current["returncode"],
                    "stdout": current["stdout"],
                    "stderr": current["stderr"],
                    "outcome_reason": current["outcome_reason"],
                    "failure_category": current["failure_category"],
                    "provider_error_category": current["provider_error_category"],
                }
            )
            return "current attempt output", ""

    monkeypatch.setattr(delegation.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())

    rc, stdout, stderr, authority_failure = delegation._run_worker_process(task_id, task, os.environ.copy())

    assert rc == 0
    assert stdout == "current attempt output"
    assert stderr == ""
    assert authority_failure == ""
    assert observed == {
        "status": "running",
        "pid": 4242,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "outcome_reason": "",
        "failure_category": None,
        "provider_error_category": None,
    }


def test_empty_response_triggers_exactly_one_cross_provider_alternate(monkeypatch, tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    _routing_workspace(monkeypatch, tmp_path)
    task_id = _queued_task(monkeypatch, tmp_path, workdir)

    runtimes: list[dict] = []
    calls = {"n": 0}

    def fake_run(task_id_arg, task, env):
        calls["n"] += 1
        runtimes.append(
            delegation.yaml.safe_load(
                (Path(env["HERMES_HOME"]) / "config.yaml").read_text(encoding="utf-8")
            )
        )
        if calls["n"] == 1:
            return 0, "No reply: the model returned empty content", "", ""
        # The alternate does real work so the apply evidence gate is satisfied.
        (workdir / "applied.txt").write_text("done\n", encoding="utf-8")
        return (
            0,
            f"{delegation.FINAL_ANSWER_BEGIN}\nApplied the change.\n{delegation.FINAL_ANSWER_END}",
            "",
            "",
        )

    monkeypatch.setattr(delegation, "_run_worker_process", fake_run)
    monkeypatch.setattr(delegation, "_schedule_automatic_continuation", lambda tid: None)

    original_attempt_id = delegation._load(task_id)["attempt_id"]
    delegation._worker(task_id)
    task = delegation._load(task_id)

    # Exactly one alternate attempt: bounded, not a walk of the provider list.
    assert calls["n"] == 2
    assert runtimes[0]["model"]["provider"] == "openrouter"
    assert runtimes[1]["model"]["provider"] == "nvidia"
    assert runtimes[1]["model"]["model"] == _NVIDIA_MODEL

    assert task["status"] == "completed"
    # New attempt identity with predecessor and preserved logical work id.
    assert task["attempt_id"] != original_attempt_id
    assert task["predecessor_attempt_id"] == original_attempt_id
    assert task["logical_work_id"].startswith("lw_")
    assert len(task["attempts"]) == 1
    assert task["attempts"][0]["attempt_id"] == original_attempt_id
    assert task["attempts"][0]["failure_class"] == routing.FailureClass.EMPTY_RESPONSE.value
    assert task["recovery_selection"]["alternate_route"]["lane"] == "nvidia"
    assert task["recovery_selection"]["failed_route"]["lane"] == "openrouter"


def test_rate_limited_primary_recovers_on_the_alternate(monkeypatch, tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    _routing_workspace(monkeypatch, tmp_path)
    task_id = _queued_task(monkeypatch, tmp_path, workdir)

    calls = {"n": 0}

    def fake_run(task_id_arg, task, env):
        calls["n"] += 1
        if calls["n"] == 1:
            return 0, "", "HTTP 429 free-tier input quota exhausted", ""
        (workdir / "applied.txt").write_text("done\n", encoding="utf-8")
        return (
            0,
            f"{delegation.FINAL_ANSWER_BEGIN}\nApplied.\n{delegation.FINAL_ANSWER_END}",
            "",
            "",
        )

    monkeypatch.setattr(delegation, "_run_worker_process", fake_run)
    monkeypatch.setattr(delegation, "_schedule_automatic_continuation", lambda tid: None)
    delegation._worker(task_id)

    task = delegation._load(task_id)
    assert calls["n"] == 2
    assert task["status"] == "completed"
    assert task["attempts"][0]["failure_class"] == routing.FailureClass.RATE_LIMIT.value


def test_permission_failure_does_not_consume_a_model_alternate(monkeypatch, tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    _routing_workspace(monkeypatch, tmp_path)
    task_id = _queued_task(monkeypatch, tmp_path, workdir)

    calls = {"n": 0}

    def fake_run(task_id_arg, task, env):
        calls["n"] += 1
        return 0, "permission denied for the requested path", "", ""

    monkeypatch.setattr(delegation, "_run_worker_process", fake_run)
    monkeypatch.setattr(delegation, "_schedule_automatic_continuation", lambda tid: None)
    delegation._worker(task_id)

    task = delegation._load(task_id)
    assert calls["n"] == 1
    assert task["status"] == "blocked"
    assert task["failure_class"] == routing.FailureClass.PERMISSION_FAILURE.value
    assert task.get("attempts") == []


def test_retry_exhaustion_fails_closed_with_no_eligible_alternate(monkeypatch, tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    # Only an unqualified Ollama model is offered and control-supplied routes are off,
    # so no alternate is eligible and the task must fail closed.
    _routing_workspace(
        monkeypatch,
        tmp_path,
        fallbacks=[{"provider": "ollama", "model": "llama3.1:8b"}],
    )
    _pin_control(monkeypatch, tmp_path, include_qualified_routes=False)
    task_id = _queued_task(monkeypatch, tmp_path, workdir)

    calls = {"n": 0}

    def fake_run(task_id_arg, task, env):
        calls["n"] += 1
        return 0, "No reply: the model returned empty content", "", ""

    monkeypatch.setattr(delegation, "_run_worker_process", fake_run)
    monkeypatch.setattr(delegation, "_schedule_automatic_continuation", lambda tid: None)
    delegation._worker(task_id)

    task = delegation._load(task_id)
    assert calls["n"] == 1
    assert task["status"] == "incomplete"
    assert task["failure_class"] == routing.FailureClass.EMPTY_RESPONSE.value
    assert task.get("attempts") == []


def test_bounded_alternates_are_each_attempted_at_most_once(monkeypatch, tmp_path):
    """Recovery may use the bounded free chain, but never repeats a failed route."""
    workdir = tmp_path / "work"
    workdir.mkdir()
    _routing_workspace(
        monkeypatch,
        tmp_path,
        fallbacks=[
            {"provider": "nvidia", "model": _NVIDIA_MODEL},
            {"provider": "gemini", "model": "gemini-3.5-flash-lite"},
        ],
    )
    task_id = _queued_task(monkeypatch, tmp_path, workdir)

    calls = {"n": 0}

    def fake_run(task_id_arg, task, env):
        calls["n"] += 1
        return 0, "No reply: the model returned empty content", "", ""

    monkeypatch.setattr(delegation, "_run_worker_process", fake_run)
    monkeypatch.setattr(delegation, "_schedule_automatic_continuation", lambda tid: None)
    delegation._worker(task_id)

    task = delegation._load(task_id)
    assert calls["n"] == 4
    assert task["status"] == "incomplete"
    assert len(task["attempts"]) == 3
    attempted_routes = {(item["provider_lane"], item["model"]) for item in task["attempts"]}
    assert len(attempted_routes) == len(task["attempts"])


def test_queued_task_records_the_routing_decision(monkeypatch, tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    _routing_workspace(monkeypatch, tmp_path)
    task_id = _queued_task(monkeypatch, tmp_path, workdir)

    audit = delegation._load(task_id)["routing_audit"]
    assert audit["primary"]["lane"] == "openrouter"
    assert audit["alternates"][0]["lane"] == "nvidia"
    assert audit["max_alternate_attempts"] == 3
    assert audit["free_only"] is True
    assert audit["excluded"]


def test_apply_prompt_requires_explicit_no_change_justification(tmp_path):
    argv = delegation._build_argv(
        prompt="do the thing",
        mode="apply",
        profile="default",
        workdir=tmp_path,
        max_turns=5,
        allow_web=False,
    )
    effective = argv[argv.index("-q") + 1]
    assert routing.NO_CHANGE_JUSTIFICATION_PREFIX in effective
    assert "silent no-op is treated as a model failure" in effective
