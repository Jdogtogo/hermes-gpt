from __future__ import annotations

import json

import operator_controller_publish as publish
import operator_policy_templates as templates


COMMIT = "d45da7ae32e54833ace63aba213be7348ac7aa40"


class FakePolicy:
    session_id = "ops_test"
    level = "workspace"
    apply_mode = "direct"

    def __init__(self):
        self.required = []

    def require_read_path(self, path):
        assert path == publish.WORKTREE
        self.required.append(("read", str(path)))

    def require_verb(self, group, verb):
        assert (group, verb) == ("git", "push")
        self.required.append((group, verb))

    def effective_dry_run(self, dry_run):
        return bool(dry_run)

    def require_mutation(self, dry_run):
        assert dry_run is False


def _runner_factory(*, dirty: bool = False, host: str = "github.com", preflight_rc: int = 0):
    calls = []

    def runner(argv, *, timeout, workdir):
        calls.append(list(argv))
        assert workdir == str(publish.WORKTREE)
        args = argv[1:]
        if args == ["branch", "--show-current"]:
            return 0, publish.BRANCH + "\n", ""
        if args == ["rev-parse", "HEAD"]:
            return 0, COMMIT + "\n", ""
        if args == ["status", "--porcelain=v1"]:
            return 0, (" M server.py\n" if dirty else ""), ""
        if args == ["config", "--get", "remote.origin.url"]:
            return 0, f"git@{host}:owner/repo.git\n", ""
        if args[:3] == ["push", "--dry-run", "--porcelain"]:
            if preflight_rc:
                return preflight_rc, "", "! [rejected] non-fast-forward"
            return 0, "To github.com:owner/repo.git\n=\tHEAD:refs/heads/test\t[up to date]\n", ""
        if args[:2] == ["push", "--porcelain"]:
            return 0, "To github.com:owner/repo.git\n \tHEAD:refs/heads/test\tdone\n", ""
        if args[:2] == ["ls-remote", "--heads"]:
            return 0, f"{COMMIT}\trefs/heads/{publish.BRANCH}\n", ""
        raise AssertionError(f"unexpected git call: {argv!r}")

    return runner, calls


def _install_policy(monkeypatch):
    monkeypatch.setattr(publish.op, "OperatorPolicy", FakePolicy)
    monkeypatch.setattr(publish.op, "audit_record", lambda **kwargs: None)


def test_release_template_is_narrow_and_non_standing():
    resolved = templates.resolve_template("hermes-controller-release")
    policy = resolved["policy"]
    assert resolved["standing_authority_eligible"] is False
    assert policy["readable_roots"] == [str(publish.WORKTREE)]
    assert policy["writable_roots"] == []
    assert policy["egress_hosts"] == ["github.com"]
    assert policy["verbs"] == {"git": ["push"]}
    assert resolved["allowed_branches"] == [publish.BRANCH]


def test_dry_run_performs_remote_non_force_preflight_only(monkeypatch):
    _install_policy(monkeypatch)
    runner, calls = _runner_factory()
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=True, runner=runner))

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["plan"]["commit"] == COMMIT
    assert result["plan"]["force_push"] is False
    assert any(call[1:4] == ["push", "--dry-run", "--porcelain"] for call in calls)
    assert not any(call[1:3] == ["push", "--porcelain"] for call in calls)
    assert all("--force" not in call and "-f" not in call for call in calls)


def test_apply_pushes_exact_head_and_verifies_remote(monkeypatch):
    _install_policy(monkeypatch)
    runner, calls = _runner_factory()
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=False, runner=runner))

    assert result["success"] is True
    assert result["changed"] is True
    assert result["commit"] == COMMIT
    assert result["remote_verified"] is True
    actual_pushes = [call for call in calls if call[1:3] == ["push", "--porcelain"]]
    assert actual_pushes == [["git", "push", "--porcelain", "origin", f"HEAD:refs/heads/{publish.BRANCH}"]]
    assert all("--force" not in call and "-f" not in call for call in calls)


def test_dirty_worktree_refuses_before_network_push(monkeypatch):
    _install_policy(monkeypatch)
    runner, calls = _runner_factory(dirty=True)
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=False, runner=runner))

    assert result["success"] is False
    assert result["code"] == "CONTROLLER_PUBLISH_ERROR"
    assert not any("push" in call for call in calls)


def test_unapproved_remote_host_refuses_before_network_push(monkeypatch):
    _install_policy(monkeypatch)
    runner, calls = _runner_factory(host="example.com")
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=False, runner=runner))

    assert result["success"] is False
    assert result["code"] == "CONTROLLER_PUBLISH_ERROR"
    assert not any("push" in call for call in calls)


def test_non_fast_forward_preflight_blocks_apply(monkeypatch):
    _install_policy(monkeypatch)
    runner, calls = _runner_factory(preflight_rc=1)
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=False, runner=runner))

    assert result["success"] is False
    assert result["code"] == "CONTROLLER_PUBLISH_ERROR"
    assert any(call[1:4] == ["push", "--dry-run", "--porcelain"] for call in calls)
    assert not any(call[1:3] == ["push", "--porcelain"] for call in calls)


def test_expected_commit_must_equal_full_lowercase_head(monkeypatch):
    _install_policy(monkeypatch)
    runner, calls = _runner_factory()
    result = json.loads(publish.hermes_controller_publish("D45DA7AE", dry_run=False, runner=runner))

    assert result["success"] is False
    assert result["code"] == "CONTROLLER_PUBLISH_ERROR"
    assert calls == []


def test_release_template_can_be_approved_into_live_task_authority(tmp_path, monkeypatch):
    import operator_policy as op
    import operator_sessions as sessions

    root = tmp_path / "sessions"
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(root))
    for name in [
        op.OPERATOR_ENABLED_ENV,
        op.OPERATOR_LEVEL_ENV,
        op.OPERATOR_APPLY_MODE_ENV,
        op.OPERATOR_ALLOWED_PATHS_ENV,
        op.OWNER_ACK_ENV,
    ]:
        monkeypatch.delenv(name, raising=False)

    resolved = templates.resolve_template("hermes-controller-release")
    request_id = sessions.request_session(
        policy_template="hermes-controller-release",
        resolved_policy=resolved["policy"],
        requested_duration_seconds=3600,
        reason="publish exact reviewed Controller commit",
        root=root,
        now=2_000_000_000,
        request_id="sr_controller_release_test",
    )
    record = sessions.approve_session_request(
        request_id,
        decided_by="localhost",
        root=root,
        now=2_000_000_001,
    )
    authority = sessions.resolve_effective_authority(now=2_000_000_002)

    assert record.policy["policy_template"] == "hermes-controller-release"
    assert authority.is_active is True
    assert authority.policy_template == "hermes-controller-release"
    assert authority.verbs == {"git": ["push"]}
