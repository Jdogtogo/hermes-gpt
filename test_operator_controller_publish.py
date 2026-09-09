from __future__ import annotations

import json
import os

import operator_controller_publish as publish
import operator_policy_templates as templates


COMMIT = "d45da7ae32e54833ace63aba213be7348ac7aa40"
SENTINEL = "gho_SECRET_SENTINEL_12345678901234567890"


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

    def require_egress_host(self, host):
        assert host == "github.com"
        self.required.append(("egress", host))

    def effective_dry_run(self, dry_run):
        return bool(dry_run)

    def require_mutation(self, dry_run):
        assert dry_run is False


def _install_runtime(tmp_path, monkeypatch, *, auth=True):
    worktree = tmp_path / "repo"
    worktree.mkdir()
    gh = worktree / "logs/.release-tools/gh/gh"
    gh.parent.mkdir(parents=True)
    gh.write_text("fake", encoding="utf-8")
    gh.chmod(0o700)
    auth_dir = worktree / "logs/.release-tools/gh-auth"
    auth_config = auth_dir / "hosts.yml"
    if auth:
        auth_dir.mkdir(parents=True)
        auth_dir.chmod(0o700)
        auth_config.write_text("github.com:\n  user: test\n  oauth_token: opaque\n", encoding="utf-8")
        auth_config.chmod(0o600)

    monkeypatch.setattr(publish, "WORKTREE", worktree)
    monkeypatch.setattr(publish, "GH_BINARY", gh)
    monkeypatch.setattr(publish, "AUTH_DIR", auth_dir)
    monkeypatch.setattr(publish, "AUTH_CONFIG", auth_config)
    monkeypatch.setattr(publish.op, "OperatorPolicy", FakePolicy)
    audits = []
    monkeypatch.setattr(publish.op, "audit_record", lambda **kwargs: audits.append(kwargs))
    return worktree, gh, auth_dir, auth_config, audits


def _runner_factory(
    *,
    dirty: bool = False,
    remote_url: str | None = None,
    preflight_rc: int = 0,
    local_rewrite: bool = False,
):
    calls = []

    def runner(argv, *, timeout, workdir, env=None):
        calls.append({"argv": list(argv), "env": dict(env) if env is not None else None})
        assert workdir == str(publish.WORKTREE)
        args = argv[1:]
        if args == ["branch", "--show-current"]:
            return 0, publish.BRANCH + "\n", ""
        if args == ["rev-parse", "HEAD"]:
            return 0, COMMIT + "\n", ""
        if args == ["status", "--porcelain=v1"]:
            return 0, (" M server.py\n" if dirty else ""), ""
        if args == ["config", "--get", "remote.origin.url"]:
            return 0, (remote_url or publish.EXPECTED_REMOTE_URL) + "\n", ""
        if args == ["config", "--local", "--get-regexp", r"^url\..*\.insteadof$"]:
            if local_rewrite:
                return 0, "url.https://evil.example.insteadOf https://github.com\n", ""
            return 1, "", ""

        # Network git has three fixed -c entries before the actual verb.
        if "push" in args:
            idx = args.index("push")
            network_args = args[idx:]
            if network_args[:3] == ["push", "--dry-run", "--porcelain"]:
                if preflight_rc:
                    return preflight_rc, "", "! [rejected] non-fast-forward"
                return 0, "To https://github.com/Jdogtogo/hermes-gpt.git\n=\tHEAD:refs/heads/test\t[up to date]\n", ""
            if network_args[:2] == ["push", "--porcelain"]:
                return 0, "To https://github.com/Jdogtogo/hermes-gpt.git\n \tHEAD:refs/heads/test\tdone\n", ""
        if "ls-remote" in args:
            return 0, f"{COMMIT}\trefs/heads/{publish.REMOTE_BRANCH}\n", ""
        raise AssertionError(f"unexpected git call: {argv!r}")

    return runner, calls


def _network_calls(calls):
    return [c for c in calls if c["env"] is not None]


def test_release_template_is_narrow_non_standing_and_auth_hard_denied():
    resolved = templates.resolve_template("hermes-controller-release")
    policy = resolved["policy"]
    assert resolved["standing_authority_eligible"] is False
    assert policy["readable_roots"] == [
        "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration"
    ]
    assert policy["writable_roots"] == []
    assert policy["egress_hosts"] == ["github.com"]
    assert policy["verbs"] == {"git": ["push"]}
    assert policy["hard_denied_paths"] == [
        "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration/logs/.release-tools/gh-auth"
    ]
    assert resolved["allowed_branches"] == [publish.BRANCH]


def test_dry_run_uses_fixed_https_url_and_release_scoped_credential_broker(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    monkeypatch.setenv("GH_TOKEN", SENTINEL)
    monkeypatch.setenv("GITHUB_TOKEN", SENTINEL)
    runner, calls = _runner_factory()
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=True, runner=runner))

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["plan"]["remote_url"] == publish.EXPECTED_REMOTE_URL
    assert result["plan"]["credential_broker"] == "release-scoped-gh"
    assert result["plan"]["force_push"] is False
    network = _network_calls(calls)
    assert len(network) == 1
    call = network[0]
    argv = call["argv"]
    env = call["env"]
    assert publish.EXPECTED_REMOTE_URL in argv
    assert argv[1:7] == publish._credential_git_prefix()
    assert publish._credential_git_prefix()[0:2] == ["-c", "credential.helper="]
    assert str(publish.GH_BINARY) in " ".join(argv)
    assert "auth git-credential" in " ".join(argv)
    assert env["GH_CONFIG_DIR"] == str(publish.AUTH_DIR)
    assert env["GH_PROMPT_DISABLED"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ASKPASS"] == "/bin/false"
    assert "GH_TOKEN" not in env and "GITHUB_TOKEN" not in env
    assert SENTINEL not in json.dumps(result)
    assert SENTINEL not in json.dumps(calls)
    assert all("--force" not in c["argv"] and "-f" not in c["argv"] for c in calls)


def test_apply_pushes_exact_head_and_verifies_fixed_https_remote(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    runner, calls = _runner_factory()
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=False, runner=runner))

    assert result["success"] is True
    assert result["changed"] is True
    assert result["remote_url"] == publish.EXPECTED_REMOTE_URL
    assert result["remote_verified"] is True
    network = _network_calls(calls)
    actual_pushes = [c["argv"] for c in network if "push" in c["argv"] and "--dry-run" not in c["argv"]]
    assert len(actual_pushes) == 1
    assert publish.EXPECTED_REMOTE_URL in actual_pushes[0]
    assert f"HEAD:refs/heads/{publish.REMOTE_BRANCH}" in actual_pushes[0]
    assert any("ls-remote" in c["argv"] for c in network)
    assert all(c["argv"][1:7] == publish._credential_git_prefix() for c in network)
    assert all("--force" not in c["argv"] and "-f" not in c["argv"] for c in calls)


def test_dirty_worktree_refuses_before_network(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    runner, calls = _runner_factory(dirty=True)
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=False, runner=runner))
    assert result["success"] is False
    assert result["code"] == "CONTROLLER_PUBLISH_ERROR"
    assert _network_calls(calls) == []


def test_non_exact_https_origin_refuses_before_network(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    runner, calls = _runner_factory(remote_url="https://github.com/Jdogtogo/another-repo.git")
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=False, runner=runner))
    assert result["success"] is False
    assert result["code"] == "CONTROLLER_PUBLISH_ERROR"
    assert _network_calls(calls) == []


def test_ssh_origin_refuses_before_network(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    runner, calls = _runner_factory(remote_url="git@github.com:Jdogtogo/hermes-gpt.git")
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=False, runner=runner))
    assert result["success"] is False
    assert _network_calls(calls) == []


def test_missing_release_auth_refuses_before_network(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch, auth=False)
    runner, calls = _runner_factory()
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=True, runner=runner))
    assert result["success"] is False
    assert "complete device authorization" in result["error"].lower()
    assert _network_calls(calls) == []


def test_local_url_rewrite_refuses_before_network(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    runner, calls = _runner_factory(local_rewrite=True)
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=True, runner=runner))
    assert result["success"] is False
    assert "url rewrite" in result["error"].lower()
    assert _network_calls(calls) == []


def test_non_fast_forward_preflight_blocks_apply(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    runner, calls = _runner_factory(preflight_rc=1)
    result = json.loads(publish.hermes_controller_publish(COMMIT, dry_run=False, runner=runner))
    assert result["success"] is False
    network = _network_calls(calls)
    assert len(network) == 1
    assert "--dry-run" in network[0]["argv"]


def test_expected_commit_must_equal_full_lowercase_head(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    runner, calls = _runner_factory()
    result = json.loads(publish.hermes_controller_publish("D45DA7AE", dry_run=False, runner=runner))
    assert result["success"] is False
    assert result["code"] == "CONTROLLER_PUBLISH_ERROR"
    assert calls == []


def test_release_errors_and_audit_never_echo_inherited_token(tmp_path, monkeypatch):
    _, _, _, _, audits = _install_runtime(tmp_path, monkeypatch)
    monkeypatch.setenv("GH_TOKEN", SENTINEL)
    runner, calls = _runner_factory(preflight_rc=1)
    payload = publish.hermes_controller_publish(COMMIT, dry_run=True, runner=runner)
    assert SENTINEL not in payload
    assert SENTINEL not in json.dumps(audits)
    assert SENTINEL not in json.dumps(calls)


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
