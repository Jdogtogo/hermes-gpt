from __future__ import annotations

import json
from pathlib import Path

import operator_ops_brain_publish as publish


TARGET = "b" * 40
REMOTE_BEFORE = "a" * 40
REMOTE_URL = "git@github.com:Jdogtogo/hermes-ops-brain.git"


class FakePolicy:
    session_id = "ops_test"
    level = "workspace"
    apply_mode = "direct"

    def __init__(self, *, allow_preflight: bool = True, allow_release: bool = True):
        self.required = []
        self.allow_preflight = allow_preflight
        self.allow_release = allow_release

    def require_level(self, level):
        assert level == "workspace"
        self.required.append(("level", level))

    def require_read_path(self, path):
        assert Path(path) == publish.CANONICAL_REPO
        self.required.append(("read", str(path)))

    def require_write_path(self, path):
        assert Path(path) == publish.PUBLISH_ROOT
        self.required.append(("write", str(path)))

    def require_egress_host(self, host):
        assert host == "github.com"
        self.required.append(("egress", host))

    def require_verb(self, group, verb):
        assert group == "opsbrain"
        assert verb in {"preflight", "release"}
        if verb == "preflight" and not self.allow_preflight:
            raise PermissionError("preflight not granted")
        if verb == "release" and not self.allow_release:
            raise PermissionError("release not granted")
        self.required.append((group, verb))

    def require_branch(self, branch):
        assert branch == "master"
        self.required.append(("branch", branch))

    def require_mutation(self, dry_run):
        assert dry_run is False
        self.required.append(("mutation", "direct"))


def _install(monkeypatch, tmp_path, *, policy=None):
    canonical = tmp_path / "ops-brain"
    canonical.mkdir(parents=True, exist_ok=True)
    scratch_root = tmp_path / "publish-scratch"
    selected_policy = policy or FakePolicy()
    monkeypatch.setattr(publish, "CANONICAL_REPO", canonical)
    monkeypatch.setattr(publish, "PUBLISH_ROOT", scratch_root)
    monkeypatch.setattr(publish.op, "OperatorPolicy", lambda: selected_policy)
    monkeypatch.setattr(publish.op, "audit_record", lambda **kwargs: None)
    # Existing fake-runner tests model Git/subprocess behaviour rather than a
    # physical clone. Dedicated tests below exercise _safe_gate_path itself.
    monkeypatch.setattr(publish, "_safe_gate_path", lambda scratch, relative: relative)
    return canonical, scratch_root


def _runner_factory(
    canonical: Path,
    *,
    remote_url: str = REMOTE_URL,
    remote_before: str = REMOTE_BEFORE,
    ancestry_rc: int = 0,
    gate_source_diff_rc: int = 0,
    validator_rc: int = 0,
    guard_rc: int = 0,
    post_validation_dirty: bool = False,
    preflight_rc: int = 0,
    apply_rc: int = 0,
    post_remote_sha: str = TARGET,
):
    calls = []
    status_count = 0

    def runner(argv, *, timeout, workdir, input_text):
        nonlocal status_count
        argv = list(argv)
        calls.append(
            {
                "argv": argv,
                "timeout": timeout,
                "workdir": workdir,
                "input_text": input_text,
            }
        )

        canonical_prefix = ["git", "-C", str(canonical)]
        if argv == canonical_prefix + ["config", "--get", "remote.origin.url"]:
            return 0, remote_url + "\n", ""
        if argv == canonical_prefix + ["cat-file", "-e", f"{TARGET}^{{commit}}"]:
            return 0, "", ""
        if argv == canonical_prefix + ["ls-remote", "--heads", "origin", "refs/heads/master"]:
            ls_calls = [c for c in calls if c["argv"] == argv]
            sha = remote_before if len(ls_calls) == 1 else post_remote_sha
            return 0, f"{sha}\trefs/heads/master\n", ""
        if argv == canonical_prefix + ["merge-base", "--is-ancestor", REMOTE_BEFORE, TARGET]:
            return ancestry_rc, "", "not ancestor" if ancestry_rc else ""
        if argv == canonical_prefix + [
            "diff",
            "--quiet",
            REMOTE_BEFORE,
            TARGET,
            "--",
            "tools",
            "scripts",
        ]:
            return gate_source_diff_rc, "", "gate sources changed" if gate_source_diff_rc else ""

        if argv[:4] == ["git", "-c", "init.templateDir=", "clone"]:
            return 0, "", ""
        if "remote" in argv and "set-url" in argv:
            return 0, "", ""
        if "update-ref" in argv:
            return 0, "", ""
        if "symbolic-ref" in argv:
            return 0, "", ""
        if "checkout" in argv and "-B" in argv:
            return 0, "", ""
        if "branch" in argv and any(x.startswith("--set-upstream-to=") for x in argv):
            return 0, "", ""
        if argv[-2:] == ["rev-parse", "HEAD"]:
            return 0, TARGET + "\n", ""
        if argv[-2:] == ["branch", "--show-current"]:
            return 0, "master\n", ""
        if argv[-2:] == ["status", "--porcelain=v1"]:
            status_count += 1
            if post_validation_dirty and status_count >= 2:
                return 0, " M changed.md\n", ""
            return 0, "", ""

        if len(argv) == 2 and argv[1] == str(publish.VALIDATOR_REL):
            return validator_rc, "SUCCESS\n" if validator_rc == 0 else "FAIL\n", "validator failed" if validator_rc else ""
        if argv[:2] == ["bash", str(publish.GUARD_REL)]:
            return guard_rc, "guard ok\n" if guard_rc == 0 else "", "guard failed" if guard_rc else ""

        if "push" in argv:
            push_index = argv.index("push")
            is_dry = "--dry-run" in argv[push_index + 1 :]
            if is_dry:
                return preflight_rc, "preflight ok\n" if preflight_rc == 0 else "", "rejected" if preflight_rc else ""
            return apply_rc, "push ok\n" if apply_rc == 0 else "", "push failed" if apply_rc else ""

        raise AssertionError(f"unexpected command: {argv!r}")

    return runner, calls


def _actual_push_calls(calls):
    result = []
    for call in calls:
        argv = call["argv"]
        if "push" not in argv:
            continue
        idx = argv.index("push")
        if "--dry-run" not in argv[idx + 1 :]:
            result.append(call)
    return result


def test_dry_run_is_exact_non_force_and_preserves_canonical_checkout(monkeypatch, tmp_path):
    canonical, scratch_root = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner))

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["changed"] is False
    assert result["validation_passed"] is True
    assert result["guard_passed"] is True
    assert result["push_preflight_passed"] is True
    assert result["push_executed"] is False
    assert result["canonical_checkout_mutated"] is False
    assert result["publish_strategy"] == "atomic_cas"
    assert result["force_with_lease"] is True
    assert result["unconstrained_force_push"] is False
    assert result["lease_target_ref"] == publish.REMOTE_REF
    assert result["lease_expected_sha"] == REMOTE_BEFORE
    assert result["history_monotonic_ancestor_verified"] is True
    assert result["cleanup_ok"] is True
    assert not scratch_root.exists() or list(scratch_root.iterdir()) == []
    assert _actual_push_calls(calls) == []
    assert not any(
        call["argv"][:3] == ["git", "-C", str(canonical)] and "status" in call["argv"]
        for call in calls
    )
    lease = f"--force-with-lease={publish.REMOTE_REF}:{REMOTE_BEFORE}"
    assert any("push" in call["argv"] and lease in call["argv"] for call in calls)
    assert all("--force" not in call["argv"] and "-f" not in call["argv"] for call in calls)


def test_apply_pushes_only_master_and_verifies_remote(monkeypatch, tmp_path):
    canonical, _ = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, False, runner=runner))

    assert result["success"] is True
    assert result["changed"] is True
    assert result["push_executed"] is True
    assert result["remote_verified"] is True
    pushes = _actual_push_calls(calls)
    assert len(pushes) == 1
    argv = pushes[0]["argv"]
    assert argv[-2:] == ["origin", "refs/heads/master:refs/heads/master"]
    assert f"--force-with-lease={publish.REMOTE_REF}:{REMOTE_BEFORE}" in argv
    assert "--force" not in argv and "-f" not in argv and not any(arg.startswith("+") for arg in argv)


def test_guard_receives_standard_pre_push_contract(monkeypatch, tmp_path):
    canonical, _ = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner))
    assert result["success"] is True

    guard_call = next(call for call in calls if call["argv"][:2] == ["bash", str(publish.GUARD_REL)])
    assert guard_call["argv"][2:] == ["origin", REMOTE_URL]
    assert guard_call["input_text"] == f"refs/heads/master {TARGET} refs/heads/master {REMOTE_BEFORE}\n"


def test_invalid_sha_fails_before_any_command(monkeypatch, tmp_path):
    _install(monkeypatch, tmp_path)
    runner_calls = []

    def runner(*args, **kwargs):
        runner_calls.append((args, kwargs))
        raise AssertionError("runner should not be called")

    result = json.loads(publish.hermes_ops_brain_publish("HEAD", REMOTE_BEFORE, True, runner=runner))
    assert result["success"] is False
    assert result["code"] == "OPSBRAIN_PUBLISH_ERROR"
    assert runner_calls == []


def test_remote_sha_mismatch_fails_before_scratch_or_push(monkeypatch, tmp_path):
    canonical, scratch_root = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical, remote_before="c" * 40)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner))

    assert result["success"] is False
    assert result["push_executed"] is False
    assert not scratch_root.exists()
    assert not any("clone" in call["argv"] for call in calls)
    assert not any("push" in call["argv"] for call in calls)


def test_ancestry_failure_fails_closed(monkeypatch, tmp_path):
    canonical, scratch_root = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical, ancestry_rc=1)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner))

    assert result["success"] is False
    assert result["push_executed"] is False
    assert not scratch_root.exists()
    assert not any("clone" in call["argv"] for call in calls)


def test_changed_governance_sources_fail_closed_before_execution(monkeypatch, tmp_path):
    canonical, scratch_root = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical, gate_source_diff_rc=1)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner))

    assert result["success"] is False
    assert result["push_executed"] is False
    assert "self-validating publication" in result["error"].lower()
    assert not scratch_root.exists()
    assert not any("clone" in call["argv"] for call in calls)
    assert not any("push" in call["argv"] for call in calls)


def test_validator_failure_cleans_scratch_and_blocks_push(monkeypatch, tmp_path):
    canonical, scratch_root = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical, validator_rc=1)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner))

    assert result["success"] is False
    assert result["validation_passed"] is False
    assert result["guard_passed"] is False
    assert result["cleanup_ok"] is True
    assert not scratch_root.exists() or list(scratch_root.iterdir()) == []
    assert not any("push" in call["argv"] for call in calls)


def test_guard_failure_cleans_scratch_and_blocks_push(monkeypatch, tmp_path):
    canonical, scratch_root = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical, guard_rc=2)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner))

    assert result["success"] is False
    assert result["validation_passed"] is True
    assert result["guard_passed"] is False
    assert result["cleanup_ok"] is True
    assert not scratch_root.exists() or list(scratch_root.iterdir()) == []
    assert not any("push" in call["argv"] for call in calls)


def test_post_validation_dirty_state_blocks_push(monkeypatch, tmp_path):
    canonical, _ = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical, post_validation_dirty=True)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner))

    assert result["success"] is False
    assert result["guard_passed"] is True
    assert not any("push" in call["argv"] for call in calls)


def test_push_preflight_rejection_blocks_apply(monkeypatch, tmp_path):
    canonical, _ = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical, preflight_rc=1)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, False, runner=runner))

    assert result["success"] is False
    assert result["push_preflight_passed"] is False
    assert result["push_executed"] is False
    assert _actual_push_calls(calls) == []


def test_post_push_remote_mismatch_reports_changed_but_unverified(monkeypatch, tmp_path):
    canonical, _ = _install(monkeypatch, tmp_path)
    runner, _calls = _runner_factory(canonical, post_remote_sha="c" * 40)

    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, False, runner=runner))

    assert result["success"] is False
    assert result["changed"] is True
    assert result["push_executed"] is True
    assert result["remote_verified"] is False


def test_bad_remote_host_repo_and_embedded_credentials_are_rejected(monkeypatch, tmp_path):
    for index, remote_url in enumerate(
        (
            "git@gitlab.com:Jdogtogo/hermes-ops-brain.git",
            "git@github.com:Jdogtogo/not-the-ops-brain.git",
            "https://user:secret@github.com/Jdogtogo/hermes-ops-brain.git",
        )
    ):
        case_root = tmp_path / f"case-{index}"
        case_root.mkdir()
        canonical, _ = _install(monkeypatch, case_root)
        runner, calls = _runner_factory(canonical, remote_url=remote_url)
        result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner))
        assert result["success"] is False
        assert not any("push" in call["argv"] for call in calls)


def test_remote_parser_accepts_only_canonical_https_and_ssh_forms():
    for url in (
        "https://github.com/Jdogtogo/hermes-ops-brain.git",
        "ssh://git@github.com/Jdogtogo/hermes-ops-brain.git",
        "git@github.com:Jdogtogo/hermes-ops-brain.git",
    ):
        host, repo = publish._validate_remote_identity(url)
        assert host == "github.com"
        assert repo.lower() == "jdogtogo/hermes-ops-brain"


def test_cleanup_failure_is_visible_after_verified_push(monkeypatch, tmp_path):
    canonical, _ = _install(monkeypatch, tmp_path)
    runner, _calls = _runner_factory(canonical)

    def broken_rmtree(path):
        raise OSError("simulated cleanup failure")

    monkeypatch.setattr(publish.shutil, "rmtree", broken_rmtree)
    result = json.loads(publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, False, runner=runner))

    assert result["success"] is True
    assert result["remote_verified"] is True
    assert result["cleanup_ok"] is False
    assert "warning" in result


def test_dry_run_and_apply_use_separate_authority_verbs(monkeypatch, tmp_path):
    preflight_policy = FakePolicy()
    canonical, _ = _install(monkeypatch, tmp_path / "preflight", policy=preflight_policy)
    runner, _calls = _runner_factory(canonical)
    dry_result = json.loads(
        publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, True, runner=runner)
    )
    assert dry_result["success"] is True
    assert ("opsbrain", "preflight") in preflight_policy.required
    assert ("opsbrain", "release") not in preflight_policy.required

    monkeypatch.undo()
    release_root = tmp_path / "release"
    release_root.mkdir()
    release_policy = FakePolicy()
    canonical, _ = _install(monkeypatch, release_root, policy=release_policy)
    runner, _calls = _runner_factory(canonical)
    apply_result = json.loads(
        publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, False, runner=runner)
    )
    assert apply_result["success"] is True
    assert ("opsbrain", "release") in release_policy.required
    assert ("opsbrain", "preflight") not in release_policy.required


def test_missing_preflight_or_release_capability_blocks_before_commands(monkeypatch, tmp_path):
    for index, (dry_run, policy) in enumerate(
        (
            (True, FakePolicy(allow_preflight=False)),
            (False, FakePolicy(allow_release=False)),
        )
    ):
        case = tmp_path / f"authority-{index}"
        case.mkdir()
        _canonical, _ = _install(monkeypatch, case, policy=policy)
        calls = []

        def runner(argv, *, timeout, workdir, input_text):
            calls.append(argv)
            raise AssertionError("runner must not be reached without authority")

        result = json.loads(
            publish.hermes_ops_brain_publish(
                TARGET, REMOTE_BEFORE, dry_run, runner=runner
            )
        )
        assert result["success"] is False
        assert calls == []
        monkeypatch.undo()


def test_dry_run_requires_exact_boolean(monkeypatch, tmp_path):
    _install(monkeypatch, tmp_path)
    calls = []

    def runner(argv, *, timeout, workdir, input_text):
        calls.append(argv)
        raise AssertionError("runner must not be reached for invalid dry_run")

    result = json.loads(
        publish.hermes_ops_brain_publish(
            TARGET, REMOTE_BEFORE, "true", runner=runner  # type: ignore[arg-type]
        )
    )
    assert result["success"] is False
    assert calls == []


def test_safe_gate_path_accepts_regular_file_inside_scratch(tmp_path):
    scratch = tmp_path / "scratch"
    gate = scratch / "tools" / "validate_ops_brain.py"
    gate.parent.mkdir(parents=True)
    gate.write_text("print('ok')\n", encoding="utf-8")
    assert publish._safe_gate_path(scratch, Path("tools/validate_ops_brain.py")) == gate.resolve()


def test_safe_gate_path_rejects_file_and_parent_symlink_escapes(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "gate.py"
    outside_file.write_text("print('outside')\n", encoding="utf-8")

    direct = scratch / "gate.py"
    direct.symlink_to(outside_file)
    try:
        publish._safe_gate_path(scratch, Path("gate.py"))
    except publish.PublishError:
        pass
    else:
        raise AssertionError("direct symlink gate must fail closed")

    parent_link = scratch / "tools"
    parent_link.symlink_to(outside, target_is_directory=True)
    try:
        publish._safe_gate_path(scratch, Path("tools/gate.py"))
    except publish.PublishError:
        pass
    else:
        raise AssertionError("parent symlink escape must fail closed")


def test_atomic_cas_never_uses_unconstrained_force_forms(monkeypatch, tmp_path):
    canonical, _ = _install(monkeypatch, tmp_path)
    runner, calls = _runner_factory(canonical)
    result = json.loads(
        publish.hermes_ops_brain_publish(TARGET, REMOTE_BEFORE, False, runner=runner)
    )
    assert result["success"] is True
    assert result["publish_strategy"] == "atomic_cas"
    assert result["force_with_lease"] is True
    assert result["unconstrained_force_push"] is False
    exact_lease = f"--force-with-lease={publish.REMOTE_REF}:{REMOTE_BEFORE}"
    for call in calls:
        argv = call["argv"]
        if "push" not in argv:
            continue
        assert exact_lease in argv
        assert "--force" not in argv
        assert "-f" not in argv
        assert "--force-with-lease" not in argv
        assert not any(arg.startswith("+") for arg in argv)
