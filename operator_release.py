"""Fixed, governed promotion of routing-policy-resolver into immutable release v019."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import operator_policy as op

SOURCE_WORKTREE = Path("/home/jfroh/.hermes/worktrees/routing-policy-resolver")
TEMP_WORKTREE = Path("/home/jfroh/.hermes/worktrees/routing-v019-main")
RELEASE_WORKTREE = Path("/home/jfroh/.hermes/releases/v019")
V018_LIVE = Path("/home/jfroh/.hermes/releases/v018-live")
SOURCE_BRANCH = "routing-policy-resolver"
TARGET_BRANCH = "main"
RELEASE_ID = "v019"
EXPECTED_SOURCE_HEAD = "0f619496a372dbe4f85668b12eaab45faa15e46b"
EXPECTED_MAIN_HEAD = "c6aa6bd15cbd42e7b71ab0ab91caab7459f7f8e0"
EXPECTED_SOURCE_MERGE_BASE = "f9b619dfae02bdc854cb5e8068beb7659a7f3b24"
ROUTING_COMMITS = [
    "ef4ae615597aed6582a9d8a3ac31954faf99be9d",
    "020b7c830cd62eb668643888ea7e98b5b0545383",
    "770aac5c8d642852e020bdfe8ea0cd1d1feccbd6",
    "8346143abb3a5b240871d23a89ca1a63afea0268",
    "0f619496a372dbe4f85668b12eaab45faa15e46b",
]
PYTHON = "/home/jfroh/.hermes/hermes-agent/venv/bin/python3"

Runner = Callable[..., tuple[int, str, str]]


def _run(argv: list[str], *, workdir: Path, timeout: int = 120, runner: Runner | None = None) -> tuple[int, str, str]:
    run_fn = runner or op.run_argv
    return run_fn(argv, timeout=timeout, workdir=str(workdir))


def _git(args: list[str], *, workdir: Path, timeout: int = 120, runner: Runner | None = None) -> tuple[int, str, str]:
    return _run(["git", *args], workdir=workdir, timeout=timeout, runner=runner)


def _must_git(args: list[str], *, workdir: Path, label: str, timeout: int = 120, runner: Runner | None = None) -> str:
    rc, out, err = _git(args, workdir=workdir, timeout=timeout, runner=runner)
    if rc != 0:
        detail = op.redact_output(err or out).strip()
        raise RuntimeError(f"{label} failed" + (f": {detail}" if detail else "."))
    return out.strip()


def _status(workdir: Path, runner: Runner | None = None) -> str:
    return _must_git(["status", "--porcelain=v1"], workdir=workdir, label="git status", runner=runner)


def _worktree_main_checkout(source: Path, runner: Runner | None = None) -> str | None:
    raw = _must_git(["worktree", "list", "--porcelain"], workdir=source, label="git worktree list", runner=runner)
    current_path: str | None = None
    for line in [*raw.splitlines(), ""]:
        if line.startswith("worktree "):
            current_path = line.removeprefix("worktree ").strip()
        elif line == f"branch refs/heads/{TARGET_BRANCH}":
            return current_path
        elif not line:
            current_path = None
    return None


def _v018_snapshot(runner: Runner | None = None) -> dict[str, str]:
    if not V018_LIVE.is_dir():
        raise RuntimeError(f"Required live release path is missing: {V018_LIVE}")
    return {
        "head": _must_git(["rev-parse", "HEAD"], workdir=V018_LIVE, label="v018-live HEAD", runner=runner),
        "status": _status(V018_LIVE, runner=runner),
    }


def _cleanup_created(*, source: Path, temp_created: bool, release_created: bool, tag_created: bool, runner: Runner | None) -> None:
    # Best-effort cleanup is restricted to exact artifacts created by this tool.
    if release_created and RELEASE_WORKTREE.exists():
        _git(["worktree", "remove", "--force", str(RELEASE_WORKTREE)], workdir=source, runner=runner)
    if tag_created:
        _git(["tag", "-d", RELEASE_ID], workdir=source, runner=runner)
    if temp_created and TEMP_WORKTREE.exists():
        _git(["worktree", "remove", "--force", str(TEMP_WORKTREE)], workdir=source, runner=runner)


def hermes_routing_release_v019(dry_run: bool = True, runner: Runner | None = None) -> str:
    """Promote the exact reviewed routing branch and create immutable release ``v019``.

    This is intentionally not a general Git command surface. Source branch,
    target branch, expected commits, test commands, tag, temporary worktree and
    release path are fixed constants. The operation refuses an existing tag or
    release path and never touches ``v018-live``.
    """
    policy: op.OperatorPolicy | None = None
    temp_created = False
    release_created = False
    tag_created = False
    main_advanced = False
    try:
        policy = op.OperatorPolicy()
        if not policy.session_id:
            raise PermissionError("hermes_routing_release_v019 requires an active Operator Session.")
        policy.require_read_path(SOURCE_WORKTREE)
        policy.require_read_path(V018_LIVE)
        policy.require_write_path(TEMP_WORKTREE)
        policy.require_write_path(RELEASE_WORKTREE)
        policy.require_verb("git", "release")
        policy.require_verb("tests", "run")

        if not SOURCE_WORKTREE.is_dir():
            raise RuntimeError(f"Source worktree is missing: {SOURCE_WORKTREE}")
        if TEMP_WORKTREE.exists():
            raise RuntimeError(f"Temporary release worktree already exists: {TEMP_WORKTREE}")
        if RELEASE_WORKTREE.exists():
            raise RuntimeError(f"Immutable release path already exists: {RELEASE_WORKTREE}")

        source_branch = _must_git(["branch", "--show-current"], workdir=SOURCE_WORKTREE, label="source branch", runner=runner)
        source_head = _must_git(["rev-parse", "HEAD"], workdir=SOURCE_WORKTREE, label="source HEAD", runner=runner)
        main_head = _must_git(["rev-parse", TARGET_BRANCH], workdir=SOURCE_WORKTREE, label="main HEAD", runner=runner)
        merge_base = _must_git(["merge-base", TARGET_BRANCH, SOURCE_BRANCH], workdir=SOURCE_WORKTREE, label="merge base", runner=runner)
        source_package = _must_git(
            ["rev-list", "--reverse", "--first-parent", f"{ROUTING_COMMITS[0]}^..{EXPECTED_SOURCE_HEAD}"],
            workdir=SOURCE_WORKTREE,
            label="routing package ancestry",
            runner=runner,
        ).splitlines()
        source_status = _status(SOURCE_WORKTREE, runner=runner)

        if source_branch != SOURCE_BRANCH:
            raise RuntimeError(f"Source branch mismatch: expected {SOURCE_BRANCH}, found {source_branch!r}.")
        if source_head != EXPECTED_SOURCE_HEAD:
            raise RuntimeError(f"Source HEAD mismatch: expected {EXPECTED_SOURCE_HEAD}, found {source_head!r}.")
        if main_head != EXPECTED_MAIN_HEAD:
            raise RuntimeError(f"Main HEAD mismatch: expected {EXPECTED_MAIN_HEAD}, found {main_head!r}.")
        if merge_base != EXPECTED_SOURCE_MERGE_BASE:
            raise RuntimeError(f"Unexpected source merge base: expected {EXPECTED_SOURCE_MERGE_BASE}, found {merge_base!r}.")
        if source_package != ROUTING_COMMITS:
            raise RuntimeError(f"Unexpected routing package ancestry: expected {ROUTING_COMMITS!r}, found {source_package!r}.")
        if source_status:
            raise RuntimeError("Source worktree is not clean.")

        main_checkout = _worktree_main_checkout(SOURCE_WORKTREE, runner=runner)
        if main_checkout:
            raise RuntimeError(f"Target branch main is already checked out at {main_checkout}; refusing to disturb it.")

        tag_rc, _, _ = _git(["show-ref", "--verify", "--quiet", f"refs/tags/{RELEASE_ID}"], workdir=SOURCE_WORKTREE, runner=runner)
        if tag_rc == 0:
            raise RuntimeError(f"Immutable release tag already exists: {RELEASE_ID}")

        v018_before = _v018_snapshot(runner=runner)
        plan = {
            "source_branch": SOURCE_BRANCH,
            "source_head": source_head,
            "target_branch": TARGET_BRANCH,
            "starting_main": main_head,
            "merge_base": merge_base,
            "integration_strategy": "replay_exact_routing_commits",
            "routing_commits": source_package,
            "temporary_worktree": str(TEMP_WORKTREE),
            "release_id": RELEASE_ID,
            "release_path": str(RELEASE_WORKTREE),
            "v018_live_head": v018_before["head"],
            "tests": [
                "git diff --check",
                f"{PYTHON} -m pytest tests/agent/test_routing_policy_resolver.py::test_free_only_excludes_paid -v -p no:cacheprovider",
                f"{PYTHON} -m pytest tests/agent/test_routing_policy_resolver.py -v -p no:cacheprovider",
            ],
        }
        if policy.effective_dry_run(dry_run):
            op.audit_record(
                tool="hermes_routing_release_v019",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="validated fixed v019 release plan",
                path=str(SOURCE_WORKTREE),
                extra={"source_head": source_head, "main_head": main_head, "release_id": RELEASE_ID},
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan}, indent=2)

        policy.require_mutation(dry_run)
        TEMP_WORKTREE.parent.mkdir(parents=True, exist_ok=True)
        RELEASE_WORKTREE.parent.mkdir(parents=True, exist_ok=True)

        _must_git(["worktree", "add", "--detach", str(TEMP_WORKTREE), EXPECTED_MAIN_HEAD], workdir=SOURCE_WORKTREE, label="create isolated main worktree", runner=runner)
        temp_created = True

        replayed_commits: list[str] = []
        for source_commit in ROUTING_COMMITS:
            _must_git(
                [
                    "-c", "user.name=Hermes Release Bot",
                    "-c", "user.email=hermes-release@localhost",
                    "cherry-pick", source_commit,
                ],
                workdir=TEMP_WORKTREE,
                label=f"replay routing commit {source_commit}",
                timeout=180,
                runner=runner,
            )
            replayed_commits.append(_must_git(["rev-parse", "HEAD"], workdir=TEMP_WORKTREE, label="replayed commit", runner=runner))

        integration_head = _must_git(["rev-parse", "HEAD"], workdir=TEMP_WORKTREE, label="integration head", runner=runner)
        _must_git(["checkout", "--detach", EXPECTED_MAIN_HEAD], workdir=TEMP_WORKTREE, label="reset merge parent to main", runner=runner)
        merge_out = _must_git(
            [
                "-c", "user.name=Hermes Release Bot",
                "-c", "user.email=hermes-release@localhost",
                "merge", "--no-ff", integration_head,
                "-m", "Merge clean routing integration for v019",
            ],
            workdir=TEMP_WORKTREE,
            label="routing integration merge",
            timeout=180,
            runner=runner,
        )
        merge_commit = _must_git(["rev-parse", "HEAD"], workdir=TEMP_WORKTREE, label="merge commit", runner=runner)
        parents = _must_git(["rev-list", "--parents", "-n", "1", merge_commit], workdir=TEMP_WORKTREE, label="merge parents", runner=runner).split()
        if len(parents) != 3 or parents[1] != EXPECTED_MAIN_HEAD or parents[2] != integration_head:
            raise RuntimeError(f"Unexpected merge parentage: {parents!r}")

        _must_git(["diff", "--check", f"{EXPECTED_MAIN_HEAD}..{merge_commit}"], workdir=TEMP_WORKTREE, label="git diff --check", runner=runner)
        test_commands = [
            [PYTHON, "-m", "pytest", "tests/agent/test_routing_policy_resolver.py::test_free_only_excludes_paid", "-v", "-p", "no:cacheprovider"],
            [PYTHON, "-m", "pytest", "tests/agent/test_routing_policy_resolver.py", "-v", "-p", "no:cacheprovider"],
        ]
        test_results: list[dict[str, object]] = []
        for command in test_commands:
            rc, out, err = _run(command, workdir=TEMP_WORKTREE, timeout=600, runner=runner)
            test_results.append({"command": command, "returncode": rc, "stdout": op.redact_output(out), "stderr": op.redact_output(err)})
            if rc != 0:
                raise RuntimeError(f"Routing validation failed: {' '.join(command)}")

        _must_git(["tag", RELEASE_ID, merge_commit], workdir=TEMP_WORKTREE, label="create immutable release tag", runner=runner)
        tag_created = True
        _must_git(["worktree", "add", "--detach", str(RELEASE_WORKTREE), merge_commit], workdir=TEMP_WORKTREE, label="create immutable release worktree", runner=runner)
        release_created = True

        release_head = _must_git(["rev-parse", "HEAD"], workdir=RELEASE_WORKTREE, label="release HEAD", runner=runner)
        release_branch = _must_git(["branch", "--show-current"], workdir=RELEASE_WORKTREE, label="release branch", runner=runner)
        release_status = _status(RELEASE_WORKTREE, runner=runner)
        tag_head = _must_git(["rev-parse", RELEASE_ID], workdir=RELEASE_WORKTREE, label="release tag", runner=runner)
        if release_head != merge_commit or tag_head != merge_commit or release_branch or release_status:
            raise RuntimeError("Release verification failed: tag/worktree is not a clean detached checkout of the merge commit.")

        _must_git(["update-ref", f"refs/heads/{TARGET_BRANCH}", merge_commit, EXPECTED_MAIN_HEAD], workdir=TEMP_WORKTREE, label="advance main atomically", runner=runner)
        main_advanced = True
        ending_main = _must_git(["rev-parse", TARGET_BRANCH], workdir=TEMP_WORKTREE, label="ending main", runner=runner)
        if ending_main != merge_commit:
            raise RuntimeError("Main did not advance to the verified merge commit.")

        v018_after = _v018_snapshot(runner=runner)
        if v018_after != v018_before:
            raise RuntimeError("v018-live changed during release; refusing completion.")

        cleanup_warning = ""
        remove_rc, _, remove_err = _git(["worktree", "remove", "--force", str(TEMP_WORKTREE)], workdir=RELEASE_WORKTREE, runner=runner)
        if remove_rc != 0:
            cleanup_warning = op.redact_output(remove_err).strip() or "temporary worktree cleanup failed"
        else:
            temp_created = False

        result = {
            "success": True,
            "dry_run": False,
            "changed": True,
            "source_head": source_head,
            "starting_main": main_head,
            "integration_head": integration_head,
            "replayed_source_commits": ROUTING_COMMITS,
            "replayed_commits": replayed_commits,
            "merge_commit": merge_commit,
            "ending_main": ending_main,
            "release_id": RELEASE_ID,
            "release_path": str(RELEASE_WORKTREE),
            "release_head": release_head,
            "release_detached": True,
            "release_status": release_status,
            "v018_live_before": v018_before,
            "v018_live_after": v018_after,
            "tests": test_results,
            "merge_output": op.redact_output(merge_out),
            "cleanup_warning": cleanup_warning,
        }
        op.audit_record(
            tool="hermes_routing_release_v019",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary=f"created {RELEASE_ID} at {merge_commit}",
            path=str(RELEASE_WORKTREE),
            extra={"source_head": source_head, "starting_main": main_head, "merge_commit": merge_commit, "release_id": RELEASE_ID},
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        if not main_advanced:
            _cleanup_created(source=SOURCE_WORKTREE, temp_created=temp_created, release_created=release_created, tag_created=tag_created, runner=runner)
        op.audit_record(
            tool="hermes_routing_release_v019",
            level=policy.level if policy is not None else "unknown",
            apply_mode=policy.apply_mode if policy is not None else "unknown",
            dry_run=dry_run,
            success=False,
            changed=main_advanced,
            error=str(exc),
            path=str(SOURCE_WORKTREE),
            extra={"release_id": RELEASE_ID, "main_advanced": main_advanced},
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="release",
                code="ROUTING_RELEASE_V019_ERROR",
                suggested_action="Resolve the reported repository, validation, or authority condition; do not bypass the fixed release workflow.",
            ),
            indent=2,
        )
