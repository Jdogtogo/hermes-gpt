"""Fixed-purpose publication of the canonical OpsBrain master branch.

This is intentionally not a general Git/network surface. Repository, remote,
branch, remote repository identity, scratch root and commands are fixed.
The caller may supply only the exact local commit they expect to publish, the
exact remote SHA they observed before publication, and dry-run/apply intent.

The canonical OpsBrain checkout is treated as read-only even when dirty. All
validation that needs a clean tree runs in a disposable local scratch clone.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import operator_policy as op

CANONICAL_REPO = Path("/home/jfroh/.hermes/ops-brain")
PUBLISH_ROOT = Path("/home/jfroh/.hermes/ops-brain-publish-scratch")
BRANCH = "master"
REMOTE = "origin"
REMOTE_REF = "refs/heads/master"
REMOTE_HOST = "github.com"
REMOTE_REPOSITORY = "Jdogtogo/hermes-ops-brain"
VALIDATOR_REL = Path("tools/validate_ops_brain.py")
GUARD_REL = Path("scripts/opsbrain-pre-push-guard.sh")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SCP_REMOTE_RE = re.compile(r"^git@([^:]+):(.+)$")

Runner = Callable[..., tuple[int, str, str]]


class PublishError(RuntimeError):
    """Fail-closed publication error."""


def _sanitized_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
    ):
        env.pop(key, None)
    return env


def _run(
    argv: list[str],
    *,
    workdir: str | Path | None = None,
    timeout: int = 120,
    input_text: str | None = None,
    runner: Runner | None = None,
) -> tuple[int, str, str]:
    if runner is not None:
        return runner(
            list(argv),
            timeout=timeout,
            workdir=str(workdir) if workdir is not None else None,
            input_text=input_text,
        )
    proc = subprocess.run(
        list(argv),
        cwd=str(workdir) if workdir is not None else None,
        env=_sanitized_env(),
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    return proc.returncode, op.redact_output(proc.stdout), op.redact_output(proc.stderr)


def _must_run(
    argv: list[str],
    *,
    label: str,
    workdir: str | Path | None = None,
    timeout: int = 120,
    input_text: str | None = None,
    runner: Runner | None = None,
) -> str:
    rc, out, err = _run(
        argv,
        workdir=workdir,
        timeout=timeout,
        input_text=input_text,
        runner=runner,
    )
    if rc != 0:
        detail = op.redact_output(err or out).strip()
        raise PublishError(f"{label} failed" + (f": {detail}" if detail else "."))
    return out.strip()


def _normalise_repo_path(path: str) -> str:
    value = path.strip().strip("/")
    if value.endswith(".git"):
        value = value[:-4]
    return value


def _remote_identity(remote_url: str) -> tuple[str, str]:
    """Return (host, owner/repo) for an approved HTTPS/SSH Git URL."""
    value = str(remote_url or "").strip()
    if not value or any(ch in value for ch in ("\n", "\r", "\x00")):
        raise PublishError("Configured OpsBrain origin URL is missing or malformed.")

    if "://" in value:
        parsed = urlparse(value)
        if parsed.password:
            raise PublishError("Configured OpsBrain origin embeds credentials; refusing publication.")
        if parsed.query or parsed.fragment:
            raise PublishError("Configured OpsBrain origin contains query/fragment data; refusing publication.")
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "https":
            if parsed.username:
                raise PublishError("Configured HTTPS OpsBrain origin contains user information.")
            if parsed.port not in (None, 443):
                raise PublishError("Configured HTTPS OpsBrain origin uses an unexpected port.")
        elif parsed.scheme in {"ssh", "git+ssh"}:
            if parsed.username != "git":
                raise PublishError("Configured SSH OpsBrain origin uses an unexpected username.")
            if parsed.port not in (None, 22):
                raise PublishError("Configured SSH OpsBrain origin uses an unexpected port.")
        else:
            raise PublishError("Configured OpsBrain origin uses an unsupported URL scheme.")
        repo = _normalise_repo_path(parsed.path)
        return host, repo

    match = _SCP_REMOTE_RE.fullmatch(value)
    if match:
        host = match.group(1).lower()
        repo = _normalise_repo_path(match.group(2))
        return host, repo

    raise PublishError("Configured OpsBrain origin is not an approved HTTPS or SSH Git form.")


def _validate_remote_identity(remote_url: str) -> tuple[str, str]:
    host, repo = _remote_identity(remote_url)
    if host != REMOTE_HOST:
        raise PublishError(f"Configured OpsBrain origin host {host!r} is not approved.")
    if repo.lower() != REMOTE_REPOSITORY.lower():
        raise PublishError("Configured OpsBrain origin does not identify the canonical repository.")
    return host, repo


def _parse_remote_head(raw: str, expected_sha: str) -> None:
    lines = [line.strip() for line in str(raw or "").splitlines() if line.strip()]
    expected_line = f"{expected_sha}\t{REMOTE_REF}"
    if lines != [expected_line]:
        raise PublishError("Remote master does not equal the expected pre-publication SHA.")


def _validate_sha(value: str, field: str) -> str:
    text = str(value or "").strip()
    if not _COMMIT_RE.fullmatch(text):
        raise ValueError(f"{field} must be an exact 40-character lowercase Git SHA.")
    return text


def _safe_remove_run_root(run_root: Path | None) -> tuple[bool, str]:
    if run_root is None:
        return True, ""
    try:
        root = PUBLISH_ROOT.resolve(strict=False)
        candidate = run_root.resolve(strict=False)
        if candidate == root or candidate == CANONICAL_REPO.resolve(strict=False):
            raise RuntimeError("refusing unsafe scratch cleanup target")
        candidate.relative_to(root)
        if run_root.is_symlink():
            raise RuntimeError("refusing to recursively remove a symlinked scratch root")
        if run_root.exists():
            shutil.rmtree(run_root)
        return True, ""
    except Exception as exc:  # cleanup failure must be visible but never broaden deletion
        return False, op.redact_output(str(exc))


def _git_read(args: list[str], *, label: str, runner: Runner | None = None, timeout: int = 120) -> str:
    return _must_run(
        ["git", "-C", str(CANONICAL_REPO), *args],
        label=label,
        timeout=timeout,
        runner=runner,
    )


def _require_trusted_gate_sources_unchanged(
    remote_before: str,
    target: str,
    *,
    runner: Runner | None = None,
) -> None:
    """Fail closed if the target changes the executable validation boundary.

    V1 executes the validator and pre-push guard from the target checkout only
    after proving the entire ``tools/`` and ``scripts/`` trees are byte-identical
    to the already-published ``expected_remote_sha`` baseline. Legitimate changes
    to those executable governance trees require a separately reviewed publisher
    increment rather than self-validating their own publication.
    """
    rc, out, err = _run(
        [
            "git",
            "-C",
            str(CANONICAL_REPO),
            "diff",
            "--quiet",
            remote_before,
            target,
            "--",
            "tools",
            "scripts",
        ],
        runner=runner,
    )
    if rc == 0:
        return
    if rc == 1:
        raise PublishError(
            "Target modifies trusted OpsBrain validator/guard sources under tools/ or scripts/; "
            "refusing self-validating publication."
        )
    detail = op.redact_output(err or out).strip()
    raise PublishError(
        "Trusted validator/guard source comparison failed"
        + (f": {detail}" if detail else ".")
    )


def hermes_ops_brain_publish(
    expected_commit: str,
    expected_remote_sha: str,
    dry_run: bool = True,
    runner: Runner | None = None,
) -> str:
    """Validate and publish one exact OpsBrain commit to canonical master.

    Safety invariants:
    - fixed canonical repository/remote/branch and exact GitHub repository;
    - custom ``opsbrain:publish`` capability, not generic ``git:push`` authority;
    - canonical checkout is read-only and may be dirty;
    - scratch clone is local, no-hardlinks, isolated and disposable;
    - remote tip must equal caller's expected pre-publication SHA;
    - expected remote SHA must be an ancestor of the target commit;
    - executable governance sources under tools/ and scripts/ must be unchanged
      from the already-published expected remote baseline;
    - validator and canonical pre-push guard must pass in the scratch clone;
    - remote update uses an exact-SHA force-with-lease CAS after an independent
      fast-forward ancestry proof; blind force push and history rewrite remain impossible;
    - apply verifies remote master resolves to the exact target afterwards.

    ``dry_run`` means no remote ref update. It still performs bounded local
    scratch creation and remote read/preflight operations, so an approved direct
    release session is required even for dry-run.
    """
    policy: op.OperatorPolicy | None = None
    run_root: Path | None = None
    scratch: Path | None = None
    error: Exception | None = None
    cleanup_ok = True
    cleanup_error = ""
    remote_url = ""
    remote_host = ""
    target = ""
    remote_before = ""
    validation_passed = False
    guard_passed = False
    push_preflight_passed = False
    push_executed = False
    remote_verified = False

    try:
        policy = op.OperatorPolicy()
        if not policy.session_id:
            raise PermissionError("hermes_ops_brain_publish requires an active Operator Session.")
        policy.require_level("workspace")
        policy.require_read_path(CANONICAL_REPO)
        policy.require_write_path(PUBLISH_ROOT)
        policy.require_egress_host(REMOTE_HOST)
        policy.require_verb("opsbrain", "publish")
        policy.require_branch(BRANCH)
        # Even remote dry-run creates and removes a bounded local scratch clone.
        policy.require_mutation(False)

        if not isinstance(dry_run, bool):
            raise ValueError("dry_run must be a boolean.")
        target = _validate_sha(expected_commit, "expected_commit")
        remote_before = _validate_sha(expected_remote_sha, "expected_remote_sha")
        if not CANONICAL_REPO.is_dir():
            raise FileNotFoundError(f"Canonical OpsBrain repository is missing: {CANONICAL_REPO}")

        remote_url = _git_read(["config", "--get", f"remote.{REMOTE}.url"], label="origin URL check", runner=runner)
        remote_host, _repo = _validate_remote_identity(remote_url)

        _git_read(["cat-file", "-e", f"{target}^{{commit}}"], label="target commit check", runner=runner)

        remote_raw = _git_read(
            ["ls-remote", "--heads", REMOTE, REMOTE_REF],
            label="remote master precondition check",
            runner=runner,
            timeout=120,
        )
        _parse_remote_head(remote_raw, remote_before)

        rc, out, err = _run(
            ["git", "-C", str(CANONICAL_REPO), "merge-base", "--is-ancestor", remote_before, target],
            runner=runner,
        )
        if rc != 0:
            detail = op.redact_output(err or out).strip()
            raise PublishError(
                "Target commit is not a fast-forward descendant of the expected remote SHA"
                + (f": {detail}" if detail else ".")
            )

        _require_trusted_gate_sources_unchanged(remote_before, target, runner=runner)

        PUBLISH_ROOT.mkdir(parents=True, exist_ok=True)
        run_root = Path(tempfile.mkdtemp(prefix="opsbrain-publish-", dir=str(PUBLISH_ROOT)))
        scratch = run_root / "repo"
        empty_hooks = run_root / "empty-hooks"
        empty_hooks.mkdir(mode=0o700)

        _must_run(
            [
                "git",
                "-c",
                "init.templateDir=",
                "clone",
                "--local",
                "--no-hardlinks",
                "--no-checkout",
                str(CANONICAL_REPO),
                str(scratch),
            ],
            label="isolated scratch clone",
            timeout=180,
            runner=runner,
        )
        _must_run(
            ["git", "-C", str(scratch), "remote", "set-url", REMOTE, remote_url],
            label="scratch origin pin",
            runner=runner,
        )
        _must_run(
            ["git", "-C", str(scratch), "update-ref", "refs/remotes/origin/master", remote_before],
            label="scratch remote baseline pin",
            runner=runner,
        )
        _must_run(
            [
                "git",
                "-C",
                str(scratch),
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/master",
            ],
            label="scratch remote HEAD pin",
            runner=runner,
        )
        _must_run(
            [
                "git",
                "-c",
                f"core.hooksPath={empty_hooks}",
                "-C",
                str(scratch),
                "checkout",
                "-B",
                BRANCH,
                target,
            ],
            label="scratch target checkout",
            timeout=180,
            runner=runner,
        )
        _must_run(
            ["git", "-C", str(scratch), "branch", "--set-upstream-to=origin/master", BRANCH],
            label="scratch upstream pin",
            runner=runner,
        )

        scratch_head = _must_run(
            ["git", "-C", str(scratch), "rev-parse", "HEAD"],
            label="scratch HEAD check",
            runner=runner,
        )
        if scratch_head != target:
            raise PublishError("Scratch checkout did not resolve to the exact expected commit.")
        scratch_branch = _must_run(
            ["git", "-C", str(scratch), "branch", "--show-current"],
            label="scratch branch check",
            runner=runner,
        )
        if scratch_branch != BRANCH:
            raise PublishError("Scratch checkout is not on canonical master.")
        scratch_status = _must_run(
            ["git", "-C", str(scratch), "status", "--porcelain=v1"],
            label="scratch cleanliness check",
            runner=runner,
        )
        if scratch_status:
            raise PublishError("Scratch checkout is not clean before validation.")

        _must_run(
            [sys.executable, str(VALIDATOR_REL)],
            label="OpsBrain validator",
            workdir=scratch,
            timeout=180,
            runner=runner,
        )
        validation_passed = True

        guard_input = f"refs/heads/{BRANCH} {target} {REMOTE_REF} {remote_before}\n"
        _must_run(
            ["bash", str(GUARD_REL), REMOTE, remote_url],
            label="OpsBrain pre-push guard",
            workdir=scratch,
            timeout=180,
            input_text=guard_input,
            runner=runner,
        )
        guard_passed = True

        # Validation/guard are not permitted to leave edits behind.
        scratch_status = _must_run(
            ["git", "-C", str(scratch), "status", "--porcelain=v1"],
            label="post-validation cleanliness check",
            runner=runner,
        )
        if scratch_status:
            raise PublishError("Validation or guard left the scratch checkout dirty; refusing publication.")
        scratch_head = _must_run(
            ["git", "-C", str(scratch), "rev-parse", "HEAD"],
            label="pre-push exact HEAD check",
            runner=runner,
        )
        if scratch_head != target:
            raise PublishError("Scratch HEAD changed after validation; refusing publication.")

        refspec = f"refs/heads/{BRANCH}:{REMOTE_REF}"
        _must_run(
            [
                "git",
                "-c",
                f"core.hooksPath={empty_hooks}",
                "-C",
                str(scratch),
                "push",
                "--dry-run",
                "--porcelain",
                f"--force-with-lease={REMOTE_REF}:{remote_before}",
                REMOTE,
                refspec,
            ],
            label="remote fast-forward preflight",
            timeout=180,
            runner=runner,
        )
        push_preflight_passed = True

        if not dry_run:
            _must_run(
                [
                    "git",
                    "-c",
                    f"core.hooksPath={empty_hooks}",
                    "-C",
                    str(scratch),
                    "push",
                    "--porcelain",
                    f"--force-with-lease={REMOTE_REF}:{remote_before}",
                    REMOTE,
                    refspec,
                ],
                label="OpsBrain push",
                timeout=180,
                runner=runner,
            )
            push_executed = True
            remote_after = _git_read(
                ["ls-remote", "--heads", REMOTE, REMOTE_REF],
                label="post-push remote verification",
                runner=runner,
                timeout=120,
            )
            _parse_remote_head(remote_after, target)
            remote_verified = True

    except Exception as exc:
        error = exc
    finally:
        cleanup_ok, cleanup_error = _safe_remove_run_root(run_root)

    changed = bool(push_executed)
    if error is not None:
        base = op.error_from_exception(
            error,
            layer="release",
            code="OPSBRAIN_PUBLISH_ERROR",
            suggested_action=(
                "Resolve the reported authority, canonical-origin, expected-SHA, ancestry, validator, guard, "
                "scratch, or remote condition; do not bypass the governed OpsBrain publisher."
            ),
        )
        base.update(
            {
                "dry_run": dry_run,
                "changed": changed,
                "expected_commit": target or str(expected_commit or ""),
                "expected_remote_sha": remote_before or str(expected_remote_sha or ""),
                "validation_passed": validation_passed,
                "guard_passed": guard_passed,
                "push_preflight_passed": push_preflight_passed,
                "push_executed": push_executed,
                "remote_verified": remote_verified,
                "cleanup_ok": cleanup_ok,
            }
        )
        if not cleanup_ok:
            base["cleanup_error"] = cleanup_error
        op.audit_record(
            tool="hermes_ops_brain_publish",
            level=policy.level if policy is not None else "unknown",
            apply_mode=policy.apply_mode if policy is not None else "unknown",
            dry_run=dry_run,
            success=False,
            changed=changed,
            error=op.redact_output(str(error)),
            path=str(CANONICAL_REPO),
            extra={
                "branch": BRANCH,
                "remote": REMOTE,
                "remote_host": remote_host,
                "expected_commit": target,
                "expected_remote_sha": remote_before,
                "validation_passed": validation_passed,
                "guard_passed": guard_passed,
                "push_executed": push_executed,
                "remote_verified": remote_verified,
                "cleanup_ok": cleanup_ok,
            },
        )
        return json.dumps(base, indent=2)

    result = {
        "success": True,
        "dry_run": dry_run,
        "changed": changed,
        "branch": BRANCH,
        "remote": REMOTE,
        "remote_host": remote_host,
        "remote_repository": REMOTE_REPOSITORY,
        "expected_commit": target,
        "expected_remote_sha": remote_before,
        "validation_passed": validation_passed,
        "guard_passed": guard_passed,
        "push_preflight_passed": push_preflight_passed,
        "push_executed": push_executed,
        "remote_verified": remote_verified if not dry_run else False,
        "force_push": False,
        "canonical_checkout_mutated": False,
        "cleanup_ok": cleanup_ok,
    }
    if not cleanup_ok:
        result["warning"] = "Publication succeeded, but disposable scratch cleanup requires attention."
        result["cleanup_error"] = cleanup_error
    op.audit_record(
        tool="hermes_ops_brain_publish",
        level=policy.level if policy is not None else "unknown",
        apply_mode=policy.apply_mode if policy is not None else "unknown",
        dry_run=dry_run,
        success=True,
        changed=changed,
        summary=(
            f"validated OpsBrain publication for {target}"
            if dry_run
            else f"published OpsBrain commit {target}"
        ),
        path=str(CANONICAL_REPO),
        extra={
            "branch": BRANCH,
            "remote": REMOTE,
            "remote_host": remote_host,
            "expected_commit": target,
            "expected_remote_sha": remote_before,
            "validation_passed": validation_passed,
            "guard_passed": guard_passed,
            "push_executed": push_executed,
            "remote_verified": remote_verified,
            "cleanup_ok": cleanup_ok,
            "force_push": False,
        },
    )
    return json.dumps(result, indent=2)
