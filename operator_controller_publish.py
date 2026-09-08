"""Fixed-purpose publication of the canonical ChatGPT Controller branch.

This module is intentionally not a general networked Git surface. Repository,
branch, remote name and allowed remote host are fixed constants. The caller can
only name the exact commit they expect to publish and choose dry-run vs apply.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import operator_policy as op

WORKTREE = Path("/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration")
BRANCH = "mission-control/preservation-integration"
REMOTE_BRANCH = "codex/operator-session-chatgpt-20260713"
REMOTE = "origin"
ALLOWED_REMOTE_HOSTS = frozenset({"github.com"})
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

Runner = Callable[..., tuple[int, str, str]]


def _run(argv: list[str], *, timeout: int = 120, runner: Runner | None = None) -> tuple[int, str, str]:
    run_fn = runner or op.run_argv
    return run_fn(argv, timeout=timeout, workdir=str(WORKTREE))


def _git(args: list[str], *, timeout: int = 120, runner: Runner | None = None) -> tuple[int, str, str]:
    return _run(["git", *args], timeout=timeout, runner=runner)


def _must_git(args: list[str], *, label: str, timeout: int = 120, runner: Runner | None = None) -> str:
    rc, out, err = _git(args, timeout=timeout, runner=runner)
    if rc != 0:
        detail = op.redact_output(err or out).strip()
        raise RuntimeError(f"{label} failed" + (f": {detail}" if detail else "."))
    return out.strip()


def _remote_host(remote_url: str) -> str:
    value = str(remote_url or "").strip()
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise RuntimeError("Configured origin URL is missing or malformed.")

    # Standard URL forms such as https://github.com/owner/repo.git and
    # ssh://git@github.com/owner/repo.git.
    if "://" in value:
        parsed = urlparse(value)
        if parsed.password:
            raise RuntimeError("Configured origin URL embeds credentials; refusing publication.")
        host = (parsed.hostname or "").lower()
        if parsed.username and parsed.scheme not in {"ssh", "git+ssh"}:
            raise RuntimeError("Configured origin URL contains user information; refusing publication.")
        if parsed.username and parsed.username != "git":
            raise RuntimeError("Configured SSH origin uses an unexpected username; refusing publication.")
        return host

    # SCP-like SSH form: git@github.com:owner/repo.git.
    match = re.fullmatch(r"git@([^:]+):.+", value)
    if match:
        return match.group(1).lower()

    raise RuntimeError("Configured origin URL is not an approved HTTPS or SSH Git form.")


def hermes_controller_publish(expected_commit: str, dry_run: bool = True, runner: Runner | None = None) -> str:
    """Publish the exact clean Controller HEAD to its fixed origin branch.

    Safety invariants:
    - fixed repository, branch and remote name;
    - caller-supplied commit must be a full lowercase SHA and equal local HEAD;
    - worktree must be clean;
    - configured origin must resolve to an allow-listed host and must not embed credentials;
    - Git push is always non-force and targets exactly HEAD -> the fixed branch;
    - dry-run performs Git's own remote push preflight without updating the remote;
    - apply verifies the remote branch resolves to the exact expected commit afterwards.
    """
    policy: op.OperatorPolicy | None = None
    changed = False
    try:
        policy = op.OperatorPolicy()
        if not policy.session_id:
            raise PermissionError("hermes_controller_publish requires an active Operator Session.")
        policy.require_read_path(WORKTREE)
        policy.require_verb("git", "push")

        expected = str(expected_commit or "").strip()
        if not _COMMIT_RE.fullmatch(expected):
            raise ValueError("expected_commit must be an exact 40-character lowercase Git SHA.")
        if not WORKTREE.is_dir():
            raise RuntimeError(f"Controller worktree is missing: {WORKTREE}")

        branch = _must_git(["branch", "--show-current"], label="branch check", runner=runner)
        head = _must_git(["rev-parse", "HEAD"], label="HEAD check", runner=runner)
        status = _must_git(["status", "--porcelain=v1"], label="clean-worktree check", runner=runner)
        remote_url = _must_git(["config", "--get", f"remote.{REMOTE}.url"], label="origin URL check", runner=runner)
        host = _remote_host(remote_url)

        if branch != BRANCH:
            raise RuntimeError(f"Controller branch mismatch: expected {BRANCH}, found {branch!r}.")
        if head != expected:
            raise RuntimeError(f"Controller HEAD mismatch: expected {expected}, found {head}.")
        if status:
            raise RuntimeError("Controller worktree is not clean; refusing remote publication.")
        if host not in ALLOWED_REMOTE_HOSTS:
            raise PermissionError(f"Configured origin host {host!r} is not approved for Controller publication.")

        refspec = f"HEAD:refs/heads/{REMOTE_BRANCH}"
        preflight = _must_git(
            ["push", "--dry-run", "--porcelain", REMOTE, refspec],
            label="remote fast-forward preflight",
            timeout=180,
            runner=runner,
        )
        plan = {
            "worktree": str(WORKTREE),
            "branch": BRANCH,
            "remote_branch": REMOTE_BRANCH,
            "commit": expected,
            "remote": REMOTE,
            "remote_host": host,
            "refspec": refspec,
            "force_push": False,
            "worktree_clean": True,
            "remote_preflight": "accepted",
        }

        if policy.effective_dry_run(dry_run):
            op.audit_record(
                tool="hermes_controller_publish",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary=f"validated Controller publication for {expected}",
                path=str(WORKTREE),
                extra={"branch": BRANCH, "remote_branch": REMOTE_BRANCH, "commit": expected, "remote": REMOTE, "remote_host": host},
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan, "preflight": op.redact_output(preflight)}, indent=2)

        policy.require_mutation(dry_run)
        push_out = _must_git(
            ["push", "--porcelain", REMOTE, refspec],
            label="Controller push",
            timeout=180,
            runner=runner,
        )
        changed = True
        remote_head_raw = _must_git(
            ["ls-remote", "--heads", REMOTE, f"refs/heads/{REMOTE_BRANCH}"],
            label="post-push remote verification",
            timeout=120,
            runner=runner,
        )
        fields = remote_head_raw.split()
        if len(fields) != 2 or fields[0] != expected or fields[1] != f"refs/heads/{REMOTE_BRANCH}":
            raise RuntimeError("Remote verification did not resolve the fixed branch to the expected commit.")

        result = {
            "success": True,
            "dry_run": False,
            "changed": True,
            "branch": BRANCH,
            "remote_branch": REMOTE_BRANCH,
            "commit": expected,
            "remote": REMOTE,
            "remote_host": host,
            "force_push": False,
            "worktree_clean": True,
            "remote_verified": True,
            "push_output": op.redact_output(push_out),
        }
        op.audit_record(
            tool="hermes_controller_publish",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary=f"published Controller commit {expected}",
            path=str(WORKTREE),
            extra={"branch": BRANCH, "remote_branch": REMOTE_BRANCH, "commit": expected, "remote": REMOTE, "remote_host": host, "force_push": False},
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool="hermes_controller_publish",
            level=policy.level if policy is not None else "unknown",
            apply_mode=policy.apply_mode if policy is not None else "unknown",
            dry_run=dry_run,
            success=False,
            changed=changed,
            error=str(exc),
            path=str(WORKTREE),
            extra={"branch": BRANCH, "remote_branch": REMOTE_BRANCH, "remote": REMOTE, "force_push": False},
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="release",
                code="CONTROLLER_PUBLISH_ERROR",
                suggested_action="Resolve the reported authority, branch, cleanliness, origin, or fast-forward condition; do not bypass the governed publication tool.",
            ),
            indent=2,
        )
