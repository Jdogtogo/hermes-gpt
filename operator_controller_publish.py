"""Fixed-purpose publication of the canonical ChatGPT Controller branch.

This module is intentionally not a general networked Git surface. Repository,
branch, remote name and allowed remote host are fixed constants. The caller can
only name the exact commit they expect to publish and choose dry-run vs apply.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import operator_policy as op

WORKTREE = Path("/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration")
BRANCH = "mission-control/preservation-integration"
REMOTE_BRANCH = "codex/operator-session-chatgpt-20260713"
REMOTE = "origin"
EXPECTED_REMOTE_URL = "https://github.com/Jdogtogo/hermes-gpt.git"
ALLOWED_REMOTE_HOSTS = frozenset({"github.com"})
GH_BINARY = WORKTREE / "logs/.release-tools/gh/gh"
AUTH_DIR = WORKTREE / "logs/.release-tools/gh-auth"
AUTH_CONFIG = AUTH_DIR / "hosts.yml"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

Runner = Callable[..., tuple[int, str, str]]


def _run(
    argv: list[str],
    *,
    timeout: int = 120,
    env: dict[str, str] | None = None,
    runner: Runner | None = None,
) -> tuple[int, str, str]:
    run_fn = runner or op.run_argv
    return run_fn(argv, timeout=timeout, workdir=str(WORKTREE), env=env)


def _git(
    args: list[str],
    *,
    timeout: int = 120,
    env: dict[str, str] | None = None,
    runner: Runner | None = None,
) -> tuple[int, str, str]:
    return _run(["git", *args], timeout=timeout, env=env, runner=runner)


def _must_git(
    args: list[str],
    *,
    label: str,
    timeout: int = 120,
    env: dict[str, str] | None = None,
    runner: Runner | None = None,
) -> str:
    rc, out, err = _git(args, timeout=timeout, env=env, runner=runner)
    if rc != 0:
        detail = op.redact_output(err or out).strip()
        raise RuntimeError(f"{label} failed" + (f": {detail}" if detail else "."))
    return out.strip()


def _remote_host(remote_url: str) -> str:
    value = str(remote_url or "").strip()
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise RuntimeError("Configured origin URL is missing or malformed.")
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.password or parsed.username:
        raise RuntimeError("Configured origin URL must be credential-free HTTPS.")
    return (parsed.hostname or "").lower()


def _release_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(AUTH_DIR),
        "GH_CONFIG_DIR": str(AUTH_DIR),
        "GH_PROMPT_DISABLED": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _credential_git_prefix() -> list[str]:
    helper = f"!{GH_BINARY} auth git-credential"
    return [
        "-c",
        "credential.helper=",
        "-c",
        "credential.useHttpPath=true",
        "-c",
        f"credential.helper={helper}",
    ]


def _network_git(
    args: list[str],
    *,
    label: str,
    timeout: int,
    runner: Runner | None,
) -> str:
    return _must_git(
        [*_credential_git_prefix(), *args],
        label=label,
        timeout=timeout,
        env=_release_env(),
        runner=runner,
    )


def _assert_release_auth_ready() -> None:
    if GH_BINARY.is_symlink() or not GH_BINARY.is_file() or not os.access(GH_BINARY, os.X_OK):
        raise RuntimeError("Pinned release-scoped GitHub CLI binary is missing or not executable.")
    if AUTH_DIR.is_symlink() or not AUTH_DIR.is_dir():
        raise RuntimeError("Fixed GitHub release auth directory is missing or invalid; complete device authorization first.")
    if stat.S_IMODE(AUTH_DIR.stat().st_mode) & 0o077:
        raise RuntimeError("Fixed GitHub release auth directory permissions are too broad.")
    if AUTH_CONFIG.is_symlink() or not AUTH_CONFIG.is_file() or AUTH_CONFIG.stat().st_size <= 0:
        raise RuntimeError("Fixed GitHub release auth config is missing; complete device authorization first.")
    if stat.S_IMODE(AUTH_CONFIG.stat().st_mode) & 0o077:
        raise RuntimeError("Fixed GitHub release auth config permissions are too broad.")


def _assert_no_local_url_rewrite(*, runner: Runner | None = None) -> None:
    rc, out, err = _git(
        ["config", "--local", "--get-regexp", r"^url\..*\.insteadof$"],
        runner=runner,
    )
    if rc not in {0, 1}:
        detail = op.redact_output(err or out).strip()
        raise RuntimeError("local URL rewrite check failed" + (f": {detail}" if detail else "."))
    if out.strip():
        raise RuntimeError("Controller repository contains a local Git URL rewrite; refusing publication.")


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
        policy.require_egress_host("github.com")

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
        if remote_url != EXPECTED_REMOTE_URL:
            raise RuntimeError(
                f"Controller origin URL mismatch: expected fixed HTTPS repository {EXPECTED_REMOTE_URL!r}."
            )
        if host not in ALLOWED_REMOTE_HOSTS:
            raise PermissionError(f"Configured origin host {host!r} is not approved for Controller publication.")

        _assert_no_local_url_rewrite(runner=runner)
        _assert_release_auth_ready()

        refspec = f"HEAD:refs/heads/{REMOTE_BRANCH}"
        preflight = _network_git(
            ["push", "--dry-run", "--porcelain", EXPECTED_REMOTE_URL, refspec],
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
            "remote_url": EXPECTED_REMOTE_URL,
            "remote_host": host,
            "credential_broker": "release-scoped-gh",
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
                extra={"branch": BRANCH, "remote_branch": REMOTE_BRANCH, "commit": expected, "remote": REMOTE, "remote_host": host, "credential_broker": "release-scoped-gh"},
            )
            return json.dumps({"success": True, "dry_run": True, "plan": plan, "preflight": op.redact_output(preflight)}, indent=2)

        policy.require_mutation(dry_run)
        push_out = _network_git(
            ["push", "--porcelain", EXPECTED_REMOTE_URL, refspec],
            label="Controller push",
            timeout=180,
            runner=runner,
        )
        changed = True
        remote_head_raw = _network_git(
            ["ls-remote", "--heads", EXPECTED_REMOTE_URL, f"refs/heads/{REMOTE_BRANCH}"],
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
            "remote_url": EXPECTED_REMOTE_URL,
            "remote_host": host,
            "credential_broker": "release-scoped-gh",
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
            extra={"branch": BRANCH, "remote_branch": REMOTE_BRANCH, "commit": expected, "remote": REMOTE, "remote_host": host, "credential_broker": "release-scoped-gh", "force_push": False},
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
            error=op.redact_output(str(exc)),
            path=str(WORKTREE),
            extra={"branch": BRANCH, "remote_branch": REMOTE_BRANCH, "remote": REMOTE, "credential_broker": "release-scoped-gh", "force_push": False},
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="release",
                code="CONTROLLER_PUBLISH_ERROR",
                suggested_action="Resolve the reported authority, branch, cleanliness, exact HTTPS origin, release auth, or fast-forward condition; do not bypass the governed publication tool.",
            ),
            indent=2,
        )
