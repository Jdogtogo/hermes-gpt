"""Fixed-purpose GitHub device authentication for governed Controller release.

The public surface never accepts or returns a bearer token.  Device-code state
and GitHub CLI auth state live only in a fixed ignored runtime directory.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import operator_policy as op

WORKTREE = Path("/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration")
RELEASE_TOOLS_ROOT = WORKTREE / "logs/.release-tools"
GH_BINARY = RELEASE_TOOLS_ROOT / "gh/gh"
AUTH_DIR = RELEASE_TOOLS_ROOT / "gh-auth"
STATE_FILE = AUTH_DIR / "device-flow.json"
AUTH_CONFIG = AUTH_DIR / "hosts.yml"
POLICY_TEMPLATE = "hermes-github-release-auth"
GITHUB_HOST = "github.com"
GITHUB_API_HOST = "api.github.com"
DEVICE_CODE_URL = "https://github.com/login/device/code"
TOKEN_URL = "https://github.com/login/oauth/access_token"
OAUTH_CLIENT_ID = "178c6fc778ccc68e1d6a"
OAUTH_SCOPES = "repo read:org gist"
VALID_ACTIONS = frozenset({"start", "complete", "status", "clear"})
_TOKEN_RE = re.compile(r"\bgh[a-z]_[A-Za-z0-9_\-]{12,}\b", re.IGNORECASE)
_DEVICE_RE = re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE)

HttpPost = Callable[[str, dict[str, str]], dict[str, Any]]
GhRunner = Callable[..., tuple[int, str, str]]


def _sanitize(text: str, *secrets: str) -> str:
    value = str(text or "")
    for secret in secrets:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = _TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", value)
    value = _DEVICE_RE.sub("[REDACTED_DEVICE_CODE]", value)
    return op.redact_output(value)


def _assert_fixed_runtime_path(path: Path) -> None:
    try:
        path.relative_to(RELEASE_TOOLS_ROOT)
    except ValueError as exc:
        raise RuntimeError("GitHub release auth path escaped the fixed release-tools root.") from exc


def _ensure_auth_dir() -> None:
    _assert_fixed_runtime_path(AUTH_DIR)
    if AUTH_DIR.exists() and AUTH_DIR.is_symlink():
        raise RuntimeError("GitHub release auth directory must not be a symlink.")
    AUTH_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(AUTH_DIR, 0o700)


def _assert_regular_nonsymlink(path: Path) -> None:
    _assert_fixed_runtime_path(path)
    if path.is_symlink():
        raise RuntimeError(f"Refusing symlink at fixed GitHub release auth path: {path.name}")
    if path.exists() and not path.is_file():
        raise RuntimeError(f"Expected regular file at fixed GitHub release auth path: {path.name}")


def _write_state(state: dict[str, Any]) -> None:
    _ensure_auth_dir()
    _assert_regular_nonsymlink(STATE_FILE)
    tmp = AUTH_DIR / ".device-flow.json.tmp"
    _assert_regular_nonsymlink(tmp)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(tmp, flags, 0o600)
    try:
        payload = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)
    os.chmod(STATE_FILE, 0o600)


def _read_state() -> dict[str, Any] | None:
    _assert_regular_nonsymlink(STATE_FILE)
    if not STATE_FILE.exists():
        return None
    mode = stat.S_IMODE(STATE_FILE.stat().st_mode)
    if mode & 0o077:
        raise RuntimeError("GitHub release device state permissions are too broad.")
    raw = STATE_FILE.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise RuntimeError("GitHub release device state is malformed.")
    return data


def _delete_state() -> bool:
    _assert_regular_nonsymlink(STATE_FILE)
    if not STATE_FILE.exists():
        return False
    STATE_FILE.unlink()
    return True


def _auth_config_present() -> bool:
    _assert_regular_nonsymlink(AUTH_CONFIG)
    return AUTH_CONFIG.exists() and AUTH_CONFIG.stat().st_size > 0


def _gh_present() -> bool:
    return GH_BINARY.is_file() and not GH_BINARY.is_symlink() and os.access(GH_BINARY, os.X_OK)


def _post_form(url: str, form: dict[str, str]) -> dict[str, Any]:
    encoded = urlencode(form).encode("utf-8")
    request = Request(
        url,
        data=encoded,
        method="POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Hermes-GPT-Controller-GitHub-Release-Auth/1.0",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            payload = response.read()
    except HTTPError as exc:
        raise RuntimeError(f"GitHub OAuth endpoint returned HTTP {exc.code}.") from exc
    except URLError as exc:
        raise RuntimeError("GitHub OAuth endpoint could not be reached.") from exc
    data = json.loads(payload.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("GitHub OAuth endpoint returned a malformed response.")
    return data


def _gh_env() -> dict[str, str]:
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


def _default_gh_runner(
    argv: list[str],
    *,
    input_text: str,
    env: dict[str, str],
    timeout: int,
    workdir: str,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            input=input_text,
            cwd=workdir,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", "GitHub CLI authentication timed out."
    except OSError as exc:
        return 127, "", str(exc)
    return proc.returncode, proc.stdout, proc.stderr


def _secure_auth_files() -> None:
    _ensure_auth_dir()
    for entry in AUTH_DIR.iterdir():
        if entry.is_symlink():
            raise RuntimeError("GitHub CLI wrote an unexpected symlink in the auth directory.")
        if entry.is_dir():
            os.chmod(entry, 0o700)
        elif entry.is_file():
            os.chmod(entry, 0o600)


def _login_with_token(token: str, *, runner: GhRunner | None = None) -> None:
    if not _gh_present():
        raise RuntimeError("Pinned release-scoped GitHub CLI binary is missing or not executable.")
    _ensure_auth_dir()
    run = runner or _default_gh_runner
    argv = [
        str(GH_BINARY),
        "auth",
        "login",
        "--with-token",
        "--hostname",
        GITHUB_HOST,
        "--git-protocol",
        "https",
        "--insecure-storage",
    ]
    rc, out, err = run(
        argv,
        input_text=token + "\n",
        env=_gh_env(),
        timeout=120,
        workdir=str(WORKTREE),
    )
    if rc != 0:
        detail = _sanitize(err or out, token).strip()
        raise RuntimeError("GitHub CLI rejected the OAuth token" + (f": {detail}" if detail else "."))
    _secure_auth_files()
    if not _auth_config_present():
        raise RuntimeError("GitHub CLI authentication completed without creating the fixed auth config.")


def _status_result() -> dict[str, Any]:
    return {
        "success": True,
        "action": "status",
        "gh_binary_present": _gh_present(),
        "auth_config_present": _auth_config_present(),
        "device_flow_pending": STATE_FILE.exists() and not STATE_FILE.is_symlink(),
    }


def _start(*, http_post: HttpPost, now: int) -> tuple[dict[str, Any], bool]:
    if not _gh_present():
        raise RuntimeError("Pinned release-scoped GitHub CLI binary is missing or not executable.")
    if _auth_config_present():
        return {
            "success": True,
            "action": "start",
            "authorized": True,
            "pending": False,
            "auth_config_present": True,
        }, False

    existing = _read_state()
    if existing is not None:
        expires_at = int(existing.get("expires_at", 0))
        if expires_at > now:
            return {
                "success": True,
                "action": "start",
                "authorized": False,
                "pending": True,
                "user_code": str(existing.get("user_code", "")),
                "verification_uri": str(existing.get("verification_uri", "https://github.com/login/device")),
                "expires_at": expires_at,
                "interval": int(existing.get("interval", 5)),
            }, False
        _delete_state()

    response = http_post(
        DEVICE_CODE_URL,
        {"client_id": OAUTH_CLIENT_ID, "scope": OAUTH_SCOPES},
    )
    required = ["device_code", "user_code", "verification_uri", "expires_in"]
    if any(not response.get(key) for key in required):
        raise RuntimeError("GitHub device authorization response was incomplete.")
    expires_in = max(1, int(response["expires_in"]))
    interval = max(5, int(response.get("interval", 5)))
    state = {
        "device_code": str(response["device_code"]),
        "user_code": str(response["user_code"]),
        "verification_uri": str(response["verification_uri"]),
        "expires_at": now + expires_in,
        "interval": interval,
        "created_at": now,
    }
    _write_state(state)
    return {
        "success": True,
        "action": "start",
        "authorized": False,
        "pending": True,
        "user_code": state["user_code"],
        "verification_uri": state["verification_uri"],
        "expires_at": state["expires_at"],
        "interval": interval,
    }, True


def _complete(*, http_post: HttpPost, runner: GhRunner | None, now: int) -> tuple[dict[str, Any], bool]:
    if _auth_config_present() and not STATE_FILE.exists():
        return {
            "success": True,
            "action": "complete",
            "authorized": True,
            "pending": False,
            "auth_config_present": True,
        }, False

    state = _read_state()
    if state is None:
        raise RuntimeError("No pending GitHub release device authorization. Start one first.")
    expires_at = int(state.get("expires_at", 0))
    if expires_at <= now:
        _delete_state()
        raise RuntimeError("GitHub release device authorization expired. Start a new authorization.")
    device_code = str(state.get("device_code", ""))
    if not device_code:
        raise RuntimeError("GitHub release device state is missing its opaque device code.")

    response = http_post(
        TOKEN_URL,
        {
            "client_id": OAUTH_CLIENT_ID,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        },
    )
    error = str(response.get("error", ""))
    if error == "authorization_pending":
        return {
            "success": True,
            "action": "complete",
            "authorized": False,
            "pending": True,
            "retry_after_seconds": int(state.get("interval", 5)),
            "expires_at": expires_at,
        }, False
    if error == "slow_down":
        interval = int(state.get("interval", 5)) + 5
        state["interval"] = interval
        _write_state(state)
        return {
            "success": True,
            "action": "complete",
            "authorized": False,
            "pending": True,
            "retry_after_seconds": interval,
            "expires_at": expires_at,
        }, True
    if error in {"expired_token", "access_denied", "incorrect_device_code"}:
        _delete_state()
        raise RuntimeError(f"GitHub device authorization ended with {error.replace('_', ' ')}.")
    if error:
        raise RuntimeError("GitHub device authorization returned an unrecognized error.")

    token = str(response.get("access_token", ""))
    if not token:
        raise RuntimeError("GitHub device authorization did not return an access token.")
    try:
        _login_with_token(token, runner=runner)
    except Exception as exc:
        raise RuntimeError(_sanitize(str(exc), token)) from exc
    finally:
        token = ""
    _delete_state()
    return {
        "success": True,
        "action": "complete",
        "authorized": True,
        "pending": False,
        "auth_config_present": True,
    }, True


def _clear() -> tuple[dict[str, Any], bool]:
    _assert_fixed_runtime_path(AUTH_DIR)
    if not AUTH_DIR.exists():
        return {"success": True, "action": "clear", "changed": False}, False
    if AUTH_DIR.is_symlink():
        raise RuntimeError("Refusing to clear a symlinked GitHub release auth directory.")
    changed = False
    for entry in list(AUTH_DIR.iterdir()):
        _assert_fixed_runtime_path(entry)
        if entry.is_symlink() or entry.is_file():
            entry.unlink()
            changed = True
        elif entry.is_dir():
            shutil.rmtree(entry)
            changed = True
        else:
            raise RuntimeError("Unexpected filesystem object in GitHub release auth directory.")
    os.chmod(AUTH_DIR, 0o700)
    return {"success": True, "action": "clear", "changed": changed}, changed


def hermes_github_release_auth(
    action: str = "status",
    *,
    http_post: HttpPost | None = None,
    gh_runner: GhRunner | None = None,
    now: int | None = None,
) -> str:
    """Drive one bounded step of the fixed GitHub release device-auth flow."""
    policy: op.OperatorPolicy | None = None
    normalized = str(action or "").strip().lower()
    changed = False
    result: dict[str, Any] | None = None
    try:
        if normalized not in VALID_ACTIONS:
            raise ValueError("action must be one of: start, complete, status, clear.")
        policy = op.OperatorPolicy()
        if not policy.session_id:
            raise PermissionError("hermes_github_release_auth requires an active Operator Session.")
        if getattr(policy, "policy_template", POLICY_TEMPLATE) != POLICY_TEMPLATE:
            raise PermissionError(f"hermes_github_release_auth requires policy template {POLICY_TEMPLATE!r}.")
        policy.require_verb("github_release_auth", normalized)
        if normalized in {"start", "complete"}:
            policy.require_egress_host(GITHUB_HOST)
        if normalized == "complete":
            policy.require_egress_host(GITHUB_API_HOST)
        if normalized in {"start", "complete", "clear"}:
            policy.require_mutation(False)

        clock = int(time.time()) if now is None else int(now)
        post = http_post or _post_form
        if normalized == "status":
            result = _status_result()
        elif normalized == "start":
            result, changed = _start(http_post=post, now=clock)
        elif normalized == "complete":
            result, changed = _complete(http_post=post, runner=gh_runner, now=clock)
        else:
            result, changed = _clear()

        op.audit_record(
            tool="hermes_github_release_auth",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=changed,
            summary=f"GitHub release auth action {normalized} completed",
            path=str(AUTH_DIR),
            extra={
                "action": normalized,
                "authorized": bool(result.get("authorized", False)),
                "pending": bool(result.get("pending", False)),
                "auth_config_present": bool(result.get("auth_config_present", False)),
            },
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        safe_error = _sanitize(str(exc))
        op.audit_record(
            tool="hermes_github_release_auth",
            level=policy.level if policy is not None else "unknown",
            apply_mode=policy.apply_mode if policy is not None else "unknown",
            dry_run=False,
            success=False,
            changed=changed,
            error=safe_error,
            path=str(AUTH_DIR),
            extra={"action": normalized if normalized in VALID_ACTIONS else "invalid"},
        )
        return json.dumps(
            op.error_from_exception(
                RuntimeError(safe_error),
                layer="release_auth",
                code="GITHUB_RELEASE_AUTH_ERROR",
                suggested_action="Use start, complete, status, or clear under the dedicated GitHub release auth authority; never paste a token into ChatGPT.",
            ),
            indent=2,
        )
