"""Narrow supervised host runner for one approved Antigravity review job.

This module deliberately does not expose a general host command surface.  It can
only launch the fixed operator-regression review packet against the fixed Hermes
operator repository and target commit, using the official host-side ``agy``
binary.  The worker creates a temporary detached worktree, runs a fixed set of
credential-free tests, grants Antigravity temporary read-only access to that
worktree, captures evidence, restores settings, and removes the worktree.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import operator_policy as op

AGY_BINARY = Path("/home/jfroh/.local/bin/agy")
HOST_USER = "jfroh"
HOST_HOME = Path("/home/jfroh")
CANONICAL_WORKTREE = Path(
    "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"
)
TARGET_COMMIT = "d37757895fb1cc835ffe28da288b90c98ff3c612"
PACKET_PATH = Path(
    "/home/jfroh/.hermes/ops-brain/antigravity/jobs/"
    "operator-regression-independent-review.yaml"
)
REPORT_PATH = Path(
    "/home/jfroh/.hermes/ops-brain/evidence/"
    "operator-regression-independent-review.md"
)
ENVELOPE_PATH = Path(
    "/home/jfroh/.hermes/ops-brain/evidence/"
    "operator-regression-independent-review.yaml"
)
SETTINGS_PATH = HOST_HOME / ".gemini/antigravity-cli/settings.json"
STATE_DIR = CANONICAL_WORKTREE / "logs" / "antigravity-review"
STATE_PATH = STATE_DIR / "state.json"
LAUNCH_LOG_PATH = STATE_DIR / "launcher.log"
# Temporary detached review worktrees must remain beneath the fixed canonical
# worktree, which is the maintenance session's approved writable root.
REVIEW_ROOT = STATE_DIR / "worktrees"
REVIEW_PREFIX = "antigravity-operator-review-d377-"
REQUIRED_TEMPLATE = "hermes-gpt-operator-maintenance"
MODEL = "gemini-3.6-flash-low"
OUTER_TIMEOUT_SECONDS = 5700
AGY_TIMEOUT = "5400s"

FIXED_TEST_LABELS: tuple[str, ...] = (
    "targeted session-extension suite",
    "targeted service-sandbox suite",
    "operator-wide suite",
    "full repository suite",
)

_MARKDOWN_START = "---BEGIN_MARKDOWN---"
_MARKDOWN_END = "---END_MARKDOWN---"
_YAML_START = "---BEGIN_YAML---"
_YAML_END = "---END_YAML---"


def _json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _read_state() -> dict[str, Any]:
    try:
        raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _write_state(**updates: Any) -> dict[str, Any]:
    state = _read_state()
    state.update(updates)
    state["updated_at"] = int(time.time())
    _atomic_write(STATE_PATH, json.dumps(state, indent=2, sort_keys=True) + "\n")
    return state


def _pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _require_authority(*, mutate: bool, dry_run: bool = False) -> op.OperatorPolicy:
    policy = op.OperatorPolicy()
    policy.require_level("workspace")
    policy.require_verb("filesystem", "read")
    policy.require_verb("tests", "run")
    if policy.policy_template != REQUIRED_TEMPLATE:
        raise PermissionError(
            f"This fixed Antigravity review requires policy template {REQUIRED_TEMPLATE!r}."
        )
    if mutate:
        policy.require_mutation(dry_run)
    return policy


def hermes_antigravity_review_start(dry_run: bool = True) -> str:
    """Start the one fixed supervised Antigravity review job."""
    policy: op.OperatorPolicy | None = None
    try:
        policy = _require_authority(mutate=True, dry_run=dry_run)
        current = _read_state()
        if current.get("status") in {"queued", "running"} and _pid_alive(
            int(current.get("pid") or 0)
        ):
            raise RuntimeError("The fixed Antigravity review is already running.")

        preview = {
            "success": True,
            "dry_run": bool(dry_run or policy.effective_dry_run(dry_run)),
            "binary": str(AGY_BINARY),
            "worktree": str(CANONICAL_WORKTREE),
            "target_commit": TARGET_COMMIT,
            "packet": str(PACKET_PATH),
            "report": str(REPORT_PATH),
            "envelope": str(ENVELOPE_PATH),
            "model": MODEL,
            "fixed_test_count": len(FIXED_TEST_LABELS),
            "session_id": policy.session_id,
        }
        if preview["dry_run"]:
            preview.update(_dry_run_validation())
            op.audit_record(
                tool="hermes_antigravity_review_start",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="validated fixed Antigravity review launch",
                path=str(CANONICAL_WORKTREE),
                extra={"target_commit": TARGET_COMMIT},
            )
            return _json(preview)

        STATE_DIR.mkdir(parents=True, exist_ok=True)
        job_id = f"agr_{uuid.uuid4().hex[:16]}"
        state = _write_state(
            schema_version=1,
            job_id=job_id,
            status="queued",
            pid=None,
            started_at=int(time.time()),
            target_commit=TARGET_COMMIT,
            packet_path=str(PACKET_PATH),
            report_path=str(REPORT_PATH),
            envelope_path=str(ENVELOPE_PATH),
            session_id=policy.session_id,
            snapshot_hash=policy.snapshot_hash,
        )
        with open(LAUNCH_LOG_PATH, "a", encoding="utf-8") as log:
            proc = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "worker", job_id],
                cwd=str(CANONICAL_WORKTREE),
                env=_sanitized_env(),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                shell=False,
                start_new_session=True,
                close_fds=True,
            )
        state = _write_state(pid=proc.pid)
        op.audit_record(
            tool="hermes_antigravity_review_start",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary="started fixed supervised Antigravity review",
            path=str(CANONICAL_WORKTREE),
            job_id=job_id,
            extra={"pid": proc.pid, "target_commit": TARGET_COMMIT},
        )
        return _json({"success": True, **state})
    except Exception as exc:
        if policy is None:
            policy = op.OperatorPolicy()
        op.audit_record(
            tool="hermes_antigravity_review_start",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=dry_run,
            success=False,
            changed=False,
            error=str(exc),
            path=str(CANONICAL_WORKTREE),
            extra={"target_commit": TARGET_COMMIT},
        )
        return _json({"success": False, "error": str(exc)})


def hermes_antigravity_review_status() -> str:
    """Return current state for the fixed supervised Antigravity review."""
    try:
        policy = _require_authority(mutate=False)
        state = _read_state()
        if not state:
            state = {"status": "not_started"}
        pid = int(state.get("pid") or 0)
        state["process_alive"] = _pid_alive(pid)
        state["success"] = True
        state["report_exists"] = REPORT_PATH.exists()
        state["envelope_exists"] = ENVELOPE_PATH.exists()
        op.audit_record(
            tool="hermes_antigravity_review_status",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=True,
            success=True,
            changed=False,
            summary=f"Antigravity review status={state.get('status')}",
            job_id=state.get("job_id"),
        )
        return _json(state)
    except Exception as exc:
        return _json({"success": False, "error": str(exc)})


def hermes_antigravity_review_cancel(dry_run: bool = True) -> str:
    """Cancel the fixed supervised Antigravity review process group."""
    policy: op.OperatorPolicy | None = None
    try:
        policy = _require_authority(mutate=True, dry_run=dry_run)
        state = _read_state()
        pid = int(state.get("pid") or 0)
        alive = _pid_alive(pid)
        effective_dry = policy.effective_dry_run(dry_run)
        if not alive:
            return _json(
                {"success": True, "dry_run": effective_dry, "changed": False, "status": "not_running"}
            )
        if effective_dry:
            return _json(
                {"success": True, "dry_run": True, "changed": False, "pid": pid, "would_cancel": True}
            )
        os.killpg(pid, signal.SIGTERM)
        _write_state(status="cancel_requested", cancel_requested_at=int(time.time()))
        op.audit_record(
            tool="hermes_antigravity_review_cancel",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary="requested cancellation of fixed Antigravity review",
            job_id=state.get("job_id"),
            extra={"pid": pid},
        )
        return _json({"success": True, "changed": True, "pid": pid, "status": "cancel_requested"})
    except Exception as exc:
        if policy is None:
            policy = op.OperatorPolicy()
        op.audit_record(
            tool="hermes_antigravity_review_cancel",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=dry_run,
            success=False,
            changed=False,
            error=str(exc),
        )
        return _json({"success": False, "error": str(exc)})


def _sanitized_env() -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(HOST_HOME)
    path_parts = [str(HOST_HOME / ".local/bin")]
    path_parts.extend(part for part in env.get("PATH", "").split(os.pathsep) if part)
    env["PATH"] = os.pathsep.join(dict.fromkeys(path_parts))
    for key in list(env):
        upper = key.upper()
        if any(marker in upper for marker in ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD")):
            env.pop(key, None)
    # Test and review subprocesses must not inherit the live operator session
    # pointer.  The worker's authority is checked before launch; child tools
    # receive no independent operator authority.
    env.pop("HERMES_GPT_OPERATOR_SESSION_ROOT", None)
    env.pop("HERMES_GPT_OPERATOR_SESSION_ID", None)
    return env


def _run(argv: list[str], *, cwd: Path, timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(
        argv,
        cwd=str(cwd),
        env=_sanitized_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
    )
    return proc.returncode, op.redact_output(proc.stdout), op.redact_output(proc.stderr)


def _preflight() -> None:
    if pwd.getpwuid(os.getuid()).pw_name != HOST_USER:
        raise RuntimeError(f"Runner must execute as Linux user {HOST_USER!r}.")
    for path, label in (
        (AGY_BINARY, "agy binary"),
        (CANONICAL_WORKTREE, "canonical worktree"),
        (PACKET_PATH, "review packet"),
    ):
        if not path.exists():
            raise FileNotFoundError(f"Required {label} is missing: {path}")
    rc, stdout, stderr = _run(
        ["git", "cat-file", "-t", TARGET_COMMIT], cwd=CANONICAL_WORKTREE, timeout=30
    )
    if rc != 0 or stdout.strip() != "commit":
        raise RuntimeError(
            f"Target commit {TARGET_COMMIT} is unavailable in the canonical repository: {stderr.strip()}"
        )


def _dry_run_validation() -> dict[str, bool]:
    review_dir: Path | None = None
    try:
        _preflight()
        review_dir = _create_detached_worktree(f"dryrun-{uuid.uuid4().hex[:12]}")
        return {
            "target_commit_exists": True,
            "detached_review_worktree_created": True,
            "launcher_validation_succeeded": True,
            "review_launched": False,
            "model_execution": False,
        }
    finally:
        _remove_detached_worktree(review_dir)


def _create_detached_worktree(job_id: str) -> Path:
    review_dir = REVIEW_ROOT / f"{REVIEW_PREFIX}{job_id}"
    if review_dir.exists():
        raise RuntimeError(f"Review worktree already exists: {review_dir}")
    REVIEW_ROOT.mkdir(parents=True, exist_ok=True)
    rc, _stdout, stderr = _run(
        ["git", "worktree", "add", "--detach", str(review_dir), TARGET_COMMIT],
        cwd=CANONICAL_WORKTREE,
        timeout=120,
    )
    if rc != 0:
        raise RuntimeError(f"Failed to create detached review worktree: {stderr.strip()}")
    return review_dir


def _remove_detached_worktree(review_dir: Path | None) -> None:
    if review_dir is None or not review_dir.exists():
        return
    _run(
        ["git", "worktree", "remove", "--force", str(review_dir)],
        cwd=CANONICAL_WORKTREE,
        timeout=120,
    )


def _fixed_test_commands(review_dir: Path) -> list[list[str]]:
    operator_tests = sorted(path.name for path in review_dir.glob("test_operator_*.py"))
    if not operator_tests:
        raise RuntimeError("No operator test files were found in the detached review worktree.")
    return [
        ["pytest", "-q", "test_operator_session_requests.py"],
        ["pytest", "-q", "test_operator_service_sandbox.py"],
        ["pytest", "-q", *operator_tests],
        ["pytest", "-q"],
    ]


def _collect_review_inputs(review_dir: Path) -> Path:
    evidence_dir = review_dir / ".antigravity-review-input"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    packet = PACKET_PATH.read_text(encoding="utf-8")
    _atomic_write(evidence_dir / "packet.yaml", packet)

    rc, stdout, stderr = _run(
        ["git", "show", "--stat", "--oneline", "--decorate=short", TARGET_COMMIT],
        cwd=review_dir,
        timeout=60,
    )
    _atomic_write(
        evidence_dir / "commit-stat.txt",
        f"returncode={rc}\n\nSTDOUT\n{stdout}\n\nSTDERR\n{stderr}\n",
    )
    rc, stdout, stderr = _run(
        ["git", "diff", f"{TARGET_COMMIT}^", TARGET_COMMIT, "--"],
        cwd=review_dir,
        timeout=120,
    )
    _atomic_write(
        evidence_dir / "commit.diff",
        f"returncode={rc}\n\n{stdout}\n\nSTDERR\n{stderr}\n",
    )

    test_sections: list[str] = []
    for argv in _fixed_test_commands(review_dir):
        label = " ".join(argv)
        started = time.time()
        try:
            rc, stdout, stderr = _run(list(argv), cwd=review_dir, timeout=1800)
        except subprocess.TimeoutExpired:
            rc, stdout, stderr = 124, "", "timed out"
        elapsed = round(time.time() - started, 3)
        test_sections.append(
            f"## {label}\nreturncode={rc}\nelapsed_seconds={elapsed}\n\nSTDOUT\n{stdout}\n\nSTDERR\n{stderr}\n"
        )
    _atomic_write(evidence_dir / "test-results.md", "\n".join(test_sections))
    return evidence_dir


def _load_settings() -> tuple[bytes | None, int | None, dict[str, Any]]:
    original: bytes | None = None
    mode: int | None = None
    data: dict[str, Any] = {}
    if SETTINGS_PATH.exists():
        original = SETTINGS_PATH.read_bytes()
        mode = SETTINGS_PATH.stat().st_mode & 0o777
        try:
            loaded = json.loads(original.decode("utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("Antigravity settings are not valid UTF-8 JSON; refusing to modify them.")
    return original, mode, data


def _is_read_file_rule(value: object) -> bool:
    return isinstance(value, str) and value.strip().startswith("read_file(")


def _install_read_permission(review_dir: Path, data: dict[str, Any], mode: int | None) -> None:
    permissions = data.setdefault("permissions", {})
    if not isinstance(permissions, dict):
        raise RuntimeError("Antigravity settings permissions field is not an object.")
    allow = permissions.setdefault("allow", [])
    ask = permissions.setdefault("ask", [])
    deny = permissions.setdefault("deny", [])
    if not isinstance(allow, list):
        raise RuntimeError("Antigravity settings permissions.allow field is not a list.")
    if not isinstance(ask, list):
        raise RuntimeError("Antigravity settings permissions.ask field is not a list.")
    if not isinstance(deny, list):
        raise RuntimeError("Antigravity settings permissions.deny field is not a list.")
    if any(_is_read_file_rule(entry) for entry in deny):
        raise RuntimeError(
            "Antigravity settings contain a read_file deny rule; refusing to weaken it for the review."
        )

    # In headless mode an ask rule takes precedence over a narrower allow rule and
    # is auto-denied. Temporarily suspend only read_file ask rules; all other ask
    # and deny rules remain intact, and the original settings bytes are restored
    # unconditionally after the bounded review.
    permissions["ask"] = [entry for entry in ask if not _is_read_file_rule(entry)]
    rule = f"read_file({review_dir})"
    if rule not in allow:
        allow.append(rule)
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(SETTINGS_PATH, json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.chmod(SETTINGS_PATH, mode if mode is not None else 0o600)


def _restore_settings(original: bytes | None, mode: int | None) -> None:
    if original is None:
        try:
            SETTINGS_PATH.unlink()
        except FileNotFoundError:
            pass
        return
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_PATH.with_suffix(SETTINGS_PATH.suffix + ".tmp")
    tmp.write_bytes(original)
    os.replace(tmp, SETTINGS_PATH)
    if mode is not None:
        os.chmod(SETTINGS_PATH, mode)


def _build_prompt(review_dir: Path) -> str:
    return f"""Act as an independent senior security reviewer. Review the fixed target commit
{TARGET_COMMIT} in the repository rooted at {review_dir}.

Read all files under {review_dir}/.antigravity-review-input first. They contain the
review packet, exact commit diff/stat, and independently executed test outputs.
Then inspect the relevant source and test files directly. Do not modify files and
do not run commands. Focus on session-extension self-approval, expiry/revocation
races, authority expansion, snapshot freshness, path/branch confinement, service
sandbox hard-denies, allowlist normalisation, and bypass paths.

Return exactly two delimited artifacts and nothing outside the delimiters:
{_MARKDOWN_START}
A complete Markdown report with final verdict PASS, PASS_WITH_FINDINGS, or FAIL;
changed-file inventory; exact findings with severity and locations; call-path
analysis; adversarial acceptance matrix; test results; unproven assumptions; and
confirmation that source and credentials were not modified.
{_MARKDOWN_END}
{_YAML_START}
schema_version: 1
review:
  target_commit: {TARGET_COMMIT}
  verdict: PASS | PASS_WITH_FINDINGS | FAIL
  blocking_findings: <integer>
  non_blocking_findings: <integer>
  targeted_tests_passed: <boolean>
  operator_suite_passed: <boolean>
  full_suite_passed: <boolean>
  source_modified: false
  credentials_accessed: false
  services_restarted: false
{_YAML_END}
"""


def _collect_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(_collect_strings(item))
        return out
    if isinstance(value, dict):
        preferred = ["response", "result", "text", "output", "message", "content"]
        out: list[str] = []
        for key in preferred:
            if key in value:
                out.extend(_collect_strings(value[key]))
        for key, item in value.items():
            if key not in preferred:
                out.extend(_collect_strings(item))
        return out
    return []


def _extract_artifacts(stdout: str) -> tuple[str, str, str | None]:
    candidates: list[str] = []
    try:
        candidates.extend(_collect_strings(json.loads(stdout)))
    except json.JSONDecodeError:
        pass
    candidates.append(stdout)
    joined = "\n".join(candidates)
    md_match = re.search(
        re.escape(_MARKDOWN_START) + r"\s*(.*?)\s*" + re.escape(_MARKDOWN_END),
        joined,
        flags=re.DOTALL,
    )
    yaml_match = re.search(
        re.escape(_YAML_START) + r"\s*(.*?)\s*" + re.escape(_YAML_END),
        joined,
        flags=re.DOTALL,
    )
    markdown_text: str | None = md_match.group(1) if md_match else None
    if markdown_text is None and yaml_match:
        # Some models emit the complete YAML artifact immediately after the
        # Markdown body but omit only the Markdown end marker. The YAML start
        # marker is an unambiguous boundary, so accept that bounded form while
        # still requiring a complete YAML artifact and all downstream checks.
        fallback_match = re.search(
            re.escape(_MARKDOWN_START) + r"\s*(.*?)\s*" + re.escape(_YAML_START),
            joined,
            flags=re.DOTALL,
        )
        if fallback_match:
            markdown_text = fallback_match.group(1)
    if markdown_text is None or not yaml_match:
        raise RuntimeError("Antigravity output did not contain both required artifact delimiters.")
    conversation_id = None
    try:
        parsed = json.loads(stdout)
        if isinstance(parsed, dict):
            for key in ("conversation_id", "conversationId", "session_id", "sessionId"):
                value = parsed.get(key)
                if isinstance(value, str) and value:
                    conversation_id = value
                    break
    except json.JSONDecodeError:
        pass
    return markdown_text.strip() + "\n", yaml_match.group(1).strip() + "\n", conversation_id


def _validate_artifacts(markdown: str, yaml_text: str) -> str:
    verdict_match = re.search(r"\b(PASS_WITH_FINDINGS|PASS|FAIL)\b", markdown)
    if not verdict_match:
        raise RuntimeError("Markdown report does not contain a valid final verdict.")
    verdict = verdict_match.group(1)
    if f"verdict: {verdict}" not in yaml_text:
        raise RuntimeError("YAML verdict does not match the Markdown verdict.")
    if TARGET_COMMIT not in markdown and TARGET_COMMIT not in yaml_text:
        raise RuntimeError("Evidence does not identify the target commit.")
    if re.search(r"<[^>]+>", yaml_text):
        raise RuntimeError("YAML evidence still contains placeholder values.")
    for field in ("blocking_findings", "non_blocking_findings"):
        if not re.search(rf"^\s*{field}:\s*\d+\s*$", yaml_text, flags=re.MULTILINE):
            raise RuntimeError(f"YAML evidence is missing an integer {field} field.")
    for field in (
        "targeted_tests_passed",
        "operator_suite_passed",
        "full_suite_passed",
        "source_modified",
        "credentials_accessed",
        "services_restarted",
    ):
        if not re.search(rf"^\s*{field}:\s*(true|false)\s*$", yaml_text, flags=re.MULTILINE):
            raise RuntimeError(f"YAML evidence is missing a boolean {field} field.")
    return verdict


def _worker(job_id: str) -> int:
    review_dir: Path | None = None
    settings_original: bytes | None = None
    settings_mode: int | None = None
    settings_restore_required = False
    try:
        _write_state(status="running", pid=os.getpid(), worker_started_at=int(time.time()))
        _preflight()
        review_dir = _create_detached_worktree(job_id)
        _write_state(review_worktree=str(review_dir))
        _collect_review_inputs(review_dir)
        settings_original, settings_mode, settings_data = _load_settings()
        settings_restore_required = True
        _install_read_permission(review_dir, settings_data, settings_mode)
        prompt = _build_prompt(review_dir)
        argv = [
            str(AGY_BINARY),
            "--print-timeout",
            AGY_TIMEOUT,
            "--model",
            MODEL,
            "--mode",
            "plan",
            "--output-format",
            "json",
            "--print",
            prompt,
        ]
        proc = subprocess.run(
            argv,
            cwd=str(review_dir),
            env=_sanitized_env(),
            capture_output=True,
            text=True,
            timeout=OUTER_TIMEOUT_SECONDS,
            shell=False,
        )
        stdout = op.redact_output(proc.stdout)
        stderr = op.redact_output(proc.stderr)
        _atomic_write(STATE_DIR / "agy-stdout.json", stdout)
        _atomic_write(STATE_DIR / "agy-stderr.log", stderr)
        if proc.returncode != 0:
            raise RuntimeError(f"agy exited with code {proc.returncode}: {stderr[-1000:]}")
        markdown, yaml_text, conversation_id = _extract_artifacts(stdout)
        verdict = _validate_artifacts(markdown, yaml_text)
        _atomic_write(REPORT_PATH, markdown)
        _atomic_write(ENVELOPE_PATH, yaml_text)
        _write_state(
            status="completed",
            finished_at=int(time.time()),
            exit_code=proc.returncode,
            verdict=verdict,
            conversation_id=conversation_id,
            report_path=str(REPORT_PATH),
            envelope_path=str(ENVELOPE_PATH),
        )
        return 0
    except subprocess.TimeoutExpired:
        _write_state(status="failed", finished_at=int(time.time()), error="agy timed out", exit_code=124)
        return 124
    except BaseException as exc:
        _write_state(status="failed", finished_at=int(time.time()), error=str(exc), exit_code=1)
        return 1
    finally:
        try:
            if settings_restore_required:
                _restore_settings(settings_original, settings_mode)
        finally:
            _remove_detached_worktree(review_dir)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "worker" and re.fullmatch(r"agr_[0-9a-f]{16}", args[1]):
        return _worker(args[1])
    print("This module only supports the internal fixed review worker.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
