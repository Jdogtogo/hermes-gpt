"""Fixed supervised host-side Antigravity review for the Projections Calculator.

This module exposes no arbitrary command, prompt, repository, commit, model, or
output-path input. It launches one pre-approved, read-only review of the fixed
Tax Calculator commits using the official host ``agy`` binary. Evidence and
state are written only to fixed Hermes-owned locations.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

import operator_policy as op

AGY_BINARY = Path("/home/jfroh/.local/bin/agy")
HOST_USER = "jfroh"
HOST_HOME = Path("/home/jfroh")
TAX_CALCULATOR_ROOT = Path("/mnt/c/Dev/Tax Calculator")
TARGET_COMMITS: tuple[str, ...] = ("9f4dfe8", "fc9494b", "2deadfc")
TARGET_RANGE = f"{TARGET_COMMITS[0]}^..{TARGET_COMMITS[-1]}"
MODEL = "gemini-3.6-flash-low"
OUTER_TIMEOUT_SECONDS = 8 * 60 * 60
WORKER_SLICE_TIMEOUT_SECONDS = 60 * 60
MAXIMUM_CONTINUATIONS = 8
AGY_TIMEOUT = "3300s"
REQUIRED_TEMPLATE = "tax-calculator-antigravity-review"
STOP_ON: tuple[str, ...] = (
    "completion",
    "material_scope_change",
    "unsafe_action",
    "repeated_failure",
    "authority_expiry",
)
STATE_DIR = Path(
    "/home/jfroh/.hermes/ops-brain/evidence/runtime/"
    "projections-calculator-antigravity-review"
)
STATE_PATH = STATE_DIR / "state.json"
LAUNCH_LOG_PATH = STATE_DIR / "launcher.log"
RUNS_DIR = STATE_DIR / "runs"
REPORT_PATH = Path(
    "/home/jfroh/.hermes/ops-brain/evidence/"
    "projections-calculator-independent-review-2026-07-31.md"
)
ENVELOPE_PATH = Path(
    "/home/jfroh/.hermes/ops-brain/evidence/"
    "projections-calculator-independent-review-2026-07-31.yaml"
)
SETTINGS_PATH = HOST_HOME / ".gemini/antigravity-cli/settings.json"
TASK_ID_PREFIX = "agt_"

_MARKDOWN_START = "---BEGIN_MARKDOWN---"
_MARKDOWN_END = "---END_MARKDOWN---"
_YAML_START = "---BEGIN_YAML---"
_YAML_END = "---END_YAML---"

_SENSITIVE_SNAPSHOT_COMPONENTS = frozenset(
    {
        "credentials",
        "api keys",
        "oauth tokens",
        "authentication databases",
        "secret stores",
        "private keys",
        "ssh material",
        "runtime session databases",
        "operator approval databases",
        "operator policy",
        "operator session state",
    }
)


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
    policy.require_read_path(TAX_CALCULATOR_ROOT)
    if mutate:
        policy.require_mutation(dry_run)
        policy.require_verb("filesystem", "edit")
        for path in (STATE_DIR, REPORT_PATH, ENVELOPE_PATH, SETTINGS_PATH):
            policy.require_write_path(path)
    return policy


def _worker_env() -> dict[str, str]:
    """Sanitise secrets while preserving the approved session pointer for the supervisor."""
    env = _sanitized_env()
    for key in ("HERMES_GPT_OPERATOR_SESSION_ROOT", "HERMES_GPT_OPERATOR_SESSION_ID"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    return env


def _assert_authority(expected_session_id: str, expected_snapshot_hash: str) -> op.OperatorPolicy:
    policy = _require_authority(mutate=False)
    if policy.session_id != expected_session_id:
        raise PermissionError("authority_expiry: originating Operator Session is no longer active")
    if policy.snapshot_hash != expected_snapshot_hash:
        raise PermissionError("authority_expiry: Operator Session authority snapshot changed")
    if not policy.expires_at or int(time.time()) >= int(policy.expires_at):
        raise PermissionError("authority_expiry: originating Operator Session expired")
    return policy


def _require_status_authority() -> op.OperatorPolicy:
    policy = op.OperatorPolicy()
    policy.require_enabled()
    for path in (STATE_PATH, REPORT_PATH, ENVELOPE_PATH):
        policy.require_read_path(path)
    return policy


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


def _run_bytes(argv: list[str], *, cwd: Path, timeout: int) -> tuple[int, bytes, str]:
    proc = subprocess.run(
        argv,
        cwd=str(cwd),
        env=_sanitized_env(),
        capture_output=True,
        text=False,
        timeout=timeout,
        shell=False,
    )
    stderr = proc.stderr.decode("utf-8", errors="replace")
    return proc.returncode, proc.stdout, op.redact_output(stderr)


def _snapshot_member_is_sensitive(relative: PurePosixPath) -> bool:
    lowered_parts = tuple(part.casefold() for part in relative.parts)
    for part in lowered_parts:
        if part == ".env" or part.startswith(".env."):
            return True
        if part in _SENSITIVE_SNAPSHOT_COMPONENTS:
            return True
    return len(lowered_parts) >= 2 and lowered_parts[-2:] == (".git", "config")


def _extract_snapshot_archive(archive_bytes: bytes, destination: Path) -> None:
    temporary = destination.with_name(destination.name + f".tmp-{uuid.uuid4().hex[:8]}")
    temporary.mkdir(parents=True, exist_ok=False)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > 100_000:
                raise RuntimeError("Review snapshot archive contains too many entries.")
            total_size = 0
            for member in members:
                relative = PurePosixPath(member.name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise RuntimeError(f"Unsafe review snapshot archive path: {member.name}")
                if _snapshot_member_is_sensitive(relative):
                    raise RuntimeError(
                        f"Sensitive path is not permitted in the review snapshot: {member.name}"
                    )
                if not (member.isdir() or member.isfile()):
                    raise RuntimeError(
                        f"Unsupported review snapshot archive entry type: {member.name}"
                    )
                total_size += max(0, int(member.size))
                if total_size > 2 * 1024 * 1024 * 1024:
                    raise RuntimeError("Review snapshot archive exceeds the 2 GiB safety limit.")
            archive.extractall(path=temporary, members=members)
        os.replace(temporary, destination)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        raise


def _create_review_snapshot(
    resolved_commits: dict[str, str],
    destination: Path,
    *,
    timeout: int,
) -> None:
    if destination.exists():
        raise RuntimeError(f"Review snapshot path already exists: {destination}")
    final_commit = resolved_commits[TARGET_COMMITS[-1]]
    rc, archive_bytes, stderr = _run_bytes(
        ["git", "archive", "--format=tar", final_commit],
        cwd=TAX_CALCULATOR_ROOT,
        timeout=timeout,
    )
    if rc != 0 or not archive_bytes:
        raise RuntimeError(
            f"Could not create immutable review snapshot for {final_commit}: {stderr.strip()}"
        )
    _extract_snapshot_archive(archive_bytes, destination)


def _output_path_is_writable(target: Path) -> bool:
    """Return whether the fixed output can be safely created or replaced.

    Existing regular files need write permission, not execute permission. Their
    parent directory still needs execute permission so an atomic replacement can
    traverse it. Directories and the nearest existing ancestor for a missing
    path require both write and execute permission.
    """
    if target.exists():
        if target.is_dir():
            return os.access(target, os.W_OK | os.X_OK)
        return os.access(target, os.W_OK) and os.access(target.parent, os.X_OK)

    probe = target.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return os.access(probe, os.W_OK | os.X_OK)


def _preflight() -> dict[str, str]:
    if pwd.getpwuid(os.getuid()).pw_name != HOST_USER:
        raise RuntimeError(f"Runner must execute as Linux user {HOST_USER!r}.")
    for path, label in ((AGY_BINARY, "agy binary"), (TAX_CALCULATOR_ROOT, "Tax Calculator repository")):
        if not path.exists():
            raise FileNotFoundError(f"Required {label} is missing: {path}")
    if not os.access(AGY_BINARY, os.X_OK):
        raise PermissionError(f"agy binary is not executable: {AGY_BINARY}")
    if not os.access(TAX_CALCULATOR_ROOT, os.R_OK | os.X_OK):
        raise PermissionError(f"Tax Calculator repository is not readable: {TAX_CALCULATOR_ROOT}")

    for target in (STATE_DIR, REPORT_PATH, ENVELOPE_PATH, SETTINGS_PATH):
        if not _output_path_is_writable(target):
            raise PermissionError(f"Runtime sandbox does not permit the fixed review output path: {target}")
    resolved: dict[str, str] = {}
    for commit in TARGET_COMMITS:
        rc, stdout, stderr = _run(
            ["git", "rev-parse", "--verify", f"{commit}^{{commit}}"],
            cwd=TAX_CALCULATOR_ROOT,
            timeout=30,
        )
        if rc != 0 or not stdout.strip():
            raise RuntimeError(f"Target commit {commit} is unavailable: {stderr.strip()}")
        resolved[commit] = stdout.strip()
    return resolved


def _collect_changed_test_commands(
    review_root: Path,
    resolved_commits: dict[str, str],
) -> list[list[str]]:
    commands: list[list[str]] = [["pytest", "-q", "-p", "no:cacheprovider"]]
    resolved_range = (
        f"{resolved_commits[TARGET_COMMITS[0]]}^.."
        f"{resolved_commits[TARGET_COMMITS[-1]]}"
    )
    rc, stdout, _stderr = _run(
        ["git", "diff", "--name-only", resolved_range],
        cwd=TAX_CALCULATOR_ROOT,
        timeout=60,
    )
    if rc == 0:
        seen: set[str] = set()
        for relative in stdout.splitlines():
            path = review_root / relative
            lowered = relative.lower()
            if not path.is_file():
                continue
            if relative.endswith(".py") and Path(relative).name.startswith("test_"):
                command = ["pytest", "-q", "-p", "no:cacheprovider", relative]
            elif relative.endswith(".mjs") and ("test" in lowered or "fixture" in lowered):
                command = ["node", relative]
            else:
                continue
            key = "\0".join(command)
            if key not in seen:
                seen.add(key)
                commands.append(command)
    for name in ("run-fixtures.mjs", "run-fixtures-v2.mjs"):
        for path in sorted(review_root.rglob(name)):
            relative = str(path.relative_to(review_root))
            command = ["node", relative]
            key = "\0".join(command)
            if not any("\0".join(existing) == key for existing in commands):
                commands.append(command)
    return commands


def _collect_review_inputs(
    resolved_commits: dict[str, str],
    input_dir: Path,
    review_root: Path,
    *,
    envelope_deadline: int,
    expected_session_id: str,
    expected_snapshot_hash: str,
) -> None:
    input_dir.mkdir(parents=True, exist_ok=True)

    def bounded_timeout(requested: int) -> int:
        _assert_authority(expected_session_id, expected_snapshot_hash)
        remaining = envelope_deadline - int(time.time())
        if remaining <= 0:
            raise subprocess.TimeoutExpired(cmd="review input collection", timeout=requested)
        return max(1, min(requested, remaining))
    baseline_rc, baseline_stdout, baseline_stderr = _run(
        ["git", "status", "--porcelain=v1"],
        cwd=TAX_CALCULATOR_ROOT,
        timeout=bounded_timeout(30),
    )
    _atomic_write(
        input_dir / "repository-baseline.txt",
        f"returncode={baseline_rc}\n\nSTDOUT\n{baseline_stdout}\n\nSTDERR\n{baseline_stderr}\n",
    )
    _atomic_write(input_dir / "resolved-commits.json", json.dumps(resolved_commits, indent=2) + "\n")
    _atomic_write(
        input_dir / "review-snapshot.json",
        json.dumps(
            {
                "source_repository": str(TAX_CALCULATOR_ROOT),
                "snapshot_root": str(review_root),
                "snapshot_commit": resolved_commits[TARGET_COMMITS[-1]],
                "source_worktree_may_contain_unrelated_changes": True,
                "tests_execute_only_in_snapshot": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )

    final_commit = resolved_commits[TARGET_COMMITS[-1]]
    resolved_range = (
        f"{resolved_commits[TARGET_COMMITS[0]]}^.."
        f"{resolved_commits[TARGET_COMMITS[-1]]}"
    )
    evidence_commands = [
        ["git", "log", "-3", "--format=fuller", "--decorate=short", final_commit],
        ["git", "diff", "--stat", resolved_range],
        ["git", "diff", resolved_range, "--"],
        ["git", "grep", "-n", "PASS=93", final_commit, "--"],
    ]
    sections: list[str] = []
    for argv in evidence_commands:
        rc, stdout, stderr = _run(
            argv,
            cwd=TAX_CALCULATOR_ROOT,
            timeout=bounded_timeout(180),
        )
        sections.append(
            f"## {' '.join(argv)}\nreturncode={rc}\n\nSTDOUT\n{stdout}\n\nSTDERR\n{stderr}\n"
        )
    for commit in TARGET_COMMITS:
        rc, stdout, stderr = _run(
            ["git", "show", "--stat", "--oneline", "--decorate=short", commit],
            cwd=TAX_CALCULATOR_ROOT,
            timeout=bounded_timeout(120),
        )
        sections.append(
            f"## git show {commit}\nreturncode={rc}\n\nSTDOUT\n{stdout}\n\nSTDERR\n{stderr}\n"
        )
    _atomic_write(input_dir / "git-evidence.md", "\n".join(sections))

    test_sections: list[str] = []
    for argv in _collect_changed_test_commands(review_root, resolved_commits):
        started = time.time()
        try:
            rc, stdout, stderr = _run(
                argv,
                cwd=review_root,
                timeout=bounded_timeout(WORKER_SLICE_TIMEOUT_SECONDS),
            )
        except subprocess.TimeoutExpired:
            rc, stdout, stderr = 124, "", "timed out"
        elapsed = round(time.time() - started, 3)
        test_sections.append(
            f"## {' '.join(argv)}\nreturncode={rc}\nelapsed_seconds={elapsed}\n\n"
            f"STDOUT\n{stdout}\n\nSTDERR\n{stderr}\n"
        )
    _atomic_write(input_dir / "test-results.md", "\n".join(test_sections))

    after_rc, after_stdout, after_stderr = _run(
        ["git", "status", "--porcelain=v1"],
        cwd=TAX_CALCULATOR_ROOT,
        timeout=bounded_timeout(30),
    )
    _atomic_write(
        input_dir / "repository-after-tests.txt",
        f"returncode={after_rc}\n\nSTDOUT\n{after_stdout}\n\nSTDERR\n{after_stderr}\n",
    )
    if (baseline_rc, baseline_stdout) != (after_rc, after_stdout):
        raise RuntimeError("Review test collection changed the Tax Calculator repository state.")


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


def _install_read_permissions(paths: list[Path], data: dict[str, Any], mode: int | None) -> None:
    permissions = data.setdefault("permissions", {})
    if not isinstance(permissions, dict):
        raise RuntimeError("Antigravity settings permissions field is not an object.")
    allow = permissions.setdefault("allow", [])
    ask = permissions.setdefault("ask", [])
    deny = permissions.setdefault("deny", [])
    if not isinstance(allow, list) or not isinstance(ask, list) or not isinstance(deny, list):
        raise RuntimeError("Antigravity settings permission lists are malformed.")
    if any(_is_read_file_rule(entry) for entry in deny):
        raise RuntimeError("Antigravity settings contain a read_file deny rule; refusing to weaken it.")
    permissions["ask"] = [entry for entry in ask if not _is_read_file_rule(entry)]
    for path in paths:
        rule = f"read_file({path})"
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


def _build_prompt(
    slice_index: int,
    checkpoint_paths: list[Path],
    input_dir: Path,
    review_root: Path,
) -> str:
    commits = ", ".join(TARGET_COMMITS)
    checkpoint_text = "\n".join(f"- {path}" for path in checkpoint_paths) or "- none (initial slice)"
    return f"""Act as an independent senior tax-calculation software reviewer.
This is bounded review slice {slice_index + 1}. Review the fixed Projections Calculator
commits {commits} using the immutable approved-commit snapshot rooted at {review_root}.
The live source repository at {TAX_CALCULATOR_ROOT} may contain unrelated work in progress;
do not inspect it directly. Use the supplied Git evidence under {input_dir} for commit history
and diffs, and use only {review_root} for source, fixtures, documentation and tests.

Read every file under {input_dir} first, including all prior slice checkpoints listed
below. Reconcile their completed work before continuing and never repeat completed
analysis merely to fill time.

Prior checkpoint files:
{checkpoint_text}

Inspect relevant source, fixtures, tests and documentation directly in the immutable
snapshot. Do not modify files and do not run commands. Independently challenge the
previous implementer's conclusions.

Verify all of the following:
1. JavaScript standard work-related deduction logic exactly matches the authoritative Python implementation.
2. FY2027-28 WATO is correct, non-refundable, based only on eligible labour income, and cannot benefit passive-income-only taxpayers.
3. Omitted labour-income data remains distinct from explicitly supplied zero labour income.
4. Client-side extrapolation does not fabricate deductions or offsets when labour-income data is unavailable.
5. Canonical Python-generated years expose the correct fields.
6. Updated fixture values are mathematically justified rather than edited only to satisfy tests.
7. CGT fixture changes are a legitimate consequence of corrected marginal-tax calculations.
8. The regression suite detects the former incorrect WATO formula.
9. Division 293, Division 296, MLS, TBC, household cash flow and unrelated authoritative calculations have not regressed.
10. Assess whether the reported PASS=93, KNOWN_FAILURE=0, BLOCKED=0, FAIL=0 audit is independently reproduced by the supplied evidence.

At the end of this slice, choose exactly one control status:
- COMPLETE when the full independent review is finished.
- CONTINUE when useful in-scope review work remains for another checkpointed slice.
- BLOCKED_MATERIAL_SCOPE_CHANGE when completion would require materially broader scope.
- BLOCKED_UNSAFE_ACTION when completion would require an unsafe action.
- FAILED when this slice cannot produce a useful checkpoint.

When COMPLETE, return the two final artifacts followed by the control line:
{_MARKDOWN_START}
A complete Markdown report with verdict ACCEPT, ACCEPT_WITH_FINDINGS, or REJECT;
findings ranked Critical, High, Medium and Low with file/line evidence; supplied test
commands/results; independent boundary calculations; missing tests; residual risks;
and a clear merge recommendation. Confirm source, credentials and services were not modified.
{_MARKDOWN_END}
{_YAML_START}
schema_version: 1
review:
  target_commits:
    - 9f4dfe8
    - fc9494b
    - 2deadfc
  verdict: ACCEPT | ACCEPT_WITH_FINDINGS | REJECT
  blocking_findings: <integer>
  non_blocking_findings: <integer>
  supplied_tests_passed: <boolean>
  reported_audit_reproduced: <boolean>
  source_modified: false
  credentials_accessed: false
  services_restarted: false
{_YAML_END}
HERMES_SLICE_STATUS: COMPLETE

When CONTINUE, return a concise durable checkpoint between these delimiters, then the
control line. The checkpoint must state criteria completed, findings/evidence already
established, unresolved criteria, and the exact next review actions:
---BEGIN_CHECKPOINT---
<checkpoint markdown>
---END_CHECKPOINT---
HERMES_SLICE_STATUS: CONTINUE

For either blocker or failure, explain the reason briefly and end with the corresponding
HERMES_SLICE_STATUS line. Return nothing after that control line.
"""


def _slice_control_status(stdout: str) -> str | None:
    candidates: list[str] = []
    try:
        candidates.extend(_collect_strings(json.loads(stdout)))
    except json.JSONDecodeError:
        pass
    candidates.append(stdout)
    joined = "\n".join(candidates)
    matches = re.findall(
        r"^\s*HERMES_SLICE_STATUS:\s*(COMPLETE|CONTINUE|BLOCKED_MATERIAL_SCOPE_CHANGE|BLOCKED_UNSAFE_ACTION|FAILED)\s*$",
        joined,
        flags=re.MULTILINE,
    )
    return matches[-1] if matches else None


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
        fallback = re.search(
            re.escape(_MARKDOWN_START) + r"\s*(.*?)\s*" + re.escape(_YAML_START),
            joined,
            flags=re.DOTALL,
        )
        if fallback:
            markdown_text = fallback.group(1)
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
    verdict_match = re.search(r"\b(ACCEPT_WITH_FINDINGS|ACCEPT|REJECT)\b", markdown)
    if not verdict_match:
        raise RuntimeError("Markdown report does not contain a valid verdict.")
    verdict = verdict_match.group(1)
    if f"verdict: {verdict}" not in yaml_text:
        raise RuntimeError("YAML verdict does not match the Markdown verdict.")
    for commit in TARGET_COMMITS:
        if commit not in markdown and commit not in yaml_text:
            raise RuntimeError(f"Evidence does not identify target commit {commit}.")
    if re.search(r"<[^>]+>", yaml_text):
        raise RuntimeError("YAML evidence still contains placeholder values.")
    for field in ("blocking_findings", "non_blocking_findings"):
        if not re.search(rf"^\s*{field}:\s*\d+\s*$", yaml_text, flags=re.MULTILINE):
            raise RuntimeError(f"YAML evidence is missing integer field {field}.")
    for field in (
        "supplied_tests_passed",
        "reported_audit_reproduced",
        "source_modified",
        "credentials_accessed",
        "services_restarted",
    ):
        if not re.search(rf"^\s*{field}:\s*(true|false)\s*$", yaml_text, flags=re.MULTILINE):
            raise RuntimeError(f"YAML evidence is missing boolean field {field}.")
    return verdict


def _terminate_process_group(pid: int) -> None:
    if pid <= 0:
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, OSError):
        return
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return
        time.sleep(0.2)
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        pass


def _run_agy_slice(
    *,
    prompt: str,
    review_root: Path,
    timeout: int,
    expected_session_id: str,
    expected_snapshot_hash: str,
) -> tuple[int, str, str]:
    proc = subprocess.Popen(
        [
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
        ],
        cwd=str(review_root),
        env=_sanitized_env(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        start_new_session=True,
        close_fds=True,
    )
    _write_state(agy_pid=proc.pid)
    started = time.monotonic()
    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                stdout, stderr = proc.communicate()
                return rc, op.redact_output(stdout), op.redact_output(stderr)
            state = _read_state()
            if state.get("status") == "cancel_requested":
                _terminate_process_group(proc.pid)
                raise RuntimeError("cancelled: operator requested cancellation")
            _assert_authority(expected_session_id, expected_snapshot_hash)
            if time.monotonic() - started >= timeout:
                _terminate_process_group(proc.pid)
                stdout, stderr = proc.communicate()
                return 124, op.redact_output(stdout), op.redact_output(stderr)
            time.sleep(2)
    except BaseException:
        if proc.poll() is None:
            _terminate_process_group(proc.pid)
        raise
    finally:
        _write_state(agy_pid=None)


def start(dry_run: bool = False) -> str:
    policy: op.OperatorPolicy | None = None
    try:
        policy = _require_authority(mutate=True, dry_run=dry_run)
        current = _read_state()
        if current.get("status") in {"queued", "running"} and _pid_alive(int(current.get("pid") or 0)):
            raise RuntimeError("The fixed Tax Calculator Antigravity review is already running.")
        resolved = _preflight()
        preview = {
            "success": True,
            "dry_run": bool(dry_run or policy.effective_dry_run(dry_run)),
            "route": "supervised-host-agy-tax-review",
            "source_repository": str(TAX_CALCULATOR_ROOT),
            "execution_source": "isolated-approved-commit-snapshot",
            "target_commits": list(TARGET_COMMITS),
            "resolved_commits": resolved,
            "model": MODEL,
            "total_task_window": OUTER_TIMEOUT_SECONDS,
            "worker_slice_timeout": WORKER_SLICE_TIMEOUT_SECONDS,
            "maximum_continuations": MAXIMUM_CONTINUATIONS,
            "resume_from_checkpoint": True,
            "stop_on": list(STOP_ON),
            "report": str(REPORT_PATH),
            "envelope": str(ENVELOPE_PATH),
            "session_id": policy.session_id,
        }
        if preview["dry_run"]:
            op.audit_record(
                tool="hermes_delegate_task",
                level=policy.level,
                apply_mode=policy.apply_mode,
                dry_run=True,
                success=True,
                changed=False,
                summary="validated fixed Tax Calculator Antigravity review",
                path=str(TAX_CALCULATOR_ROOT),
                extra={"target_commits": ",".join(TARGET_COMMITS)},
            )
            return _json(preview)
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        task_id = TASK_ID_PREFIX + uuid.uuid4().hex[:20]
        run_dir = RUNS_DIR / task_id
        input_dir = run_dir / "review-input"
        run_dir.mkdir(parents=True, exist_ok=False)
        for stale_artifact in (REPORT_PATH, ENVELOPE_PATH):
            try:
                stale_artifact.unlink()
            except FileNotFoundError:
                pass
        _atomic_write(STATE_PATH, "{}\n")
        started_at = int(time.time())
        state = _write_state(
            schema_version=1,
            task_id=task_id,
            job_kind="projections-calculator-independent-review",
            status="queued",
            pid=None,
            started_at=started_at,
            envelope_deadline=started_at + OUTER_TIMEOUT_SECONDS,
            worker_slice_timeout=WORKER_SLICE_TIMEOUT_SECONDS,
            maximum_continuations=MAXIMUM_CONTINUATIONS,
            continuation_count=0,
            resume_from_checkpoint=True,
            stop_on=list(STOP_ON),
            final_stop_reason=None,
            target_commits=list(TARGET_COMMITS),
            resolved_commits=resolved,
            run_dir=str(run_dir),
            input_dir=str(input_dir),
            report_path=str(REPORT_PATH),
            envelope_path=str(ENVELOPE_PATH),
            session_id=policy.session_id,
            snapshot_hash=policy.snapshot_hash,
        )
        with open(LAUNCH_LOG_PATH, "a", encoding="utf-8") as log:
            proc = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "worker", task_id],
                cwd=str(STATE_DIR.parent),
                env=_worker_env(),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=log,
                text=True,
                shell=False,
                start_new_session=True,
                close_fds=True,
            )
        state = _write_state(pid=proc.pid)
        op.audit_record(
            tool="hermes_delegate_task",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary="started fixed Tax Calculator Antigravity review",
            path=str(TAX_CALCULATOR_ROOT),
            job_id=task_id,
            extra={"pid": proc.pid, "target_commits": ",".join(TARGET_COMMITS)},
        )
        return _json({"success": True, **state})
    except Exception as exc:
        if policy is None:
            policy = op.OperatorPolicy()
        return _json(op.error_from_exception(
            exc,
            layer="operator",
            code="ANTIGRAVITY_TAX_REVIEW_START_ERROR",
            suggested_action=f"Use an approved {REQUIRED_TEMPLATE} Operator Session.",
        ))


def status(task_id: str | None = None) -> str:
    try:
        _require_status_authority()
        state = _read_state() or {"status": "not_started"}
        if task_id and state.get("task_id") not in {None, task_id}:
            raise FileNotFoundError(f"Tax Calculator Antigravity task not found: {task_id}")
        state["process_alive"] = _pid_alive(int(state.get("pid") or 0))
        state["agy_process_alive"] = _pid_alive(int(state.get("agy_pid") or 0))
        state["success"] = True
        state["report_exists"] = REPORT_PATH.exists()
        state["envelope_exists"] = ENVELOPE_PATH.exists()
        return _json(state)
    except Exception as exc:
        return _json(op.error_from_exception(
            exc,
            layer="operator",
            code="ANTIGRAVITY_TAX_REVIEW_STATUS_ERROR",
            suggested_action=f"Use an approved {REQUIRED_TEMPLATE} Operator Session and check the task id.",
        ))


def result(task_id: str) -> str:
    loaded = json.loads(status(task_id))
    if not loaded.get("success"):
        return _json(loaded)
    current = str(loaded.get("status") or "not_started")
    if current not in {"completed", "failed", "cancelled", "blocked"}:
        return _json({
            "success": True,
            "task_id": task_id,
            "status": current,
            "ready": False,
            "continuation_count": loaded.get("continuation_count", 0),
            "maximum_continuations": loaded.get("maximum_continuations", MAXIMUM_CONTINUATIONS),
            "envelope_deadline": loaded.get("envelope_deadline"),
            "latest_checkpoint": loaded.get("latest_checkpoint"),
        })
    report = REPORT_PATH.read_text(encoding="utf-8") if REPORT_PATH.is_file() else ""
    envelope = ENVELOPE_PATH.read_text(encoding="utf-8") if ENVELOPE_PATH.is_file() else ""
    return _json({
        "success": current == "completed",
        "task_id": task_id,
        "status": current,
        "ready": True,
        "verdict": loaded.get("verdict"),
        "report": report,
        "envelope": envelope,
        "error": loaded.get("error", ""),
        "conversation_id": loaded.get("conversation_id"),
        "continuation_count": loaded.get("continuation_count", 0),
        "maximum_continuations": loaded.get("maximum_continuations", MAXIMUM_CONTINUATIONS),
        "envelope_deadline": loaded.get("envelope_deadline"),
        "latest_checkpoint": loaded.get("latest_checkpoint"),
        "final_stop_reason": loaded.get("final_stop_reason"),
    })


def cancel(task_id: str, dry_run: bool = False) -> str:
    policy: op.OperatorPolicy | None = None
    try:
        policy = _require_authority(mutate=True, dry_run=dry_run)
        state = _read_state()
        if state.get("task_id") != task_id:
            raise FileNotFoundError(f"Tax Calculator Antigravity task not found: {task_id}")
        pid = int(state.get("pid") or 0)
        agy_pid = int(state.get("agy_pid") or 0)
        alive = _pid_alive(pid) or _pid_alive(agy_pid)
        effective_dry = policy.effective_dry_run(dry_run)
        if not alive:
            return _json({"success": True, "task_id": task_id, "changed": False, "status": state.get("status")})
        if effective_dry:
            return _json({"success": True, "task_id": task_id, "dry_run": True, "would_cancel": True})
        _write_state(status="cancel_requested", cancel_requested_at=int(time.time()))
        if agy_pid:
            _terminate_process_group(agy_pid)
        # Do not terminate the supervisor process. It must observe the durable
        # cancel request, mark the task cancelled, and restore the exact
        # pre-run Antigravity settings bytes in its finally block.
        return _json({"success": True, "task_id": task_id, "changed": True, "status": "cancel_requested"})
    except Exception as exc:
        return _json(op.error_from_exception(
            exc,
            layer="operator",
            code="ANTIGRAVITY_TAX_REVIEW_CANCEL_ERROR",
            suggested_action=f"Use an approved {REQUIRED_TEMPLATE} Operator Session and check the task id.",
        ))


def _worker(task_id: str) -> int:
    settings_original: bytes | None = None
    settings_mode: int | None = None
    restore_required = False
    try:
        state = _read_state()
        if state.get("task_id") != task_id:
            raise RuntimeError(f"Task state mismatch for {task_id}")
        expected_session_id = str(state.get("session_id") or "")
        expected_snapshot_hash = str(state.get("snapshot_hash") or "")
        envelope_deadline = int(state.get("envelope_deadline") or 0)
        run_dir = Path(str(state.get("run_dir") or ""))
        input_dir = Path(str(state.get("input_dir") or ""))
        review_root = run_dir / "approved-commit-snapshot"
        expected_runs_root = RUNS_DIR.resolve(strict=False)
        resolved_run_dir = run_dir.resolve(strict=False)
        resolved_input_dir = input_dir.resolve(strict=False)
        if (
            not run_dir.is_absolute()
            or not input_dir.is_absolute()
            or resolved_run_dir.parent != expected_runs_root
            or resolved_input_dir.parent != resolved_run_dir
        ):
            raise RuntimeError("Task state contains invalid run directory paths.")
        _assert_authority(expected_session_id, expected_snapshot_hash)
        _write_state(status="running", pid=os.getpid(), worker_started_at=int(time.time()))

        resolved = _preflight()
        remaining_for_snapshot = envelope_deadline - int(time.time())
        if remaining_for_snapshot <= 0:
            raise subprocess.TimeoutExpired(cmd="git archive", timeout=300)
        _create_review_snapshot(
            resolved,
            review_root,
            timeout=max(1, min(300, remaining_for_snapshot)),
        )
        _write_state(
            snapshot_root=str(review_root),
            snapshot_commit=resolved[TARGET_COMMITS[-1]],
        )
        _collect_review_inputs(
            resolved,
            input_dir,
            review_root,
            envelope_deadline=envelope_deadline,
            expected_session_id=expected_session_id,
            expected_snapshot_hash=expected_snapshot_hash,
        )
        _assert_authority(expected_session_id, expected_snapshot_hash)

        settings_original, settings_mode, settings_data = _load_settings()
        restore_required = True
        _install_read_permissions([review_root, input_dir], settings_data, settings_mode)

        checkpoint_dir = input_dir / "checkpoints"
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_paths: list[Path] = []
        continuation_count = int(state.get("continuation_count") or 0)
        previous_failure_signature: str | None = None
        consecutive_failure_count = 0
        slice_index = 0

        while True:
            current = _read_state()
            if current.get("status") == "cancel_requested":
                _write_state(
                    status="cancelled",
                    finished_at=int(time.time()),
                    final_stop_reason="cancelled",
                    exit_code=130,
                )
                return 130
            now = int(time.time())
            if not envelope_deadline or now >= envelope_deadline:
                _write_state(
                    status="failed",
                    finished_at=now,
                    final_stop_reason="envelope_deadline",
                    error="Eight-hour task envelope expired before completion.",
                    exit_code=124,
                )
                return 124
            _assert_authority(expected_session_id, expected_snapshot_hash)
            remaining = max(1, envelope_deadline - now)
            slice_timeout = min(WORKER_SLICE_TIMEOUT_SECONDS, remaining)
            if slice_timeout < 30:
                _write_state(
                    status="failed",
                    finished_at=now,
                    final_stop_reason="envelope_deadline",
                    error="Insufficient envelope time remained for another bounded slice.",
                    exit_code=124,
                )
                return 124

            _write_state(
                status="running",
                current_slice=slice_index + 1,
                continuation_count=continuation_count,
                latest_checkpoint=str(checkpoint_paths[-1]) if checkpoint_paths else None,
            )
            rc, stdout, stderr = _run_agy_slice(
                prompt=_build_prompt(slice_index, checkpoint_paths, input_dir, review_root),
                review_root=review_root,
                timeout=slice_timeout,
                expected_session_id=expected_session_id,
                expected_snapshot_hash=expected_snapshot_hash,
            )
            stdout_path = run_dir / f"agy-slice-{slice_index + 1:02d}-stdout.json"
            stderr_path = run_dir / f"agy-slice-{slice_index + 1:02d}-stderr.log"
            _atomic_write(stdout_path, stdout)
            _atomic_write(stderr_path, stderr)
            control = _slice_control_status(stdout)
            signature = hashlib.sha256(
                f"{rc}:{control}:{stderr[-2000:]}:{stdout[-2000:]}".encode("utf-8")
            ).hexdigest()

            if control == "COMPLETE" and rc == 0:
                markdown, yaml_text, conversation_id = _extract_artifacts(stdout)
                verdict = _validate_artifacts(markdown, yaml_text)
                _atomic_write(REPORT_PATH, markdown)
                _atomic_write(ENVELOPE_PATH, yaml_text)
                _write_state(
                    status="completed",
                    finished_at=int(time.time()),
                    exit_code=0,
                    verdict=verdict,
                    conversation_id=conversation_id,
                    final_stop_reason="completion",
                    continuation_count=continuation_count,
                    latest_checkpoint=str(checkpoint_paths[-1]) if checkpoint_paths else None,
                )
                return 0

            if control == "BLOCKED_MATERIAL_SCOPE_CHANGE":
                _write_state(
                    status="blocked",
                    finished_at=int(time.time()),
                    exit_code=2,
                    final_stop_reason="material_scope_change",
                    error=stdout[-4000:],
                )
                return 2
            if control == "BLOCKED_UNSAFE_ACTION":
                _write_state(
                    status="blocked",
                    finished_at=int(time.time()),
                    exit_code=2,
                    final_stop_reason="unsafe_action",
                    error=stdout[-4000:],
                )
                return 2

            checkpoint_path = checkpoint_dir / f"slice-{slice_index + 1:02d}.txt"
            _atomic_write(
                checkpoint_path,
                f"returncode={rc}\ncontrol={control or 'MISSING'}\n\nSTDOUT\n{stdout}\n\nSTDERR\n{stderr}\n",
            )
            checkpoint_paths.append(checkpoint_path)

            useful_continuation = control == "CONTINUE" and rc == 0
            if useful_continuation:
                previous_failure_signature = None
                consecutive_failure_count = 0
            else:
                consecutive_failure_count = (
                    consecutive_failure_count + 1
                    if previous_failure_signature == signature
                    else 1
                )
                previous_failure_signature = signature
                if consecutive_failure_count >= 2:
                    _write_state(
                        status="failed",
                        finished_at=int(time.time()),
                        exit_code=rc or 1,
                        final_stop_reason="repeated_failure",
                        error=(stderr or stdout)[-4000:],
                        continuation_count=continuation_count,
                        latest_checkpoint=str(checkpoint_path),
                    )
                    return rc or 1

            if continuation_count >= MAXIMUM_CONTINUATIONS:
                _write_state(
                    status="failed",
                    finished_at=int(time.time()),
                    exit_code=rc or 1,
                    final_stop_reason="continuation_limit",
                    error="Maximum automatic continuation count reached before completion.",
                    continuation_count=continuation_count,
                    latest_checkpoint=str(checkpoint_path),
                )
                return rc or 1

            continuation_count += 1
            slice_index += 1
            _write_state(
                status="awaiting_continuation",
                continuation_count=continuation_count,
                latest_checkpoint=str(checkpoint_path),
                previous_slice_returncode=rc,
                previous_slice_control=control,
            )
    except subprocess.TimeoutExpired as exc:
        _write_state(
            status="failed",
            finished_at=int(time.time()),
            error=str(exc),
            exit_code=124,
            final_stop_reason="envelope_deadline",
        )
        return 124
    except PermissionError as exc:
        _write_state(
            status="blocked",
            finished_at=int(time.time()),
            error=str(exc),
            exit_code=3,
            final_stop_reason="authority_expiry",
        )
        return 3
    except BaseException as exc:
        message = str(exc)
        if message.startswith("material_scope_change:"):
            status_value, reason, exit_code = "blocked", "material_scope_change", 2
        elif message.startswith("cancelled:"):
            status_value, reason, exit_code = "cancelled", "cancelled", 130
        else:
            status_value, reason, exit_code = "failed", "terminal_failure", 1
        _write_state(
            status=status_value,
            finished_at=int(time.time()),
            error=message,
            exit_code=exit_code,
            final_stop_reason=reason,
        )
        return exit_code
    finally:
        restore_error: Exception | None = None
        if restore_required:
            try:
                _restore_settings(settings_original, settings_mode)
            except Exception as exc:
                restore_error = exc
        _write_state(agy_pid=None)
        if restore_error is not None:
            _write_state(
                status="failed",
                finished_at=int(time.time()),
                error=f"Failed to restore Antigravity settings: {restore_error}",
                exit_code=1,
                final_stop_reason="settings_restore_failure",
            )
            raise RuntimeError("Failed to restore Antigravity settings") from restore_error


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) == 2 and args[0] == "worker" and re.fullmatch(r"agt_[0-9a-f]{20}", args[1]):
        return _worker(args[1])
    print("This module only supports the internal fixed Tax Calculator review worker.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
