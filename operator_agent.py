"""Structured, path-gated, non-interactive Hermes Agent execution."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Callable

import operator_policy as op


HERMES_BIN = str(Path.home() / ".local" / "bin" / "hermes")
AGENT_MODES = frozenset({"plan", "read_only", "apply"})
READ_ONLY_TOOLSET = "file_read_only"
APPLY_TOOLSETS = ("terminal", "file", "skills", "todo")
FILE_READ_SAFE_ROOT_ENV = "HERMES_FILE_READ_SAFE_ROOT"
MAX_PROMPT_BYTES = 65536
MAX_OUTPUT_CHARS = 4096
MAX_TIMEOUT_SECONDS = 3600

_MODE_PREFIXES = {
    "plan": (
        "Inspect files only within the supplied working directory and produce "
        "a plan. Do not modify files, configuration, services, external "
        "systems, or persistent state."
    ),
    "read_only": (
        "Perform read-only inspection only within the supplied working "
        "directory. Do not access paths outside it. Do not modify files, "
        "configuration, services, external systems, or persistent state."
    ),
    "apply": (
        "Execute the requested task within the supplied working directory. "
        "Do not access paths outside it. Report changes and verification."
    ),
}


def _fingerprint(text: str) -> tuple[int, str]:
    data = text.encode("utf-8", errors="replace")
    return len(data), hashlib.sha256(data).hexdigest()


def _safe_output(text: str) -> str:
    redacted = op.redact_output(text or "")
    if len(redacted) <= MAX_OUTPUT_CHARS:
        return redacted
    omitted = len(redacted) - MAX_OUTPUT_CHARS
    return redacted[:MAX_OUTPUT_CHARS] + f"\n... [truncated {omitted} chars]"


def _output_summary(text: str) -> dict[str, object]:
    length, digest = _fingerprint(text or "")
    return {
        "captured_bytes": length,
        "sha256": digest,
        "truncated": "... [truncated " in (text or ""),
    }


def _resolve_workdir(workdir: str | None) -> Path:
    if workdir is None or not str(workdir).strip():
        raise ValueError("workdir is required.")
    candidate = Path(workdir).expanduser()
    if not candidate.is_absolute():
        raise ValueError("workdir must be an absolute path.")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise NotADirectoryError(f"workdir is not a directory: {resolved}")
    return resolved


def _build_argv(
    *,
    prompt: str,
    mode: str,
    profile: str,
    resolved_workdir: Path,
    max_turns: int,
    allow_web: bool,
) -> list[str]:
    argv = [HERMES_BIN]
    if profile != "default":
        argv.extend(["--profile", profile])

    argv.extend(
        [
            "chat",
            "-Q",
            "--source",
            "tool",
            "--max-turns",
            str(max_turns),
        ]
    )

    if mode in {"plan", "read_only"}:
        toolsets = [READ_ONLY_TOOLSET]
    else:
        toolsets = list(APPLY_TOOLSETS)
    if allow_web:
        toolsets.append("web")

    argv.extend(["-t", ",".join(toolsets)])
    effective_prompt = (
        f"{_MODE_PREFIXES[mode]}\n\n"
        f"Allowed working directory: {resolved_workdir}\n\n"
        f"User task:\n{prompt}"
    )
    argv.extend(["-q", effective_prompt])
    return argv


def _redacted_argv(argv: list[str], prompt: str) -> list[str]:
    prompt_len, prompt_sha = _fingerprint(prompt)
    return [
        *argv[:-1],
        f"<prompt:{prompt_len} bytes sha256:{prompt_sha}>",
    ]


def hermes_agent_run(
    prompt: str,
    mode: str = "read_only",
    profile: str = "default",
    workdir: str | None = None,
    max_turns: int = 30,
    timeout: int = 300,
    allow_web: bool = False,
    apply: bool = False,
    *,
    transport: str = "unknown",
    hermes_root: Path | None = None,
    runner: Callable[..., tuple[int, str, str]] | None = None,
) -> str:
    """Run one Hermes task using a fixed argv and no caller-supplied command."""
    audit_mode = str(mode)[:32]
    audit_profile = str(profile)[:64]
    audit_workdir = str(workdir or "")[:500]

    try:
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("prompt is required.")
        prompt_len, prompt_sha = _fingerprint(prompt)
        if prompt_len > MAX_PROMPT_BYTES:
            raise ValueError(
                f"prompt exceeds the {MAX_PROMPT_BYTES}-byte limit."
            )

        normalized_mode = str(mode).strip().lower()
        if normalized_mode not in AGENT_MODES:
            raise ValueError("mode must be one of: plan, read_only, apply.")
        if not isinstance(allow_web, bool):
            raise ValueError("allow_web must be a boolean.")
        if not isinstance(apply, bool):
            raise ValueError("apply must be a boolean.")
        if apply and normalized_mode != "apply":
            raise ValueError("apply=true is only valid when mode='apply'.")

        turns = int(max_turns)
        if not 1 <= turns <= 100:
            raise ValueError("max_turns must be between 1 and 100.")
        capped_timeout = int(timeout)
        if not 1 <= capped_timeout <= MAX_TIMEOUT_SECONDS:
            raise ValueError(
                f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds."
            )

        policy = op.OperatorPolicy()
        policy.require_enabled()
        canonical_profile = op.validate_profile_name(profile)
        policy.require_profile(canonical_profile, hermes_root)
        resolved_workdir = _resolve_workdir(workdir)

        # Every mode exposes local file access. Fail closed unless the exact
        # working directory passes the operator allowed/denied path policy.
        policy.require_workspace_path(str(resolved_workdir))

        argv = _build_argv(
            prompt=prompt,
            mode=normalized_mode,
            profile=canonical_profile,
            resolved_workdir=resolved_workdir,
            max_turns=turns,
            allow_web=allow_web,
        )

        if normalized_mode == "apply":
            policy.require_owner(dry_run=not apply)

            if not apply:
                op.audit_record(
                    tool="hermes_agent_run",
                    level=policy.level,
                    apply_mode=policy.apply_mode,
                    dry_run=True,
                    success=True,
                    changed=False,
                    summary="apply-mode preview",
                    profile=canonical_profile,
                    prompt=prompt,
                    extra={
                        "mode": normalized_mode,
                        "transport": transport,
                        "allow_web": allow_web,
                        "workdir": str(resolved_workdir),
                        "max_turns": turns,
                        "timeout": capped_timeout,
                        "returncode": None,
                    },
                )
                return json.dumps(
                    {
                        "success": True,
                        "dry_run": True,
                        "mode": normalized_mode,
                        "profile": canonical_profile,
                        "workdir": str(resolved_workdir),
                        "allow_web": allow_web,
                        "prompt_len": prompt_len,
                        "prompt_sha256": prompt_sha,
                        "plan": {
                            "argv": _redacted_argv(argv, prompt),
                            "shell": False,
                            "timeout": capped_timeout,
                            "max_turns": turns,
                            "yolo": False,
                        },
                    },
                    indent=2,
                )

            if transport != "stdio":
                raise PermissionError(
                    "apply mode is disabled over HTTP, SSE, unknown, and "
                    "unauthenticated tunnel transports. Use a local stdio MCP "
                    "client. No authenticated remote transport is implemented."
                )

            policy.require_mutation(dry_run=False)

        child_env = os.environ.copy()
        child_env[FILE_READ_SAFE_ROOT_ENV] = str(resolved_workdir)

        run_fn = runner or op.run_argv
        returncode, stdout, stderr = run_fn(
            argv,
            timeout=capped_timeout,
            workdir=str(resolved_workdir),
            env=child_env,
        )
        safe_stdout = _safe_output(stdout)
        safe_stderr = _safe_output(stderr)
        timed_out = returncode == 124

        op.audit_record(
            tool="hermes_agent_run",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=returncode == 0,
            changed=False,
            summary=f"agent run completed rc={returncode}",
            error=(
                "Hermes Agent timed out."
                if timed_out
                else (
                    "Hermes Agent returned a non-zero status."
                    if returncode != 0
                    else ""
                )
            ),
            profile=canonical_profile,
            prompt=prompt,
            extra={
                "mode": normalized_mode,
                "transport": transport,
                "allow_web": allow_web,
                "workdir": str(resolved_workdir),
                "max_turns": turns,
                "timeout": capped_timeout,
                "returncode": returncode,
                "timed_out": timed_out,
                "mutation_possible": normalized_mode == "apply",
                "stdout_summary": _output_summary(safe_stdout),
                "stderr_summary": _output_summary(safe_stderr),
            },
        )

        return json.dumps(
            {
                "success": returncode == 0,
                "dry_run": False,
                "mode": normalized_mode,
                "profile": canonical_profile,
                "workdir": str(resolved_workdir),
                "allow_web": allow_web,
                "max_turns": turns,
                "timeout": capped_timeout,
                "timed_out": timed_out,
                "returncode": returncode,
                "prompt_len": prompt_len,
                "prompt_sha256": prompt_sha,
                "stdout": safe_stdout,
                "stderr": safe_stderr,
            },
            indent=2,
        )
    except Exception as exc:
        op.audit_record(
            tool="hermes_agent_run",
            level="owner" if audit_mode == "apply" else "read_only",
            apply_mode="unknown",
            dry_run=audit_mode == "apply" and not bool(apply),
            success=False,
            changed=False,
            error=str(exc),
            profile=audit_profile,
            prompt=prompt if isinstance(prompt, str) else None,
            extra={
                "mode": audit_mode,
                "transport": transport,
                "workdir": audit_workdir,
                "returncode": None,
            },
        )
        return json.dumps(
            op.error_from_exception(
                exc,
                layer="operator",
                code="AGENT_RUN_ERROR",
                suggested_action=(
                    "Configure an explicit allowed workdir and check mode, "
                    "profile, operator policy, transport, and apply authorization."
                ),
            ),
            indent=2,
        )
