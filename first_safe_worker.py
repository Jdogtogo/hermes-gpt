#!/usr/bin/env python3
"""Trusted host-side FIRST_SAFE worker -- the ONLY component that runs the
hermes-exec acceptance.

This file is deliberately NOT registered as an MCP tool and is never imported by
``server.py``. It is launched locally by the operator (or a local systemd unit),
so the remote operation is initiated by the trusted Hermes side rather than by a
connector tool call.

It accepts no operational input. There is no --host, --user, --command,
--script, --model, --key, --config or --python flag, and no way to pass program
text: the transport constants live here and the operation is defined entirely by
``operator_hermes_exec_model``. The only arguments are which locally-recorded
intent to consume and whether to actually execute.

What it does
------------
1. Claims exactly one ``prepared`` FIRST_SAFE intent from the local store.
2. Re-derives the specification hash and refuses the intent unless it matches,
   so a stored record can never be edited into a different operation.
3. Independently re-validates that the approving authority is still live,
   task-bound, the exact FIRST_SAFE template, and still grants zero writable
   roots -- it does not trust the record's claims about approval.
4. Runs the fixed remote program and applies every acceptance invariant.
5. Stores allow-listed evidence only.

Usage:
    python first_safe_worker.py --dry-run          # default; no remote contact
    python first_safe_worker.py --execute          # performs the real acceptance
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import operator_first_safe as intents
import operator_hermes_exec_model as spec
import operator_policy as op
import operator_sessions as sessions

WORKER_NAME = "first_safe_worker"
# The trusted worker is part of the chatgpt-operator deployment and must
# revalidate authority against that deployment's canonical session store,
# regardless of the ambient shell/Codex environment it was launched from.
# Tests may monkeypatch this fixed deployment constant to an isolated root.
WORKER_SESSION_ROOT = Path.home() / ".hermes" / "operator-sessions" / "chatgpt-operator"
EXPECTED_SPEC_PATH = Path(__file__).resolve().with_name("operator_hermes_exec_model.py")


def _assert_fixed_spec_origin() -> None:
    """Require the worker to use the spec module beside this trusted worker."""
    observed = Path(str(getattr(spec, "__file__", ""))).resolve()
    if observed != EXPECTED_SPEC_PATH:
        raise RuntimeError(
            f"FIRST_SAFE spec import drift: expected {EXPECTED_SPEC_PATH}, observed {observed}"
        )


# Transport constants. Fixed here, in the trusted component, and nowhere on the
# connector-facing import path. None of these is ever caller-supplied.
VM_NAME = "hermes-exec"
SSH_USER = "jfroh"
SSH_BINARY = "/mnt/c/Windows/System32/OpenSSH/ssh.exe"
REMOTE_PYTHON = "/home/jfroh/.hermes/hermes-agent/venv/bin/python3"
REMOTE_TIMEOUT_SECONDS = 900


def _resolve_target_ipv4() -> str:
    """Return the fixed private IPv4 verified reachable from the Windows host."""
    return "172.29.176.132"


def _ssh_argv() -> list[str]:
    """The one fixed remote invocation. No component of this is parameterised."""
    ssh_target = f"{SSH_USER}@{_resolve_target_ipv4()}"
    return [
        SSH_BINARY, "-T",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "ConnectionAttempts=1",
        ssh_target,
        REMOTE_PYTHON, "-",
    ]


def _run_fixed_remote() -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            _ssh_argv(), input=spec.REMOTE_PROGRAM, capture_output=True,
            text=True, timeout=REMOTE_TIMEOUT_SECONDS, shell=False,
        )
        return (
            completed.returncode,
            completed.stdout[-spec.MAX_OUTPUT:],
            completed.stderr[-spec.MAX_OUTPUT:],
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        err = exc.stderr if isinstance(exc.stderr, str) else ""
        return 124, out[-spec.MAX_OUTPUT:], (err or f"timeout after {REMOTE_TIMEOUT_SECONDS}s")[-spec.MAX_OUTPUT:]
    except FileNotFoundError as exc:
        return 127, "", str(exc)[-spec.MAX_OUTPUT:]


def _revalidate_authority(row: Any, *, now: int) -> None:
    """Re-derive the approval independently of the stored record.

    The intent record is a work order, not a credential. Every authority claim
    it carries is checked again here against the live chatgpt-operator session
    store, so editing a record or launching the worker from a differently
    configured shell cannot manufacture or hide authority.
    """
    previous_root = os.environ.get(sessions.SESSION_ROOT_ENV)
    previous_active = os.environ.get(sessions.ACTIVE_SESSION_ID_ENV)
    os.environ[sessions.SESSION_ROOT_ENV] = str(WORKER_SESSION_ROOT)
    os.environ.pop(sessions.ACTIVE_SESSION_ID_ENV, None)
    try:
        authority = sessions.resolve_effective_authority(now=now)
    finally:
        if previous_root is None:
            os.environ.pop(sessions.SESSION_ROOT_ENV, None)
        else:
            os.environ[sessions.SESSION_ROOT_ENV] = previous_root
        if previous_active is None:
            os.environ.pop(sessions.ACTIVE_SESSION_ID_ENV, None)
        else:
            os.environ[sessions.ACTIVE_SESSION_ID_ENV] = previous_active
    if not authority.is_active:
        raise PermissionError(
            f"FIRST_SAFE authority is not live (state: {authority.status}); refusing to execute."
        )
    if authority.policy_template != intents.POLICY_TEMPLATE:
        raise PermissionError(
            f"live authority is {authority.policy_template!r}, not {intents.POLICY_TEMPLATE!r}."
        )
    if authority.authority_kind == "standing":
        raise PermissionError("FIRST_SAFE can never be satisfied by standing authority.")
    if authority.writable_roots:
        raise PermissionError("FIRST_SAFE authority must grant no writable roots.")
    if str(row["session_id"]) != str(authority.session_id):
        raise PermissionError(
            "intent was prepared under a different Operator Session than the live one."
        )
    if str(row["logical_task_id"]) != str(authority.logical_task_id):
        raise PermissionError(
            "intent was prepared under a different logical task than the live authority."
        )
    if str(row["snapshot_hash"]) != str(authority.snapshot_hash):
        raise PermissionError(
            "approved policy snapshot changed since the intent was prepared; re-approve."
        )


def claim_and_run(*, execute: bool, intent_id: str | None = None, now: int | None = None) -> dict[str, Any]:
    current = int(time.time() if now is None else now)
    try:
        _assert_fixed_spec_origin()
    except RuntimeError as exc:
        return {"success": False, "error": "SPEC_ORIGIN_MISMATCH", "detail": str(exc)}
    digest = spec.spec_hash()

    with intents._connect() as connection:
        if intent_id:
            row = connection.execute(
                "SELECT * FROM first_safe_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT * FROM first_safe_intents WHERE state=? ORDER BY created_at LIMIT 1",
                (intents.STATE_PREPARED,),
            ).fetchone()
        if row is None:
            return {"success": False, "error": "NO_PREPARED_FIRST_SAFE_INTENT"}
        if str(row["state"]) != intents.STATE_PREPARED:
            return {
                "success": False, "error": "INTENT_NOT_PREPARED",
                "state": str(row["state"]), "intent_id": str(row["intent_id"]),
            }
        if int(row["expires_at"]) < current:
            connection.execute(
                "UPDATE first_safe_intents SET state=?, failure_reason=? WHERE intent_id=?",
                (intents.STATE_FAILED, "intent expired before execution", str(row["intent_id"])),
            )
            connection.commit()
            return {"success": False, "error": "INTENT_EXPIRED", "intent_id": str(row["intent_id"])}
        # A record whose spec hash does not match the current specification
        # describes a different operation than the one this worker implements.
        if str(row["spec_hash"]) != digest:
            connection.execute(
                "UPDATE first_safe_intents SET state=?, failure_reason=? WHERE intent_id=?",
                (intents.STATE_FAILED, "specification hash mismatch", str(row["intent_id"])),
            )
            connection.commit()
            return {"success": False, "error": "SPEC_HASH_MISMATCH", "intent_id": str(row["intent_id"])}
        if str(row["policy_template"]) != intents.POLICY_TEMPLATE:
            return {"success": False, "error": "WRONG_POLICY_TEMPLATE", "intent_id": str(row["intent_id"])}
        if str(row["lease_owner"]) != intents.REQUIRED_LEASE_OWNER:
            return {"success": False, "error": "WRONG_LEASE_OWNER", "intent_id": str(row["intent_id"])}

        target_id = str(row["intent_id"])
        try:
            _revalidate_authority(row, now=current)
        except PermissionError as exc:
            connection.execute(
                "UPDATE first_safe_intents SET state=?, failure_reason=? WHERE intent_id=?",
                (intents.STATE_FAILED, str(exc), target_id),
            )
            connection.commit()
            return {"success": False, "error": "AUTHORITY_REVALIDATION_FAILED",
                    "detail": str(exc), "intent_id": target_id}

        if not execute:
            return {
                "success": True, "dry_run": True, "intent_id": target_id,
                "would_execute": True, "spec_hash": digest,
                "plan": json.loads(str(row["plan_json"])),
                "remote_contact_made": False,
            }

        # Claim exclusively: the UPDATE only succeeds from 'prepared', so two
        # concurrent workers cannot both run the acceptance.
        claimed = connection.execute(
            "UPDATE first_safe_intents SET state=?, claimed_at=? WHERE intent_id=? AND state=?",
            (intents.STATE_CLAIMED, current, target_id, intents.STATE_PREPARED),
        ).rowcount
        connection.commit()
        if not claimed:
            return {"success": False, "error": "INTENT_ALREADY_CLAIMED", "intent_id": target_id}

    returncode, raw_out, raw_err = _run_fixed_remote()
    stdout = op.redact_output(raw_out)
    stderr = op.redact_output(raw_err)
    try:
        if returncode != 0 and not stdout:
            raise RuntimeError(f"remote acceptance returned code {returncode}")
        payload = spec.extract_result(stdout)
        spec.validate_acceptance_payload(payload)
        evidence = spec.bounded_evidence(payload)
    except Exception as exc:
        reason = op.redact_output(str(exc))
        with intents._connect() as connection:
            connection.execute(
                "UPDATE first_safe_intents SET state=?, completed_at=?, failure_reason=? "
                "WHERE intent_id=?",
                (intents.STATE_FAILED, int(time.time()), reason, target_id),
            )
            connection.commit()
        op.audit_record(
            tool=WORKER_NAME, level="workspace", apply_mode="direct", dry_run=False,
            success=False, changed=False, error=reason,
            extra={"intent_id": target_id, "host": spec.EGRESS_HOST},
        )
        return {"success": False, "error": "ACCEPTANCE_FAILED", "detail": reason,
                "intent_id": target_id}

    with intents._connect() as connection:
        connection.execute(
            "UPDATE first_safe_intents SET state=?, completed_at=?, evidence_json=? "
            "WHERE intent_id=?",
            (intents.STATE_COMPLETED, int(time.time()), json.dumps(evidence, sort_keys=True), target_id),
        )
        connection.commit()
    op.audit_record(
        tool=WORKER_NAME, level="workspace", apply_mode="direct", dry_run=False,
        success=True, changed=bool(evidence.get("changed")),
        summary=f"FIRST_SAFE acceptance passed with {evidence.get('selected_model')}",
        extra={
            "intent_id": target_id, "host": spec.EGRESS_HOST,
            "selected_model": str(evidence.get("selected_model")),
            "guard_kind": spec.GUARD_KIND,
            "guard_required_checks": list(spec.REQUIRED_GUARD_CHECKS),
            "acceptance_calls": 2,
            "estimated_cost_usd": 0.0, "cooldown_rotation_events": 0,
        },
    )
    return {"success": True, "dry_run": False, "intent_id": target_id, "evidence": evidence}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Trusted host-side FIRST_SAFE worker. Consumes one locally prepared, "
            "human-approved FIRST_SAFE intent and performs the fixed hermes-exec "
            "acceptance. Accepts no host, command, script, model or credential input."
        )
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Perform the real acceptance. Without this the worker only validates.",
    )
    parser.add_argument(
        "--intent-id", default=None,
        help="Consume this specific prepared intent instead of the oldest one.",
    )
    args = parser.parse_args(argv)
    result = claim_and_run(execute=bool(args.execute), intent_id=args.intent_id)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
