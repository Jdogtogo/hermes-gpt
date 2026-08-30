"""FIRST_SAFE Prepare / Verify -- the ChatGPT-facing half of the governed
hermes-exec first-safe-model acceptance.

Why this module exists
----------------------
The previous design exposed one MCP tool that, although its only public input
was ``dry_run``, internally launched ``ssh.exe`` against ``hermes-exec`` and
piped a large inline Python program to a legacy privileged ``hermes`` runtime. Whatever
the input surface looked like, the tool WAS a remote-command-execution
mechanism, and a connector safety boundary is entitled to treat it as one.

This module removes execution from the connector path entirely and splits the
operation into three stages with a trust boundary in the middle:

1. ``hermes_first_safe_model_prepare`` (here, ChatGPT-facing) -- validates the
   human-approved authority and the Mission Control lease, then records ONE
   bounded, immutable execution intent locally. It performs no ssh, no
   subprocess, no model call and no config mutation.
2. ``first_safe_worker.py`` (trusted, host-side, NOT an MCP tool) -- the only
   component that talks to hermes-exec. It is started locally by the operator,
   re-derives every invariant from the immutable specification, and refuses any
   intent whose recorded spec hash does not match.
3. ``hermes_first_safe_model_verify`` (here, ChatGPT-facing) -- read-only.
   Returns allow-listed structured evidence and nothing else.

What Mission Control can and cannot say
---------------------------------------
Both tools take ZERO caller-controlled operational parameters. There is no
host, user, path, command, script, program text, model name, credential,
timeout or config-key argument anywhere in this surface. Prepare takes no
arguments at all; Verify takes at most an intent id, which is validated against
a strict opaque-token pattern and only ever used to look up a local record.
The intent record stores no command text -- it stores the spec hash of the
constants in ``operator_hermes_exec_model.py`` plus the approval binding.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

import operator_hermes_exec_model as spec
import operator_lease as lease
import operator_policy as op
import operator_sessions as sessions

PREPARE_TOOL_NAME = "hermes_first_safe_model_prepare"
VERIFY_TOOL_NAME = "hermes_first_safe_model_verify"

POLICY_TEMPLATE = spec.POLICY_TEMPLATE
REQUIRED_LEASE_OWNER = "chatgpt-mission-control"

# How long a prepared-but-unclaimed intent stays executable. A stale intent must
# not sit around waiting to be picked up long after the approving human moved on.
INTENT_TTL_SECONDS = 60 * 60

STATE_PREPARED = "prepared"
STATE_CLAIMED = "claimed"
STATE_COMPLETED = "completed"
STATE_FAILED = "failed"
TERMINAL_STATES = frozenset({STATE_COMPLETED, STATE_FAILED})

_INTENT_ID_RE = re.compile(r"^fsi_[A-Za-z0-9_-]{16,64}$")


def state_root() -> Path:
    """Directory holding FIRST_SAFE intent records.

    Follows the operator-session root when one is configured so tests and any
    isolated deployment stay isolated, exactly like the lease and session
    stores. Never caller-supplied.
    """
    override = os.environ.get("HERMES_GPT_FIRST_SAFE_ROOT", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return (
        Path.home()
        / ".hermes"
        / "worktrees"
        / "chatgpt-operator-scratch"
        / "operator-first-safe"
    )


def db_path() -> Path:
    return state_root() / "first_safe_intents.sqlite3"


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS first_safe_intents (
            intent_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            spec_hash TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            policy_template TEXT NOT NULL,
            session_id TEXT NOT NULL,
            logical_task_id TEXT NOT NULL,
            snapshot_hash TEXT NOT NULL,
            lease_owner TEXT NOT NULL,
            lease_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            claimed_at INTEGER,
            completed_at INTEGER,
            evidence_json TEXT,
            failure_reason TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_first_safe_intent_state
            ON first_safe_intents(state, created_at);
        """
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return connection


def _row_to_public(row: sqlite3.Row, *, include_evidence: bool = True) -> dict[str, Any]:
    """Project a stored intent onto its non-secret, bounded public shape."""
    public: dict[str, Any] = {
        "intent_id": str(row["intent_id"]),
        "state": str(row["state"]),
        "spec_hash": str(row["spec_hash"]),
        "policy_template": str(row["policy_template"]),
        "session_id": str(row["session_id"]),
        "logical_task_id": str(row["logical_task_id"]),
        "snapshot_hash": str(row["snapshot_hash"]),
        "lease_owner": str(row["lease_owner"]),
        "lease_id": str(row["lease_id"]),
        "created_at": int(row["created_at"]),
        "expires_at": int(row["expires_at"]),
        "claimed_at": int(row["claimed_at"]) if row["claimed_at"] is not None else None,
        "completed_at": int(row["completed_at"]) if row["completed_at"] is not None else None,
        "plan": json.loads(str(row["plan_json"])),
    }
    if row["failure_reason"]:
        public["failure_reason"] = str(row["failure_reason"])
    if include_evidence and row["evidence_json"]:
        public["evidence"] = json.loads(str(row["evidence_json"]))
    return public


# ---------------------------------------------------------------------------
# Authority gate (shared by Prepare and Verify)
# ---------------------------------------------------------------------------


def _require_first_safe_authority(*, for_mutation: bool) -> op.OperatorPolicy:
    """Require a live, human-approved FIRST_SAFE task-bound authority.

    Identical gate for both stages except that Verify does not require the
    mutation axis. Nothing here can be satisfied by a standing authority: the
    status must be a session/task-bound one AND the policy template must be
    exactly the FIRST_SAFE template, which is not standing-eligible.
    """
    policy = op.OperatorPolicy()
    policy.require_level("workspace")
    # "task_bound" is the Task-Bound Authority v2 spelling of a live approved
    # session and is strictly stronger than "active". "standing" is deliberately
    # absent: standing authority can never satisfy FIRST_SAFE.
    if policy.session_status not in {"active", "task_bound"} or not policy.session_id:
        raise PermissionError(
            "FIRST_SAFE requires a live human-approved Operator Session "
            f"(session state: {policy.session_status})."
        )
    if policy.policy_template != POLICY_TEMPLATE:
        raise PermissionError(f"FIRST_SAFE requires policy template {POLICY_TEMPLATE!r}.")
    if policy.authority_kind == "standing":
        raise PermissionError("FIRST_SAFE can never be satisfied by standing authority.")
    policy.require_verb("filesystem", "edit")
    policy.require_verb("tests", "run")
    policy.require_egress_host(spec.EGRESS_HOST)
    if for_mutation:
        policy.require_mutation(dry_run=False)
    return policy


def _require_mission_control_lease() -> dict[str, Any]:
    """Require the Mission Control coordination lease, held by Mission Control.

    Uses the narrow mission_control:lease_status capability path, so this check
    needs no filesystem:read and grants nothing.
    """
    status = lease.verify_lease(owner=REQUIRED_LEASE_OWNER, require_owner_match=True)
    if status.get("success") is not True or status.get("has_lease") is not True:
        raise PermissionError(
            "FIRST_SAFE requires a live Mission Control lease held by "
            f"{REQUIRED_LEASE_OWNER!r} (lease state: {status.get('error') or status.get('message')})."
        )
    if status.get("owner") != REQUIRED_LEASE_OWNER or status.get("owner_match") is not True:
        raise PermissionError("Mission Control lease is held by a different owner.")
    return status


# ---------------------------------------------------------------------------
# Stage 1 -- Prepare
# ---------------------------------------------------------------------------


def prepare_intent(*, now: int | None = None) -> dict[str, Any]:
    """Validate authority + lease and record one bounded execution intent.

    Idempotent: while a non-expired ``prepared`` intent exists for the same
    logical task and the same specification, that same intent is returned rather
    than a second one being minted.
    """
    current = int(time.time() if now is None else now)
    policy = _require_first_safe_authority(for_mutation=True)
    lease_status = _require_mission_control_lease()

    authority = sessions.resolve_effective_authority(now=current)
    if not authority.is_active or authority.logical_task_id is None:
        raise PermissionError("FIRST_SAFE requires live task-bound authority.")
    if authority.policy_template != POLICY_TEMPLATE:
        raise PermissionError(f"FIRST_SAFE requires policy template {POLICY_TEMPLATE!r}.")
    # The approved snapshot must still grant zero local write surface.
    if authority.writable_roots:
        raise PermissionError(
            "FIRST_SAFE authority must grant no writable roots; refusing to prepare."
        )

    digest = spec.spec_hash()
    plan = spec.fixed_plan()

    with _connect() as connection:
        connection.execute(
            "UPDATE first_safe_intents SET state=?, failure_reason=? "
            "WHERE state IN (?, ?) AND expires_at < ?",
            (STATE_FAILED, "intent expired before execution", STATE_PREPARED, STATE_CLAIMED, current),
        )
        existing = connection.execute(
            "SELECT * FROM first_safe_intents WHERE state=? AND logical_task_id=? "
            "AND spec_hash=? AND expires_at >= ? ORDER BY created_at DESC LIMIT 1",
            (STATE_PREPARED, authority.logical_task_id, digest, current),
        ).fetchone()
        if existing is not None:
            result = _row_to_public(existing)
            result["reused_existing_intent"] = True
            return result

        intent_id = f"fsi_{secrets.token_urlsafe(24)}"
        connection.execute(
            "INSERT INTO first_safe_intents(intent_id, state, spec_hash, plan_json, "
            "policy_template, session_id, logical_task_id, snapshot_hash, lease_owner, "
            "lease_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                intent_id, STATE_PREPARED, digest,
                json.dumps(plan, sort_keys=True),
                POLICY_TEMPLATE,
                str(authority.session_id),
                str(authority.logical_task_id),
                str(authority.snapshot_hash),
                REQUIRED_LEASE_OWNER,
                str(lease_status.get("lease_id") or ""),
                current, current + INTENT_TTL_SECONDS,
            ),
        )
        connection.commit()
        row = connection.execute(
            "SELECT * FROM first_safe_intents WHERE intent_id=?", (intent_id,)
        ).fetchone()

    op.audit_record(
        tool=PREPARE_TOOL_NAME, level=policy.level, apply_mode=policy.apply_mode,
        dry_run=False, success=True, changed=True,
        summary="recorded bounded FIRST_SAFE execution intent (no remote execution)",
        extra={
            "intent_id": intent_id, "spec_hash": digest,
            "logical_task_id": str(authority.logical_task_id),
            "policy_template": POLICY_TEMPLATE, "host": spec.EGRESS_HOST,
            "remote_execution_performed": False,
        },
    )
    result = _row_to_public(row)
    result["reused_existing_intent"] = False
    return result


# ---------------------------------------------------------------------------
# Stage 3 -- Verify
# ---------------------------------------------------------------------------


def verify_intent(intent_id: str | None = None) -> dict[str, Any]:
    """Read-only bounded evidence for a FIRST_SAFE intent."""
    _require_first_safe_authority(for_mutation=False)
    with _connect() as connection:
        if intent_id:
            token = str(intent_id).strip()
            if not _INTENT_ID_RE.match(token):
                raise ValueError("intent_id is not a valid FIRST_SAFE intent identifier.")
            row = connection.execute(
                "SELECT * FROM first_safe_intents WHERE intent_id=?", (token,)
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT * FROM first_safe_intents ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
    if row is None:
        return {"success": True, "found": False, "message": "No FIRST_SAFE intent exists."}
    public = _row_to_public(row)
    public["success"] = True
    public["found"] = True
    return public


# ---------------------------------------------------------------------------
# MCP tool wrappers
# ---------------------------------------------------------------------------


def hermes_first_safe_model_prepare() -> str:
    """Record the bounded FIRST_SAFE hermes-exec acceptance intent (no execution).

    Validates that a live, human-approved Tier 3 ``hermes-exec-first-safe-model``
    Operator Session is in force and that Mission Control holds the coordination
    lease, then records one immutable execution intent locally.

    This tool does NOT contact hermes-exec, run any command, change any
    configuration, or call any model. It takes no parameters: the operation is
    fully described by the locally registered policy template, so there is no
    host, user, path, command, script, model or credential input to supply.
    Execution is performed separately by the trusted host-side FIRST_SAFE
    worker, which the operator launches locally.

    Returns:
        JSON intent record: intent_id, state, spec_hash, approval binding and
        the fixed plan. No secrets, no transport details.
    """
    try:
        result = prepare_intent()
        result["success"] = True
        return json.dumps(result, indent=2)
    except Exception as exc:
        op.audit_record(
            tool=PREPARE_TOOL_NAME, level="unknown", apply_mode="unknown",
            dry_run=False, success=False, changed=False,
            error=op.redact_output(str(exc)),
            extra={"host": spec.EGRESS_HOST, "remote_execution_performed": False},
        )
        return json.dumps(
            op.error_from_exception(
                exc, layer="first_safe", code="FIRST_SAFE_PREPARE_ERROR",
                suggested_action=(
                    "Obtain a fresh local human approval for hermes-exec-first-safe-model "
                    "and ensure Mission Control holds the coordination lease. Do not bypass "
                    "the governed FIRST_SAFE workflow."
                ),
            ),
            indent=2,
        )


def hermes_first_safe_model_verify(intent_id: str | None = None) -> str:
    """Report bounded evidence for a FIRST_SAFE acceptance intent (read-only).

    Returns the intent's state and, once the trusted host-side worker has
    completed it, the structured acceptance evidence: selected model and
    selection reason, previous and resulting ``model.default``, provider and
    base URL, the versioned runtime free-only guard result, per-call cost/provider/API
    call counts for both acceptance calls, cooldown and rotation counts, Git
    cleanliness, and confirmation that only ``model.default`` changed.

    Never returns secrets, credentials, ssh or transport details, or raw remote
    logs. Changes no state.

    Args:
        intent_id: Optional FIRST_SAFE intent identifier. Defaults to the most
            recent intent.

    Returns:
        JSON evidence record.
    """
    try:
        return json.dumps(verify_intent(intent_id), indent=2)
    except Exception as exc:
        return json.dumps(
            op.error_from_exception(
                exc, layer="first_safe", code="FIRST_SAFE_VERIFY_ERROR",
                suggested_action="Provide a valid FIRST_SAFE intent id under the approved session.",
            ),
            indent=2,
        )
