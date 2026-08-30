"""Governed Prepare/Verify surface for pre-live FIRST_SAFE profile provisioning.

This module never contacts hermes-exec. Prepare records one immutable intent under
an exact Tier-3 policy and Mission Control lease. A separate trusted host worker
consumes the intent. Verify exposes bounded non-secret evidence only.
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

PREPARE_TOOL_NAME = "hermes_first_safe_provision_prepare"
EXECUTE_TOOL_NAME = "hermes_first_safe_provision_execute"
VERIFY_TOOL_NAME = "hermes_first_safe_provision_verify"
POLICY_TEMPLATE = "hermes-exec-first-safe-provision"
REQUIRED_LEASE_OWNER = "chatgpt-mission-control"
INTENT_TTL_SECONDS = 60 * 60
STATE_PREPARED = "prepared"
STATE_CLAIMED = "claimed"
STATE_COMPLETED = "completed"
STATE_FAILED = "failed"
_INTENT_ID_RE = re.compile(r"^fsp_[A-Za-z0-9_-]{16,64}$")


def fixed_plan() -> dict[str, Any]:
    return {
        "operation": "first_safe_static_profile_provision",
        "egress_host": spec.EGRESS_HOST,
        "remote_runtime_user": spec.REMOTE_RUNTIME_USER,
        "remote_linux_home": spec.REMOTE_LINUX_HOME,
        "hermes_root": spec.REMOTE_HERMES_ROOT,
        "profile": spec.REMOTE_PROFILE,
        "profile_home": spec.REMOTE_PROFILE_HOME,
        "config_path": spec.REMOTE_CONFIG,
        "provider": spec.APPROVED_PROVIDER,
        "base_url": spec.OPENROUTER_BASE_URL,
        "approved_model": spec.APPROVED_MODEL,
        "credential_contract": "target profile-local .env must pre-exist privately with OPENROUTER_API_KEY; worker never reads or returns its value",
        "live_model_calls": 0,
        "service_changes": False,
        "git_changes": False,
        "cloudflare_changes": False,
        "cron_changes": False,
        "cutover": False,
    }


def plan_hash() -> str:
    import hashlib
    return hashlib.sha256(json.dumps(fixed_plan(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def state_root() -> Path:
    override = os.environ.get("HERMES_GPT_FIRST_SAFE_PROVISION_ROOT", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".hermes" / "worktrees" / "chatgpt-operator-scratch" / "operator-first-safe-provision"


def db_path() -> Path:
    return state_root() / "provision_intents.sqlite3"


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    c = sqlite3.connect(path, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=FULL")
    c.executescript("""
      CREATE TABLE IF NOT EXISTS provision_intents (
        intent_id TEXT PRIMARY KEY, state TEXT NOT NULL, plan_hash TEXT NOT NULL,
        plan_json TEXT NOT NULL, policy_template TEXT NOT NULL, session_id TEXT NOT NULL,
        logical_task_id TEXT NOT NULL, snapshot_hash TEXT NOT NULL, lease_owner TEXT NOT NULL,
        lease_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        claimed_at INTEGER, completed_at INTEGER, evidence_json TEXT, failure_reason TEXT
      );
    """)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return c


def _public(row: sqlite3.Row) -> dict[str, Any]:
    out = {k: row[k] for k in (
        "intent_id", "state", "plan_hash", "policy_template", "session_id",
        "logical_task_id", "snapshot_hash", "lease_owner", "lease_id",
        "created_at", "expires_at", "claimed_at", "completed_at"
    )}
    out["plan"] = json.loads(row["plan_json"])
    if row["failure_reason"]:
        out["failure_reason"] = row["failure_reason"]
    if row["evidence_json"]:
        out["evidence"] = json.loads(row["evidence_json"])
    return out


def _require_authority(*, mutation: bool) -> op.OperatorPolicy:
    policy = op.OperatorPolicy()
    policy.require_level("workspace")
    if policy.session_status not in {"active", "task_bound"} or not policy.session_id:
        raise PermissionError("FIRST_SAFE provisioning requires a live human-approved Operator Session.")
    if policy.policy_template != POLICY_TEMPLATE:
        raise PermissionError(f"FIRST_SAFE provisioning requires policy template {POLICY_TEMPLATE!r}.")
    if policy.authority_kind == "standing":
        raise PermissionError("FIRST_SAFE provisioning cannot use standing authority.")
    policy.require_verb("filesystem", "edit")
    policy.require_verb("tests", "run")
    policy.require_egress_host(spec.EGRESS_HOST)
    if mutation:
        policy.require_mutation(dry_run=False)
    return policy


def _require_lease() -> dict[str, Any]:
    status = lease.verify_lease(owner=REQUIRED_LEASE_OWNER, require_owner_match=True)
    if status.get("success") is not True or status.get("has_lease") is not True or status.get("owner_match") is not True:
        raise PermissionError("FIRST_SAFE provisioning requires the Mission Control lease held by chatgpt-mission-control.")
    return status


def prepare_intent(*, now: int | None = None) -> dict[str, Any]:
    current = int(time.time() if now is None else now)
    policy = _require_authority(mutation=True)
    lease_status = _require_lease()
    authority = sessions.resolve_effective_authority(now=current)
    if not authority.is_active or authority.logical_task_id is None:
        raise PermissionError("FIRST_SAFE provisioning requires task-bound authority.")
    if authority.policy_template != POLICY_TEMPLATE:
        raise PermissionError("Provisioning authority mismatch.")
    if authority.writable_roots:
        raise PermissionError("Provisioning connector authority must grant zero local writable roots.")
    digest = plan_hash()
    plan = fixed_plan()
    with _connect() as c:
        c.execute("UPDATE provision_intents SET state=?, failure_reason=? WHERE state IN (?,?) AND expires_at < ?",
                  (STATE_FAILED, "intent expired before execution", STATE_PREPARED, STATE_CLAIMED, current))
        row = c.execute("SELECT * FROM provision_intents WHERE state=? AND logical_task_id=? AND plan_hash=? AND expires_at>=? ORDER BY created_at DESC LIMIT 1",
                        (STATE_PREPARED, authority.logical_task_id, digest, current)).fetchone()
        if row is None:
            intent_id = f"fsp_{secrets.token_urlsafe(24)}"
            c.execute("INSERT INTO provision_intents(intent_id,state,plan_hash,plan_json,policy_template,session_id,logical_task_id,snapshot_hash,lease_owner,lease_id,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                      (intent_id, STATE_PREPARED, digest, json.dumps(plan, sort_keys=True), POLICY_TEMPLATE,
                       str(authority.session_id), str(authority.logical_task_id), str(authority.snapshot_hash),
                       REQUIRED_LEASE_OWNER, str(lease_status.get("lease_id") or ""), current, current + INTENT_TTL_SECONDS))
            c.commit()
            row = c.execute("SELECT * FROM provision_intents WHERE intent_id=?", (intent_id,)).fetchone()
            reused = False
        else:
            reused = True
    result = _public(row)
    result["reused_existing_intent"] = reused
    op.audit_record(tool=PREPARE_TOOL_NAME, level=policy.level, apply_mode=policy.apply_mode,
                    dry_run=False, success=True, changed=True,
                    summary="recorded bounded FIRST_SAFE provisioning intent (no remote execution)",
                    extra={"intent_id": result["intent_id"], "plan_hash": digest,
                           "policy_template": POLICY_TEMPLATE, "host": spec.EGRESS_HOST,
                           "remote_execution_performed": False})
    return result


def verify_intent(intent_id: str | None = None) -> dict[str, Any]:
    _require_authority(mutation=False)
    with _connect() as c:
        if intent_id:
            token = str(intent_id).strip()
            if not _INTENT_ID_RE.match(token):
                raise ValueError("intent_id is not a valid FIRST_SAFE provisioning identifier.")
            row = c.execute("SELECT * FROM provision_intents WHERE intent_id=?", (token,)).fetchone()
        else:
            row = c.execute("SELECT * FROM provision_intents ORDER BY created_at DESC LIMIT 1").fetchone()
    if row is None:
        return {"success": True, "found": False, "message": "No FIRST_SAFE provisioning intent exists."}
    out = _public(row)
    out.update({"success": True, "found": True})
    return out


def hermes_first_safe_provision_prepare() -> str:
    try:
        result = prepare_intent(); result["success"] = True
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="first_safe_provision", code="FIRST_SAFE_PROVISION_PREPARE_ERROR",
                                                  suggested_action="Use a fresh approved hermes-exec-first-safe-provision session and Mission Control lease."), indent=2)


def hermes_first_safe_provision_execute(intent_id: str) -> str:
    """Execute exactly one prepared FIRST_SAFE provisioning intent via the trusted fixed worker."""
    try:
        token = str(intent_id).strip()
        if not _INTENT_ID_RE.fullmatch(token):
            raise ValueError("intent_id is not a valid FIRST_SAFE provisioning identifier.")
        policy = _require_authority(mutation=True)
        # Import lazily because the trusted worker imports this module for the
        # canonical intent contract.  The worker has no caller-supplied host,
        # user, command, path, model or credential parameters.
        import first_safe_provision_worker as worker

        evidence = worker.execute(token)
        result = {
            "success": True,
            "intent_id": token,
            "state": STATE_COMPLETED,
            "plan_hash": plan_hash(),
            "policy_template": POLICY_TEMPLATE,
            "evidence": evidence,
        }
        op.audit_record(
            tool=EXECUTE_TOOL_NAME,
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary="executed bounded FIRST_SAFE provisioning intent via fixed trusted worker",
            extra={
                "intent_id": token,
                "plan_hash": result["plan_hash"],
                "policy_template": POLICY_TEMPLATE,
                "host": spec.EGRESS_HOST,
                "remote_execution_performed": True,
                "model_api_calls": evidence.get("model_api_calls", 0),
            },
        )
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(
            exc,
            layer="first_safe_provision",
            code="FIRST_SAFE_PROVISION_EXECUTE_ERROR",
            suggested_action="Use the exact prepared provisioning intent under its bound approved session and Mission Control lease.",
        ), indent=2)


def hermes_first_safe_provision_verify(intent_id: str | None = None) -> str:
    try:
        return json.dumps(verify_intent(intent_id), indent=2)
    except Exception as exc:
        return json.dumps(op.error_from_exception(exc, layer="first_safe_provision", code="FIRST_SAFE_PROVISION_VERIFY_ERROR",
                                                  suggested_action="Provide a valid provisioning intent under the approved session."), indent=2)
