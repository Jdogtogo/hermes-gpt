"""Immutable Operator Session policy snapshots for hermes-gpt."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SESSION_ROOT_ENV = "HERMES_GPT_OPERATOR_SESSION_ROOT"
ACTIVE_SESSION_ID_ENV = "HERMES_GPT_OPERATOR_SESSION_ID"
DEFAULT_SESSION_ROOT = Path.home() / ".hermes" / "operator-sessions"

# A session's total lifetime (from creation) can never exceed
# MAX_SESSION_DURATION_SECONDS, regardless of how many extensions are
# approved. Each extension grants at most EXTENSION_SECONDS and always
# requires a separate local-only approval step (see approve_extension);
# a session can never extend itself.
DEFAULT_SESSION_DURATION_SECONDS = 2 * 60 * 60
MAX_SESSION_DURATION_SECONDS = 4 * 60 * 60
EXTENSION_SECONDS = 30 * 60

# How long a human has to act on a pending session-creation request (via
# Telegram or the localhost approval page) before it expires unactioned.
SESSION_REQUEST_TTL_SECONDS = 15 * 60
DEFAULT_HARD_DENIES = (
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.docker",
    "~/.azure",
    "~/.hermes/mcp-tokens",
    "~/.hermes/auth",
    "~/.cloudflared",
)


class SessionPolicyInvariantError(ValueError):
    """Raised when a session would be persisted in a state that violates a hard
    invariant.

    Currently the enforced invariant is: an *approved* session snapshot must
    always carry a non-empty ``policy_template`` that binds it to the named,
    human-approved template it was granted from. Failing loudly here -- rather
    than silently storing an unbound snapshot -- is what stops a stale writer
    process from minting an approved session that the template-scoped guards
    (e.g. operator-service restart) can never accept. See
    ``docs/OPERATOR_RESTART_INVESTIGATION.md``.
    """


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    snapshot_hash: str
    policy: dict[str, Any]
    created_at: int
    expires_at: int
    revoked_at: int | None
    approval_state: str


@dataclass(frozen=True)
class EffectiveAuthority:
    """The single authoritative answer to "what may the operator runtime do
    right now, and why". Produced only by resolve_effective_authority();
    consumed by OperatorPolicy (all mutation guards) and by both operator
    status tools, so status reporting and enforcement can never diverge.

    When ``is_active`` is False the level/apply_mode fields are always the
    fail-closed pair ("read_only"/"dry_run") REGARDLESS of environment
    variables; env-derived authority is layered on separately by
    OperatorPolicy only when no session deployment is configured at all
    (``status == "none_configured"``).
    """

    session_id: str | None       # the active session's id (None unless is_active)
    pointed_session_id: str | None  # what the pointer/env referenced, even if invalid
    status: str                  # active | expired | revoked | not_approved |
                                 # missing | malformed | none_configured
    level: str
    apply_mode: str
    approved_at: int | None      # session created_at (approval bound)
    expires_at: int | None       # reported even for expired sessions, for diagnostics
    policy_template: str | None
    snapshot_hash: str | None
    readable_roots: list[str]
    writable_roots: list[str]
    verbs: dict[str, Any]
    is_active: bool
    failure_reason: str | None   # human-readable, secret-free; None when active


def _session_files_secure(root: Path) -> str | None:
    """Best-effort ownership/permission validation of persisted session
    state. Returns a failure reason string, or None when acceptable. Never
    raises. Windows (os.name != 'posix') has no comparable uid/mode model, so
    the check is a no-op there rather than a false failure."""
    if os.name != "posix":
        return None
    try:
        uid = os.getuid()
        for candidate in (_active_pointer_path(root), db_path(root)):
            if not candidate.exists():
                continue
            info = candidate.stat()
            if info.st_uid != uid:
                return f"Session state file {candidate.name} is not owned by the current user."
            if info.st_mode & 0o022:
                return f"Session state file {candidate.name} is group/other-writable."
    except OSError as exc:
        return f"Session state could not be validated: {exc.__class__.__name__}."
    return None


def session_deployment_configured() -> bool:
    """True when THIS process is explicitly configured as a session-governed
    deployment (session root and/or active-session id set in the
    environment, as the operator sidecar units do). Env-authority
    deployments (e.g. the local owner sidecar) configure neither and must
    not have their env-granted authority overridden by session state found
    in the shared default root."""
    return bool(
        os.environ.get(SESSION_ROOT_ENV, "").strip()
        or os.environ.get(ACTIVE_SESSION_ID_ENV, "").strip()
    )


def resolve_effective_authority(*, now: int | None = None) -> EffectiveAuthority:
    """Resolve the runtime's effective operator authority from the
    authoritative session record (pointer file first, env id fallback),
    classifying every non-active outcome instead of collapsing them to None.

    Fail-closed contract: every path that is not a fully validated, approved,
    unexpired, unrevoked session with intact persisted state yields
    level="read_only", apply_mode="dry_run", is_active=False, and a
    failure_reason explaining why -- so status tools can SHOW the reason and
    guards can act on exactly the same answer.
    """
    current = int(time.time() if now is None else now)

    def _closed(status: str, pointed: str | None, reason: str | None,
                *, approved_at: int | None = None, expires_at: int | None = None) -> EffectiveAuthority:
        return EffectiveAuthority(
            session_id=None, pointed_session_id=pointed, status=status,
            level="read_only", apply_mode="dry_run",
            approved_at=approved_at, expires_at=expires_at,
            policy_template=None, snapshot_hash=None,
            readable_roots=[], writable_roots=[], verbs={},
            is_active=False, failure_reason=reason,
        )

    try:
        root = session_root()
    except Exception as exc:  # session root itself unresolvable
        return _closed("malformed", None, f"Session root could not be resolved: {exc.__class__.__name__}.")

    sid = ""
    try:
        pointer_path = _active_pointer_path(root)
        if pointer_path.is_file():
            sid = pointer_path.read_text(encoding="utf-8").strip()
    except Exception:
        return _closed("malformed", None, "Active-session pointer exists but could not be read.")
    if not sid:
        sid = os.environ.get(ACTIVE_SESSION_ID_ENV, "").strip()
    if not sid:
        return _closed("none_configured", None, "No operator session is configured for this deployment.")

    perm_reason = _session_files_secure(root)
    if perm_reason is not None:
        return _closed("malformed", sid, perm_reason)

    try:
        with _connect(root) as connection:
            row = connection.execute(
                "SELECT s.session_id, s.snapshot_hash, p.canonical_json, s.created_at, s.expires_at, "
                "s.revoked_at, s.approval_state "
                "FROM operator_sessions s JOIN policy_snapshots p ON p.snapshot_hash = s.snapshot_hash "
                "WHERE s.session_id = ?",
                (sid,),
            ).fetchone()
    except Exception as exc:
        return _closed("malformed", sid, f"Session store could not be read: {exc.__class__.__name__}.")

    if row is None:
        return _closed("missing", sid, f"Pointed-to operator session {sid!r} does not exist in the session store.")

    created_at = int(row["created_at"])
    expires_at = int(row["expires_at"])
    if row["approval_state"] != "approved":
        return _closed(
            "not_approved", sid,
            f"Operator session {sid!r} has approval state {row['approval_state']!r}, not 'approved'.",
            approved_at=created_at, expires_at=expires_at,
        )
    if row["revoked_at"] is not None:
        return _closed(
            "revoked", sid,
            f"Operator session {sid!r} was revoked at {int(row['revoked_at'])}.",
            approved_at=created_at, expires_at=expires_at,
        )
    if expires_at < current:
        return _closed(
            "expired", sid,
            f"Operator session {sid!r} expired at {expires_at} "
            f"({current - expires_at}s ago). Request and approve a new session.",
            approved_at=created_at, expires_at=expires_at,
        )

    try:
        snapshot = json.loads(str(row["canonical_json"]))
        if not isinstance(snapshot, dict):
            raise ValueError("snapshot is not an object")
    except Exception:
        return _closed(
            "malformed", sid,
            f"Operator session {sid!r} has a malformed policy snapshot.",
            approved_at=created_at, expires_at=expires_at,
        )

    raw_level = str(snapshot.get("level") or "workspace").strip().lower()
    level = raw_level if raw_level in _POLICY_LEVELS else "workspace"
    raw_mode = str(snapshot.get("apply_mode") or "direct").strip().lower()
    apply_mode = raw_mode if raw_mode in {"dry_run", "direct"} else "direct"
    writable = [str(p) for p in snapshot.get("writable_roots", [])]
    if level == "workspace" and not writable:
        return _closed(
            "malformed", sid,
            f"Operator session {sid!r} grants workspace level but has no writable roots.",
            approved_at=created_at, expires_at=expires_at,
        )

    return EffectiveAuthority(
        session_id=sid,
        pointed_session_id=sid,
        status="active",
        level=level,
        apply_mode=apply_mode,
        approved_at=created_at,
        expires_at=expires_at,
        policy_template=(str(snapshot["policy_template"]) if snapshot.get("policy_template") else None),
        snapshot_hash=str(row["snapshot_hash"]),
        readable_roots=[str(p) for p in snapshot.get("readable_roots", [])],
        writable_roots=writable,
        verbs=dict(snapshot.get("verbs", {})),
        is_active=True,
        failure_reason=None,
    )


# Mirrors operator_policy.LEVELS without importing it (operator_policy imports
# this module at top level; importing back would be circular).
_POLICY_LEVELS = {"read_only", "cron", "skills", "skills_config", "workspace", "owner"}


def session_root() -> Path:
    return Path(os.environ.get(SESSION_ROOT_ENV, str(DEFAULT_SESSION_ROOT))).expanduser().resolve()


def db_path(root: Path | None = None) -> Path:
    return (root or session_root()) / "operator_sessions.sqlite3"


def canonical_policy(policy: dict[str, Any]) -> str:
    normalized = normalize_policy(policy)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def snapshot_hash(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_policy(policy).encode("utf-8")).hexdigest()


def _normalize_path_text(value: str) -> str:
    return str(Path(value).expanduser().resolve())


def _normalize_list(values: Any, *, paths: bool = False) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            continue
        text = _normalize_path_text(item) if paths else item.strip()
        if text not in out:
            out.append(text)
    return sorted(out)


def normalize_policy(policy: dict[str, Any]) -> dict[str, Any]:
    verbs = policy.get("verbs") if isinstance(policy.get("verbs"), dict) else {}
    normalized_verbs: dict[str, list[str]] = {}
    for key, value in sorted(verbs.items()):
        if isinstance(key, str):
            normalized_verbs[key] = _normalize_list(value)
    return {
        "version": 1,
        "policy_template": (
            str(policy.get("policy_template")).strip()
            if policy.get("policy_template")
            else None
        ),
        "level": str(policy.get("level") or "workspace"),
        "apply_mode": str(policy.get("apply_mode") or "direct"),
        "readable_roots": _normalize_list(policy.get("readable_roots"), paths=True),
        "writable_roots": _normalize_list(policy.get("writable_roots"), paths=True),
        "egress_hosts": _normalize_list(policy.get("egress_hosts")),
        "git_remotes": _normalize_list(policy.get("git_remotes")),
        "service_units": _normalize_list(policy.get("service_units")),
        "hard_denied_paths": _normalize_list(
            [*DEFAULT_HARD_DENIES, *(policy.get("hard_denied_paths") or [])],
            paths=True,
        ),
        "verbs": normalized_verbs,
    }


def _connect(root: Path | None = None) -> sqlite3.Connection:
    path = db_path(root)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS policy_snapshots (
            snapshot_hash TEXT PRIMARY KEY,
            canonical_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS operator_sessions (
            session_id TEXT PRIMARY KEY,
            snapshot_hash TEXT NOT NULL REFERENCES policy_snapshots(snapshot_hash),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked_at INTEGER,
            approval_state TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_operator_sessions_snapshot
            ON operator_sessions(snapshot_hash);
        CREATE TABLE IF NOT EXISTS session_extension_requests (
            request_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES operator_sessions(session_id),
            requested_at INTEGER NOT NULL,
            requested_seconds INTEGER NOT NULL,
            status TEXT NOT NULL,
            decided_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_extension_requests_session
            ON session_extension_requests(session_id);
        CREATE TABLE IF NOT EXISTS session_creation_requests (
            request_id TEXT PRIMARY KEY,
            policy_template TEXT NOT NULL,
            resolved_policy_json TEXT NOT NULL,
            requested_duration_seconds INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            decided_by TEXT,
            decided_at INTEGER,
            resulting_session_id TEXT
        );
        """
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return connection


def create_session(
    policy: dict[str, Any],
    *,
    duration_seconds: int | None = None,
    approval_state: str = "approved",
    root: Path | None = None,
    session_id: str | None = None,
    now: int | None = None,
) -> SessionRecord:
    created = int(time.time() if now is None else now)
    requested = DEFAULT_SESSION_DURATION_SECONDS if duration_seconds is None else int(duration_seconds)
    ttl = max(60, min(requested, MAX_SESSION_DURATION_SECONDS))
    normalized = normalize_policy(policy)
    # Hard invariant: an approved session snapshot must always be bound to a
    # named policy template. This is the single chokepoint through which every
    # snapshot is written, so enforcing here means no path -- normal approval,
    # break-glass CLI, or a future caller -- can persist an unbound approved
    # session. A pending (not-yet-approved) request row is exempt; the binding
    # is asserted again at approval time in approve_session_request().
    if approval_state == "approved" and not normalized.get("policy_template"):
        raise SessionPolicyInvariantError(
            "Refusing to create an approved operator session without a "
            "policy_template. Every approved session snapshot must be bound to "
            "the named, human-approved template it was granted from. If this "
            "surfaced in production it almost always means a stale writer "
            "process approved the request with pre-template code -- restart "
            "every service that imports operator_sessions (see "
            "docs/OPERATOR_RESTART_INVESTIGATION.md) and re-approve."
        )
    canonical = canonical_policy(normalized)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    sid = session_id or f"ops_{secrets.token_urlsafe(24)}"
    expires = created + ttl
    with _connect(root) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO policy_snapshots(snapshot_hash, canonical_json, created_at) VALUES (?, ?, ?)",
            (digest, canonical, created),
        )
        connection.execute(
            "INSERT INTO operator_sessions(session_id, snapshot_hash, created_at, expires_at, revoked_at, approval_state) "
            "VALUES (?, ?, ?, ?, NULL, ?)",
            (sid, digest, created, expires, approval_state),
        )
    return SessionRecord(sid, digest, normalized, created, expires, None, approval_state)


def load_session(session_id: str, *, root: Path | None = None, now: int | None = None) -> SessionRecord:
    current = int(time.time() if now is None else now)
    with _connect(root) as connection:
        row = connection.execute(
            "SELECT s.session_id, s.snapshot_hash, p.canonical_json, s.created_at, s.expires_at, "
            "s.revoked_at, s.approval_state "
            "FROM operator_sessions s JOIN policy_snapshots p ON p.snapshot_hash = s.snapshot_hash "
            "WHERE s.session_id = ?",
            (session_id,),
        ).fetchone()
    if row is None:
        raise PermissionError("Operator session does not exist.")
    if row["approval_state"] != "approved":
        raise PermissionError("Operator session is not approved.")
    if row["revoked_at"] is not None:
        raise PermissionError("Operator session is revoked.")
    if int(row["expires_at"]) < current:
        raise PermissionError("Operator session is expired.")
    return SessionRecord(
        session_id=str(row["session_id"]),
        snapshot_hash=str(row["snapshot_hash"]),
        policy=json.loads(str(row["canonical_json"])),
        created_at=int(row["created_at"]),
        expires_at=int(row["expires_at"]),
        revoked_at=int(row["revoked_at"]) if row["revoked_at"] is not None else None,
        approval_state=str(row["approval_state"]),
    )


def _audit_decision(*, request_id: str, request_type: str, decision: str, decided_by: str, extra: dict[str, Any]) -> None:
    """Best-effort audit of an approval/denial decision. Lazily imports
    operator_policy to avoid a circular import (operator_policy imports this
    module at the top level). Never records secrets, tokens, or codes."""
    try:
        import operator_policy as op_policy
        payload = {"request_id": request_id, "request_type": request_type, "decision": decision, "approval_source": decided_by}
        payload.update(extra)
        op_policy.audit_record(
            tool="session_approval",
            level="session",
            apply_mode="approval",
            dry_run=False,
            success=True,
            summary=f"{request_type} request {decision}",
            extra=payload,
        )
    except Exception:
        pass


def revoke_session(session_id: str, *, root: Path | None = None, now: int | None = None) -> bool:
    current = int(time.time() if now is None else now)
    with _connect(root) as connection:
        changed = connection.execute(
            "UPDATE operator_sessions SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL",
            (current, session_id),
        ).rowcount
    return changed > 0


def request_extension(
    session_id: str,
    *,
    seconds: int = EXTENSION_SECONDS,
    root: Path | None = None,
    now: int | None = None,
    request_id: str | None = None,
) -> str:
    """Record a pending extension request. This never extends the session by
    itself — a separate, local-only ``approve_extension`` call is required.
    A session can never approve its own extension."""
    current = int(time.time() if now is None else now)
    load_session(session_id, root=root, now=current)  # must be active to request
    rid = request_id or f"ext_{secrets.token_urlsafe(16)}"
    bounded_seconds = max(60, min(int(seconds), EXTENSION_SECONDS))
    with _connect(root) as connection:
        connection.execute(
            "INSERT INTO session_extension_requests"
            "(request_id, session_id, requested_at, requested_seconds, status, decided_at) "
            "VALUES (?, ?, ?, ?, 'pending', NULL)",
            (rid, session_id, current, bounded_seconds),
        )
    return rid


def list_pending_extensions(*, root: Path | None = None) -> list[dict[str, Any]]:
    with _connect(root) as connection:
        rows = connection.execute(
            "SELECT request_id, session_id, requested_at, requested_seconds, status "
            "FROM session_extension_requests WHERE status = 'pending' ORDER BY requested_at"
        ).fetchall()
    return [dict(row) for row in rows]


def approve_extension(
    request_id: str, *, decided_by: str = "local-cli", root: Path | None = None, now: int | None = None
) -> SessionRecord:
    """Local-only: grant a pending extension request. Never callable by the
    session itself — intended to be invoked by a human via Telegram, the
    localhost approval page, or (break-glass) the CLI in this module —
    never exposed as a remote MCP tool."""
    current = int(time.time() if now is None else now)
    with _connect(root) as connection:
        row = connection.execute(
            "SELECT session_id, requested_seconds, status FROM session_extension_requests "
            "WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise PermissionError("Extension request does not exist.")
        if row["status"] != "pending":
            raise PermissionError(f"Extension request already {row['status']}.")
        session_id = str(row["session_id"])
        session_row = connection.execute(
            "SELECT created_at, expires_at, revoked_at, approval_state FROM operator_sessions "
            "WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if session_row is None:
            raise PermissionError("Operator session does not exist.")
        if session_row["revoked_at"] is not None:
            raise PermissionError("Cannot extend a revoked session.")
        if session_row["approval_state"] != "approved":
            raise PermissionError("Cannot extend a session that was never approved.")
        if int(session_row["expires_at"]) < current:
            raise PermissionError("Cannot extend an already-expired session.")
        max_expiry = int(session_row["created_at"]) + MAX_SESSION_DURATION_SECONDS
        new_expiry = min(int(session_row["expires_at"]) + int(row["requested_seconds"]), max_expiry)
        connection.execute(
            "UPDATE operator_sessions SET expires_at = ? WHERE session_id = ?",
            (new_expiry, session_id),
        )
        connection.execute(
            "UPDATE session_extension_requests SET status = 'approved', decided_at = ? WHERE request_id = ?",
            (current, request_id),
        )
    record = load_session(session_id, root=root, now=current)
    _audit_decision(
        request_id=request_id, request_type="extension", decision="approved", decided_by=decided_by,
        extra={"session_id": session_id, "resulting_expires_at": record.expires_at},
    )
    return record


def deny_extension(
    request_id: str, *, decided_by: str = "local-cli", root: Path | None = None, now: int | None = None
) -> bool:
    current = int(time.time() if now is None else now)
    with _connect(root) as connection:
        row = connection.execute(
            "SELECT session_id FROM session_extension_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        changed = connection.execute(
            "UPDATE session_extension_requests SET status = 'denied', decided_at = ? "
            "WHERE request_id = ? AND status = 'pending'",
            (current, request_id),
        ).rowcount
    if changed:
        _audit_decision(
            request_id=request_id, request_type="extension", decision="denied", decided_by=decided_by,
            extra={"session_id": row["session_id"] if row else None},
        )
    return changed > 0


# ---------------------------------------------------------------------------
# Session-creation requests (request-only; approval creates the session)
# ---------------------------------------------------------------------------
#
# hermes_operator_session_request (the MCP tool) never creates authority
# itself — it only ever calls request_session() below, which records a
# pending request carrying the fully *resolved* policy (not just the
# template name) so a human approver sees exactly what they're granting.
# Only approve_session_request(), called from Telegram, the localhost
# approval page, or the break-glass CLI, actually creates the session.


def request_session(
    *,
    policy_template: str,
    resolved_policy: dict[str, Any],
    requested_duration_seconds: int,
    reason: str,
    root: Path | None = None,
    now: int | None = None,
    request_id: str | None = None,
) -> str:
    current = int(time.time() if now is None else now)
    rid = request_id or f"sr_{secrets.token_hex(4)}"
    expires_at = current + SESSION_REQUEST_TTL_SECONDS
    with _connect(root) as connection:
        connection.execute(
            "INSERT INTO session_creation_requests"
            "(request_id, policy_template, resolved_policy_json, requested_duration_seconds, "
            "reason, status, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)",
            (
                rid,
                policy_template,
                json.dumps(resolved_policy, sort_keys=True),
                int(requested_duration_seconds),
                reason,
                current,
                expires_at,
            ),
        )
    return rid


def list_pending_session_requests(*, root: Path | None = None) -> list[dict[str, Any]]:
    now = int(time.time())
    with _connect(root) as connection:
        connection.execute(
            "DELETE FROM session_creation_requests WHERE status = 'pending' AND expires_at < ?",
            (now,),
        )
        rows = connection.execute(
            "SELECT request_id, policy_template, resolved_policy_json, requested_duration_seconds, "
            "reason, created_at, expires_at FROM session_creation_requests "
            "WHERE status = 'pending' ORDER BY created_at"
        ).fetchall()
    return [
        {
            "request_id": row["request_id"],
            "policy_template": row["policy_template"],
            "resolved_policy": json.loads(row["resolved_policy_json"]),
            "requested_duration_seconds": row["requested_duration_seconds"],
            "reason": row["reason"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
        }
        for row in rows
    ]


def approve_session_request(
    request_id: str, *, decided_by: str = "local-cli", root: Path | None = None, now: int | None = None
) -> SessionRecord:
    current = int(time.time() if now is None else now)
    with _connect(root) as connection:
        row = connection.execute(
            "SELECT policy_template, resolved_policy_json, requested_duration_seconds, "
            "status, expires_at FROM session_creation_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise ValueError("Session request does not exist or has expired.")
        if row["status"] != "pending":
            raise ValueError(f"Session request already {row['status']}.")
        if int(row["expires_at"]) < current:
            connection.execute(
                "UPDATE session_creation_requests SET status = 'expired' WHERE request_id = ?",
                (request_id,),
            )
            raise ValueError("Session request has expired.")
        policy = json.loads(row["resolved_policy_json"])
        # Bind the locally resolved template identity into the immutable
        # approved snapshot. The remote caller can only name a registered
        # template; raw policy JSON is never accepted over MCP. Fail the
        # approval explicitly if the request carries no template rather than
        # minting an unbound session (create_session enforces the same
        # invariant, but asserting here gives a request-scoped error message).
        template_name = str(row["policy_template"] or "").strip()
        if not template_name:
            raise SessionPolicyInvariantError(
                f"Session creation request {request_id!r} has no policy_template; "
                "refusing to approve an unbound operator session."
            )
        policy["policy_template"] = template_name
        duration = int(row["requested_duration_seconds"])
    # create_session opens its own connection; keep it outside the block
    # above so a same-thread nested SQLite write never deadlocks.
    record = create_session(policy, duration_seconds=duration, root=root, now=current)
    # Update the live pointer so the already-running server picks this up on
    # its very next tool call — no restart needed.
    _write_active_pointer(record.session_id, root=root)
    with _connect(root) as connection:
        connection.execute(
            "UPDATE session_creation_requests SET status = 'approved', decided_by = ?, "
            "decided_at = ?, resulting_session_id = ? WHERE request_id = ?",
            (decided_by, current, record.session_id, request_id),
        )
    _audit_decision(
        request_id=request_id, request_type="session_creation", decision="approved", decided_by=decided_by,
        extra={
            "resulting_session_id": record.session_id,
            "snapshot_hash": record.snapshot_hash,
            "requested_duration_seconds": duration,
            "approved_duration_seconds": record.expires_at - record.created_at,
        },
    )
    return record


def deny_session_request(
    request_id: str, *, decided_by: str = "local-cli", root: Path | None = None, now: int | None = None
) -> bool:
    current = int(time.time() if now is None else now)
    with _connect(root) as connection:
        row = connection.execute(
            "SELECT policy_template FROM session_creation_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        changed = connection.execute(
            "UPDATE session_creation_requests SET status = 'denied', decided_by = ?, decided_at = ? "
            "WHERE request_id = ? AND status = 'pending'",
            (decided_by, current, request_id),
        ).rowcount
    if changed:
        _audit_decision(
            request_id=request_id, request_type="session_creation", decision="denied", decided_by=decided_by,
            extra={"policy_template": row["policy_template"] if row else None},
        )
    return changed > 0


ACTIVE_SESSION_POINTER_NAME = "active_session_id"


def _active_pointer_path(root: Path | None = None) -> Path:
    return (root or session_root()) / ACTIVE_SESSION_POINTER_NAME


def _write_active_pointer(session_id: str, *, root: Path | None = None) -> None:
    """Record which session is "the" active one for this deployment. A
    freshly-approved session (via Telegram, the localhost approval page, or
    the CLI) becomes active immediately for the already-running server
    process — no restart required — because active_session() re-reads this
    file on every call rather than relying on a startup-time env var."""
    path = _active_pointer_path(root)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(session_id, encoding="utf-8")
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def active_session(*, now: int | None = None) -> SessionRecord | None:
    """Return the currently active session, or None if there isn't one.

    An expired, revoked, or otherwise invalid pointed-to session is treated
    identically to "no active session" rather than raised — the server must
    keep running and serving OAuth/status/request tools regardless of
    whether the last operator session lapsed. Checks the live pointer file
    first (updated in place by approve_session_request), then falls back to
    the ACTIVE_SESSION_ID_ENV env var for test/back-compat purposes.

    This is called on every OperatorPolicy() construction — i.e. on every
    tool call — so the pointer-file lookup is deliberately maximally
    defensive: any unexpected error there (missing dir, permissions, a
    caller-mutated os.name mid-call, whatever) must never take down policy
    evaluation. It only ever downgrades to "no pointer file found".
    """
    authority = resolve_effective_authority(now=now)
    if not authority.is_active or authority.session_id is None:
        return None
    try:
        return load_session(authority.session_id, now=now)
    except PermissionError:
        return None


def path_under(path: str | os.PathLike[str], roots: list[str]) -> bool:
    resolved = Path(path).expanduser().resolve()
    for root in roots:
        try:
            resolved.relative_to(Path(root).expanduser().resolve())
            return True
        except ValueError:
            continue
    return False


def remote_matches(remote: str, allowed: list[str]) -> bool:
    text = (remote or "").strip()
    if not text:
        return False
    parsed = urlparse(text)
    host_path = ""
    if parsed.hostname:
        host_path = f"{parsed.hostname}{parsed.path}".rstrip("/")
    elif ":" in text and "@" in text:
        host_path = text.split("@", 1)[1].replace(":", "/", 1).rstrip("/")
    candidates = {text.rstrip("/"), host_path}
    for item in allowed:
        allowed_item = item.rstrip("/")
        if allowed_item.endswith("/*"):
            prefix = allowed_item[:-1]
            if any(candidate.startswith(prefix) for candidate in candidates):
                return True
        if allowed_item in candidates:
            return True
    return False


def _cli() -> None:
    """Local-only session administration. Never expose this as a remote MCP
    tool: creation and extension approval must stay a human, local action."""
    import argparse

    parser = argparse.ArgumentParser(description="Hermes-GPT operator session admin (local only).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    create = sub.add_parser("create-session", help="Create and approve a new operator session.")
    create.add_argument("--policy-file", required=True, help="Path to a JSON policy document.")
    create.add_argument("--duration-seconds", type=int, default=DEFAULT_SESSION_DURATION_SECONDS)

    sub.add_parser("list-pending-extensions", help="List pending extension requests.")

    approve = sub.add_parser("approve-extension", help="Approve a pending extension request.")
    approve.add_argument("request_id")

    deny = sub.add_parser("deny-extension", help="Deny a pending extension request.")
    deny.add_argument("request_id")

    revoke = sub.add_parser("revoke-session", help="Revoke an operator session immediately.")
    revoke.add_argument("session_id")

    sub.add_parser(
        "list-pending-sessions",
        help="[break-glass] List pending session-creation requests. Normal workflow is Telegram/localhost.",
    )
    approve_session = sub.add_parser(
        "approve-session",
        help="[break-glass] Approve a pending session-creation request. Normal workflow is Telegram/localhost.",
    )
    approve_session.add_argument("request_id")
    deny_session = sub.add_parser(
        "deny-session",
        help="[break-glass] Deny a pending session-creation request. Normal workflow is Telegram/localhost.",
    )
    deny_session.add_argument("request_id")

    args = parser.parse_args()

    if args.cmd == "create-session":
        policy = json.loads(Path(args.policy_file).read_text(encoding="utf-8"))
        record = create_session(policy, duration_seconds=args.duration_seconds)
        print(json.dumps({
            "session_id": record.session_id,
            "snapshot_hash": record.snapshot_hash,
            "created_at": record.created_at,
            "expires_at": record.expires_at,
            "approval_state": record.approval_state,
        }, indent=2))
        print(f"\nTo activate: set {ACTIVE_SESSION_ID_ENV}={record.session_id} for the service and restart it.")
    elif args.cmd == "list-pending-extensions":
        print(json.dumps(list_pending_extensions(), indent=2))
    elif args.cmd == "approve-extension":
        record = approve_extension(args.request_id, decided_by="cli-break-glass")
        print(json.dumps({"session_id": record.session_id, "expires_at": record.expires_at}, indent=2))
    elif args.cmd == "deny-extension":
        print(json.dumps({"denied": deny_extension(args.request_id, decided_by="cli-break-glass")}, indent=2))
    elif args.cmd == "revoke-session":
        print(json.dumps({"revoked": revoke_session(args.session_id)}, indent=2))
    elif args.cmd == "list-pending-sessions":
        print(json.dumps(list_pending_session_requests(), indent=2))
    elif args.cmd == "approve-session":
        record = approve_session_request(args.request_id, decided_by="cli-break-glass")
        print(json.dumps({"session_id": record.session_id, "expires_at": record.expires_at}, indent=2))
    elif args.cmd == "deny-session":
        print(json.dumps({"denied": deny_session_request(args.request_id, decided_by="cli-break-glass")}, indent=2))


if __name__ == "__main__":
    _cli()
