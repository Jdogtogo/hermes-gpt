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


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    snapshot_hash: str
    policy: dict[str, Any]
    created_at: int
    expires_at: int
    revoked_at: int | None
    approval_state: str


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


def approve_extension(request_id: str, *, root: Path | None = None, now: int | None = None) -> SessionRecord:
    """Local-only: grant a pending extension request. Never callable by the
    session itself — intended to be invoked by the human operator via the
    CLI in this module, not exposed as a remote MCP tool."""
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
    return load_session(session_id, root=root, now=current)


def deny_extension(request_id: str, *, root: Path | None = None, now: int | None = None) -> bool:
    current = int(time.time() if now is None else now)
    with _connect(root) as connection:
        changed = connection.execute(
            "UPDATE session_extension_requests SET status = 'denied', decided_at = ? "
            "WHERE request_id = ? AND status = 'pending'",
            (current, request_id),
        ).rowcount
    return changed > 0


def active_session(*, now: int | None = None) -> SessionRecord | None:
    sid = os.environ.get(ACTIVE_SESSION_ID_ENV, "").strip()
    if not sid:
        return None
    return load_session(sid, now=now)


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
        record = approve_extension(args.request_id)
        print(json.dumps({"session_id": record.session_id, "expires_at": record.expires_at}, indent=2))
    elif args.cmd == "deny-extension":
        print(json.dumps({"denied": deny_extension(args.request_id)}, indent=2))
    elif args.cmd == "revoke-session":
        print(json.dumps({"revoked": revoke_session(args.session_id)}, indent=2))


if __name__ == "__main__":
    _cli()
