"""Mission Control exclusive lease for hermes-gpt operator.

This module provides durable, cross-process exclusive lease management with:
- Atomic acquire with owner/token and issued/expires timestamps
- Durable state persisted to JSON file (survives controller restarts)
- Only current owner/token can release
- Expired leases can be safely reacquired
- Status/verify reports owner match and TTL/expiry without leaking secrets
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import operator_policy as op_policy

# Lease state file location - persists across controller processes
_LEASE_STATE_DIR = Path.home() / ".hermes" / "operator-leases"
_LEASE_STATE_PATH = _LEASE_STATE_DIR / "mission-control-lease.json"
_LEASE_LOCK_PATH = _LEASE_STATE_DIR / "mission-control-lease.lock"


@contextmanager
def _lease_lock() -> Iterator[None]:
    """Cross-process exclusive lock guarding lease read/modify/write cycles."""
    _LEASE_STATE_DIR.mkdir(parents=True, exist_ok=True)
    with _LEASE_LOCK_PATH.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

# Lease duration in seconds (default 10 minutes, configurable via env)
# Reduced from 1 hour to limit friction from stale/abandoned leases.
# Workflows that need longer hold must explicitly renew.
DEFAULT_LEASE_DURATION_SECONDS = int(
    os.environ.get("HERMES_MISSION_CONTROL_LEASE_TTL", str(10 * 60))
)
# Maximum allowed lease duration (12 hours)
MAX_LEASE_DURATION_SECONDS = 12 * 60 * 60
# Minimum allowed lease duration (1 minute)
MIN_LEASE_DURATION_SECONDS = 60
# Maximum lease renewals before requiring full reacquisition (prevents indefinite extension)
MAX_RENEWALS = 12  # 12 * 10min = 2 hours max continuous hold


@dataclass(frozen=True)
class LeaseState:
    """Persisted lease state - survives process restarts."""
    owner: str                    # Owner identity (OAuth subject or session ID)
    token: str                    # Opaque token for release verification (NOT returned in status)
    issued_at: int                # Unix timestamp when lease was acquired
    expires_at: int               # Unix timestamp when lease expires
    lease_id: str                 # Unique lease identifier for this acquisition
    renewal_count: int = 0        # Number of times this lease has been renewed


def _atomic_write(path: Path, content: str) -> None:
    """Atomic write using tmp file + os.replace for durability."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _read_lease_state() -> LeaseState | None:
    """Read lease state from disk. Returns None if no valid lease exists."""
    try:
        raw = json.loads(_LEASE_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(raw, dict):
        return None

    required = {"owner", "token", "issued_at", "expires_at", "lease_id"}
    if not all(k in raw for k in required):
        return None

    try:
        return LeaseState(
            owner=str(raw["owner"]),
            token=str(raw["token"]),
            issued_at=int(raw["issued_at"]),
            expires_at=int(raw["expires_at"]),
            lease_id=str(raw["lease_id"]),
            renewal_count=int(raw.get("renewal_count", 0)),
        )
    except (ValueError, TypeError):
        return None


def _write_lease_state(state: LeaseState) -> None:
    """Persist lease state atomically."""
    _atomic_write(
        _LEASE_STATE_PATH,
        json.dumps(
            {
                "owner": state.owner,
                "token": state.token,
                "issued_at": state.issued_at,
                "expires_at": state.expires_at,
                "lease_id": state.lease_id,
                "renewal_count": state.renewal_count,
            },
            indent=2,
            sort_keys=True,
        ) + "\n",
    )


def _delete_lease_state() -> None:
    """Remove lease state file (used on release/expiry)."""
    try:
        _LEASE_STATE_PATH.unlink(missing_ok=True)
    except OSError:
        pass


# The narrow, fixed-purpose capability for INSPECTING the coordination lease.
# It authorizes exactly one thing: reading the single lease record at
# _LEASE_STATE_PATH and reporting ownership/TTL. It grants no path input, no
# enumeration, no write, and no authority. It is deliberately NOT a filesystem
# verb, so a session can be allowed to verify the lease without being allowed
# to read files.
LEASE_STATUS_CAPABILITY = ("mission_control", "lease_status")
# The broad verb that used to be the only way to reach lease status. Still
# accepted so every template that already grants it keeps working unchanged;
# it additionally permits the expired-record cleanup that the narrow
# capability does not.
LEASE_STATUS_LEGACY_CAPABILITY = ("filesystem", "read")


def _require_operator_authority(*, mutate: bool = True, dry_run: bool = False) -> op_policy.OperatorPolicy:
    """Require operator policy with appropriate level for lease MUTATION and
    for token verification.

    Acquire, release and token verification continue to require the broad
    ``filesystem:read`` verb. They are deliberately NOT reachable through the
    narrow lease-status capability: holding the right to *check* the lease must
    never imply the right to take, drop, or authenticate against it.
    """
    policy = op_policy.OperatorPolicy()
    policy.require_level("workspace")
    policy.require_verb("filesystem", "read")
    if mutate:
        # Leases mutate durable state on disk. Dry-run acquires/releases are
        # validation-only and must be permitted without a live operator session,
        # so the guard sees the same dry_run flag the caller passed in.
        policy.require_mutation(dry_run=dry_run)
    return policy


def _require_lease_status_authority() -> tuple[op_policy.OperatorPolicy, bool]:
    """Authorize the read-only lease-status operation.

    Accepts the narrow ``mission_control:lease_status`` capability OR the
    legacy broad ``filesystem:read`` verb. Returns the policy plus whether the
    caller may perform the one incidental write this operation can otherwise
    do (deleting an already-expired lease record).

    A session authorized ONLY by the narrow capability is treated as strictly
    read-only: it reports an expired lease as expired but never removes the
    record, so a policy whose whole point is a zero local write surface (e.g.
    hermes-exec-first-safe-model, writable_roots == []) does not acquire an
    unlink through the back door.
    """
    policy = op_policy.OperatorPolicy()
    policy.require_level("workspace")
    policy.require_any_verb([LEASE_STATUS_CAPABILITY, LEASE_STATUS_LEGACY_CAPABILITY])
    may_reap = policy.has_verb(*LEASE_STATUS_LEGACY_CAPABILITY)
    return policy, may_reap


def _generate_token() -> str:
    """Generate a cryptographically secure opaque token for lease ownership."""
    return secrets.token_urlsafe(32)


def _generate_lease_id() -> str:
    """Generate a unique lease ID."""
    return secrets.token_urlsafe(16)


def _now() -> int:
    """Current Unix timestamp."""
    return int(time.time())


def _is_expired(state: LeaseState) -> bool:
    """Check if lease has expired."""
    return _now() >= state.expires_at


def _sanitize_owner(owner: str) -> str:
    """Sanitize owner for storage - accept as-is, no transformation needed."""
    return owner.strip()


def acquire_lease(
    owner: str | None = None,
    ttl_seconds: int | None = None,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Acquire the Mission Control exclusive lease.

    Args:
        owner: Owner identity. If not provided, uses current OAuth subject or session ID.
        ttl_seconds: Lease duration in seconds (default: 1 hour, min: 1 min, max: 12 hours).
        dry_run: If True, validate but don't persist.

    Returns:
        Dict with success, lease details (owner, issued_at, expires_at, lease_id, token).
        The token is ONLY returned on successful acquire - never in status/verify.

    Raises:
        PermissionError: If operator authority insufficient.
        RuntimeError: If lease already held by another owner and not expired.
    """
    policy = _require_operator_authority(mutate=True, dry_run=dry_run)

    # Determine owner identity
    if owner is None:
        owner = policy.session_id or policy.current_oauth_identity()[0] or "unknown"
    owner = _sanitize_owner(owner)

    # Validate TTL
    if ttl_seconds is None:
        ttl_seconds = DEFAULT_LEASE_DURATION_SECONDS
    ttl_seconds = max(MIN_LEASE_DURATION_SECONDS, min(int(ttl_seconds), MAX_LEASE_DURATION_SECONDS))

    now = _now()
    issued_at = now
    expires_at = now + ttl_seconds
    lease_id = _generate_lease_id()
    token = _generate_token()

    # The entire read/decide/write cycle is protected by one cross-process
    # exclusive lock. This is the mutual-exclusion guarantee used by the
    # staggered Mission Control schedulers.
    with _lease_lock():
        current = _read_lease_state()
        if current and not _is_expired(current):
            if current.owner != owner:
                return {
                    "success": False,
                    "error": "LEASE_HELD_BY_OTHER",
                    "message": "Mission Control lease is held by another owner and has not expired",
                    "current_owner": current.owner,
                    "current_issued_at": current.issued_at,
                    "current_expires_at": current.expires_at,
                    "current_lease_id": current.lease_id,
                }
            return {
                "success": False,
                "error": "LEASE_ALREADY_HELD",
                "message": "Mission Control lease is already held by this owner and has not expired; release it with the existing token or wait for expiry",
                "current_owner": current.owner,
                "current_issued_at": current.issued_at,
                "current_expires_at": current.expires_at,
                "current_lease_id": current.lease_id,
            }

        new_state = LeaseState(
            owner=owner,
            token=token,
            issued_at=issued_at,
            expires_at=expires_at,
            lease_id=lease_id,
        )

        if not dry_run:
            _write_lease_state(new_state)
            try:
                op_policy.audit_record(
                    tool="hermes_mission_control_lease_acquire",
                    level=policy.level,
                    apply_mode=policy.apply_mode,
                    dry_run=False,
                    success=True,
                    changed=True,
                    summary="Mission Control exclusive lease acquired",
                    extra={
                        "owner": owner,
                        "lease_id": lease_id,
                        "issued_at": issued_at,
                        "expires_at": expires_at,
                        "ttl_seconds": ttl_seconds,
                        "dry_run": False,
                    },
                )
            except Exception:
                # Acquire is failure-atomic: if post-write auditing fails, remove
                # only the lease created by this call.  The owner/token match is
                # checked while the same cross-process lease lock is held so a
                # different or replacement lease can never be deleted.
                persisted = _read_lease_state()
                if (
                    persisted
                    and persisted.owner == owner
                    and secrets.compare_digest(persisted.token, token)
                ):
                    _delete_lease_state()
                raise

    return {
        "success": True,
        "owner": owner,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "lease_id": lease_id,
        "token": token,  # ONLY returned on acquire - caller MUST save this
        "ttl_seconds": ttl_seconds,
        "dry_run": dry_run,
    }


def release_lease(token: str, *, dry_run: bool = False) -> dict[str, Any]:
    """Release the Mission Control exclusive lease.

    Only the current owner with the correct token can release.

    Args:
        token: The token returned from acquire_lease.
        dry_run: If True, validate but don't persist.

    Returns:
        Dict with success status.

    Raises:
        PermissionError: If operator authority insufficient.
        RuntimeError: If token doesn't match current lease owner.
    """
    policy = _require_operator_authority(mutate=True, dry_run=dry_run)

    with _lease_lock():
        current = _read_lease_state()
        if not current:
            return {
                "success": False,
                "error": "NO_LEASE",
                "message": "No Mission Control lease exists to release",
            }

        if _is_expired(current):
            if not dry_run:
                _delete_lease_state()
            return {
                "success": False,
                "error": "LEASE_EXPIRED",
                "message": "Mission Control lease has already expired",
                "expired_at": current.expires_at,
            }

        if not secrets.compare_digest(current.token, token):
            return {
                "success": False,
                "error": "INVALID_TOKEN",
                "message": "Invalid token for lease release",
            }

        owner = current.owner
        lease_id = current.lease_id

        if not dry_run:
            _delete_lease_state()

    if not dry_run:
        op_policy.audit_record(
            tool="hermes_mission_control_lease_release",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=True,
            summary="Mission Control exclusive lease released",
            extra={
                "owner": owner,
                "lease_id": lease_id,
                "dry_run": False,
            },
        )

    return {
        "success": True,
        "message": "Mission Control lease released",
        "owner": owner,
        "lease_id": lease_id,
        "dry_run": dry_run,
    }


def verify_lease_token(token: str) -> dict[str, Any]:
    """Verify a live Mission Control lease bearer token without exposing it.

    This is an internal helper for lease-owned reconciliation actions. It is
    intentionally not registered as an MCP tool and never returns the token.
    """
    _require_operator_authority(mutate=False)
    if not isinstance(token, str) or not token:
        return {"success": False, "error": "LEASE_TOKEN_REQUIRED"}

    with _lease_lock():
        current = _read_lease_state()
        now = _now()
        if not current:
            return {"success": False, "error": "NO_ACTIVE_LEASE"}
        if _is_expired(current):
            return {
                "success": False,
                "error": "LEASE_EXPIRED",
                "owner": current.owner,
                "lease_id": current.lease_id,
                "expires_at": current.expires_at,
            }
        if not secrets.compare_digest(current.token, token):
            return {
                "success": False,
                "error": "INVALID_LEASE_TOKEN",
                "owner": current.owner,
                "lease_id": current.lease_id,
                "expires_at": current.expires_at,
            }
        return {
            "success": True,
            "owner": current.owner,
            "lease_id": current.lease_id,
            "issued_at": current.issued_at,
            "expires_at": current.expires_at,
            "renewal_count": current.renewal_count,
            "ttl_seconds": max(0, current.expires_at - now),
        }


def renew_lease(
    token: str,
    ttl_seconds: int | None = None,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Renew the Mission Control exclusive lease.

    Extends the lease expiry by the requested TTL (default: DEFAULT_LEASE_DURATION_SECONDS).
    Only the current owner with the correct token can renew.

    Args:
        token: The token returned from acquire_lease or a previous renew.
        ttl_seconds: Additional lease duration in seconds (default: 10 min, min: 1 min, max: 12 hours).
        dry_run: If True, validate but don't persist.

    Returns:
        Dict with success, updated lease details (owner, issued_at, expires_at, lease_id, renewal_count).
        The token is NOT returned on renew - caller keeps the existing token.

    Raises:
        PermissionError: If operator authority insufficient.
        RuntimeError: If token doesn't match current lease owner, lease expired, or max renewals reached.
    """
    policy = _require_operator_authority(mutate=True, dry_run=dry_run)

    # Validate TTL
    if ttl_seconds is None:
        ttl_seconds = DEFAULT_LEASE_DURATION_SECONDS
    ttl_seconds = max(MIN_LEASE_DURATION_SECONDS, min(int(ttl_seconds), MAX_LEASE_DURATION_SECONDS))

    with _lease_lock():
        current = _read_lease_state()
        if not current:
            return {
                "success": False,
                "error": "NO_LEASE",
                "message": "No Mission Control lease exists to renew",
            }

        if _is_expired(current):
            if not dry_run:
                _delete_lease_state()
            return {
                "success": False,
                "error": "LEASE_EXPIRED",
                "message": "Mission Control lease has already expired; cannot renew",
                "expired_at": current.expires_at,
            }

        if not secrets.compare_digest(current.token, token):
            return {
                "success": False,
                "error": "INVALID_TOKEN",
                "message": "Invalid token for lease renewal",
            }

        # Check renewal limit
        if current.renewal_count >= MAX_RENEWALS:
            return {
                "success": False,
                "error": "MAX_RENEWALS_REACHED",
                "message": f"Lease has been renewed {MAX_RENEWALS} times; must reacquire for continued access",
                "renewal_count": current.renewal_count,
                "max_renewals": MAX_RENEWALS,
            }

        owner = current.owner
        lease_id = current.lease_id
        issued_at = current.issued_at
        now = _now()
        new_expires_at = now + ttl_seconds
        new_renewal_count = current.renewal_count + 1

        new_state = LeaseState(
            owner=owner,
            token=current.token,  # Token stays the same
            issued_at=issued_at,
            expires_at=new_expires_at,
            lease_id=lease_id,
            renewal_count=new_renewal_count,
        )

        if not dry_run:
            _write_lease_state(new_state)
            try:
                op_policy.audit_record(
                    tool="hermes_mission_control_lease_renew",
                    level=policy.level,
                    apply_mode=policy.apply_mode,
                    dry_run=False,
                    success=True,
                    changed=True,
                    summary="Mission Control exclusive lease renewed",
                    extra={
                        "owner": owner,
                        "lease_id": lease_id,
                        "issued_at": issued_at,
                        "expires_at": new_expires_at,
                        "ttl_seconds": ttl_seconds,
                        "renewal_count": new_renewal_count,
                        "dry_run": False,
                    },
                )
            except Exception:
                # Renew is failure-atomic: if post-write auditing fails, rollback
                # to previous state (same token check protects against race)
                persisted = _read_lease_state()
                if (
                    persisted
                    and persisted.owner == owner
                    and secrets.compare_digest(persisted.token, token)
                    and persisted.renewal_count == new_renewal_count
                ):
                    # Write back the old state
                    old_state = LeaseState(
                        owner=owner,
                        token=current.token,
                        issued_at=issued_at,
                        expires_at=current.expires_at,
                        lease_id=lease_id,
                        renewal_count=current.renewal_count,
                    )
                    _write_lease_state(old_state)
                raise

    return {
        "success": True,
        "owner": owner,
        "issued_at": issued_at,
        "expires_at": new_expires_at,
        "lease_id": lease_id,
        "renewal_count": new_renewal_count,
        "ttl_seconds": ttl_seconds,
        "dry_run": dry_run,
    }


def handoff_lease(
    token: str,
    new_owner: str,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Hand off the Mission Control exclusive lease to another owner identity.

    Transfers lease ownership to a new identity while preserving the original token.
    This allows related workflows from the same logical operator to continue work
    without waiting for expiry. Only the current owner with the correct token can handoff.

    The handoff preserves the lease's original issued_at and lease_id, resets renewal_count,
    and extends expiry by the default TTL. The token remains unchanged so the new owner
    can renew or release.

    Args:
        token: The token returned from acquire_lease or a previous renew/handoff.
        new_owner: The new owner identity to transfer the lease to.
        dry_run: If True, validate but don't persist.

    Returns:
        Dict with success, updated lease details (new_owner, issued_at, expires_at, lease_id).
        The token is NOT returned - caller keeps the existing token.

    Raises:
        PermissionError: If operator authority insufficient.
        RuntimeError: If token doesn't match current lease owner, lease expired, or same owner.
    """
    policy = _require_operator_authority(mutate=True, dry_run=dry_run)

    new_owner = _sanitize_owner(new_owner)

    with _lease_lock():
        current = _read_lease_state()
        if not current:
            return {
                "success": False,
                "error": "NO_LEASE",
                "message": "No Mission Control lease exists to handoff",
            }

        if _is_expired(current):
            if not dry_run:
                _delete_lease_state()
            return {
                "success": False,
                "error": "LEASE_EXPIRED",
                "message": "Mission Control lease has already expired; cannot handoff",
                "expired_at": current.expires_at,
            }

        if not secrets.compare_digest(current.token, token):
            return {
                "success": False,
                "error": "INVALID_TOKEN",
                "message": "Invalid token for lease handoff",
            }

        if current.owner == new_owner:
            return {
                "success": False,
                "error": "SAME_OWNER",
                "message": "Lease is already owned by the requested identity; use renew instead",
                "current_owner": current.owner,
            }

        owner = new_owner
        lease_id = current.lease_id
        issued_at = current.issued_at
        now = _now()
        new_expires_at = now + DEFAULT_LEASE_DURATION_SECONDS

        new_state = LeaseState(
            owner=owner,
            token=current.token,  # Token stays the same
            issued_at=issued_at,
            expires_at=new_expires_at,
            lease_id=lease_id,
            renewal_count=0,  # Reset renewal count on handoff
        )

        if not dry_run:
            _write_lease_state(new_state)
            try:
                op_policy.audit_record(
                    tool="hermes_mission_control_lease_handoff",
                    level=policy.level,
                    apply_mode=policy.apply_mode,
                    dry_run=False,
                    success=True,
                    changed=True,
                    summary="Mission Control exclusive lease handed off",
                    extra={
                        "previous_owner": current.owner,
                        "new_owner": owner,
                        "lease_id": lease_id,
                        "issued_at": issued_at,
                        "expires_at": new_expires_at,
                        "dry_run": False,
                    },
                )
            except Exception:
                # Handoff is failure-atomic: rollback to previous state
                persisted = _read_lease_state()
                if (
                    persisted
                    and persisted.owner == owner
                    and secrets.compare_digest(persisted.token, token)
                    and persisted.renewal_count == 0
                ):
                    old_state = LeaseState(
                        owner=current.owner,
                        token=current.token,
                        issued_at=issued_at,
                        expires_at=current.expires_at,
                        lease_id=lease_id,
                        renewal_count=current.renewal_count,
                    )
                    _write_lease_state(old_state)
                raise

    return {
        "success": True,
        "owner": owner,
        "previous_owner": current.owner,
        "issued_at": issued_at,
        "expires_at": new_expires_at,
        "lease_id": lease_id,
        "renewal_count": 0,
        "ttl_seconds": DEFAULT_LEASE_DURATION_SECONDS,
        "dry_run": dry_run,
    }


def verify_lease(
    owner: str | None = None,
    *,
    require_owner_match: bool = False,
) -> dict[str, Any]:
    """Verify/return Mission Control lease status.

    Reports owner match and TTL/expiry without leaking the token.

    Args:
        owner: Optional owner identity to check against current lease.
        require_owner_match: If True, treat owner mismatch as failure.

    Returns:
        Dict with lease status including owner match, TTL, expiry.
        Never returns the token.
    """
    _policy, may_reap = _require_lease_status_authority()

    current = _read_lease_state()
    now = _now()

    if not current:
        return {
            "success": True,
            "has_lease": False,
            "message": "No Mission Control lease exists",
            "owner_match": None,
            "ttl_seconds": 0,
            "expires_at": None,
        }

    expired = _is_expired(current)
    if expired:
        # Lease exists but expired - report as no lease. The record is only
        # reaped when the caller holds the broad verb; a narrow lease-status
        # caller stays purely read-only and leaves the stale record in place
        # for the next broadly-authorized reader (or the acquire path, which
        # reacquires over an expired lease anyway).
        if may_reap:
            _delete_lease_state()
        return {
            "success": True,
            "has_lease": False,
            "message": "Mission Control lease has expired",
            "owner_match": None,
            "ttl_seconds": 0,
            "expires_at": None,
            "was_expired": True,
            "expired_lease_id": current.lease_id,
            "expired_owner": current.owner,
            "expired_at": current.expires_at,
            "expired_record_reaped": may_reap,
        }

    # Valid lease exists
    owner_match = (owner is not None) and (current.owner == owner)

    if require_owner_match and owner is not None and not owner_match:
        return {
            "success": False,
            "error": "OWNER_MISMATCH",
            "message": "Current lease held by different owner",
            "current_owner": current.owner,
            "requested_owner": owner,
            "has_lease": True,
            "owner_match": False,
            "ttl_seconds": max(0, current.expires_at - now),
            "expires_at": current.expires_at,
            "lease_id": current.lease_id,
        }

    return {
        "success": True,
        "has_lease": True,
        "owner": current.owner,
        "owner_match": owner_match,
        "ttl_seconds": max(0, current.expires_at - now),
        "expires_at": current.expires_at,
        "issued_at": current.issued_at,
        "lease_id": current.lease_id,
        "requested_owner": owner,
    }


# MCP tool wrappers

def hermes_mission_control_lease_acquire(
    owner: str | None = None,
    ttl_seconds: int | None = None,
    dry_run: bool = False,
) -> str:
    """Acquire the local Mission Control coordination lease (temporary, bounded).

    This is an advisory mutual-exclusion marker whose only purpose is to stop
    the staggered Mission Control schedulers from running at the same time. A
    successful call writes one small JSON record under ~/.hermes/operator-leases
    on this host and returns an opaque release token that the caller keeps so it
    can release the lease afterwards. Holding the lease grants no additional
    permissions or authority.

    Scope and limits:
    - Local and closed-world: it touches one lease file on this machine. It
      makes no network calls and reaches no external service or third party.
    - Non-destructive: it does not read, alter, or delete user content, files,
      credentials, secrets, policy, authority grants, schedules, or any other
      unrelated state. Only the lease record itself is written.
    - Bounded and self-expiring: ttl_seconds defaults to 3600 and is clamped to
      a 60 second minimum and a 43200 second (12 hour) maximum. An expired
      lease is reclaimable automatically; no manual cleanup is required.
    - Additive only: if the lease is already held and unexpired, nothing is
      written and the call reports success=false with the current holder.
    - dry_run=true validates the request and persists nothing: no lease is
      created, no token is issued, and any existing lease is left untouched.

    Args:
        owner: Owner identity (defaults to current session/OAuth identity).
        ttl_seconds: Lease duration in seconds (default 3600, min 60, max 43200).
        dry_run: Validate only; persist nothing.

    Returns:
        JSON with lease details, including the release token on a successful
        real acquire only. The token is never returned by the status tool.
    """
    try:
        result = acquire_lease(owner=owner, ttl_seconds=ttl_seconds, dry_run=dry_run)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="LEASE_ACQUIRE_ERROR",
                suggested_action="Check operator policy and lease state.",
            ),
            indent=2,
        )


def hermes_mission_control_lease_release(token: str, dry_run: bool = False) -> str:
    """Release the local Mission Control coordination lease.

    Ends the temporary advisory lease created by
    hermes_mission_control_lease_acquire by clearing that one lease record under
    ~/.hermes/operator-leases on this host. Only the current holder, presenting
    the release token returned by acquire, can release it; a missing or wrong
    token changes nothing.

    Scope and limits:
    - Local and closed-world: it touches one lease file on this machine and
      makes no network calls to any external service.
    - Non-destructive: it deletes no user data and alters no files, content,
      credentials, secrets, policy, authority grants, schedules, or other
      unrelated state. Clearing the lease is the normal end of the lease
      lifecycle and is equivalent to letting its TTL expire on its own.
    - Idempotent: releasing an already-released or already-expired lease
      reports success=false and makes no further change.
    - dry_run=true validates the token and persists nothing: the lease is left
      exactly as it was.

    Args:
        token: The release token returned from hermes_mission_control_lease_acquire.
        dry_run: Validate only; persist nothing.

    Returns:
        JSON with release status.
    """
    try:
        result = release_lease(token=token, dry_run=dry_run)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="LEASE_RELEASE_ERROR",
                suggested_action="Provide the correct token from lease acquire.",
            ),
            indent=2,
        )


def hermes_mission_control_lease_status(
    owner: str | None = None,
    require_owner_match: bool = False,
) -> str:
    """Report Mission Control coordination lease status (read-only).

    Reports whether a lease is currently held, by whom, its remaining TTL and
    expiry, and whether it matches an optional expected owner. The release token
    is never returned.

    Scope and limits:
    - Local and closed-world: it reads one lease file on this machine and makes
      no network calls to any external service.
    - Non-destructive: it changes no user content, files, credentials, secrets,
      policy, authority grants, or schedules. The only write it ever performs is
      routine cleanup of a lease record that has already expired.

    Args:
        owner: Optional owner identity to check against the current lease.
        require_owner_match: If True, report an error on owner mismatch.

    Returns:
        JSON with lease status (never includes the release token).
    """
    try:
        result = verify_lease(owner=owner, require_owner_match=require_owner_match)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="LEASE_STATUS_ERROR",
                suggested_action="Check operator policy.",
            ),
            indent=2,
        )


def hermes_mission_control_lease_renew(
    token: str,
    ttl_seconds: int | None = None,
    dry_run: bool = False,
) -> str:
    """Renew the local Mission Control coordination lease.

    Extends the lease expiry by the requested TTL (default: 10 minutes).
    Only the current holder, presenting the release token returned by acquire,
    can renew it; a missing or wrong token changes nothing.

    Scope and limits:
    - Local and closed-world: it touches one lease file on this machine.
    - Non-destructive: it extends the existing lease record.
    - Bounded: max 12 renewals (2 hours total) before requiring reacquisition.
    - dry_run=true validates the token and persists nothing.

    Args:
        token: The release token returned from hermes_mission_control_lease_acquire.
        ttl_seconds: Additional lease duration in seconds (default 600, min 60, max 43200).
        dry_run: Validate only; persist nothing.

    Returns:
        JSON with lease details (token is NOT returned on renew).
    """
    try:
        result = renew_lease(token=token, ttl_seconds=ttl_seconds, dry_run=dry_run)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="LEASE_RENEW_ERROR",
                suggested_action="Provide the correct token from lease acquire.",
            ),
            indent=2,
        )


def hermes_mission_control_lease_handoff(
    token: str,
    new_owner: str,
    dry_run: bool = False,
) -> str:
    """Hand off the local Mission Control coordination lease to another owner.

    Transfers lease ownership to a new identity while preserving the original token.
    This allows related workflows from the same logical operator to continue work
    without waiting for expiry. Only the current holder with the correct token can handoff.

    Scope and limits:
    - Local and closed-world: it touches one lease file on this machine.
    - Non-destructive: it modifies the existing lease record.
    - Token-preserving: the same token works for the new owner to renew/release.
    - dry_run=true validates the token and persists nothing.

    Args:
        token: The release token returned from hermes_mission_control_lease_acquire.
        new_owner: The new owner identity to transfer the lease to.
        dry_run: Validate only; persist nothing.

    Returns:
        JSON with lease details including new owner (token is NOT returned).
    """
    try:
        result = handoff_lease(token=token, new_owner=new_owner, dry_run=dry_run)
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="LEASE_HANDOFF_ERROR",
                suggested_action="Provide the correct token from lease acquire and a valid new owner.",
            ),
            indent=2,
        )