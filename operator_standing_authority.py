"""Durable standing-low-risk authorization for Hermes-GPT operator.

This module implements standing authority for LOW-risk operations:
- Immutable, revocable, locally resolved
- Policy-hash/version bound (invalidates on template change)
- NO time expiry - elapsed wall-clock time alone does not invalidate
- Valid until explicit revocation, policy/template version/hash change,
  material risk/scope increase, containment failure, or guardrail breach
- Separate fields for authorization validity vs operational task deadline/watchdog
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from operator_risk import (
    RISK_BASED_AUTHORITY_ENABLED_ENV,
    RiskClass,
    RiskDecision,
    RiskFactors,
    RiskReason,
    check_escalation,
    classify_risk,
    compute_risk_factors_from_session,
    risk_based_authority_enabled,
)
from operator_sessions import SESSION_ROOT_ENV, _connect, session_root


# ============================================================================
# Standing Authority Data Structures
# ============================================================================

@dataclass(frozen=True)
class StandingAuthority:
    """Durable standing authorization for LOW-risk operations.

    Key properties:
    - Immutable once created (frozen dataclass)
    - No expiration time - valid until explicit revocation or invalidation trigger
    - Bound to policy template hash/version
    - Revocable by human operator
    - Locally resolved (no remote trust)
    - Separate operational_deadline for watchdog/runaway controls
    """
    authority_id: str
    policy_template: str
    policy_template_hash: str
    policy_template_version: int
    risk_factors_hash: str
    approved_risk_factors: RiskFactors
    risk_decision: RiskDecision  # Must be LOW risk
    created_at: int
    created_by: str  # Human who approved (telegram:user_id, localhost, cli)
    revoked_at: int | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None

    # Operational watchdog deadline (SEPARATE from authorization validity)
    # This is a runaway-process control, NOT an authorization expiry
    operational_deadline: int | None = None  # Unix timestamp, or None for no deadline
    operational_deadline_reason: str | None = None

    # Containment verification
    containment_verified_at: int | None = None
    containment_verified_by: str | None = None

    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_valid(self, *, current_time: int | None = None) -> tuple[bool, str | None]:
        """Check if standing authority is currently valid.

        Returns (is_valid, reason_if_invalid).
        Elapsed wall-clock time alone NEVER invalidates.
        """
        if self.is_revoked():
            return False, f"Revoked at {self.revoked_at} by {self.revoked_by}: {self.revocation_reason}"

        # Operational deadlines are watchdog controls, not authorization expiry.
        return True, None

    def operational_deadline_exceeded(self, *, current_time: int | None = None) -> bool:
        if self.operational_deadline is None:
            return False
        now = int(time.time()) if current_time is None else int(current_time)
        return now > self.operational_deadline

    def authorization_validity_summary(self) -> str:
        """Human-readable summary of authorization validity (not operational deadline)."""
        if self.is_revoked():
            return f"REVOKED: {self.revocation_reason} (at {datetime.fromtimestamp(self.revoked_at, tz=timezone.utc).isoformat()})"
        return f"STANDING: Valid until explicit revocation or policy/template change (approved {datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat()})"

    def operational_status_summary(self) -> str:
        """Human-readable summary of operational watchdog status."""
        if self.operational_deadline is None:
            return "No operational deadline set (no watchdog)"
        now = int(time.time())
        if now > self.operational_deadline:
            return f"OPERATIONAL DEADLINE EXCEEDED: {datetime.fromtimestamp(self.operational_deadline, tz=timezone.utc).isoformat()} (watchdog triggered)"
        remaining = self.operational_deadline - now
        return f"Operational deadline in {remaining}s ({datetime.fromtimestamp(self.operational_deadline, tz=timezone.utc).isoformat()})"

    def to_dict(self) -> dict[str, Any]:
        """Serialize for storage."""
        return {
            "authority_id": self.authority_id,
            "policy_template": self.policy_template,
            "policy_template_hash": self.policy_template_hash,
            "policy_template_version": self.policy_template_version,
            "risk_factors_hash": self.risk_factors_hash,
            "approved_risk_factors": self.approved_risk_factors.to_dict(),
            "risk_decision": {
                "risk_class": self.risk_decision.risk_class.value,
                "reasons": [
                    {"factor": r.factor, "detail": r.detail, "severity": r.severity.value}
                    for r in self.risk_decision.reasons
                ],
                "factors_hash": self.risk_decision.factors_hash,
                "standing_authority_eligible": self.risk_decision.standing_authority_eligible,
                "authority_bundle_eligible": self.risk_decision.authority_bundle_eligible,
                "requires_human_approval": self.risk_decision.requires_human_approval,
                "prohibited_reasons": list(self.risk_decision.prohibited_reasons),
            },
            "created_at": self.created_at,
            "created_by": self.created_by,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
            "revocation_reason": self.revocation_reason,
            "operational_deadline": self.operational_deadline,
            "operational_deadline_reason": self.operational_deadline_reason,
            "containment_verified_at": self.containment_verified_at,
            "containment_verified_by": self.containment_verified_by,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StandingAuthority":
        """Deserialize from storage."""
        rd = data["risk_decision"]
        risk_decision = RiskDecision(
            risk_class=RiskClass(rd["risk_class"]),
            reasons=tuple(
                RiskReason(r["factor"], r["detail"], RiskClass(r["severity"]))
                for r in rd["reasons"]
            ),
            factors_hash=rd["factors_hash"],
            standing_authority_eligible=rd["standing_authority_eligible"],
            authority_bundle_eligible=rd["authority_bundle_eligible"],
            requires_human_approval=rd["requires_human_approval"],
            prohibited_reasons=tuple(rd.get("prohibited_reasons", [])),
        )
        approved_risk_factors = RiskFactors.from_dict(data["approved_risk_factors"])
        if approved_risk_factors.compute_hash() != data["risk_factors_hash"]:
            raise StandingAuthorityInvalidatedError("Stored risk factors hash mismatch")
        return cls(
            authority_id=data["authority_id"],
            policy_template=data["policy_template"],
            policy_template_hash=data["policy_template_hash"],
            policy_template_version=data["policy_template_version"],
            risk_factors_hash=data["risk_factors_hash"],
            approved_risk_factors=approved_risk_factors,
            risk_decision=risk_decision,
            created_at=data["created_at"],
            created_by=data["created_by"],
            revoked_at=data.get("revoked_at"),
            revoked_by=data.get("revoked_by"),
            revocation_reason=data.get("revocation_reason"),
            operational_deadline=data.get("operational_deadline"),
            operational_deadline_reason=data.get("operational_deadline_reason"),
            containment_verified_at=data.get("containment_verified_at"),
            containment_verified_by=data.get("containment_verified_by"),
        )


# ============================================================================
# Storage
# ============================================================================

STANDING_AUTH_DB_NAME = "standing_authorities.sqlite3"
_active_pointer_name = "active_standing_authority_id"

_lock = threading.Lock()


def _standing_db_path(root: Path | None = None) -> Path:
    return (root or session_root()) / STANDING_AUTH_DB_NAME


def _active_pointer_path(root: Path | None = None) -> Path:
    return (root or session_root()) / _active_pointer_name


def _initialize_standing_db(connection: sqlite3.Connection) -> None:
    """Initialize standing authority tables."""
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS standing_authorities (
            authority_id TEXT PRIMARY KEY,
            canonical_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            policy_template TEXT NOT NULL,
            policy_template_hash TEXT NOT NULL,
            policy_template_version INTEGER NOT NULL,
            risk_factors_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_standing_template
            ON standing_authorities(policy_template);
        CREATE INDEX IF NOT EXISTS idx_standing_template_hash
            ON standing_authorities(policy_template_hash);
        """
    )


def _write_active_pointer(authority_id: str, *, root: Path | None = None) -> None:
    path = _active_pointer_path(root)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(authority_id, encoding="utf-8")
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ============================================================================
# Standing Authority Operations
# ============================================================================

class StandingAuthorityError(ValueError):
    """Base error for standing authority operations."""
    pass


class StandingAuthorityNotFoundError(StandingAuthorityError):
    pass


class StandingAuthorityRevokedError(StandingAuthorityError):
    pass


class StandingAuthorityInvalidatedError(StandingAuthorityError):
    """Raised when authority is invalidated due to policy/template change or escalation."""
    pass


class StandingAuthorityEscalationError(StandingAuthorityError):
    """Raised when requested operation escalates beyond standing authority."""
    pass


def create_standing_authority(
    risk_factors: RiskFactors,
    risk_decision: RiskDecision,
    *,
    created_by: str,
    operational_deadline: int | None = None,
    operational_deadline_reason: str | None = None,
    root: Path | None = None,
    authority_id: str | None = None,
    now: int | None = None,
) -> StandingAuthority:
    """Create a new standing authority after human approval.

    Requires:
    - risk_decision must be LOW risk
    - created_by must be a human identifier (not the session itself)
    """
    if not risk_based_authority_enabled():
        raise StandingAuthorityError("Risk-based authority feature is disabled")

    if risk_decision.risk_class != RiskClass.LOW:
        raise StandingAuthorityError(
            f"Standing authority only available for LOW risk, got {risk_decision.risk_class.value}"
        )

    if not risk_decision.standing_authority_eligible:
        raise StandingAuthorityError("Risk decision indicates standing authority not eligible")
    if risk_decision.factors_hash != risk_factors.compute_hash():
        raise StandingAuthorityError("Risk decision does not match supplied risk factors")

    current = int(time.time() if now is None else now)
    aid = authority_id or f"sa_{secrets.token_urlsafe(24)}"

    authority = StandingAuthority(
        authority_id=aid,
        policy_template=risk_factors.policy_template or "unknown",
        policy_template_hash=risk_factors.policy_template_hash or "",
        policy_template_version=risk_factors.policy_template_version or 1,
        risk_factors_hash=risk_factors.compute_hash(),
        approved_risk_factors=risk_factors,
        risk_decision=risk_decision,
        created_at=current,
        created_by=created_by,
        operational_deadline=operational_deadline,
        operational_deadline_reason=operational_deadline_reason,
    )

    canonical = json.dumps(authority.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    lock_claimed = False
    if risk_factors.single_writer_verified and risk_factors.writable_roots:
        from operator_worktree_lock import claim_writer_locks

        claim_writer_locks(aid, risk_factors.writable_roots, root=root, now=current)
        lock_claimed = True
    try:
        with _connect(root) as conn:
            _initialize_standing_db(conn)
            conn.execute(
                """INSERT INTO standing_authorities
                   (authority_id, canonical_json, created_at, policy_template,
                    policy_template_hash, policy_template_version, risk_factors_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    aid, canonical, current,
                    authority.policy_template,
                    authority.policy_template_hash,
                    authority.policy_template_version,
                    authority.risk_factors_hash,
                ),
            )
            _write_active_pointer(aid, root=root)
    except Exception:
        if lock_claimed:
            from operator_worktree_lock import release_writer_locks

            release_writer_locks(aid, risk_factors.writable_roots, root=root)
        raise

    return authority


def load_standing_authority(
    authority_id: str,
    *,
    root: Path | None = None,
) -> StandingAuthority:
    """Load a standing authority by ID."""
    with _connect(root) as conn:
        _initialize_standing_db(conn)
        row = conn.execute(
            "SELECT canonical_json FROM standing_authorities WHERE authority_id = ?",
            (authority_id,),
        ).fetchone()
    if row is None:
        raise StandingAuthorityNotFoundError(f"Standing authority {authority_id!r} not found")
    return StandingAuthority.from_dict(json.loads(row["canonical_json"]))


def list_standing_authorities(
    *,
    root: Path | None = None,
    policy_template: str | None = None,
    include_revoked: bool = False,
) -> list[StandingAuthority]:
    """List all standing authorities, optionally filtered by template."""
    with _connect(root) as conn:
        _initialize_standing_db(conn)
        if policy_template:
            rows = conn.execute(
                "SELECT canonical_json FROM standing_authorities WHERE policy_template = ?",
                (policy_template,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT canonical_json FROM standing_authorities"
            ).fetchall()

    authorities = []
    for row in rows:
        auth = StandingAuthority.from_dict(json.loads(row["canonical_json"]))
        if not include_revoked and auth.is_revoked():
            continue
        authorities.append(auth)
    return authorities


def get_active_standing_authority(
    *,
    root: Path | None = None,
    now: int | None = None,
) -> StandingAuthority | None:
    """Get the currently active standing authority, if valid."""
    try:
        pointer_path = _active_pointer_path(root)
        if not pointer_path.is_file():
            return None
        aid = pointer_path.read_text(encoding="utf-8").strip()
        if not aid:
            return None
    except Exception:
        return None

    try:
        auth = load_standing_authority(aid, root=root)
    except StandingAuthorityNotFoundError:
        return None

    # Check validity (but NOT operational deadline - that's separate)
    valid, reason = auth.is_valid(current_time=now)
    if not valid and "Operational deadline" not in (reason or ""):
        # Authorization invalid (revoked or policy change) - not just watchdog
        return None

    return auth


def revoke_standing_authority(
    authority_id: str,
    *,
    revoked_by: str,
    reason: str,
    root: Path | None = None,
    now: int | None = None,
) -> bool:
    """Revoke a standing authority immediately.

    This is the primary invalidation mechanism - explicit human revocation.
    """
    current = int(time.time() if now is None else now)

    # Load first to verify it exists
    auth = load_standing_authority(authority_id, root=root)

    if auth.is_revoked():
        return False  # Already revoked

    # Create revoked version
    revoked = StandingAuthority(
        authority_id=auth.authority_id,
        policy_template=auth.policy_template,
        policy_template_hash=auth.policy_template_hash,
        policy_template_version=auth.policy_template_version,
        risk_factors_hash=auth.risk_factors_hash,
        approved_risk_factors=auth.approved_risk_factors,
        risk_decision=auth.risk_decision,
        created_at=auth.created_at,
        created_by=auth.created_by,
        revoked_at=current,
        revoked_by=revoked_by,
        revocation_reason=reason,
        operational_deadline=auth.operational_deadline,
        operational_deadline_reason=auth.operational_deadline_reason,
        containment_verified_at=auth.containment_verified_at,
        containment_verified_by=auth.containment_verified_by,
    )

    canonical = json.dumps(revoked.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    with _connect(root) as conn:
        _initialize_standing_db(conn)
        conn.execute(
            "UPDATE standing_authorities SET canonical_json = ? WHERE authority_id = ?",
            (canonical, authority_id),
        )
    if auth.approved_risk_factors.single_writer_verified and auth.approved_risk_factors.writable_roots:
        from operator_worktree_lock import release_writer_locks

        release_writer_locks(
            authority_id,
            auth.approved_risk_factors.writable_roots,
            root=root,
        )

    return True


def check_standing_authority_validity(
    authority: StandingAuthority,
    current_risk_factors: RiskFactors,
    *,
    current_time: int | None = None,
) -> tuple[bool, str | None]:
    """Check if a standing authority remains valid given current risk factors.

    This is the core re-validation logic that runs on each use. It checks:
    1. Explicit revocation
    2. Policy/template hash or version change
    3. Material risk/scope increase (escalation)
    4. Containment failure/weakening
    5. Guardrail breach (prohibited factors now present)

    Returns (is_valid, reason_if_invalid).
    Elapsed wall-clock time alone NEVER invalidates.
    """
    # 1. Check explicit revocation
    if authority.is_revoked():
        return False, f"Explicitly revoked: {authority.revocation_reason}"

    # 2. Check policy/template hash change
    if current_risk_factors.policy_template_hash != authority.policy_template_hash:
        return False, f"Policy template hash changed (was {authority.policy_template_hash[:16]}..., now {current_risk_factors.policy_template_hash[:16]}...)"

    # 3. Check policy/template version change
    if current_risk_factors.policy_template_version != authority.policy_template_version:
        return False, f"Policy template version changed (was v{authority.policy_template_version}, now v{current_risk_factors.policy_template_version})"

    # 4. Reclassify and compare against the fully persisted approved facts.
    current_decision = classify_risk(current_risk_factors)
    if current_decision.risk_class == RiskClass.PROHIBITED:
        return False, f"Guardrail breach: {', '.join(current_decision.prohibited_reasons)}"
    escalation = check_escalation(authority.approved_risk_factors, current_risk_factors)
    if escalation.escalated or current_decision.risk_class != RiskClass.LOW:
        return False, f"Risk escalation detected: {escalation.summary()}"
    if current_risk_factors.containment_weakened or not current_risk_factors.containment_verified:
        return False, "Containment weakened or is no longer verified"
    if current_risk_factors.compute_hash() != authority.risk_factors_hash:
        return False, "Approved scope or immutable risk facts changed"
    if current_risk_factors.single_writer_verified and current_risk_factors.writable_roots:
        from operator_worktree_lock import assert_writer_locks
        try:
            assert_writer_locks(authority.authority_id, current_risk_factors.writable_roots)
        except ValueError:
            return False, "Single-writer ownership is missing or held by another authority"

    # All checks passed - authorization remains valid
    # Operational deadline is checked separately (watchdog)
    return True, None


def set_operational_deadline(
    authority_id: str,
    deadline: int,
    reason: str,
    *,
    root: Path | None = None,
) -> StandingAuthority:
    """Set or update an operational watchdog deadline.

    This is SEPARATE from authorization validity. It's a runaway-process control.
    """
    auth = load_standing_authority(authority_id, root=root)

    updated = StandingAuthority(
        authority_id=auth.authority_id,
        policy_template=auth.policy_template,
        policy_template_hash=auth.policy_template_hash,
        policy_template_version=auth.policy_template_version,
        risk_factors_hash=auth.risk_factors_hash,
        approved_risk_factors=auth.approved_risk_factors,
        risk_decision=auth.risk_decision,
        created_at=auth.created_at,
        created_by=auth.created_by,
        revoked_at=auth.revoked_at,
        revoked_by=auth.revoked_by,
        revocation_reason=auth.revocation_reason,
        operational_deadline=deadline,
        operational_deadline_reason=reason,
        containment_verified_at=auth.containment_verified_at,
        containment_verified_by=auth.containment_verified_by,
    )

    canonical = json.dumps(updated.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    with _connect(root) as conn:
        _initialize_standing_db(conn)
        conn.execute(
            "UPDATE standing_authorities SET canonical_json = ? WHERE authority_id = ?",
            (canonical, authority_id),
        )

    return updated


def clear_operational_deadline(
    authority_id: str,
    *,
    root: Path | None = None,
) -> StandingAuthority:
    """Clear an operational watchdog deadline without changing authorization."""
    auth = load_standing_authority(authority_id, root=root)
    updated = StandingAuthority(
        authority_id=auth.authority_id,
        policy_template=auth.policy_template,
        policy_template_hash=auth.policy_template_hash,
        policy_template_version=auth.policy_template_version,
        risk_factors_hash=auth.risk_factors_hash,
        approved_risk_factors=auth.approved_risk_factors,
        risk_decision=auth.risk_decision,
        created_at=auth.created_at,
        created_by=auth.created_by,
        revoked_at=auth.revoked_at,
        revoked_by=auth.revoked_by,
        revocation_reason=auth.revocation_reason,
        operational_deadline=None,
        operational_deadline_reason=None,
        containment_verified_at=auth.containment_verified_at,
        containment_verified_by=auth.containment_verified_by,
    )
    canonical = json.dumps(updated.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with _connect(root) as conn:
        _initialize_standing_db(conn)
        conn.execute(
            "UPDATE standing_authorities SET canonical_json = ? WHERE authority_id = ?",
            (canonical, authority_id),
        )
    return updated


def verify_containment(
    authority_id: str,
    *,
    verified_by: str,
    root: Path | None = None,
    now: int | None = None,
) -> StandingAuthority:
    """Record a containment verification."""
    current = int(time.time() if now is None else now)
    auth = load_standing_authority(authority_id, root=root)

    updated = StandingAuthority(
        authority_id=auth.authority_id,
        policy_template=auth.policy_template,
        policy_template_hash=auth.policy_template_hash,
        policy_template_version=auth.policy_template_version,
        risk_factors_hash=auth.risk_factors_hash,
        approved_risk_factors=auth.approved_risk_factors,
        risk_decision=auth.risk_decision,
        created_at=auth.created_at,
        created_by=auth.created_by,
        revoked_at=auth.revoked_at,
        revoked_by=auth.revoked_by,
        revocation_reason=auth.revocation_reason,
        operational_deadline=auth.operational_deadline,
        operational_deadline_reason=auth.operational_deadline_reason,
        containment_verified_at=current,
        containment_verified_by=verified_by,
    )

    canonical = json.dumps(updated.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    with _connect(root) as conn:
        _initialize_standing_db(conn)
        conn.execute(
            "UPDATE standing_authorities SET canonical_json = ? WHERE authority_id = ?",
            (canonical, authority_id),
        )

    return updated