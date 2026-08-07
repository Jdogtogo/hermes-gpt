"""Bounded Authority Bundle for MATERIAL-risk operations.

This module implements the Authority Bundle pattern for MATERIAL-risk operations:
- Immutable, revocable, locally resolved
- Reusable ONLY inside exact approved scope
- One human approval for the bundle
- Actions inside proceed without repeated approval until:
  - Completion
  - Explicit revocation
  - Scope/risk change
  - Guardrail breach
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
from operator_sessions import _connect, session_root


# ============================================================================
# Authority Bundle Data Structures
# ============================================================================

@dataclass(frozen=True)
class AuthorityBundle:
    """Bounded immutable authority bundle for MATERIAL-risk operations.

    Key properties:
    - Immutable once created (frozen dataclass)
    - Single human approval for the entire bundle
    - Exact scope binding - reuse ONLY inside approved boundaries
    - No time expiry for authorization (operational deadline is separate)
    - Revocable by human operator
    - Locally resolved (no remote trust)
    - Tracks completion status
    """
    bundle_id: str
    policy_template: str
    policy_template_hash: str
    policy_template_version: int
    risk_factors_hash: str
    approved_risk_factors: RiskFactors
    risk_decision: RiskDecision  # Must be MATERIAL risk
    approved_scope: dict[str, Any]  # Exact approved scope (roots, verbs, egress, etc.)
    required_deliverables: tuple[str, ...]
    verified_deliverables: tuple[str, ...]
    created_at: int
    created_by: str  # Human who approved (telegram:user_id, localhost, cli)
    revoked_at: int | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None
    completed_at: int | None = None
    completed_by: str | None = None

    # Operational watchdog deadline (SEPARATE from authorization validity)
    operational_deadline: int | None = None  # Unix timestamp, or None for no deadline
    operational_deadline_reason: str | None = None

    # Containment verification
    containment_verified_at: int | None = None
    containment_verified_by: str | None = None

    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def is_completed(self) -> bool:
        return self.completed_at is not None

    def is_valid(self, *, current_time: int | None = None) -> tuple[bool, str | None]:
        """Check if authority bundle is currently valid for use.

        Returns (is_valid, reason_if_invalid).
        Elapsed wall-clock time alone NEVER invalidates authorization.
        """
        if self.is_revoked():
            return False, f"Revoked at {self.revoked_at} by {self.revoked_by}: {self.revocation_reason}"

        if self.is_completed():
            return False, f"Completed at {self.completed_at} by {self.completed_by}"

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
        if self.is_completed():
            return f"COMPLETED: (at {datetime.fromtimestamp(self.completed_at, tz=timezone.utc).isoformat()})"
        return f"BUNDLE: Valid until completion, revocation, or scope/risk change (approved {datetime.fromtimestamp(self.created_at, tz=timezone.utc).isoformat()})"

    def operational_status_summary(self) -> str:
        """Human-readable summary of operational watchdog status."""
        if self.operational_deadline is None:
            return "No operational deadline set (no watchdog)"
        now = int(time.time())
        if now > self.operational_deadline:
            return f"OPERATIONAL DEADLINE EXCEEDED: {datetime.fromtimestamp(self.operational_deadline, tz=timezone.utc).isoformat()} (watchdog triggered)"
        remaining = self.operational_deadline - now
        return f"Operational deadline in {remaining}s ({datetime.fromtimestamp(self.operational_deadline, tz=timezone.utc).isoformat()})"

    def scope_summary(self) -> str:
        """Human-readable summary of approved scope."""
        parts = []
        if self.approved_scope.get("readable_roots"):
            parts.append(f"read: {len(self.approved_scope['readable_roots'])} roots")
        if self.approved_scope.get("writable_roots"):
            parts.append(f"write: {len(self.approved_scope['writable_roots'])} roots")
        if self.approved_scope.get("verbs"):
            verb_count = sum(len(v) for v in self.approved_scope["verbs"].values())
            parts.append(f"verbs: {verb_count} actions")
        if self.approved_scope.get("egress_hosts"):
            parts.append(f"egress: {len(self.approved_scope['egress_hosts'])} hosts")
        if self.approved_scope.get("service_units"):
            parts.append(f"services: {len(self.approved_scope['service_units'])} units")
        return "; ".join(parts) if parts else "empty scope"

    def to_dict(self) -> dict[str, Any]:
        """Serialize for storage."""
        return {
            "bundle_id": self.bundle_id,
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
            "approved_scope": self.approved_scope,
            "required_deliverables": list(self.required_deliverables),
            "verified_deliverables": list(self.verified_deliverables),
            "created_at": self.created_at,
            "created_by": self.created_by,
            "revoked_at": self.revoked_at,
            "revoked_by": self.revoked_by,
            "revocation_reason": self.revocation_reason,
            "completed_at": self.completed_at,
            "completed_by": self.completed_by,
            "operational_deadline": self.operational_deadline,
            "operational_deadline_reason": self.operational_deadline_reason,
            "containment_verified_at": self.containment_verified_at,
            "containment_verified_by": self.containment_verified_by,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthorityBundle":
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
            raise AuthorityBundleEscalationError("Stored risk factors hash mismatch")
        return cls(
            bundle_id=data["bundle_id"],
            policy_template=data["policy_template"],
            policy_template_hash=data["policy_template_hash"],
            policy_template_version=data["policy_template_version"],
            risk_factors_hash=data["risk_factors_hash"],
            approved_risk_factors=approved_risk_factors,
            risk_decision=risk_decision,
            approved_scope=data["approved_scope"],
            required_deliverables=tuple(data.get("required_deliverables", ())),
            verified_deliverables=tuple(data.get("verified_deliverables", ())),
            created_at=data["created_at"],
            created_by=data["created_by"],
            revoked_at=data.get("revoked_at"),
            revoked_by=data.get("revoked_by"),
            revocation_reason=data.get("revocation_reason"),
            completed_at=data.get("completed_at"),
            completed_by=data.get("completed_by"),
            operational_deadline=data.get("operational_deadline"),
            operational_deadline_reason=data.get("operational_deadline_reason"),
            containment_verified_at=data.get("containment_verified_at"),
            containment_verified_by=data.get("containment_verified_by"),
        )


# ============================================================================
# Scope Matching
# ============================================================================

@dataclass(frozen=True)
class ScopeCheckResult:
    """Result of checking if an operation is within approved bundle scope."""
    within_scope: bool
    reason: str | None = None
    escalation: str | None = None  # If outside scope, what would be needed


def check_scope(
    bundle: AuthorityBundle,
    requested_roots: tuple[Path, ...] = (),
    requested_writable: tuple[Path, ...] = (),
    requested_verbs: dict[str, list[str]] | None = None,
    requested_egress: tuple[str, ...] = (),
    requested_services: tuple[str, ...] = (),
) -> ScopeCheckResult:
    """Check if requested operation is within the bundle's approved scope.

    This is the core scope enforcement - operations must stay within the
    exact boundaries approved in the bundle. Any deviation requires
    a new bundle or escalation.
    """
    scope = bundle.approved_scope

    # Check readable roots
    approved_readable = tuple(Path(p) for p in scope.get("readable_roots", []))
    for root in requested_roots:
        if not _path_under_any(root, approved_readable):
            return ScopeCheckResult(
                within_scope=False,
                reason=f"Requested readable root {root} not within approved readable roots",
                escalation="New authority bundle required with expanded readable roots",
            )

    # Check writable roots
    approved_writable = tuple(Path(p) for p in scope.get("writable_roots", []))
    for root in requested_writable:
        if not _path_under_any(root, approved_writable):
            return ScopeCheckResult(
                within_scope=False,
                reason=f"Requested writable root {root} not within approved writable roots",
                escalation="New authority bundle required with expanded writable roots",
            )

    # Check verbs
    approved_verbs = scope.get("verbs", {})
    if requested_verbs:
        for resource, actions in requested_verbs.items():
            approved_actions = set(approved_verbs.get(resource, []))
            for action in actions:
                if action not in approved_actions:
                    return ScopeCheckResult(
                        within_scope=False,
                        reason=f"Verb {resource}:{action} not in approved scope",
                        escalation=f"New authority bundle required with {resource}:{action}",
                    )

    # Check egress
    approved_egress = set(scope.get("egress_hosts", []))
    for host in requested_egress:
        if host not in approved_egress:
            return ScopeCheckResult(
                within_scope=False,
                reason=f"Egress host {host} not in approved egress hosts",
                escalation="New authority bundle required with expanded egress",
            )

    # Check services
    approved_services = set(scope.get("service_units", []))
    for service in requested_services:
        if service not in approved_services:
            return ScopeCheckResult(
                within_scope=False,
                reason=f"Service unit {service} not in approved service units",
                escalation="New authority bundle required with expanded service units",
            )

    return ScopeCheckResult(within_scope=True)


def _path_under_any(path: Path, roots: tuple[Path, ...]) -> bool:
    """Check if path is under any of the given roots."""
    try:
        resolved = path.resolve()
    except Exception:
        return False
    for root in roots:
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


# ============================================================================
# Storage
# ============================================================================

BUNDLE_DB_NAME = "authority_bundles.sqlite3"
_active_pointer_name = "active_authority_bundle_id"

_lock = threading.Lock()


def _bundle_db_path(root: Path | None = None) -> Path:
    return (root or session_root()) / BUNDLE_DB_NAME


def _active_pointer_path(root: Path | None = None) -> Path:
    return (root or session_root()) / _active_pointer_name


def _initialize_bundle_db(connection: sqlite3.Connection) -> None:
    """Initialize authority bundle tables."""
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS authority_bundles (
            bundle_id TEXT PRIMARY KEY,
            canonical_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            policy_template TEXT NOT NULL,
            policy_template_hash TEXT NOT NULL,
            policy_template_version INTEGER NOT NULL,
            risk_factors_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'  -- active, revoked, completed
        );
        CREATE INDEX IF NOT EXISTS idx_bundle_template
            ON authority_bundles(policy_template);
        CREATE INDEX IF NOT EXISTS idx_bundle_template_hash
            ON authority_bundles(policy_template_hash);
        CREATE INDEX IF NOT EXISTS idx_bundle_status
            ON authority_bundles(status);
        """
    )


def _write_active_pointer(bundle_id: str, *, root: Path | None = None) -> None:
    path = _active_pointer_path(root)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    tmp.write_text(bundle_id, encoding="utf-8")
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ============================================================================
# Authority Bundle Operations
# ============================================================================

class AuthorityBundleError(ValueError):
    """Base error for authority bundle operations."""
    pass


class AuthorityBundleNotFoundError(AuthorityBundleError):
    pass


class AuthorityBundleRevokedError(AuthorityBundleError):
    pass


class AuthorityBundleCompletedError(AuthorityBundleError):
    pass


class AuthorityBundleDeliverableError(AuthorityBundleError):
    """Raised when completion evidence is missing or invalid."""
    pass


class AuthorityBundleScopeError(AuthorityBundleError):
    """Raised when an operation is outside the bundle's approved scope."""
    pass


class AuthorityBundleEscalationError(AuthorityBundleError):
    """Raised when requested operation escalates beyond bundle scope."""
    pass


def create_authority_bundle(
    risk_factors: RiskFactors,
    risk_decision: RiskDecision,
    approved_scope: dict[str, Any],
    *,
    created_by: str,
    required_deliverables: tuple[str, ...] = (),
    operational_deadline: int | None = None,
    operational_deadline_reason: str | None = None,
    root: Path | None = None,
    bundle_id: str | None = None,
    now: int | None = None,
) -> AuthorityBundle:
    """Create a new authority bundle after human approval.

    Requires:
    - risk_decision must be MATERIAL risk (or LOW, which can also use bundles)
    - created_by must be a human identifier (not the session itself)
    - approved_scope must exactly match what was presented to the human
    """
    if not risk_based_authority_enabled():
        raise AuthorityBundleError("Risk-based authority feature is disabled")

    if risk_decision.risk_class not in (RiskClass.LOW, RiskClass.MATERIAL):
        raise AuthorityBundleError(
            f"Authority bundle only available for LOW/MATERIAL risk, got {risk_decision.risk_class.value}"
        )

    if not risk_decision.authority_bundle_eligible:
        raise AuthorityBundleError("Risk decision indicates authority bundle not eligible")
    if risk_decision.factors_hash != risk_factors.compute_hash():
        raise AuthorityBundleError("Risk decision does not match supplied risk factors")

    current = int(time.time() if now is None else now)
    bid = bundle_id or f"ab_{secrets.token_urlsafe(24)}"

    bundle = AuthorityBundle(
        bundle_id=bid,
        policy_template=risk_factors.policy_template or "unknown",
        policy_template_hash=risk_factors.policy_template_hash or "",
        policy_template_version=risk_factors.policy_template_version or 1,
        risk_factors_hash=risk_factors.compute_hash(),
        approved_risk_factors=risk_factors,
        risk_decision=risk_decision,
        approved_scope=approved_scope,
        required_deliverables=tuple(required_deliverables),
        verified_deliverables=(),
        created_at=current,
        created_by=created_by,
        operational_deadline=operational_deadline,
        operational_deadline_reason=operational_deadline_reason,
    )

    canonical = json.dumps(bundle.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    lock_claimed = False
    if risk_factors.single_writer_verified and risk_factors.writable_roots:
        from operator_worktree_lock import claim_writer_locks

        claim_writer_locks(bid, risk_factors.writable_roots, root=root, now=current)
        lock_claimed = True
    try:
        with _connect(root) as conn:
            _initialize_bundle_db(conn)
            conn.execute(
                """INSERT INTO authority_bundles
                   (bundle_id, canonical_json, created_at, policy_template,
                    policy_template_hash, policy_template_version, risk_factors_hash, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'active')""",
                (
                    bid, canonical, current,
                    bundle.policy_template,
                    bundle.policy_template_hash,
                    bundle.policy_template_version,
                    bundle.risk_factors_hash,
                ),
            )
            _write_active_pointer(bid, root=root)
    except Exception:
        if lock_claimed:
            from operator_worktree_lock import release_writer_locks

            release_writer_locks(bid, risk_factors.writable_roots, root=root)
        raise

    return bundle


def load_authority_bundle(
    bundle_id: str,
    *,
    root: Path | None = None,
) -> AuthorityBundle:
    """Load an authority bundle by ID."""
    with _connect(root) as conn:
        _initialize_bundle_db(conn)
        row = conn.execute(
            "SELECT canonical_json FROM authority_bundles WHERE bundle_id = ?",
            (bundle_id,),
        ).fetchone()
    if row is None:
        raise AuthorityBundleNotFoundError(f"Authority bundle {bundle_id!r} not found")
    return AuthorityBundle.from_dict(json.loads(row["canonical_json"]))


def list_authority_bundles(
    *,
    root: Path | None = None,
    policy_template: str | None = None,
    status: str | None = None,  # active, revoked, completed
) -> list[AuthorityBundle]:
    """List all authority bundles, optionally filtered."""
    with _connect(root) as conn:
        _initialize_bundle_db(conn)
        query = "SELECT canonical_json FROM authority_bundles WHERE 1=1"
        params: list[Any] = []
        if policy_template:
            query += " AND policy_template = ?"
            params.append(policy_template)
        if status:
            query += " AND status = ?"
            params.append(status)
        rows = conn.execute(query, params).fetchall()

    bundles = []
    for row in rows:
        bundles.append(AuthorityBundle.from_dict(json.loads(row["canonical_json"])))
    return bundles


def get_active_authority_bundle(
    *,
    root: Path | None = None,
    now: int | None = None,
) -> AuthorityBundle | None:
    """Get the currently active authority bundle, if valid."""
    try:
        pointer_path = _active_pointer_path(root)
        if not pointer_path.is_file():
            return None
        bid = pointer_path.read_text(encoding="utf-8").strip()
        if not bid:
            return None
    except Exception:
        return None

    try:
        bundle = load_authority_bundle(bid, root=root)
    except AuthorityBundleNotFoundError:
        return None

    # Check validity (but NOT operational deadline - that's separate)
    valid, reason = bundle.is_valid(current_time=now)
    if not valid and "Operational deadline" not in (reason or ""):
        # Authorization invalid (revoked or completed) - not just watchdog
        return None

    return bundle


def revoke_authority_bundle(
    bundle_id: str,
    *,
    revoked_by: str,
    reason: str,
    root: Path | None = None,
    now: int | None = None,
) -> bool:
    """Revoke an authority bundle immediately."""
    current = int(time.time() if now is None else now)

    bundle = load_authority_bundle(bundle_id, root=root)

    if bundle.is_revoked():
        return False

    if bundle.is_completed():
        return False  # Cannot revoke completed bundle

    revoked = AuthorityBundle(
        bundle_id=bundle.bundle_id,
        policy_template=bundle.policy_template,
        policy_template_hash=bundle.policy_template_hash,
        policy_template_version=bundle.policy_template_version,
        risk_factors_hash=bundle.risk_factors_hash,
        approved_risk_factors=bundle.approved_risk_factors,
        risk_decision=bundle.risk_decision,
        approved_scope=bundle.approved_scope,
        required_deliverables=bundle.required_deliverables,
        verified_deliverables=bundle.verified_deliverables,
        created_at=bundle.created_at,
        created_by=bundle.created_by,
        revoked_at=current,
        revoked_by=revoked_by,
        revocation_reason=reason,
        completed_at=bundle.completed_at,
        completed_by=bundle.completed_by,
        operational_deadline=bundle.operational_deadline,
        operational_deadline_reason=bundle.operational_deadline_reason,
        containment_verified_at=bundle.containment_verified_at,
        containment_verified_by=bundle.containment_verified_by,
    )

    canonical = json.dumps(revoked.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    with _connect(root) as conn:
        _initialize_bundle_db(conn)
        conn.execute(
            "UPDATE authority_bundles SET canonical_json = ?, status = 'revoked' WHERE bundle_id = ?",
            (canonical, bundle_id),
        )
    if bundle.approved_risk_factors.single_writer_verified and bundle.approved_risk_factors.writable_roots:
        from operator_worktree_lock import release_writer_locks

        release_writer_locks(bundle_id, bundle.approved_risk_factors.writable_roots, root=root)

    return True


def verify_bundle_deliverable(
    bundle_id: str,
    deliverable: str,
    *,
    verified_by: str,
    root: Path | None = None,
) -> AuthorityBundle:
    """Record deterministic evidence for one required deliverable."""
    bundle = load_authority_bundle(bundle_id, root=root)
    if bundle.is_revoked() or bundle.is_completed():
        raise AuthorityBundleDeliverableError("Bundle is not active")
    if deliverable not in bundle.required_deliverables:
        raise AuthorityBundleDeliverableError(
            f"Deliverable {deliverable!r} was not part of the approved bundle"
        )
    verified = tuple(dict.fromkeys((*bundle.verified_deliverables, deliverable)))
    updated = AuthorityBundle(
        bundle_id=bundle.bundle_id,
        policy_template=bundle.policy_template,
        policy_template_hash=bundle.policy_template_hash,
        policy_template_version=bundle.policy_template_version,
        risk_factors_hash=bundle.risk_factors_hash,
        approved_risk_factors=bundle.approved_risk_factors,
        risk_decision=bundle.risk_decision,
        approved_scope=bundle.approved_scope,
        required_deliverables=bundle.required_deliverables,
        verified_deliverables=verified,
        created_at=bundle.created_at,
        created_by=bundle.created_by,
        revoked_at=bundle.revoked_at,
        revoked_by=bundle.revoked_by,
        revocation_reason=bundle.revocation_reason,
        completed_at=bundle.completed_at,
        completed_by=bundle.completed_by,
        operational_deadline=bundle.operational_deadline,
        operational_deadline_reason=bundle.operational_deadline_reason,
        containment_verified_at=bundle.containment_verified_at,
        containment_verified_by=verified_by,
    )
    canonical = json.dumps(updated.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with _connect(root) as conn:
        _initialize_bundle_db(conn)
        conn.execute(
            "UPDATE authority_bundles SET canonical_json = ? WHERE bundle_id = ?",
            (canonical, bundle_id),
        )
    return updated


def complete_authority_bundle(
    bundle_id: str,
    *,
    completed_by: str,
    root: Path | None = None,
    now: int | None = None,
) -> bool:
    """Mark an authority bundle as completed."""
    current = int(time.time() if now is None else now)

    bundle = load_authority_bundle(bundle_id, root=root)

    if bundle.is_revoked():
        raise AuthorityBundleRevokedError("Cannot complete a revoked bundle")

    if bundle.is_completed():
        return False
    missing = tuple(
        item for item in bundle.required_deliverables
        if item not in set(bundle.verified_deliverables)
    )
    if missing:
        raise AuthorityBundleDeliverableError(
            f"Cannot complete bundle; unverified deliverables: {', '.join(missing)}"
        )

    completed = AuthorityBundle(
        bundle_id=bundle.bundle_id,
        policy_template=bundle.policy_template,
        policy_template_hash=bundle.policy_template_hash,
        policy_template_version=bundle.policy_template_version,
        risk_factors_hash=bundle.risk_factors_hash,
        approved_risk_factors=bundle.approved_risk_factors,
        risk_decision=bundle.risk_decision,
        approved_scope=bundle.approved_scope,
        required_deliverables=bundle.required_deliverables,
        verified_deliverables=bundle.verified_deliverables,
        created_at=bundle.created_at,
        created_by=bundle.created_by,
        revoked_at=bundle.revoked_at,
        revoked_by=bundle.revoked_by,
        revocation_reason=bundle.revocation_reason,
        completed_at=current,
        completed_by=completed_by,
        operational_deadline=bundle.operational_deadline,
        operational_deadline_reason=bundle.operational_deadline_reason,
        containment_verified_at=bundle.containment_verified_at,
        containment_verified_by=bundle.containment_verified_by,
    )

    canonical = json.dumps(completed.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    with _connect(root) as conn:
        _initialize_bundle_db(conn)
        conn.execute(
            "UPDATE authority_bundles SET canonical_json = ?, status = 'completed' WHERE bundle_id = ?",
            (canonical, bundle_id),
        )
    if bundle.approved_risk_factors.single_writer_verified and bundle.approved_risk_factors.writable_roots:
        from operator_worktree_lock import release_writer_locks

        release_writer_locks(bundle_id, bundle.approved_risk_factors.writable_roots, root=root)

    return True


def check_authority_bundle_validity(
    bundle: AuthorityBundle,
    current_risk_factors: RiskFactors,
    *,
    current_time: int | None = None,
) -> tuple[bool, str | None]:
    """Check if an authority bundle remains valid given current risk factors.

    Checks:
    1. Explicit revocation
    2. Completion
    3. Policy/template hash or version change
    4. Material risk/scope increase (escalation)
    5. Containment failure/weakening
    6. Guardrail breach (prohibited factors now present)

    Returns (is_valid, reason_if_invalid).
    Elapsed wall-clock time alone NEVER invalidates.
    """
    # 1. Check explicit revocation
    if bundle.is_revoked():
        return False, f"Explicitly revoked: {bundle.revocation_reason}"

    # 2. Check completion
    if bundle.is_completed():
        return False, f"Already completed at {bundle.completed_at}"

    # 3. Check policy/template hash change
    if current_risk_factors.policy_template_hash != bundle.policy_template_hash:
        return False, f"Policy template hash changed (was {bundle.policy_template_hash[:16]}..., now {current_risk_factors.policy_template_hash[:16]}...)"

    # 4. Check policy/template version change
    if current_risk_factors.policy_template_version != bundle.policy_template_version:
        return False, f"Policy template version changed (was v{bundle.policy_template_version}, now v{current_risk_factors.policy_template_version})"

    # 5. Reclassify and compare against fully persisted approved facts.
    current_decision = classify_risk(current_risk_factors)
    if current_decision.risk_class == RiskClass.PROHIBITED:
        return False, f"Guardrail breach: {', '.join(current_decision.prohibited_reasons)}"
    escalation = check_escalation(bundle.approved_risk_factors, current_risk_factors)
    if escalation.escalated or current_decision.risk_class in (RiskClass.HIGH, RiskClass.PROHIBITED):
        return False, f"Risk escalation detected: {escalation.summary()}"
    if current_risk_factors.containment_weakened or not current_risk_factors.containment_verified:
        return False, "Containment weakened or is no longer verified"
    if current_risk_factors.compute_hash() != bundle.risk_factors_hash:
        return False, "Approved scope or immutable risk facts changed"
    if current_risk_factors.single_writer_verified and current_risk_factors.writable_roots:
        from operator_worktree_lock import assert_writer_locks
        try:
            assert_writer_locks(bundle.bundle_id, current_risk_factors.writable_roots)
        except ValueError:
            return False, "Single-writer ownership is missing or held by another authority"

    return True, None


def check_and_enforce_scope(
    bundle: AuthorityBundle,
    requested_roots: tuple[Path, ...] = (),
    requested_writable: tuple[Path, ...] = (),
    requested_verbs: dict[str, list[str]] | None = None,
    requested_egress: tuple[str, ...] = (),
    requested_services: tuple[str, ...] = (),
) -> ScopeCheckResult:
    """Check scope and raise if outside approved boundaries."""
    result = check_scope(
        bundle, requested_roots, requested_writable,
        requested_verbs, requested_egress, requested_services
    )
    if not result.within_scope:
        raise AuthorityBundleScopeError(
            f"Operation outside approved bundle scope: {result.reason}. "
            f"Escalation path: {result.escalation}"
        )
    return result


def set_operational_deadline(
    bundle_id: str,
    deadline: int,
    reason: str,
    *,
    root: Path | None = None,
) -> AuthorityBundle:
    """Set or update an operational watchdog deadline (separate from auth validity)."""
    bundle = load_authority_bundle(bundle_id, root=root)

    updated = AuthorityBundle(
        bundle_id=bundle.bundle_id,
        policy_template=bundle.policy_template,
        policy_template_hash=bundle.policy_template_hash,
        policy_template_version=bundle.policy_template_version,
        risk_factors_hash=bundle.risk_factors_hash,
        approved_risk_factors=bundle.approved_risk_factors,
        risk_decision=bundle.risk_decision,
        approved_scope=bundle.approved_scope,
        required_deliverables=bundle.required_deliverables,
        verified_deliverables=bundle.verified_deliverables,
        created_at=bundle.created_at,
        created_by=bundle.created_by,
        revoked_at=bundle.revoked_at,
        revoked_by=bundle.revoked_by,
        revocation_reason=bundle.revocation_reason,
        completed_at=bundle.completed_at,
        completed_by=bundle.completed_by,
        operational_deadline=deadline,
        operational_deadline_reason=reason,
        containment_verified_at=bundle.containment_verified_at,
        containment_verified_by=bundle.containment_verified_by,
    )

    canonical = json.dumps(updated.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    with _connect(root) as conn:
        _initialize_bundle_db(conn)
        conn.execute(
            "UPDATE authority_bundles SET canonical_json = ? WHERE bundle_id = ?",
            (canonical, bundle_id),
        )

    return updated


def clear_operational_deadline(
    bundle_id: str,
    *,
    root: Path | None = None,
) -> AuthorityBundle:
    """Clear an operational watchdog deadline."""
    return set_operational_deadline(bundle_id, 0, "cleared", root=root)


def verify_containment(
    bundle_id: str,
    *,
    verified_by: str,
    root: Path | None = None,
    now: int | None = None,
) -> AuthorityBundle:
    """Record a containment verification."""
    current = int(time.time() if now is None else now)
    bundle = load_authority_bundle(bundle_id, root=root)

    updated = AuthorityBundle(
        bundle_id=bundle.bundle_id,
        policy_template=bundle.policy_template,
        policy_template_hash=bundle.policy_template_hash,
        policy_template_version=bundle.policy_template_version,
        risk_factors_hash=bundle.risk_factors_hash,
        approved_risk_factors=bundle.approved_risk_factors,
        risk_decision=bundle.risk_decision,
        approved_scope=bundle.approved_scope,
        required_deliverables=bundle.required_deliverables,
        verified_deliverables=bundle.verified_deliverables,
        created_at=bundle.created_at,
        created_by=bundle.created_by,
        revoked_at=bundle.revoked_at,
        revoked_by=bundle.revoked_by,
        revocation_reason=bundle.revocation_reason,
        completed_at=bundle.completed_at,
        completed_by=bundle.completed_by,
        operational_deadline=bundle.operational_deadline,
        operational_deadline_reason=bundle.operational_deadline_reason,
        containment_verified_at=current,
        containment_verified_by=verified_by,
    )

    canonical = json.dumps(updated.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    with _connect(root) as conn:
        _initialize_bundle_db(conn)
        conn.execute(
            "UPDATE authority_bundles SET canonical_json = ? WHERE bundle_id = ?",
            (canonical, bundle_id),
        )

    return updated