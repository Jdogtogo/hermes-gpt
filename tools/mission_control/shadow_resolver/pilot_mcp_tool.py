"""MCP Tool: hermes_operator_phase3_r1_pilot_request

This is the MINIMUM LIVE ACTIVATION SEAM for Phase 3 R1 pilot.

It allows the Controller to request the exact R1 capability-composed grant
by using the deterministic capability composer, which then flows through
the EXISTING approval/session machinery (operator_sessions).

This tool:
1. Accepts a pre-approved logical task ID (no arbitrary forecast from caller)
2. Runs the trusted deterministic capability composer
3. Produces a policy_snapshot for the pilot grant
4. Calls operator_sessions.request_session() with that resolved policy
5. Returns the pending request for human approval

The legacy named-template path remains completely unchanged.
"""

from __future__ import annotations

import json
import os

from .capability_composition import (
    create_pilot_forecast,
    create_pilot_grant,
    get_pilot_policy_template_name,
)
from .pilot_template import is_pilot_enabled, get_pilot_template

# Import operator modules (lazy to avoid circular imports)
def _import_operator_sessions():
    import operator_sessions as op_sessions
    return op_sessions

def _import_operator_policy():
    import operator_policy as op_policy
    return op_policy

def _import_operator_policy_templates():
    import operator_policy_templates as op_templates
    return op_templates

def _import_operator_risk():
    import operator_risk as op_risk
    return op_risk


def hermes_operator_phase3_r1_pilot_request(
    logical_task_id: str = "opsbrain-r1-pilot-2026-09-05",
    reason: str = "Phase 3 R1 pilot: edit pilot doc, run validator, commit locally",
    requested_duration_minutes: int = 60,
) -> str:
    """Request the Phase 3 R1 pilot grant via capability composition.

    This is the MINIMUM LIVE ACTIVATION SEAM.
    
    Caller MUST provide the exact logical_task_id for the pilot.
    No arbitrary forecast, roots, verbs, or policy JSON accepted.
    
    The deterministic capability composer runs inside the trusted Controller
    boundary and produces the exact R1 grant for the pilot.
    
    Returns a pending request for human approval via existing machinery.
    """
    try:
        # 1. Feature flag check
        if not is_pilot_enabled():
            return json.dumps({
                "success": False,
                "error": "Phase 3 R1 pilot not enabled. Set HERMES_PHASE3_R1_PILOT_ENABLED=1 to enable.",
                "layer": "operator",
                "code": "PILOT_NOT_ENABLED",
                "suggested_action": "Enable pilot feature flag and restart operator sidecar.",
            }, indent=2)

        # 2. Validate logical task ID matches pilot
        if logical_task_id != "opsbrain-r1-pilot-2026-09-05":
            return json.dumps({
                "success": False,
                "error": f"Invalid logical_task_id. Only 'opsbrain-r1-pilot-2026-09-05' is allowed for this pilot.",
                "layer": "operator",
                "code": "INVALID_PILOT_TASK_ID",
                "suggested_action": "Use the exact pilot logical_task_id.",
            }, indent=2)

        # 3. Run deterministic capability composition
        forecast = create_pilot_forecast()
        grant = create_pilot_grant()

        # 4. Build policy snapshot from capability composition
        policy_template = get_pilot_policy_template_name()
        policy_snapshot = grant.to_policy_snapshot(policy_template)

        # 5. Add template metadata (allowed_branches, authority_mode)
        pilot_template = get_pilot_template()
        if pilot_template:
            policy_snapshot["allowed_branches"] = pilot_template.get("allowed_branches")
        policy_snapshot["authority_mode"] = "session"
        policy_snapshot["standing_authority_eligible"] = False

        # 6. Risk classification via existing operator_risk machinery
        op_risk = _import_operator_risk()
        factor_snapshot = dict(policy_snapshot)
        factor_snapshot["snapshot_hash"] = _import_operator_sessions().snapshot_hash(policy_snapshot)
        risk_factors = op_risk.compute_risk_factors_from_session(
            factor_snapshot, template_baseline=policy_snapshot
        )
        risk_decision = op_risk.classify_risk(risk_factors)

        # Pilot must be R1 LOW risk
        if risk_decision.risk_class != op_risk.RiskClass.LOW or risk_decision.tier != 1:
            return json.dumps({
                "success": False,
                "error": f"Pilot grant risk classification failed: expected R1/LOW, got {risk_decision.risk_class.value}/tier {risk_decision.tier}",
                "layer": "operator",
                "code": "PILOT_RISK_MISMATCH",
                "suggested_action": "Verify pilot grant composition.",
            }, indent=2)

        approval_forecast = {
            "risk_class": risk_decision.risk_class.value,
            "tier": risk_decision.tier,
            "standing_authority_eligible": risk_decision.standing_authority_eligible,
            "authority_bundle_eligible": risk_decision.authority_bundle_eligible,
            "requires_human_approval": risk_decision.requires_human_approval,
            "factors_hash": risk_decision.factors_hash,
            "reasons": [
                {"factor": item.factor, "detail": item.detail, "severity": item.severity.value}
                for item in risk_decision.reasons
            ],
        }

        # 7. Cap duration at template maximum
        requested_seconds = max(60, int(requested_duration_minutes) * 60)
        capped_seconds = min(requested_seconds, pilot_template["max_duration_seconds"])

        # 8. Request session via EXISTING operator_sessions machinery
        op_sessions = _import_operator_sessions()
        request_id = op_sessions.request_session(
            policy_template=policy_template,
            resolved_policy=policy_snapshot,
            requested_duration_seconds=capped_seconds,
            reason=reason.strip(),
        )

        # 9. Audit via existing machinery
        op_policy = _import_operator_policy()
        op_policy.audit_record(
            tool="hermes_operator_phase3_r1_pilot_request",
            level="session",
            apply_mode="request-only",
            dry_run=False,
            success=True,
            summary=f"requested Phase 3 R1 pilot grant for {logical_task_id}",
            extra={
                "request_id": request_id,
                "logical_task_id": logical_task_id,
                "policy_template": policy_template,
                "requested_duration_seconds": capped_seconds,
                "risk_class": approval_forecast["risk_class"],
                "risk_tier": approval_forecast["tier"],
                "risk_factors_hash": approval_forecast["factors_hash"],
                "scope_hash": grant.scope_hash,
            },
        )

        # 10. Notify via existing notification path
        notification = _notify_pending_pilot_request(
            "phase3_r1_pilot",
            request_id,
            {
                "request_id": request_id,
                "logical_task_id": logical_task_id,
                "policy_template": policy_template,
                "resolved_policy": policy_snapshot,
                "requested_duration_seconds": capped_seconds,
                "approval_forecast": approval_forecast,
                "reason": reason.strip(),
                "grant_capabilities": [str(c) for c in grant.capability_atoms],
            },
        )

        return json.dumps({
            "success": True,
            "request_id": request_id,
            "logical_task_id": logical_task_id,
            "policy_template": policy_template,
            "resolved_policy": policy_snapshot,
            "requested_duration_seconds": capped_seconds,
            "approval_forecast": approval_forecast,
            "status": "pending",
            "notification": notification,
            "grant_capabilities": [str(c) for c in grant.capability_atoms],
            "note": (
                "Phase 3 R1 pilot grant. Requires local (Telegram or localhost) approval. "
                "Grants exact R1 capabilities: read OpsBrain, edit pilot file, run validator, "
                "local git commit (no push), no service restart, no config/profile/routing mutation."
            ),
        }, indent=2)

    except Exception as exc:
        op_policy = _import_operator_policy()
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="PHASE3_R1_PILOT_REQUEST_ERROR",
                suggested_action="Check logical_task_id, reason, and pilot feature flag.",
            ),
            indent=2,
        )


def _notify_pending_pilot_request(
    request_type: str,
    request_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Notify via existing Telegram/localhost approval channels."""
    try:
        from operator_approval_web import notify_pending_request
        return notify_pending_request(request_type, request_id, payload)
    except Exception:
        return {"sent": False, "reason": "Notification path unavailable"}


def _notify_pending_request(
    request_type: str,
    request_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Legacy notification compatibility."""
    return _notify_pending_pilot_request(request_type, request_id, payload)