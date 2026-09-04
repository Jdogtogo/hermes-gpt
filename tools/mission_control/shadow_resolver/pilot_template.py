"""Pilot policy template for Phase 3 R1 OpsBrain pilot.

This template is registered in operator_policy_templates.py but gated behind
a feature flag so it doesn't affect existing workflows until explicitly
enabled for the controlled pilot.
"""

from typing import Any, Dict

# This module provides the template definition that gets imported into
# operator_policy_templates.py. The actual registration is done there with
# a feature flag check.

PILOT_TEMPLATE_NAME = "hermes-opsbrain-r1-pilot"

PILOT_TEMPLATE: Dict[str, Any] = {
    "active": True,  # Controlled by feature flag at registration time
    "description": (
        "Phase 3 R1 pilot: exact OpsBrain documentation/state edit+validate+commit. "
        "No push, no service restart, no config/profile/routing mutation, no credentials."
    ),
    "policy": {
        "level": "workspace",
        "apply_mode": "direct",
        "allowed_profiles": ["default"],
        "readable_roots": [
            "/home/jfroh/.hermes/ops-brain",
        ],
        "writable_roots": [
            "/home/jfroh/.hermes/ops-brain/projects/phase3-r1-pilot-validation.md",
        ],
        "service_units": [],
        "verbs": {
            "filesystem": ["read", "edit"],
            "git": ["commit"],
            "tests": ["run"],
        },
        "hard_denied_paths": [
            "/home/jfroh/.hermes/.env",
            "/home/jfroh/.hermes/.env.*",
            "/home/jfroh/.hermes/auth",
            "/home/jfroh/.hermes/auth.json",
            "/home/jfroh/.hermes/credentials",
            "/home/jfroh/.hermes/**/credentials",
            "/home/jfroh/.hermes/**/API keys",
            "/home/jfroh/.hermes/**/OAuth tokens",
            "/home/jfroh/.hermes/**/secret stores",
            "/home/jfroh/.hermes/**/private keys",
            "/home/jfroh/.hermes/**/SSH material",
            "/home/jfroh/.hermes/**/.git/config",
            "/home/jfroh/.hermes/**/runtime session databases",
            "/home/jfroh/.hermes/**/operator approval databases",
            "/home/jfroh/.hermes/**/operator policy/session state",
            "/home/jfroh/.hermes/config.yaml",
            "/home/jfroh/.hermes/profiles",
            "/home/jfroh/.hermes/model-routing-migration",
            "/home/jfroh/.hermes/worktrees",
        ],
        "containment_strength": "container",
        "containment_verified": True,
        "bounded_roots_verified": True,
        "branch_guard_verified": True,
        "baseline_guard_verified": True,
        "single_writer_verified": True,
        "untracked_delete_protected": True,
        "version_controlled_rollback": True,
        "deliverable_verification_required": True,
        "deliverable_verification_verified": False,
        "data_sensitivity": "internal",
        "production_effect": "none",
        "paid_route_change": "none",
        "has_secret_access": False,
        "has_credential_access": False,
        "has_client_identifiable_data": False,
        "has_financial_data": False,
        "has_external_communication": False,
        "has_deployment": False,
    },
    "max_duration_seconds": 4 * 60 * 60,
    "allowed_branches": ["master"],
    "baseline_required": False,
}


def is_pilot_enabled() -> bool:
    """Check if the Phase 3 R1 pilot is enabled via feature flag."""
    import os
    return os.environ.get("HERMES_PHASE3_R1_PILOT_ENABLED", "0") == "1"


def get_pilot_template() -> Dict[str, Any] | None:
    """Return the pilot template if enabled, None otherwise."""
    if is_pilot_enabled():
        from copy import deepcopy
        return deepcopy(PILOT_TEMPLATE)
    return None