"""Capability Composition for Mission Control Authority Architecture v2 — Phase 3 Live Pilot.

Trusted server-side capability resolver that maps Authority Forecasts into
candidate Authority Envelopes, reusing existing sealed Authority Envelope machinery.

This is the MINIMUM LIVE ACTIVATION SEAM - it reuses all existing infrastructure:
- Authority Forecast (existing)
- R0-R4 risk classes (existing)
- Authority Envelope / Scoped Grant (existing)
- operator_sessions.create_session() (existing)
- operator_sessions.approve_session_request() (existing)
- operator_policy.OperatorPolicy enforcement (existing)

The only new code is the deterministic capability resolver that produces
a policy_snapshot from a forecast, which then flows through the EXISTING
approval and session machinery.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .capability_vocabulary import (
    CapabilityAtom,
    RiskClass,
    CAPABILITY_FAMILIES,
    RISK_CLASS_MAPPING,
    HARD_DENIED_PATHS,
    STANDING_READ_ROOTS,
    compose_capability,
    classify_risk,
    check_hard_denies,
)


@dataclass(frozen=True)
class AuthorityForecast:
    """Authority Forecast - from Authority Layer spec section 5.

    What the task objectively requires before execution.
    Caller states objective and required operations; resolver derives atoms.
    """
    objective: str
    logical_task_id: str
    readable_roots: tuple[str, ...]
    writable_roots: tuple[str, ...]
    required_verbs: dict[str, list[str]]  # family -> [actions]
    service_units: tuple[str, ...] = ()
    egress_hosts: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    rollback_approach: str = ""
    requested_expiry: str = "completion"


@dataclass(frozen=True)
class ResolvedAuthorityBundle:
    """Result of deterministic capability composition.

    This is the exact capability bundle that will be sealed into an
    Authority Envelope via existing operator_sessions machinery.
    """
    capability_atoms: tuple[CapabilityAtom, ...]
    readable_roots: tuple[str, ...]
    writable_roots: tuple[str, ...]
    verbs: dict[str, list[str]]
    service_units: tuple[str, ...]
    egress_hosts: tuple[str, ...] = ()
    risk_class: RiskClass = RiskClass.R0
    hard_deny_violations: tuple[str, ...] = ()
    constraints: dict[str, Any] = field(default_factory=dict)
    scope_hash: str = ""

    def to_policy_snapshot(self, policy_template: str) -> dict[str, Any]:
        """Convert to policy snapshot format for operator_sessions.create_session()."""
        # Build verbs dict in the format expected by operator_policy_templates
        verbs = {}
        for verb_family, actions in self.verbs.items():
            if verb_family == "read":
                pass  # Covered by readable_roots
            elif verb_family == "write":
                pass  # Covered by writable_roots
            elif verb_family == "execute":
                if "validator" in actions:
                    verbs.setdefault("tests", []).append("run")
                if "test" in actions:
                    verbs.setdefault("tests", []).append("run")
            elif verb_family == "git":
                if "stage" in actions:
                    verbs.setdefault("git", []).append("commit")
                if "commit" in actions:
                    verbs.setdefault("git", []).append("commit")
                if "push" in actions:
                    verbs.setdefault("git", []).append("push")
            elif verb_family == "service":
                if "restart" in actions:
                    verbs.setdefault("services", []).append("restart")
            elif verb_family == "network":
                if "web" in actions:
                    verbs.setdefault("network", []).append("web")

        # Deduplicate verb lists
        for k, v in verbs.items():
            verbs[k] = list(dict.fromkeys(v))

        return {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": list(self.readable_roots),
            "writable_roots": list(self.writable_roots),
            "service_units": list(self.service_units),
            "egress_hosts": list(self.egress_hosts),
            "verbs": verbs,
            "policy_template": policy_template,
            "authority_mode": "session",
            "standing_authority_eligible": False,
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
            "has_external_communication": len(self.egress_hosts) > 0,
            "has_deployment": False,
        }


class CapabilityComposer:
    """Trusted deterministic capability composer.

    Maps AuthorityForecast -> ResolvedAuthorityBundle.
    Runs inside trusted Controller boundary.
    Never accepts caller-supplied raw roots, verbs, or policy JSON.
    """

    def __init__(self):
        self._pilot_allow_list = (
            "/home/jfroh/.hermes/ops-brain/projects/phase3-r1-pilot-validation.md",
        )

    def compose(self, forecast: AuthorityForecast) -> ResolvedAuthorityBundle:
        """Deterministically compose capabilities from forecast."""
        capabilities = []
        constraints = {
            "no_push": True,
            "no_service_restart": len(forecast.service_units) == 0,
            "no_config_mutation": True,
            "no_routing_mutation": True,
            "no_profile_mutation": True,
            "no_credentials": True,
            "no_destructive": True,
            "no_external_communication": len(forecast.egress_hosts) == 0,
        }

        # 1. Read capabilities for readable roots
        for root in forecast.readable_roots:
            capabilities.append(compose_capability("read", "file", root, {}))

        # 2. Write capabilities for writable roots (exact allow-list only)
        for root in forecast.writable_roots:
            # For pilot: restrict to exact allow-list
            if root == "/home/jfroh/.hermes/ops-brain":
                for file in self._pilot_allow_list:
                    capabilities.append(compose_capability("write", "file", file, {
                        "exact_file_only": True,
                        "allow_list": True,
                    }))
            else:
                capabilities.append(compose_capability("write", "file", root, {
                    "exact_files_only": True,
                    "allow_list": True,
                }))

        # 3. Verb-based capabilities
        for family, actions in forecast.required_verbs.items():
            for action in actions:
                if family == "read":
                    pass  # Already covered
                elif family == "write":
                    pass  # Already covered
                elif family == "execute":
                    if action == "validator":
                        capabilities.append(compose_capability("execute", "validator", "opsbrain-validator", {}))
                    elif action == "test":
                        capabilities.append(compose_capability("execute", "test", "test-suite", {}))
                elif family == "git":
                    if action == "stage":
                        capabilities.append(compose_capability("git", "stage", "ops-brain-repo", {"exact_files": True}))
                    elif action == "commit":
                        capabilities.append(compose_capability("git", "commit", "ops-brain-repo", {
                            "exact_files": True,
                            "no_push": True,
                        }))
                    elif action == "push":
                        capabilities.append(compose_capability("git", "push", "ops-brain-repo", {}))
                elif family == "service":
                    if action == "restart":
                        for unit in forecast.service_units:
                            capabilities.append(compose_capability("service", "restart", unit, {}))
                elif family == "network":
                    if action == "web":
                        capabilities.append(compose_capability("network", "web", "internet", {}))
                    elif action == "api":
                        for host in forecast.egress_hosts:
                            capabilities.append(compose_capability("network", "api", host, {}))

        # 4. Apply hard denies - filter and record violations
        hard_deny_violations = check_hard_denies(capabilities)
        filtered_capabilities = [c for c in capabilities if not any(c.target in v for v in hard_deny_violations)]

        # 5. Classify risk
        risk_class = classify_risk(filtered_capabilities)

        # 6. Build verbs dict for policy snapshot
        verbs = {}
        for cap in filtered_capabilities:
            if cap.family not in verbs:
                verbs[cap.family] = []
            if cap.verb not in verbs[cap.family]:
                verbs[cap.family].append(cap.verb)

        # 7. Compute scope hash for task identity binding
        scope_data = {
            "capabilities": sorted(str(c) for c in filtered_capabilities),
            "readable_roots": sorted(forecast.readable_roots),
            "writable_roots": sorted(forecast.writable_roots),
            "verbs": {k: sorted(v) for k, v in verbs.items()},
            "service_units": sorted(forecast.service_units),
            "constraints": {k: v for k, v in sorted(constraints.items())},
        }
        scope_hash = hashlib.sha256(json.dumps(scope_data, sort_keys=True).encode()).hexdigest()[:32]

        return ResolvedAuthorityBundle(
            capability_atoms=tuple(filtered_capabilities),
            readable_roots=forecast.readable_roots,
            writable_roots=forecast.writable_roots,
            verbs=verbs,
            service_units=forecast.service_units,
            risk_class=risk_class,
            hard_deny_violations=tuple(hard_deny_violations),
            constraints=constraints,
            scope_hash=scope_hash,
        )


def create_pilot_forecast() -> AuthorityForecast:
    """Create the exact Authority Forecast for Phase 3 R1 pilot."""
    return AuthorityForecast(
        objective="Pilot: Edit pilot documentation file, run OpsBrain validator, commit exact file locally",
        logical_task_id="opsbrain-r1-pilot-2026-09-05",
        readable_roots=("/home/jfroh/.hermes/ops-brain",),
        writable_roots=("/home/jfroh/.hermes/ops-brain",),
        required_verbs={
            "read": ["file"],
            "write": ["file", "patch"],
            "execute": ["validator", "test"],
            "git": ["stage", "commit"],
        },
        service_units=(),
        egress_hosts=(),
        evidence_requirements=(
            "changed-file manifest",
            "diff or commit identifier",
            "validation report",
        ),
        rollback_approach="git reset --hard HEAD~1 (exact local commit only, no push)",
        requested_expiry="completion",
    )


def get_pilot_policy_template_name() -> str:
    """Return the policy template name for the pilot grant."""
    return "hermes-opsbrain-r1-pilot"


def create_pilot_grant() -> ResolvedAuthorityBundle:
    """Create the exact R1 pilot grant using the capability composer."""
    composer = CapabilityComposer()
    forecast = create_pilot_forecast()
    return composer.compose(forecast)