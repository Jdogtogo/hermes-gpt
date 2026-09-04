"""Shadow Resolver - deterministic capability composition for Authority Architecture v2 Phase 2.

This is the core resolver that maps Authority Forecasts into candidate Authority Envelopes
without changing live authorization. It runs in SHADOW MODE only - comparing against
current named-template resolution.
"""

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
    decompose_template,
    classify_risk,
    check_hard_denies,
)
from .fixtures import AuthorityForecast, AuthorityEnvelope, OpsBrainReconciliationFixture


@dataclass(frozen=True)
class ShadowComparison:
    """Result of comparing shadow resolver output with current template resolution."""

    # Task identification
    objective: str
    logical_task_id: str

    # Requested capabilities (from forecast)
    requested_capabilities: list[CapabilityAtom]
    requested_roots: list[str]
    requested_verbs: dict[str, list[str]]
    constraints: dict[str, Any]

    # Risk classification
    calculated_risk_class: RiskClass

    # Shadow resolver proposed capability bundle
    proposed_capability_bundle: list[CapabilityAtom]

    # Current named template selected
    current_named_template: str
    current_effective_capabilities: list[CapabilityAtom]
    current_effective_roots: dict[str, list[str]]  # readable, writable
    current_effective_verbs: dict[str, list[str]]
    current_risk_metadata: dict[str, Any]

    # Comparison results
    over_grant: list[CapabilityAtom]  # capabilities current grants but task doesn't need
    under_grant: list[CapabilityAtom]  # capabilities task needs but current doesn't grant
    hard_denies_applied: list[str]
    reapproval_required: bool
    escalation_required: bool

    # Deterministic comparison result
    comparison_result: str  # "EXACT_MATCH" | "OVER_GRANT" | "UNDER_GRANT" | "MIXED" | "HARD_DENY"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for evidence recording."""
        return {
            "objective": self.objective,
            "logical_task_id": self.logical_task_id,
            "requested_capabilities": [str(c) for c in self.requested_capabilities],
            "requested_roots": self.requested_roots,
            "requested_verbs": self.requested_verbs,
            "constraints": self.constraints,
            "calculated_risk_class": self.calculated_risk_class.value,
            "proposed_capability_bundle": [str(c) for c in self.proposed_capability_bundle],
            "current_named_template": self.current_named_template,
            "current_effective_capabilities": [str(c) for c in self.current_effective_capabilities],
            "current_effective_roots": self.current_effective_roots,
            "current_effective_verbs": self.current_effective_verbs,
            "current_risk_metadata": self.current_risk_metadata,
            "over_grant": [str(c) for c in self.over_grant],
            "under_grant": [str(c) for c in self.under_grant],
            "hard_denies_applied": self.hard_denies_applied,
            "reapproval_required": self.reapproval_required,
            "escalation_required": self.escalation_required,
            "comparison_result": self.comparison_result,
        }


class ShadowResolver:
    """Trusted deterministic capability resolver - SHADOW MODE ONLY.

    Maps Authority Forecast -> deterministic capability composition -> candidate Authority Envelope.
    Never changes live authorization. Only compares against current named-template mechanism.
    """

    def __init__(self):
        self._template_cache: dict[str, dict[str, Any]] = {}

    def resolve(self, forecast: AuthorityForecast) -> list[CapabilityAtom]:
        """Resolve an Authority Forecast into deterministic capability atoms.

        This is the core composition logic - deterministic, no caller-supplied raw roots/verbs.
        """
        capabilities = []

        # 1. Read capabilities for readable roots
        for root in forecast.readable_roots:
            capabilities.append(compose_capability("read", "file", root, {}))

        # 2. Write capabilities for writable roots (with exact file constraints)
        for root in forecast.writable_roots:
            # The forecast should specify exact files; we use the root as base
            capabilities.append(compose_capability("write", "file", root, {
                "exact_files_only": True,
                "allow_list": True,
            }))

        # 3. Verb-based capabilities
        for family, actions in forecast.required_verbs.items():
            for action in actions:
                if family == "read":
                    # Already covered by readable roots
                    pass
                elif family == "write":
                    # Already covered by writable roots
                    pass
                elif family == "execute":
                    if action == "validator":
                        capabilities.append(compose_capability("execute", "validator", "task-validator", {}))
                    elif action == "test":
                        capabilities.append(compose_capability("execute", "test", "test-suite", {}))
                elif family == "git":
                    if action == "stage":
                        capabilities.append(compose_capability("git", "stage", "repository", {
                            "exact_files": True,
                        }))
                    elif action == "commit":
                        capabilities.append(compose_capability("git", "commit", "repository", {
                            "exact_files": True,
                            "no_push": True,
                        }))
                    elif action == "push":
                        capabilities.append(compose_capability("git", "push", "repository", {}))
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

        # 4. Apply hard denies - filter out any capabilities that violate them
        hard_deny_violations = check_hard_denies(capabilities)
        if hard_deny_violations:
            # In shadow mode, we record but don't fail - the comparison will show hard denies
            pass

        return capabilities

    def resolve_with_constraints(self, forecast: AuthorityForecast) -> tuple[list[CapabilityAtom], list[str]]:
        """Resolve forecast and return capabilities plus any hard deny violations."""
        capabilities = self.resolve(forecast)
        violations = check_hard_denies(capabilities)
        return capabilities, violations

    def decompose_current_template(self, template_name: str, template: dict[str, Any]) -> list[CapabilityAtom]:
        """Decompose a current named template into capability atoms."""
        return decompose_template(template_name, template)

    def compare_with_template(
        self,
        forecast: AuthorityForecast,
        template_name: str,
        template: dict[str, Any],
    ) -> ShadowComparison:
        """Compare shadow resolver output with a specific current template."""
        # Resolve forecast to proposed capabilities
        proposed_capabilities, hard_deny_violations = self.resolve_with_constraints(forecast)

        # Decompose current template to its effective capabilities
        current_capabilities = self.decompose_current_template(template_name, template)

        # Extract roots and verbs from current template
        current_roots = {
            "readable": list(template.get("readable_roots", [])),
            "writable": list(template.get("writable_roots", [])),
        }
        current_verbs = dict(template.get("verbs", {}))

        # Compare capabilities
        over_grant, under_grant = self._compare_capabilities(proposed_capabilities, current_capabilities)

        # Calculate risk class
        calculated_risk = classify_risk(proposed_capabilities)

        # Determine if reapproval/escalation needed
        reapproval_required = len(under_grant) > 0
        escalation_required = calculated_risk in (RiskClass.R3, RiskClass.R4) or len(hard_deny_violations) > 0

        # Determine comparison result
        if len(hard_deny_violations) > 0:
            comparison_result = "HARD_DENY"
        elif len(over_grant) > 0 and len(under_grant) > 0:
            comparison_result = "MIXED"
        elif len(over_grant) > 0:
            comparison_result = "OVER_GRANT"
        elif len(under_grant) > 0:
            comparison_result = "UNDER_GRANT"
        else:
            comparison_result = "EXACT_MATCH"

        return ShadowComparison(
            objective=forecast.objective,
            logical_task_id=forecast.logical_task_id,
            requested_capabilities=proposed_capabilities,
            requested_roots=list(forecast.readable_roots) + list(forecast.writable_roots),
            requested_verbs=forecast.required_verbs,
            constraints={
                "service_units": forecast.service_units,
                "egress_hosts": forecast.egress_hosts,
                "no_push": True,
                "no_service_restart": len(forecast.service_units) == 0,
                "no_config_mutation": True,
                "no_routing_mutation": True,
                "no_profile_mutation": True,
                "no_credentials": True,
                "no_destructive": True,
                "no_external_communication": len(forecast.egress_hosts) == 0,
            },
            calculated_risk_class=calculated_risk,
            proposed_capability_bundle=proposed_capabilities,
            current_named_template=template_name,
            current_effective_capabilities=current_capabilities,
            current_effective_roots=current_roots,
            current_effective_verbs=current_verbs,
            current_risk_metadata={
                "risk_class": template.get("risk_class", "unknown"),
                "risk_tier": template.get("risk_tier", "unknown"),
            },
            over_grant=over_grant,
            under_grant=under_grant,
            hard_denies_applied=hard_deny_violations,
            reapproval_required=reapproval_required,
            escalation_required=escalation_required,
            comparison_result=comparison_result,
        )

    def compare_with_all_templates(self, forecast: AuthorityForecast) -> dict[str, ShadowComparison]:
        """Compare shadow resolver output against all current templates."""
        results = {}
        templates = OpsBrainReconciliationFixture.all_current_templates()

        for template_name, template in templates.items():
            results[template_name] = self.compare_with_template(forecast, template_name, template)

        return results

    def _compare_capabilities(
        self,
        proposed: list[CapabilityAtom],
        current: list[CapabilityAtom],
    ) -> tuple[list[CapabilityAtom], list[CapabilityAtom]]:
        """Compare two capability lists.

        Returns (over_grant, under_grant) where:
        - over_grant: capabilities in current but not needed by proposed
        - under_grant: capabilities needed by proposed but not in current
        """
        # Normalize for comparison
        proposed_normalized = {str(c) for c in proposed}
        current_normalized = {str(c) for c in current}

        over_grant = [c for c in current if str(c) not in proposed_normalized]
        under_grant = [c for c in proposed if str(c) not in current_normalized]

        return over_grant, under_grant

    def get_standing_read_capabilities(self) -> list[CapabilityAtom]:
        """Get standing read capabilities that remain independently usable."""
        capabilities = []
        for root in STANDING_READ_ROOTS:
            capabilities.append(compose_capability("read", "file", root, {"standing": True}))
        return capabilities


def run_shadow_comparison(forecast: AuthorityForecast | None = None) -> dict[str, ShadowComparison]:
    """Run the shadow comparison for the given forecast (defaults to OpsBrain reconciliation)."""
    if forecast is None:
        forecast = OpsBrainReconciliationFixture.forecast()

    resolver = ShadowResolver()
    return resolver.compare_with_all_templates(forecast)