"""Tests for deterministic risk tiers and containment facts."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import operator_risk as op_risk


def tier1_factors(**overrides):
    base = op_risk.RiskFactors(
        roots=(Path("/workspace"),),
        writable_roots=(Path("/workspace"),),
        verbs=("filesystem:edit", "tests:run", "git:commit"),
        has_write=True,
        containment_strength=op_risk.ContainmentStrength.CONTAINER,
        bounded_roots_verified=True,
        containment_verified=True,
        branch_guard_verified=True,
        baseline_guard_verified=True,
        single_writer_verified=True,
        untracked_delete_protected=True,
        version_controlled_rollback=True,
        deliverable_verification_required=True,
        policy_template="contained-maintenance",
        policy_template_hash="abc123",
        policy_template_version=1,
    )
    return replace(base, **overrides)


class TestOrderingAndSerialization:
    def test_risk_class_ordering_is_explicit(self):
        assert op_risk.RiskClass.LOW < op_risk.RiskClass.MATERIAL
        assert op_risk.RiskClass.MATERIAL < op_risk.RiskClass.HIGH
        assert op_risk.RiskClass.HIGH < op_risk.RiskClass.PROHIBITED
        assert op_risk.risk_rank(op_risk.RiskClass.HIGH) == 2

    def test_factors_round_trip_losslessly(self):
        original = tier1_factors(deliverable_verification_verified=True)
        restored = op_risk.RiskFactors.from_dict(original.to_dict())
        assert restored == original
        assert restored.compute_hash() == original.compute_hash()

    def test_hash_changes_with_containment_fact(self):
        original = tier1_factors()
        changed = replace(original, single_writer_verified=False)
        assert original.compute_hash() != changed.compute_hash()


class TestTierZeroAndTierOne:
    def test_container_read_only_is_low_not_material(self):
        factors = op_risk.RiskFactors(
            roots=(Path("/workspace"),),
            containment_strength=op_risk.ContainmentStrength.CONTAINER,
            containment_verified=True,
            bounded_roots_verified=True,
        )
        decision = op_risk.classify_risk(factors)
        assert decision.risk_class == op_risk.RiskClass.LOW
        assert decision.tier == 0
        assert decision.standing_authority_eligible is True
        assert decision.requires_human_approval is False

    def test_vm_and_air_gapped_read_only_are_low(self):
        for strength in (
            op_risk.ContainmentStrength.VM,
            op_risk.ContainmentStrength.AIR_GAPPED,
        ):
            decision = op_risk.classify_risk(
                op_risk.RiskFactors(
                    roots=(Path("/workspace"),),
                    containment_strength=strength,
                    containment_verified=True,
                )
            )
            assert decision.risk_class == op_risk.RiskClass.LOW

    def test_fully_contained_reversible_maintenance_is_low_tier_one(self):
        decision = op_risk.classify_risk(tier1_factors())
        assert decision.risk_class == op_risk.RiskClass.LOW
        assert decision.tier == 1
        assert decision.standing_authority_eligible is True
        assert any("Contained reversible" in reason.detail for reason in decision.reasons)

    @pytest.mark.parametrize(
        "field",
        [
            "bounded_roots_verified",
            "containment_verified",
            "branch_guard_verified",
            "baseline_guard_verified",
            "single_writer_verified",
            "untracked_delete_protected",
            "version_controlled_rollback",
            "deliverable_verification_required",
        ],
    )
    def test_missing_tier_one_invariant_is_material(self, field):
        factors = replace(tier1_factors(), **{field: False})
        decision = op_risk.classify_risk(factors)
        assert decision.risk_class == op_risk.RiskClass.MATERIAL
        assert decision.authority_bundle_eligible is True
        assert decision.standing_authority_eligible is False

    def test_unverified_write_is_material(self):
        factors = op_risk.RiskFactors(
            roots=(Path("/workspace"),),
            writable_roots=(Path("/workspace"),),
            has_write=True,
            containment_strength=op_risk.ContainmentStrength.CONTAINER,
        )
        decision = op_risk.classify_risk(factors)
        assert decision.risk_class == op_risk.RiskClass.MATERIAL
        assert decision.requires_human_approval is True

    def test_loopback_egress_is_material(self):
        decision = op_risk.classify_risk(
            op_risk.RiskFactors(
                roots=(Path("/workspace"),),
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
                containment_verified=True,
                egress_class=op_risk.EgressClass.LOOPBACK_ONLY,
            )
        )
        assert decision.risk_class == op_risk.RiskClass.MATERIAL


class TestHighAndProhibitedBoundaries:
    @pytest.mark.parametrize(
        "factors",
        [
            op_risk.RiskFactors(
                has_service_restart=True,
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            ),
            op_risk.RiskFactors(
                has_force_push=True,
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            ),
            op_risk.RiskFactors(
                has_delete=True,
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            ),
            op_risk.RiskFactors(
                production_effect=op_risk.ProductionEffect.CONFIG_CHANGE,
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            ),
            op_risk.RiskFactors(
                production_effect=op_risk.ProductionEffect.DEPLOYMENT,
                has_deployment=True,
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            ),
            op_risk.RiskFactors(
                egress_class=op_risk.EgressClass.ALLOWLISTED_HOSTS,
                egress_hosts=("api.example.com",),
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            ),
            op_risk.RiskFactors(
                has_external_communication=True,
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            ),
            op_risk.RiskFactors(
                has_client_identifiable_data=True,
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            ),
            op_risk.RiskFactors(
                has_financial_data=True,
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            ),
        ],
    )
    def test_high_risk_boundaries_are_never_standing(self, factors):
        decision = op_risk.classify_risk(factors)
        assert decision.risk_class == op_risk.RiskClass.HIGH
        assert decision.standing_authority_eligible is False
        assert decision.authority_bundle_eligible is False
        assert decision.requires_human_approval is True

    def test_deterministic_severity_prefers_high_over_material(self):
        factors = replace(tier1_factors(), has_service_restart=True)
        decision = op_risk.classify_risk(factors)
        assert decision.risk_class == op_risk.RiskClass.HIGH

    @pytest.mark.parametrize(
        "factors, phrase",
        [
            (
                op_risk.RiskFactors(
                    has_secret_access=True,
                    containment_strength=op_risk.ContainmentStrength.CONTAINER,
                ),
                "secret",
            ),
            (
                op_risk.RiskFactors(
                    has_credential_access=True,
                    containment_strength=op_risk.ContainmentStrength.CONTAINER,
                ),
                "credential",
            ),
            (
                op_risk.RiskFactors(
                    egress_class=op_risk.EgressClass.UNRESTRICTED,
                    containment_strength=op_risk.ContainmentStrength.CONTAINER,
                ),
                "unrestricted",
            ),
            (
                op_risk.RiskFactors(
                    paid_route_change=op_risk.PaidRouteChange.MODEL_CHANGE,
                    containment_strength=op_risk.ContainmentStrength.CONTAINER,
                ),
                "paid route",
            ),
            (
                op_risk.RiskFactors(
                    root_expansion=True,
                    containment_strength=op_risk.ContainmentStrength.CONTAINER,
                ),
                "root expansion",
            ),
            (
                op_risk.RiskFactors(
                    containment_weakened=True,
                    containment_strength=op_risk.ContainmentStrength.CONTAINER,
                ),
                "containment",
            ),
        ],
    )
    def test_prohibited_boundaries_fail_closed(self, factors, phrase):
        decision = op_risk.classify_risk(factors)
        assert decision.risk_class == op_risk.RiskClass.PROHIBITED
        assert decision.standing_authority_eligible is False
        assert decision.authority_bundle_eligible is False
        assert any(phrase in reason.lower() for reason in decision.prohibited_reasons)

    def test_weak_containment_is_high(self):
        for strength in (
            op_risk.ContainmentStrength.NONE,
            op_risk.ContainmentStrength.PROCESS_ISOLATION,
        ):
            decision = op_risk.classify_risk(
                op_risk.RiskFactors(roots=(Path("/workspace"),), containment_strength=strength)
            )
            assert decision.risk_class == op_risk.RiskClass.HIGH


class TestSessionFactorComputation:
    def test_hard_denied_secret_paths_are_protection_not_access(self):
        snapshot = {
            "readable_roots": ["/workspace"],
            "writable_roots": [],
            "verbs": {"filesystem": ["read"]},
            "hard_denied_paths": ["/home/user/.ssh", "/home/user/.aws/credentials"],
            "containment_strength": "container",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "policy_template": "read-only",
            "snapshot_hash": "hash",
            "version": 1,
        }
        factors = op_risk.compute_risk_factors_from_session(snapshot)
        assert factors.hard_denies_present is True
        assert factors.has_secret_access is False
        assert factors.has_credential_access is False
        assert op_risk.classify_risk(factors).risk_class == op_risk.RiskClass.LOW

    def test_session_computes_tier_one_facts(self):
        snapshot = {
            "readable_roots": ["/workspace"],
            "writable_roots": ["/workspace"],
            "verbs": {
                "filesystem": ["read", "edit"],
                "tests": ["run"],
                "git": ["commit"],
            },
            "containment_strength": "container",
            "bounded_roots_verified": True,
            "containment_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": True,
            "deliverable_verification_required": True,
            "policy_template": "contained-maintenance",
            "snapshot_hash": "abc",
            "version": 2,
        }
        factors = op_risk.compute_risk_factors_from_session(snapshot)
        assert factors.has_write is True
        assert factors.verbs == ("filesystem:read", "filesystem:edit", "tests:run", "git:commit")
        assert factors.policy_template_version == 2
        assert op_risk.classify_risk(factors).risk_class == op_risk.RiskClass.LOW

    def test_root_expansion_is_detected(self):
        snapshot = {
            "writable_roots": ["/workspace", "/extra"],
            "verbs": {},
            "containment_strength": "container",
        }
        baseline = {
            "writable_roots": ["/workspace"],
            "containment_strength": "container",
        }
        factors = op_risk.compute_risk_factors_from_session(snapshot, template_baseline=baseline)
        assert factors.root_expansion is True
        assert op_risk.classify_risk(factors).risk_class == op_risk.RiskClass.PROHIBITED

    def test_containment_weakening_is_detected(self):
        snapshot = {
            "writable_roots": ["/workspace"],
            "verbs": {},
            "containment_strength": "process",
        }
        baseline = {
            "writable_roots": ["/workspace"],
            "containment_strength": "container",
        }
        factors = op_risk.compute_risk_factors_from_session(snapshot, template_baseline=baseline)
        assert factors.containment_weakened is True


class TestEscalation:
    def test_same_factors_do_not_escalate(self):
        result = op_risk.check_escalation(tier1_factors(), tier1_factors())
        assert result.escalated is False
        assert result.from_class == result.to_class == op_risk.RiskClass.LOW

    def test_low_to_high_escalates(self):
        current = tier1_factors()
        proposed = replace(current, has_service_restart=True)
        result = op_risk.check_escalation(current, proposed)
        assert result.escalated is True
        assert result.from_class == op_risk.RiskClass.LOW
        assert result.to_class == op_risk.RiskClass.HIGH
        assert "has_service_restart" in result.changed_factors

    def test_low_to_prohibited_escalates(self):
        current = tier1_factors()
        proposed = replace(current, has_secret_access=True)
        result = op_risk.check_escalation(current, proposed)
        assert result.escalated is True
        assert result.to_class == op_risk.RiskClass.PROHIBITED
        assert result.new_prohibited

    def test_deescalation_is_not_reported_as_escalation(self):
        current = replace(tier1_factors(), has_service_restart=True)
        result = op_risk.check_escalation(current, tier1_factors())
        assert result.escalated is False


class TestSummaryAndFeatureFlag:
    def test_summary_contains_reason(self):
        decision = op_risk.classify_risk(
            op_risk.RiskFactors(
                has_write=True,
                containment_strength=op_risk.ContainmentStrength.CONTAINER,
            )
        )
        assert "MATERIAL risk" in decision.summary()
        assert "Write, test or normal-commit" in decision.summary()

    def test_feature_flag_default_off(self, monkeypatch):
        monkeypatch.delenv(op_risk.RISK_BASED_AUTHORITY_ENABLED_ENV, raising=False)
        assert op_risk.risk_based_authority_enabled() is False

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", "enabled"])
    def test_feature_flag_truthy(self, monkeypatch, value):
        monkeypatch.setenv(op_risk.RISK_BASED_AUTHORITY_ENABLED_ENV, value)
        assert op_risk.risk_based_authority_enabled() is True
