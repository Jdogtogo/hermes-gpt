"""Tests for operator_authority_bundle: bounded MATERIAL-risk authority bundles."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import operator_risk as op_risk
import operator_authority_bundle as op_bundle
import operator_sessions as op_sessions


@pytest.fixture
def session_env(tmp_path, monkeypatch):
    root = tmp_path / "sessions"
    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(root))
    monkeypatch.setenv(op_bundle.RISK_BASED_AUTHORITY_ENABLED_ENV, "1")
    yield root


@pytest.fixture
def material_risk_factors():
    """Risk factors that classify as MATERIAL risk (write capability)."""
    return op_risk.RiskFactors(
        roots=(Path("/home/safe/read"),),
        writable_roots=(Path("/home/safe/write"),),
        has_write=True,
        containment_strength=op_risk.ContainmentStrength.CONTAINER,
        policy_template="test-template",
        policy_template_hash="abc123",
        policy_template_version=1,
    )


@pytest.fixture
def material_risk_decision(material_risk_factors):
    """Risk decision for MATERIAL risk factors."""
    return op_risk.classify_risk(material_risk_factors)


@pytest.fixture
def approved_scope():
    """Approved scope matching the material risk factors."""
    return {
        "readable_roots": ["/home/safe/read"],
        "writable_roots": ["/home/safe/write"],
        "verbs": {"filesystem": ["read", "edit"]},
        "egress_hosts": [],
        "service_units": [],
    }


class TestAuthorityBundle:
    def test_create_authority_bundle(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        bundle = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        assert bundle.bundle_id.startswith("ab_")
        assert bundle.policy_template == "test-template"
        assert bundle.policy_template_hash == "abc123"
        assert bundle.created_by == "telegram:12345"
        assert bundle.revoked_at is None
        assert not bundle.is_revoked()
        assert not bundle.is_completed()

    def test_create_authority_bundle_requires_material_or_low_risk(self, session_env):
        """Creating authority bundle with HIGH/PROHIBITED risk should fail."""
        factors = op_risk.RiskFactors(
            roots=(Path("/home/safe"),),
            has_service_restart=True,  # HIGH risk
            containment_strength=op_risk.ContainmentStrength.CONTAINER,
        )
        decision = op_risk.classify_risk(factors)
        assert decision.risk_class == op_risk.RiskClass.HIGH

        with pytest.raises(op_bundle.AuthorityBundleError, match="LOW/MATERIAL risk"):
            op_bundle.create_authority_bundle(
                risk_factors=factors,
                risk_decision=decision,
                approved_scope={},
                created_by="telegram:12345",
                root=session_env,
            )

    def test_create_authority_bundle_feature_flag_off(self, session_env, monkeypatch, material_risk_factors, material_risk_decision, approved_scope):
        """Creating authority bundle with feature flag off should fail."""
        monkeypatch.setenv(op_bundle.RISK_BASED_AUTHORITY_ENABLED_ENV, "0")
        with pytest.raises(op_bundle.AuthorityBundleError, match="disabled"):
            op_bundle.create_authority_bundle(
                risk_factors=material_risk_factors,
                risk_decision=material_risk_decision,
                approved_scope=approved_scope,
                created_by="telegram:12345",
                root=session_env,
            )

    def test_load_authority_bundle(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        loaded = op_bundle.load_authority_bundle(created.bundle_id, root=session_env)
        assert loaded.bundle_id == created.bundle_id
        assert loaded.policy_template == created.policy_template
        assert loaded.created_by == created.created_by

    def test_load_nonexistent_raises(self, session_env):
        with pytest.raises(op_bundle.AuthorityBundleNotFoundError):
            op_bundle.load_authority_bundle("ab_nonexistent", root=session_env)

    def test_list_authority_bundles(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:67890",
            root=session_env,
        )
        bundles = op_bundle.list_authority_bundles(root=session_env)
        assert len(bundles) == 2

    def test_revoke_authority_bundle(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        assert op_bundle.revoke_authority_bundle(
            created.bundle_id, revoked_by="telegram:12345", reason="test revocation", root=session_env
        ) is True

        loaded = op_bundle.load_authority_bundle(created.bundle_id, root=session_env)
        assert loaded.is_revoked()
        assert loaded.revoked_by == "telegram:12345"
        assert loaded.revocation_reason == "test revocation"

    def test_revoke_already_revoked_returns_false(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        op_bundle.revoke_authority_bundle(
            created.bundle_id, revoked_by="telegram:12345", reason="first", root=session_env
        )
        assert op_bundle.revoke_authority_bundle(
            created.bundle_id, revoked_by="telegram:12345", reason="second", root=session_env
        ) is False

    def test_complete_authority_bundle(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        assert op_bundle.complete_authority_bundle(
            created.bundle_id, completed_by="telegram:12345", root=session_env
        ) is True

        loaded = op_bundle.load_authority_bundle(created.bundle_id, root=session_env)
        assert loaded.is_completed()
        assert loaded.completed_by == "telegram:12345"

    def test_complete_revoked_bundle_raises(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        op_bundle.revoke_authority_bundle(
            created.bundle_id, revoked_by="telegram:12345", reason="test", root=session_env
        )
        with pytest.raises(op_bundle.AuthorityBundleRevokedError, match="Cannot complete a revoked bundle"):
            op_bundle.complete_authority_bundle(
                created.bundle_id, completed_by="telegram:12345", root=session_env
            )

    def test_is_valid_not_revoked(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        valid, reason = created.is_valid()
        assert valid is True
        assert reason is None

    def test_is_valid_revoked(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        op_bundle.revoke_authority_bundle(
            created.bundle_id, revoked_by="telegram:12345", reason="test", root=session_env
        )
        loaded = op_bundle.load_authority_bundle(created.bundle_id, root=session_env)
        valid, reason = loaded.is_valid()
        assert valid is False
        assert "Revoked" in reason

    def test_is_valid_completed(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        op_bundle.complete_authority_bundle(
            created.bundle_id, completed_by="telegram:12345", root=session_env
        )
        loaded = op_bundle.load_authority_bundle(created.bundle_id, root=session_env)
        valid, reason = loaded.is_valid()
        assert valid is False
        assert "Completed" in reason

    def test_is_valid_operational_deadline_exceeded(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        """Operational deadline exceeded should return False but is WATCHDOG not auth invalidation."""
        past_deadline = int(time.time()) - 100
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            operational_deadline=past_deadline,
            operational_deadline_reason="test watchdog",
            root=session_env,
        )
        valid, reason = created.is_valid()
        assert valid is True
        assert reason is None
        assert created.operational_deadline_exceeded() is True

    def test_authorization_validity_summary(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        summary = created.authorization_validity_summary()
        assert "BUNDLE" in summary
        assert "Valid until completion, revocation, or scope/risk change" in summary

    def test_operational_status_summary_no_deadline(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        summary = created.operational_status_summary()
        assert "No operational deadline set (no watchdog)" in summary

    def test_operational_status_summary_with_deadline(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        future_deadline = int(time.time()) + 3600
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            operational_deadline=future_deadline,
            operational_deadline_reason="test",
            root=session_env,
        )
        summary = created.operational_status_summary()
        assert "Operational deadline in" in summary

    def test_scope_summary(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        summary = created.scope_summary()
        assert "read: 1 roots" in summary
        assert "write: 1 roots" in summary
        assert "verbs: 2 actions" in summary


class TestScopeChecking:
    def test_check_scope_within_approved(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        result = op_bundle.check_scope(
            created,
            requested_roots=(Path("/home/safe/read/subdir"),),
            requested_writable=(Path("/home/safe/write/subdir"),),
        )
        assert result.within_scope is True

    def test_check_scope_outside_readable_roots(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        result = op_bundle.check_scope(
            created,
            requested_roots=(Path("/home/outside"),),
        )
        assert result.within_scope is False
        assert "not within approved readable roots" in result.reason

    def test_check_scope_outside_writable_roots(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        result = op_bundle.check_scope(
            created,
            requested_writable=(Path("/home/outside/write"),),
        )
        assert result.within_scope is False
        assert "not within approved writable roots" in result.reason

    def test_check_scope_verbs(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        # Approved verb
        result = op_bundle.check_scope(
            created,
            requested_verbs={"filesystem": ["read"]},
        )
        assert result.within_scope is True

        # Unapproved verb
        result = op_bundle.check_scope(
            created,
            requested_verbs={"filesystem": ["delete"]},
        )
        assert result.within_scope is False
        assert "Verb filesystem:delete not in approved scope" in result.reason

    def test_check_scope_egress(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        scope_with_egress = {**approved_scope, "egress_hosts": ["localhost", "api.example.com"]}
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=scope_with_egress,
            created_by="telegram:12345",
            root=session_env,
        )
        result = op_bundle.check_scope(
            created,
            requested_egress=("localhost",),
        )
        assert result.within_scope is True

        result = op_bundle.check_scope(
            created,
            requested_egress=("evil.com",),
        )
        assert result.within_scope is False
        assert "Egress host evil.com not in approved egress hosts" in result.reason

    def test_check_and_enforce_scope_raises_on_violation(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        with pytest.raises(op_bundle.AuthorityBundleScopeError, match="outside approved bundle scope"):
            op_bundle.check_and_enforce_scope(
                created,
                requested_roots=(Path("/home/outside"),),
            )


class TestAuthorityBundleValidity:
    def test_check_validity_policy_hash_change(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate policy template hash change
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            has_write=True,
            containment_strength=op_risk.ContainmentStrength.CONTAINER,
            policy_template="test-template",
            policy_template_hash="different_hash",
            policy_template_version=1,
        )
        valid, reason = op_bundle.check_authority_bundle_validity(created, changed_factors)
        assert valid is False
        assert "hash changed" in reason.lower()

    def test_check_validity_policy_version_change(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate policy template version change
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            has_write=True,
            containment_strength=op_risk.ContainmentStrength.CONTAINER,
            policy_template="test-template",
            policy_template_hash="abc123",
            policy_template_version=2,  # Changed version
        )
        valid, reason = op_bundle.check_authority_bundle_validity(created, changed_factors)
        assert valid is False
        assert "version changed" in reason.lower()

    def test_check_validity_risk_factors_hash_change(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate risk factors change (e.g., added service restart = HIGH risk)
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            has_write=True,
            has_service_restart=True,  # Adds HIGH risk
            containment_strength=op_risk.ContainmentStrength.CONTAINER,
            policy_template="test-template",
            policy_template_hash="abc123",
            policy_template_version=1,
        )
        valid, reason = op_bundle.check_authority_bundle_validity(created, changed_factors)
        assert valid is False
        assert "escalated" in reason.lower() or "risk class" in reason.lower()

    def test_check_validity_containment_weakened(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate containment weakening
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            has_write=True,
            containment_strength=op_risk.ContainmentStrength.PROCESS_ISOLATION,  # Weaker than CONTAINER
            containment_weakened=True,
            policy_template="test-template",
            policy_template_hash="abc123",
            policy_template_version=1,
        )
        valid, reason = op_bundle.check_authority_bundle_validity(created, changed_factors)
        assert valid is False
        assert "containment" in reason.lower()

    def test_check_validity_guardrail_breach(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate guardrail breach (secret access added)
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            has_write=True,
            has_secret_access=True,  # PROHIBITED
            containment_strength=op_risk.ContainmentStrength.CONTAINER,
            policy_template="test-template",
            policy_template_hash="abc123",
            policy_template_version=1,
        )
        valid, reason = op_bundle.check_authority_bundle_validity(created, changed_factors)
        assert valid is False
        assert "guardrail breach" in reason.lower() or "secret" in reason.lower()


class TestOperationalDeadline:
    def test_set_operational_deadline(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        future = int(time.time()) + 3600
        updated = op_bundle.set_operational_deadline(created.bundle_id, future, "test deadline", root=session_env)
        assert updated.operational_deadline == future
        assert updated.operational_deadline_reason == "test deadline"

    def test_clear_operational_deadline(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            operational_deadline=int(time.time()) + 3600,
            operational_deadline_reason="test",
            root=session_env,
        )
        updated = op_bundle.clear_operational_deadline(created.bundle_id, root=session_env)
        assert updated.operational_deadline == 0

    def test_verify_containment(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        updated = op_bundle.verify_containment(created.bundle_id, verified_by="telegram:12345", root=session_env)
        assert updated.containment_verified_at is not None
        assert updated.containment_verified_by == "telegram:12345"


class TestGetActiveAuthorityBundle:
    def test_get_active_authority_bundle(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        active = op_bundle.get_active_authority_bundle(root=session_env)
        assert active is not None
        assert active.bundle_id == created.bundle_id

    def test_get_active_authority_bundle_revoked_returns_none(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
        )
        op_bundle.revoke_authority_bundle(
            created.bundle_id, revoked_by="telegram:12345", reason="test", root=session_env
        )
        active = op_bundle.get_active_authority_bundle(root=session_env)
        assert active is None


class TestAuthorityBundleSerialization:
    def test_to_dict_and_from_dict(self, material_risk_factors, material_risk_decision, approved_scope):
        bundle = op_bundle.AuthorityBundle(
            bundle_id="ab_test",
            policy_template="test",
            policy_template_hash="abc",
            policy_template_version=1,
            risk_factors_hash=material_risk_factors.compute_hash(),
            approved_risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            required_deliverables=("tests", "commit"),
            verified_deliverables=("tests",),
            created_at=1000,
            created_by="telegram:12345",
        )
        d = bundle.to_dict()
        assert d["bundle_id"] == "ab_test"
        assert d["policy_template"] == "test"
        assert d["risk_decision"]["risk_class"] == "material"

        loaded = op_bundle.AuthorityBundle.from_dict(d)
        assert loaded.bundle_id == bundle.bundle_id
        assert loaded.policy_template == bundle.policy_template
        assert loaded.risk_decision.risk_class == bundle.risk_decision.risk_class


class TestAuthorityBundleNoTimeExpiry:
    def test_authority_bundle_no_time_expiry(self, session_env, material_risk_factors, material_risk_decision, approved_scope):
        """AUTHORITY BUNDLE MUST NOT EXPIRE DUE TO ELAPSED TIME ALONE."""
        created = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            root=session_env,
            now=1000,  # Created at time 1000
        )
        # Check validity at time 1000000 (far future)
        valid, reason = created.is_valid(current_time=1000000)
        assert valid is True
        assert reason is None


class TestDeliverableAwareCompletion:
    def test_completion_requires_all_approved_deliverables(
        self, session_env, material_risk_factors, material_risk_decision, approved_scope
    ):
        bundle = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            required_deliverables=("focused_tests", "commit_evidence"),
            root=session_env,
        )
        with pytest.raises(op_bundle.AuthorityBundleDeliverableError, match="unverified"):
            op_bundle.complete_authority_bundle(
                bundle.bundle_id, completed_by="mission-control", root=session_env
            )
        first = op_bundle.verify_bundle_deliverable(
            bundle.bundle_id, "focused_tests", verified_by="mission-control", root=session_env
        )
        assert first.verified_deliverables == ("focused_tests",)
        with pytest.raises(op_bundle.AuthorityBundleDeliverableError, match="commit_evidence"):
            op_bundle.complete_authority_bundle(
                bundle.bundle_id, completed_by="mission-control", root=session_env
            )
        final = op_bundle.verify_bundle_deliverable(
            bundle.bundle_id, "commit_evidence", verified_by="mission-control", root=session_env
        )
        assert set(final.verified_deliverables) == {"focused_tests", "commit_evidence"}
        assert op_bundle.complete_authority_bundle(
            bundle.bundle_id, completed_by="mission-control", root=session_env
        ) is True
        assert op_bundle.load_authority_bundle(bundle.bundle_id, root=session_env).is_completed()

    def test_unapproved_deliverable_cannot_be_verified(
        self, session_env, material_risk_factors, material_risk_decision, approved_scope
    ):
        bundle = op_bundle.create_authority_bundle(
            risk_factors=material_risk_factors,
            risk_decision=material_risk_decision,
            approved_scope=approved_scope,
            created_by="telegram:12345",
            required_deliverables=("focused_tests",),
            root=session_env,
        )
        with pytest.raises(op_bundle.AuthorityBundleDeliverableError, match="not part"):
            op_bundle.verify_bundle_deliverable(
                bundle.bundle_id, "external_publish", verified_by="mission-control", root=session_env
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])