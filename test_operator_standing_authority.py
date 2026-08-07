"""Tests for operator_standing_authority: durable standing-low-risk authorization."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

import operator_risk as op_risk
import operator_standing_authority as op_standing
import operator_sessions as op_sessions


@pytest.fixture
def session_env(tmp_path, monkeypatch):
    root = tmp_path / "sessions"
    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(root))
    monkeypatch.setenv(op_standing.RISK_BASED_AUTHORITY_ENABLED_ENV, "1")
    yield root


@pytest.fixture
def low_risk_factors():
    """Risk factors that classify as LOW risk."""
    return op_risk.RiskFactors(
        roots=(Path("/home/safe/read"),),
        writable_roots=(Path("/home/safe/write"),),
        containment_strength=op_risk.ContainmentStrength.VM,
        policy_template="test-template",
        policy_template_hash="abc123",
        policy_template_version=1,
    )


@pytest.fixture
def low_risk_decision(low_risk_factors):
    """Risk decision for LOW risk factors."""
    return op_risk.classify_risk(low_risk_factors)


class TestStandingAuthority:
    def test_create_standing_authority(self, session_env, low_risk_factors, low_risk_decision):
        authority = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        assert authority.authority_id.startswith("sa_")
        assert authority.policy_template == "test-template"
        assert authority.policy_template_hash == "abc123"
        assert authority.created_by == "telegram:12345"
        assert authority.revoked_at is None
        assert not authority.is_revoked()

    def test_create_standing_authority_requires_low_risk(self, session_env):
        """Creating standing authority with non-LOW risk should fail."""
        factors = op_risk.RiskFactors(
            roots=(Path("/home/safe"),),
            has_write=True,
            containment_strength=op_risk.ContainmentStrength.CONTAINER,
        )
        decision = op_risk.classify_risk(factors)
        assert decision.risk_class == op_risk.RiskClass.MATERIAL

        with pytest.raises(op_standing.StandingAuthorityError, match="LOW risk"):
            op_standing.create_standing_authority(
                risk_factors=factors,
                risk_decision=decision,
                created_by="telegram:12345",
                root=session_env,
            )

    def test_create_standing_authority_feature_flag_off(self, session_env, monkeypatch, low_risk_factors, low_risk_decision):
        """Creating standing authority with feature flag off should fail."""
        monkeypatch.setenv(op_standing.RISK_BASED_AUTHORITY_ENABLED_ENV, "0")
        with pytest.raises(op_standing.StandingAuthorityError, match="disabled"):
            op_standing.create_standing_authority(
                risk_factors=low_risk_factors,
                risk_decision=low_risk_decision,
                created_by="telegram:12345",
                root=session_env,
            )

    def test_load_standing_authority(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        loaded = op_standing.load_standing_authority(created.authority_id, root=session_env)
        assert loaded.authority_id == created.authority_id
        assert loaded.policy_template == created.policy_template
        assert loaded.created_by == created.created_by

    def test_load_nonexistent_raises(self, session_env):
        with pytest.raises(op_standing.StandingAuthorityNotFoundError):
            op_standing.load_standing_authority("sa_nonexistent", root=session_env)

    def test_list_standing_authorities(self, session_env, low_risk_factors, low_risk_decision):
        op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:67890",
            root=session_env,
        )
        authorities = op_standing.list_standing_authorities(root=session_env)
        assert len(authorities) == 2

    def test_revoke_standing_authority(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        assert op_standing.revoke_standing_authority(
            created.authority_id, revoked_by="telegram:12345", reason="test revocation", root=session_env
        ) is True

        loaded = op_standing.load_standing_authority(created.authority_id, root=session_env)
        assert loaded.is_revoked()
        assert loaded.revoked_by == "telegram:12345"
        assert loaded.revocation_reason == "test revocation"

    def test_revoke_already_revoked_returns_false(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        op_standing.revoke_standing_authority(
            created.authority_id, revoked_by="telegram:12345", reason="first", root=session_env
        )
        assert op_standing.revoke_standing_authority(
            created.authority_id, revoked_by="telegram:12345", reason="second", root=session_env
        ) is False

    def test_is_valid_not_revoked(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        valid, reason = created.is_valid()
        assert valid is True
        assert reason is None

    def test_is_valid_revoked(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        op_standing.revoke_standing_authority(
            created.authority_id, revoked_by="telegram:12345", reason="test", root=session_env
        )
        loaded = op_standing.load_standing_authority(created.authority_id, root=session_env)
        valid, reason = loaded.is_valid()
        assert valid is False
        assert "Revoked" in reason

    def test_is_valid_operational_deadline_exceeded(self, session_env, low_risk_factors, low_risk_decision):
        """Operational deadline exceeded should return False but is WATCHDOG not auth invalidation."""
        past_deadline = int(time.time()) - 100
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            operational_deadline=past_deadline,
            operational_deadline_reason="test watchdog",
            root=session_env,
        )
        valid, reason = created.is_valid()
        assert valid is True
        assert reason is None
        assert created.operational_deadline_exceeded() is True

    def test_authorization_validity_summary(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        summary = created.authorization_validity_summary()
        assert "STANDING" in summary
        assert "Valid until explicit revocation" in summary

    def test_operational_status_summary_no_deadline(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        summary = created.operational_status_summary()
        assert "No operational deadline" in summary

    def test_operational_status_summary_with_deadline(self, session_env, low_risk_factors, low_risk_decision):
        future_deadline = int(time.time()) + 3600
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            operational_deadline=future_deadline,
            operational_deadline_reason="test",
            root=session_env,
        )
        summary = created.operational_status_summary()
        assert "Operational deadline in" in summary

    def test_check_validity_policy_hash_change(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate policy template hash change
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            containment_strength=op_risk.ContainmentStrength.VM,
            policy_template="test-template",
            policy_template_hash="different_hash",
            policy_template_version=1,
        )
        valid, reason = op_standing.check_standing_authority_validity(created, changed_factors)
        assert valid is False
        assert "hash changed" in reason.lower()

    def test_check_validity_policy_version_change(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate policy template version change
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            containment_strength=op_risk.ContainmentStrength.VM,
            policy_template="test-template",
            policy_template_hash="abc123",
            policy_template_version=2,  # Changed version
        )
        valid, reason = op_standing.check_standing_authority_validity(created, changed_factors)
        assert valid is False
        assert "version changed" in reason.lower()

    def test_check_validity_risk_factors_hash_change(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate risk factors change (e.g., added write capability)
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            has_write=True,  # Added write capability
            containment_strength=op_risk.ContainmentStrength.VM,
            policy_template="test-template",
            policy_template_hash="abc123",
            policy_template_version=1,
        )
        valid, reason = op_standing.check_standing_authority_validity(created, changed_factors)
        assert valid is False
        assert "changed" in reason.lower() or "escalation" in reason.lower()

    def test_check_validity_containment_weakened(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate containment weakening
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            containment_strength=op_risk.ContainmentStrength.PROCESS_ISOLATION,  # Weaker than VM
            containment_weakened=True,
            policy_template="test-template",
            policy_template_hash="abc123",
            policy_template_version=1,
        )
        valid, reason = op_standing.check_standing_authority_validity(created, changed_factors)
        assert valid is False
        assert "containment" in reason.lower()

    def test_check_validity_guardrail_breach(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate guardrail breach (secret access added)
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            has_secret_access=True,  # PROHIBITED
            containment_strength=op_risk.ContainmentStrength.VM,
            policy_template="test-template",
            policy_template_hash="abc123",
            policy_template_version=1,
        )
        valid, reason = op_standing.check_standing_authority_validity(created, changed_factors)
        assert valid is False
        assert "guardrail breach" in reason.lower() or "secret" in reason.lower()

    def test_check_validity_risk_class_escalation(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        # Simulate escalation to HIGH risk
        changed_factors = op_risk.RiskFactors(
            roots=(Path("/home/safe/read"),),
            writable_roots=(Path("/home/safe/write"),),
            has_service_restart=True,  # HIGH risk
            containment_strength=op_risk.ContainmentStrength.VM,
            policy_template="test-template",
            policy_template_hash="abc123",
            policy_template_version=1,
        )
        valid, reason = op_standing.check_standing_authority_validity(created, changed_factors)
        assert valid is False
        assert "high" in reason.lower()

    def test_standing_authority_no_time_expiry(self, session_env, low_risk_factors, low_risk_decision):
        """STANDING AUTHORITY MUST NOT EXPIRE DUE TO ELAPSED TIME ALONE."""
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
            now=1000,  # Created at time 1000
        )
        # Check validity at time 1000000 (far future)
        valid, reason = created.is_valid(current_time=1000000)
        assert valid is True
        assert reason is None

    def test_set_operational_deadline(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        future = int(time.time()) + 3600
        updated = op_standing.set_operational_deadline(created.authority_id, future, "test deadline", root=session_env)
        assert updated.operational_deadline == future
        assert updated.operational_deadline_reason == "test deadline"

    def test_clear_operational_deadline(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            operational_deadline=int(time.time()) + 3600,
            operational_deadline_reason="test",
            root=session_env,
        )
        updated = op_standing.clear_operational_deadline(created.authority_id, root=session_env)
        assert updated.operational_deadline is None
        assert updated.operational_deadline_reason is None

    def test_verify_containment(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        updated = op_standing.verify_containment(created.authority_id, verified_by="telegram:12345", root=session_env)
        assert updated.containment_verified_at is not None
        assert updated.containment_verified_by == "telegram:12345"

    def test_get_active_standing_authority(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        active = op_standing.get_active_standing_authority(root=session_env)
        assert active is not None
        assert active.authority_id == created.authority_id

    def test_get_active_standing_authority_revoked_returns_none(self, session_env, low_risk_factors, low_risk_decision):
        created = op_standing.create_standing_authority(
            risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_by="telegram:12345",
            root=session_env,
        )
        op_standing.revoke_standing_authority(
            created.authority_id, revoked_by="telegram:12345", reason="test", root=session_env
        )
        active = op_standing.get_active_standing_authority(root=session_env)
        assert active is None


class TestStandingAuthoritySerialization:
    def test_to_dict_and_from_dict(self, low_risk_factors, low_risk_decision):
        authority = op_standing.StandingAuthority(
            authority_id="sa_test",
            policy_template="test",
            policy_template_hash="abc",
            policy_template_version=1,
            risk_factors_hash=low_risk_factors.compute_hash(),
            approved_risk_factors=low_risk_factors,
            risk_decision=low_risk_decision,
            created_at=1000,
            created_by="telegram:12345",
        )
        d = authority.to_dict()
        assert d["authority_id"] == "sa_test"
        assert d["policy_template"] == "test"

        loaded = op_standing.StandingAuthority.from_dict(d)
        assert loaded.authority_id == authority.authority_id
        assert loaded.policy_template == authority.policy_template
        assert loaded.risk_decision.risk_class == authority.risk_decision.risk_class


if __name__ == "__main__":
    pytest.main([__file__, "-v"])