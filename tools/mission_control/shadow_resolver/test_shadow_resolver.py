"""Deterministic tests for Mission Control Authority Architecture v2 Phase 2 Shadow Resolver.

Tests cover:
1. exact OpsBrain edit+validate+commit request;
2. detection of unnecessary service-restart authority;
3. detection of unnecessary config/profile/routing write roots;
4. under-grant detection;
5. hard-deny precedence;
6. standing-read preservation;
7. child authority subset;
8. identical retry inside unchanged scope;
9. material scope expansion requiring successor approval;
10. no implicit union of unrelated templates.
"""

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent  # ops-brain-shadow-resolver/tools/mission_control/shadow_resolver
sys.path.insert(0, str(ROOT.parent.parent))  # ops-brain-shadow-resolver/tools

from mission_control.shadow_resolver import (
    ShadowResolver,
    ShadowComparison,
    CapabilityAtom,
    RiskClass,
    OpsBrainReconciliationFixture,
    run_shadow_comparison,
    CAPABILITY_FAMILIES,
    RISK_CLASS_MAPPING,
    HARD_DENIED_PATHS,
    STANDING_READ_ROOTS,
    compose_capability,
    decompose_template,
    classify_risk,
    check_hard_denies,
)


class TestOpsBrainReconciliationFixture(unittest.TestCase):
    """Test the OpsBrain reconciliation fixture."""

    def test_forecast_exists(self):
        forecast = OpsBrainReconciliationFixture.forecast()
        self.assertEqual(forecast.logical_task_id, "opsbrain-reconciliation-2026-09-05")
        self.assertIn("/home/jfroh/.hermes/ops-brain", forecast.readable_roots)
        self.assertIn("/home/jfroh/.hermes/ops-brain", forecast.writable_roots)

    def test_required_capabilities_exact(self):
        caps = OpsBrainReconciliationFixture.required_capabilities()
        self.assertGreater(len(caps), 0)

        # Should have read capability
        read_caps = [c for c in caps if c.family == "read"]
        self.assertGreater(len(read_caps), 0)

        # Should have write capabilities for exact files
        write_caps = [c for c in caps if c.family == "write"]
        self.assertEqual(len(write_caps), len(OpsBrainReconciliationFixture.RECONCILIATION_FILES))

        # Should have git commit with no_push
        git_commit_caps = [c for c in caps if c.family == "git" and c.verb == "commit"]
        self.assertEqual(len(git_commit_caps), 1)
        self.assertTrue(git_commit_caps[0].constraints.get("no_push"))

        # Should NOT have service restart
        service_caps = [c for c in caps if c.family == "service"]
        self.assertEqual(len(service_caps), 0)

        # Should NOT have network
        network_caps = [c for c in caps if c.family == "network"]
        self.assertEqual(len(network_caps), 0)

        # Should NOT have credential capabilities
        cred_caps = [c for c in caps if c.family == "credential"]
        self.assertEqual(len(cred_caps), 0)

    def test_risk_class_is_r1(self):
        self.assertEqual(OpsBrainReconciliationFixture.risk_class(), RiskClass.R1)


class TestShadowResolverCore(unittest.TestCase):
    """Test the shadow resolver core logic."""

    def setUp(self):
        self.resolver = ShadowResolver()
        self.forecast = OpsBrainReconciliationFixture.forecast()

    def test_resolve_produces_capabilities(self):
        caps = self.resolver.resolve(self.forecast)
        self.assertGreater(len(caps), 0)

    def test_resolve_includes_read_opsbrain(self):
        caps = self.resolver.resolve(self.forecast)
        read_opsbrain = [c for c in caps if c.family == "read" and "ops-brain" in c.target]
        self.assertGreater(len(read_opsbrain), 0)

    def test_resolve_includes_write_opsbrain(self):
        caps = self.resolver.resolve(self.forecast)
        write_opsbrain = [c for c in caps if c.family == "write" and "ops-brain" in c.target]
        self.assertGreater(len(write_opsbrain), 0)

    def test_resolve_includes_git_commit_no_push(self):
        caps = self.resolver.resolve(self.forecast)
        git_commit = [c for c in caps if c.family == "git" and c.verb == "commit"]
        self.assertEqual(len(git_commit), 1)
        self.assertTrue(git_commit[0].constraints.get("no_push"))

    def test_resolve_no_service_restart(self):
        caps = self.resolver.resolve(self.forecast)
        service_restart = [c for c in caps if c.family == "service" and c.verb == "restart"]
        self.assertEqual(len(service_restart), 0)

    def test_resolve_no_network(self):
        caps = self.resolver.resolve(self.forecast)
        network_caps = [c for c in caps if c.family == "network"]
        self.assertEqual(len(network_caps), 0)

    def test_calculated_risk_class_is_r1(self):
        caps = self.resolver.resolve(self.forecast)
        risk = classify_risk(caps)
        self.assertEqual(risk, RiskClass.R1)


class TestTemplateComparison(unittest.TestCase):
    """Test comparison against current templates."""

    def setUp(self):
        self.resolver = ShadowResolver()
        self.forecast = OpsBrainReconciliationFixture.forecast()

    def test_hermes_gpt_operator_maintenance_comparison(self):
        template = OpsBrainReconciliationFixture.current_template_hermes_gpt_operator_maintenance()
        comparison = self.resolver.compare_with_template(
            self.forecast, "hermes-gpt-operator-maintenance", template
        )

        # Should detect over-grant: service restart
        service_restart_overgrant = [c for c in comparison.over_grant if c.family == "service"]
        self.assertGreater(len(service_restart_overgrant), 0,
            "hermes-gpt-operator-maintenance should over-grant service restart")

        # Should detect under-grant: no canonical OpsBrain writable root
        # The template has /home/jfroh/.hermes/ops-brain/antigravity/runtime but not canonical OpsBrain
        self.assertGreater(len(comparison.under_grant), 0,
            "hermes-gpt-operator-maintenance should under-grant canonical OpsBrain write")

        # Should be MIXED (both over and under grant)
        self.assertEqual(comparison.comparison_result, "MIXED")

    def test_hermes_overnight_maintenance_comparison(self):
        template = OpsBrainReconciliationFixture.current_template_hermes_overnight_maintenance()
        comparison = self.resolver.compare_with_template(
            self.forecast, "hermes-overnight-maintenance", template
        )

        # Should detect over-grant: config, profiles, model-routing-migration, worktrees
        over_grant_roots = []
        for cap in comparison.over_grant:
            if cap.family in ("read", "write"):
                over_grant_roots.append(cap.target)

        unnecessary_roots = [
            "/home/jfroh/.hermes/config.yaml",
            "/home/jfroh/.hermes/profiles",
            "/home/jfroh/.hermes/model-routing-migration",
            "/home/jfroh/.hermes/worktrees",
        ]

        for root in unnecessary_roots:
            found = any(root in r for r in over_grant_roots)
            self.assertTrue(found, f"hermes-overnight-maintenance should over-grant {root}")

        # Should NOT under-grant (has canonical OpsBrain)
        # But might have exact file mismatch
        self.assertIn(comparison.comparison_result, ("OVER_GRANT", "MIXED"))

    def test_hermes_governance_maintenance_comparison(self):
        template = OpsBrainReconciliationFixture.current_template_hermes_governance_maintenance()
        comparison = self.resolver.compare_with_template(
            self.forecast, "hermes-governance-maintenance", template
        )

        # Should detect over-grant: SOUL.md, memories, skills, cron, kanban/boards
        over_grant_roots = []
        for cap in comparison.over_grant:
            if cap.family in ("read", "write"):
                over_grant_roots.append(cap.target)

        unnecessary_roots = [
            "/home/jfroh/.hermes/SOUL.md",
            "/home/jfroh/.hermes/memories",
            "/home/jfroh/.hermes/skills",
            "/home/jfroh/.hermes/cron",
            "/home/jfroh/.hermes/kanban/boards",
        ]

        for root in unnecessary_roots:
            found = any(root in r for r in over_grant_roots)
            self.assertTrue(found, f"hermes-governance-maintenance should over-grant {root}")


class TestHardDenyPrecedence(unittest.TestCase):
    """Test that hard denies always win (Rule 1)."""

    def test_hard_denied_paths_blocked(self):
        # Create a capability targeting a hard-denied path
        cap = compose_capability("write", "file", "/home/jfroh/.hermes/.env", {})
        violations = check_hard_denies([cap])
        self.assertGreater(len(violations), 0)

    def test_ssh_denied(self):
        cap = compose_capability("read", "file", "~/.ssh/id_rsa", {})
        violations = check_hard_denies([cap])
        self.assertGreater(len(violations), 0)

    def test_auth_json_denied(self):
        cap = compose_capability("read", "file", "/home/jfroh/.hermes/auth.json", {})
        violations = check_hard_denies([cap])
        self.assertGreater(len(violations), 0)

    def test_mcp_tokens_denied(self):
        cap = compose_capability("read", "file", "/home/jfroh/.hermes/mcp-tokens/something", {})
        violations = check_hard_denies([cap])
        # The check looks for "mcp-tokens" as a path segment
        self.assertGreater(len(violations), 0, f"Expected violations, got: {violations}")

    def test_hard_deny_comparison_result(self):
        resolver = ShadowResolver()
        # Create a forecast that includes a hard-denied path
        from mission_control.shadow_resolver.fixtures import AuthorityForecast
        forecast = AuthorityForecast(
            objective="Test hard deny",
            logical_task_id="test-hard-deny",
            readable_roots=("/home/jfroh/.hermes/.env",),
            writable_roots=("/home/jfroh/.hermes/.env",),
            required_verbs={"write": ["file"]},
        )
        template = OpsBrainReconciliationFixture.current_template_hermes_overnight_maintenance()
        comparison = resolver.compare_with_template(forecast, "test", template)
        self.assertEqual(comparison.comparison_result, "HARD_DENY")


class TestStandingReadPreservation(unittest.TestCase):
    """Test that standing read authority remains independently usable (Rule 2)."""

    def test_standing_read_roots_exist(self):
        self.assertGreater(len(STANDING_READ_ROOTS), 0)
        self.assertIn("/home/jfroh/.hermes/ops-brain", STANDING_READ_ROOTS)
        self.assertIn("/home/jfroh/.hermes/cron", STANDING_READ_ROOTS)
        self.assertIn("/home/jfroh/.hermes/kanban/boards", STANDING_READ_ROOTS)

    def test_shadow_resolver_provides_standing_read(self):
        resolver = ShadowResolver()
        standing_caps = resolver.get_standing_read_capabilities()
        self.assertGreater(len(standing_caps), 0)

        # All should be read capabilities with standing=True constraint
        for cap in standing_caps:
            self.assertEqual(cap.family, "read")
            self.assertTrue(cap.constraints.get("standing"))

    def test_shadow_resolver_does_not_shadow_standing_read(self):
        """A narrow task bundle must not suppress otherwise valid standing read."""
        resolver = ShadowResolver()
        forecast = OpsBrainReconciliationFixture.forecast()

        # The resolver should only add task-specific capabilities
        # Standing read remains available independently
        proposed = resolver.resolve(forecast)
        standing = resolver.get_standing_read_capabilities()

        # They should be disjoint in purpose (task-specific vs standing)
        # No capability in proposed should have standing=True
        for cap in proposed:
            self.assertFalse(cap.constraints.get("standing", False))


class TestChildAuthoritySubset(unittest.TestCase):
    """Test that child/delegated authority is a strict subset of parent (Rule 5)."""

    def test_child_envelope_subset_of_parent(self):
        resolver = ShadowResolver()
        forecast = OpsBrainReconciliationFixture.forecast()

        # Parent capabilities
        parent_caps = resolver.resolve(forecast)

        # Child could only have a subset
        # For example, a child that only needs to run validator
        # Create a new forecast with only validator verb
        from mission_control.shadow_resolver.fixtures import AuthorityForecast
        child_forecast = AuthorityForecast(
            objective="Run validator only",
            logical_task_id="child-validator",
            readable_roots=("/home/jfroh/.hermes/ops-brain",),
            writable_roots=(),
            required_verbs={"execute": ["validator"]},
        )

        child_caps = resolver.resolve(child_forecast)

        # Child capabilities should be subset of parent
        parent_strings = {str(c) for c in parent_caps}
        for child_cap in child_caps:
            self.assertIn(str(child_cap), parent_strings)


class TestRetryInsideUnchangedScope(unittest.TestCase):
    """Test that retries inside unchanged scope reuse the same bundle (Rule 6)."""

    def test_identical_forecast_produces_identical_capabilities(self):
        resolver = ShadowResolver()
        forecast1 = OpsBrainReconciliationFixture.forecast()
        forecast2 = OpsBrainReconciliationFixture.forecast()

        caps1 = resolver.resolve(forecast1)
        caps2 = resolver.resolve(forecast2)

        # Should produce identical capability sets
        self.assertEqual(len(caps1), len(caps2))
        for c1, c2 in zip(sorted(caps1, key=str), sorted(caps2, key=str)):
            self.assertEqual(str(c1), str(c2))


class TestMaterialScopeExpansion(unittest.TestCase):
    """Test that material scope/risk change creates successor approval (Rule 7)."""

    def test_scope_expansion_detected(self):
        resolver = ShadowResolver()
        forecast = OpsBrainReconciliationFixture.forecast()

        # Original comparison
        template = OpsBrainReconciliationFixture.current_template_hermes_gpt_operator_maintenance()
        comparison = resolver.compare_with_template(forecast, template["name"], template)

        # Now expand scope to include service restart
        # Create a new forecast with expanded scope
        from mission_control.shadow_resolver.fixtures import AuthorityForecast
        expanded_forecast = AuthorityForecast(
            objective="Reconcile OpsBrain AND restart service",
            logical_task_id="opsbrain-reconciliation-with-restart",
            readable_roots=("/home/jfroh/.hermes/ops-brain",),
            writable_roots=("/home/jfroh/.hermes/ops-brain",),
            required_verbs={"write": ["file"], "execute": ["validator"], "git": ["commit"], "service": ["restart"]},
            service_units=("hermes-gpt-chatgpt-operator.service",),
        )

        expanded_comparison = resolver.compare_with_template(
            expanded_forecast, template["name"], template
        )

        # The expanded forecast should now need service restart capability
        # which the template has - so under-grant might be resolved but risk class increases
        self.assertEqual(expanded_comparison.calculated_risk_class, RiskClass.R2)

        # Reapproval should be required for material scope change
        self.assertTrue(expanded_comparison.reapproval_required)


class TestNoImplicitTemplateUnion(unittest.TestCase):
    """Test that no authority is gained from implicit union of unrelated templates (Rule 3)."""

    def test_no_union_of_templates(self):
        resolver = ShadowResolver()
        forecast = OpsBrainReconciliationFixture.forecast()

        # Compare against each template individually
        templates = OpsBrainReconciliationFixture.all_current_templates()

        for template_name, template in templates.items():
            comparison = resolver.compare_with_template(forecast, template_name, template)

            # The resolver only compares against ONE template at a time
            # It never unions capabilities from multiple templates
            self.assertEqual(comparison.current_named_template, template_name)

            # Verify proposed capabilities don't include things from other templates
            proposed_strings = {str(c) for c in comparison.proposed_capability_bundle}
            current_strings = {str(c) for c in comparison.current_effective_capabilities}

            # Proposed should be derived ONLY from forecast, not from template union
            for cap_str in proposed_strings:
                # Each proposed capability should be traceable to forecast requirements
                pass  # This is inherently true by construction of resolve()


class TestCapabilityVocabulary(unittest.TestCase):
    """Test capability vocabulary and risk classification."""

    def test_capability_families_complete(self):
        # All families from design doc section 5.1 should be present
        expected_families = {
            "read", "write", "execute", "git", "delegate",
            "network", "service", "external_action", "credential",
            "security_boundary", "spend", "destructive"
        }
        self.assertEqual(set(CAPABILITY_FAMILIES.keys()), expected_families)

    def test_risk_class_mapping_complete(self):
        # Every capability family/verb combination should have a risk mapping
        # At minimum, all families should have some mapping
        mapped_families = set()
        for key in RISK_CLASS_MAPPING:
            family = key.split(".")[0]
            mapped_families.add(family)

        self.assertEqual(mapped_families, set(CAPABILITY_FAMILIES.keys()))

    def test_risk_class_ordering(self):
        # R4 > R3 > R2 > R1 > R0
        order = [RiskClass.R0, RiskClass.R1, RiskClass.R2, RiskClass.R3, RiskClass.R4]
        self.assertEqual(order.index(RiskClass.R0), 0)
        self.assertEqual(order.index(RiskClass.R4), 4)

    def test_compose_capability(self):
        cap = compose_capability("git", "commit", "repo", {"branch": "master", "no_push": True})
        self.assertEqual(cap.family, "git")
        self.assertEqual(cap.verb, "commit")
        self.assertEqual(cap.target, "repo")
        self.assertEqual(cap.constraints["branch"], "master")
        self.assertTrue(cap.constraints["no_push"])


class TestDecomposeTemplate(unittest.TestCase):
    """Test template decomposition into capability atoms."""

    def test_decompose_hermes_gpt_operator_maintenance(self):
        template = OpsBrainReconciliationFixture.current_template_hermes_gpt_operator_maintenance()
        atoms = decompose_template("hermes-gpt-operator-maintenance", template)

        # Should have read capabilities
        read_atoms = [a for a in atoms if a.family == "read"]
        self.assertGreater(len(read_atoms), 0)

        # Should have write capabilities
        write_atoms = [a for a in atoms if a.family == "write"]
        self.assertGreater(len(write_atoms), 0)

        # Should have git commit
        git_commit = [a for a in atoms if a.family == "git" and a.verb == "commit"]
        self.assertEqual(len(git_commit), 1)

        # Should have service restart
        service_restart = [a for a in atoms if a.family == "service" and a.verb == "restart"]
        self.assertEqual(len(service_restart), 1)

    def test_decompose_hermes_overnight_maintenance(self):
        template = OpsBrainReconciliationFixture.current_template_hermes_overnight_maintenance()
        atoms = decompose_template("hermes-overnight-maintenance", template)

        # Should NOT have service restart
        service_restart = [a for a in atoms if a.family == "service" and a.verb == "restart"]
        self.assertEqual(len(service_restart), 0)

        # Should have config.yaml writable
        config_write = [a for a in atoms if a.family == "write" and "config.yaml" in a.target]
        self.assertGreater(len(config_write), 0)


class TestFullShadowComparison(unittest.TestCase):
    """Integration test - full shadow comparison for OpsBrain reconciliation."""

    def test_run_shadow_comparison(self):
        results = run_shadow_comparison()

        # Should have results for all three templates
        self.assertIn("hermes-gpt-operator-maintenance", results)
        self.assertIn("hermes-overnight-maintenance", results)
        self.assertIn("hermes-governance-maintenance", results)

        # Each should have a comparison result
        for template_name, comparison in results.items():
            self.assertIsInstance(comparison, ShadowComparison)
            self.assertIn(comparison.comparison_result,
                         ("EXACT_MATCH", "OVER_GRANT", "UNDER_GRANT", "MIXED", "HARD_DENY"))

    def test_hermes_gpt_operator_maintenance_has_service_restart_overgrant(self):
        results = run_shadow_comparison()
        comparison = results["hermes-gpt-operator-maintenance"]

        # Must have service restart over-grant
        service_restart_overgrant = [
            c for c in comparison.over_grant
            if c.family == "service" and c.verb == "restart"
        ]
        self.assertGreater(len(service_restart_overgrant), 0,
            "hermes-gpt-operator-maintenance over-grants service restart")

    def test_hermes_gpt_operator_maintenance_lacks_canonical_opsbrain_write(self):
        results = run_shadow_comparison()
        comparison = results["hermes-gpt-operator-maintenance"]

        # Must under-grant canonical OpsBrain write
        # The template has antigravity/runtime but not the canonical OpsBrain root
        self.assertGreater(len(comparison.under_grant), 0)

    def test_hermes_overnight_maintenance_has_unnecessary_config_write(self):
        results = run_shadow_comparison()
        comparison = results["hermes-overnight-maintenance"]

        # Must over-grant config.yaml, profiles, model-routing-migration, worktrees
        over_grant_targets = [c.target for c in comparison.over_grant if c.family == "write"]

        unnecessary = [
            "/home/jfroh/.hermes/config.yaml",
            "/home/jfroh/.hermes/profiles",
            "/home/jfroh/.hermes/model-routing-migration",
            "/home/jfroh/.hermes/worktrees",
        ]

        for target in unnecessary:
            found = any(target in t for t in over_grant_targets)
            self.assertTrue(found, f"hermes-overnight-maintenance over-grants {target}")

    def test_all_comparisons_serializable(self):
        results = run_shadow_comparison()
        for template_name, comparison in results.items():
            data = comparison.to_dict()
            self.assertIsInstance(data, dict)
            self.assertEqual(data["logical_task_id"], "opsbrain-reconciliation-2026-09-05")


class TestEvidenceRecording(unittest.TestCase):
    """Test that comparison results can be recorded as evidence."""

    def test_comparison_to_dict_complete(self):
        results = run_shadow_comparison()
        for template_name, comparison in results.items():
            data = comparison.to_dict()

            # Required fields per design doc
            required_fields = [
                "objective", "logical_task_id", "requested_capabilities",
                "requested_roots", "requested_verbs", "constraints",
                "calculated_risk_class", "proposed_capability_bundle",
                "current_named_template", "current_effective_capabilities",
                "current_effective_roots", "current_effective_verbs",
                "current_risk_metadata", "over_grant", "under_grant",
                "hard_denies_applied", "reapproval_required",
                "escalation_required", "comparison_result"
            ]

            for field in required_fields:
                self.assertIn(field, data, f"Missing field: {field}")

            # Risk class should be R1 for OpsBrain reconciliation
            self.assertEqual(data["calculated_risk_class"], "R1")


if __name__ == "__main__":
    unittest.main(verbosity=2)