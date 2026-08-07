"""Tests for the named operator-session policy template registry."""

from __future__ import annotations

import pytest

import operator_policy_templates as templates


def test_sandbox_resolves_to_exact_paths():
    resolved = templates.resolve_template("sandbox")
    policy = resolved["policy"]
    assert policy["readable_roots"] == ["/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch"]
    assert policy["writable_roots"] == ["/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch"]


def test_canonical_preservation_integration_is_read_only_on_canonical_and_release_roots():
    resolved = templates.resolve_template("hermes-canonical-preservation-integration")
    policy = resolved["policy"]
    canonical = "/home/jfroh/hermes-gpt"
    integration = "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration"
    assert canonical in policy["readable_roots"]
    assert canonical not in policy["writable_roots"]
    assert integration in policy["writable_roots"]
    assert resolved["allowed_branches"] == ["mission-control/preservation-integration"]
    assert resolved["baseline_required"] is True
    assert resolved["risk_tier"] == 2
    assert policy["allowed_profiles"] == ["default", "hy3-free-test", "nvidia-live-test"]
    assert policy["egress_hosts"] == []
    assert policy["service_units"] == []
    assert "services" not in policy["verbs"]
    assert "network" not in policy["verbs"]
    assert "/home/jfroh/.hermes/releases/v018-live" in policy["hard_denied_paths"]
    assert "/home/jfroh/.hermes/releases/v019" in policy["hard_denied_paths"]
    assert all(not root.startswith("/home/jfroh/.hermes/releases/") for root in policy["writable_roots"])


def test_maintenance_resolves_to_exact_paths_and_branch_restriction():
    resolved = templates.resolve_template("hermes-gpt-operator-maintenance")
    policy = resolved["policy"]
    assert policy["readable_roots"] == [
        "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"
    ]
    assert policy["writable_roots"] == [
        "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"
    ]
    assert resolved["allowed_branches"] == ["codex/operator-session-chatgpt-20260713"]
    assert policy["service_units"] == [
        "hermes-gpt-chatgpt-operator.service",
        "hermes-gpt-approval-web.service",
    ]
    assert policy["verbs"]["services"] == ["restart"]
    assert set(policy["allowed_profiles"]) == {
        "default",
        "backend-eng",
        "hy3-free-test",
        "nvidia-live-test",
        "gemini-live-test",
        "ollama-live-test",
        "gemini-flash",
        "coder-deepseek-v4-pro",
        "coder-deepseek-v4-flash",
        "worker-nemotron-super",
        "multimodal-kimi-k26",
        "vision-nemotron-omni",
    }
    assert "*" not in policy["allowed_profiles"]


def test_antigravity_pilot_profiles_are_narrow_and_explicit():
    policy = templates.resolve_template("hermes-antigravity-pilot")["policy"]
    assert policy["allowed_profiles"] == ["default", "backend-eng"]
    assert "*" not in policy["allowed_profiles"]


def test_approval_web_maintenance_is_exact_and_narrow():
    resolved = templates.resolve_template("hermes-approval-web-maintenance")
    policy = resolved["policy"]
    assert policy["service_units"] == ["hermes-gpt-approval-web.service"]
    assert policy["verbs"]["services"] == ["restart"]
    assert policy["allowed_profiles"] == ["default"]
    assert policy["readable_roots"] == [
        "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"
    ]
    assert policy["writable_roots"] == policy["readable_roots"]
    assert resolved["allowed_branches"] == ["codex/operator-session-chatgpt-20260713"]


def test_tax_calculator_resolves_to_exact_scope_and_branch():
    resolved = templates.resolve_template("tax-calculator-controller")
    policy = resolved["policy"]
    assert policy["readable_roots"] == ["/mnt/c/Dev/Tax Calculator"]
    assert policy["writable_roots"] == ["/mnt/c/Dev/Tax Calculator"]
    assert resolved["allowed_branches"] == ["feat/projection-architecture-discovery"]
    assert resolved["baseline_required"] is True
    assert resolved["max_duration_seconds"] == 4 * 60 * 60
    assert policy["hard_denied_paths"] == [
        "/mnt/c/Dev/Tax Calculator/.claude",
        "/mnt/c/Dev/Tax Calculator/powerautomate_flow_rebuild",
    ]


def test_allowed_verbs_are_scoped_not_owner_level():
    for name in (
        "sandbox",
        "hermes-gpt-operator-maintenance",
        "tax-calculator-controller",
    ):
        resolved = templates.resolve_template(name)
        verbs = resolved["policy"]["verbs"]
        assert resolved["policy"]["level"] == "workspace"
        assert set(verbs["filesystem"]) == {"read", "edit"}
        assert verbs["git"] == ["commit"]
        assert verbs["tests"] == ["run"]
        if name == "hermes-gpt-operator-maintenance":
            assert verbs["services"] == ["restart"]
            assert resolved["policy"]["service_units"] == [
                "hermes-gpt-chatgpt-operator.service",
                "hermes-gpt-approval-web.service",
            ]
        else:
            assert "services" not in verbs
            assert "service_units" not in resolved["policy"]
        # No verb set here ever grants arbitrary command execution or owner
        # mode. The maintenance-only service grant is exact and separately
        # bound to the single ChatGPT operator service unit.
        for verb_list in verbs.values():
            assert "run_command" not in verb_list
            assert "force_push" not in verb_list
            assert "reset_hard" not in verb_list


def test_maximum_duration_bounded_for_every_active_template():
    for name in templates.active_template_names():
        resolved = templates.resolve_template(name)
        assert 0 < resolved["max_duration_seconds"] <= 12 * 60 * 60
        if name in {"hermes-overnight-maintenance", "tax-calculator-antigravity-review"}:
            assert resolved["max_duration_seconds"] == 10 * 60 * 60
        else:
            assert resolved["max_duration_seconds"] <= 4 * 60 * 60


def test_overnight_maintenance_has_expected_scope_and_denials():
    resolved = templates.resolve_template("hermes-overnight-maintenance")
    policy = resolved["policy"]
    assert resolved["max_duration_seconds"] == 10 * 60 * 60
    assert "/home/jfroh/.hermes/hermes-agent" in policy["readable_roots"]
    assert "/home/jfroh/.hermes/hermes-agent" not in policy["writable_roots"]
    assert "/home/jfroh/.hermes/worktrees" in policy["writable_roots"]
    assert "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt" in policy["hard_denied_paths"]
    assert "/home/jfroh/.hermes/worktrees/hermes-operator-telegram-approval" in policy["hard_denied_paths"]
    assert policy["verbs"] == {
        "filesystem": ["read", "edit"],
        "git": ["commit"],
        "tests": ["run"],
    }


def test_tax_calculator_antigravity_review_is_fixed_read_only_source_scope():
    resolved = templates.resolve_template("tax-calculator-antigravity-review")
    policy = resolved["policy"]
    assert resolved["max_duration_seconds"] == 10 * 60 * 60
    assert policy["allowed_profiles"] == ["antigravity-operator"]
    assert "/mnt/c/Dev/Tax Calculator" in policy["readable_roots"]
    assert "/mnt/c/Dev/Tax Calculator" not in policy["writable_roots"]
    assert policy["verbs"] == {
        "filesystem": ["read", "edit"],
        "tests": ["run"],
    }
    assert "git" not in policy["verbs"]
    assert "services" not in policy["verbs"]
    assert "/mnt/c/Dev/Tax Calculator/**/.git/config" in policy["hard_denied_paths"]
    assert all(
        root.startswith("/home/jfroh/.hermes/") or root == "/home/jfroh/.gemini/antigravity-cli/settings.json"
        for root in policy["writable_roots"]
    )


def test_unknown_template_rejected():
    with pytest.raises(templates.UnknownPolicyTemplateError):
        templates.resolve_template("does-not-exist")


def test_jb_mailbox_reconciliation_is_narrow_and_source_read_only():
    resolved = templates.resolve_template("jb-mailbox-canonical-asset-reconciliation")
    policy = resolved["policy"]
    source_root = "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage"

    assert resolved["active"] is True
    assert resolved["max_duration_seconds"] == 4 * 60 * 60
    assert policy["allowed_profiles"] == ["backend-eng"]
    assert source_root in policy["readable_roots"]
    assert source_root not in policy["writable_roots"]
    assert policy["writable_roots"] == [
        "/home/jfroh/.hermes/ops-brain/evidence",
        "/home/jfroh/.hermes/ops-brain/projects/jb-mailbox-triage-dashboard.md",
    ]
    assert policy["verbs"] == {
        "filesystem": ["read", "edit"],
        "tests": ["run"],
    }
    assert "git" not in policy["verbs"]
    assert "services" not in policy["verbs"]
    assert f"{source_root}/**/.git/config" in policy["hard_denied_paths"]


def test_tax_calculator_template_is_active():
    assert "tax-calculator-controller" in templates.active_template_names()
    assert "sandbox" in templates.active_template_names()
    assert "hermes-gpt-operator-maintenance" in templates.active_template_names()
    resolved = templates.resolve_template("tax-calculator-controller")
    assert resolved["active"] is True


def test_resolved_snapshot_is_immutable_from_caller_mutation():
    """Mutating a resolved template must never corrupt the registry for a
    later caller in the same process — this is the actual security property
    that matters, since the broker/Telegram/localhost code all resolve the
    same in-process registry repeatedly."""
    first = templates.resolve_template("sandbox")
    first["policy"]["readable_roots"].append("/etc")
    first["policy"]["verbs"]["filesystem"].append("owner_write")
    first["max_duration_seconds"] = 10 ** 9

    second = templates.resolve_template("sandbox")
    assert second["policy"]["readable_roots"] == [
        "/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch"
    ]
    assert "owner_write" not in second["policy"]["verbs"]["filesystem"]
    assert second["max_duration_seconds"] == 4 * 60 * 60


def test_resolve_template_only_accepts_a_name_no_path_injection_channel():
    """resolve_template has no path/roots parameter at all — there is no
    channel through which a caller-supplied filesystem path could ever reach
    the resolved policy. Attempting to smuggle a path via the name argument
    (e.g. traversal-looking strings, or a name that also happens to be an
    existing path) must simply fail closed as an unknown template."""
    injection_attempts = [
        "../../../etc/passwd",
        "/home/jfroh/hermes-gpt",
        "sandbox/../hermes-gpt-operator-maintenance",
        "sandbox\x00hermes-gpt-operator-maintenance",
        "",
    ]
    for attempt in injection_attempts:
        with pytest.raises(templates.UnknownPolicyTemplateError):
            templates.resolve_template(attempt)


def test_tax_calculator_template_has_only_the_intended_repository_root():
    resolved = templates.resolve_template("tax-calculator-controller")
    policy = resolved["policy"]
    assert policy["readable_roots"] == policy["writable_roots"]
    assert policy["writable_roots"] == ["/mnt/c/Dev/Tax Calculator"]
    assert "/home/jfroh" not in policy["writable_roots"]
    assert "/mnt/c/Dev" not in policy["writable_roots"]


def test_hermes_context_maintenance_resolves_to_exact_roots():
    resolved = templates.resolve_template("hermes-context-maintenance")
    policy = resolved["policy"]
    assert policy["readable_roots"] == [
        "/home/jfroh/.hermes/hermes-agent",
        "/home/jfroh/.hermes/ops-brain",
    ]
    assert policy["writable_roots"] == [
        "/home/jfroh/.hermes/hermes-agent",
        "/home/jfroh/.hermes/ops-brain",
    ]
    assert resolved["max_duration_seconds"] == 4 * 60 * 60
    assert resolved["allowed_branches"] is None
    assert resolved["baseline_required"] is False


def test_hermes_context_maintenance_hard_denied_paths_cover_secrets():
    resolved = templates.resolve_template("hermes-context-maintenance")
    policy = resolved["policy"]
    denied = policy["hard_denied_paths"]

    # Must include the critical secret paths for both roots
    assert "/home/jfroh/.hermes/hermes-agent/.env" in denied
    assert "/home/jfroh/.hermes/hermes-agent/.env.*" in denied
    assert "/home/jfroh/.hermes/hermes-agent/credentials" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/credentials" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/API keys" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/OAuth tokens" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/authentication databases" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/secret stores" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/private keys" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/SSH material" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/.git/config" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/runtime session databases" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/operator approval databases" in denied
    assert "/home/jfroh/.hermes/hermes-agent/*/operator policy/session state" in denied

    assert "/home/jfroh/.hermes/ops-brain/.env" in denied
    assert "/home/jfroh/.hermes/ops-brain/.env.*" in denied
    assert "/home/jfroh/.hermes/ops-brain/credentials" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/credentials" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/API keys" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/OAuth tokens" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/authentication databases" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/secret stores" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/private keys" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/SSH material" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/.git/config" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/runtime session databases" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/operator approval databases" in denied
    assert "/home/jfroh/.hermes/ops-brain/*/operator policy/session state" in denied


def test_hermes_context_maintenance_verbs_are_scoped():
    resolved = templates.resolve_template("hermes-context-maintenance")
    verbs = resolved["policy"]["verbs"]
    assert resolved["policy"]["level"] == "workspace"
    assert set(verbs["filesystem"]) == {"read", "edit"}
    assert verbs["git"] == ["commit"]
    assert verbs["tests"] == ["run"]
    # No owner-level verbs
    for verb_list in verbs.values():
        assert "run_command" not in verb_list
        assert "force_push" not in verb_list
        assert "reset_hard" not in verb_list
    # No service control, no egress hosts, no git remotes
    assert "services" not in verbs
    assert "service_units" not in resolved["policy"]
    assert "egress_hosts" not in resolved["policy"]
    assert "git_remotes" not in resolved["policy"]


def test_hermes_context_maintenance_template_is_active():
    assert "hermes-context-maintenance" in templates.active_template_names()
    resolved = templates.resolve_template("hermes-context-maintenance")
    assert resolved["active"] is True


def test_hermes_context_maintenance_template_must_be_requested_by_exact_name():
    # Unknown or injection attempts must fail closed
    injection_attempts = [
        "../../../etc/passwd",
        "/home/jfroh/.hermes/hermes-agent",
        "hermes-context-maintenance/../sandbox",
        "hermes-context-maintenance\x00tax-calculator-controller",
        "",
        "hermes-context-maintenance ",  # trailing space
        " hermes-context-maintenance",  # leading space
    ]
    for attempt in injection_attempts:
        try:
            templates.resolve_template(attempt)
            assert False, f"Should have rejected: {attempt!r}"
        except templates.UnknownPolicyTemplateError:
            pass


def test_governance_inventory_includes_opsbrain_and_remains_strictly_read_only():
    resolved = templates.resolve_template("hermes-governance-inventory")
    policy = resolved["policy"]
    assert "/home/jfroh/.hermes/ops-brain" in policy["readable_roots"]
    assert policy["writable_roots"] == []
    assert policy["level"] == "read_only"
    assert policy["apply_mode"] == "dry_run"
    assert policy["verbs"] == {"filesystem": ["read"]}
    assert "services" not in policy["verbs"]
    assert "git" not in policy["verbs"]
    assert "tests" not in policy["verbs"]
