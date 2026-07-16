"""Tests for the named operator-session policy template registry."""

from __future__ import annotations

import pytest

import operator_policy_templates as templates


def test_sandbox_resolves_to_exact_paths():
    resolved = templates.resolve_template("sandbox")
    policy = resolved["policy"]
    assert policy["readable_roots"] == ["/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch"]
    assert policy["writable_roots"] == ["/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch"]


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


def test_tax_calculator_resolves_to_exact_scope_and_branch():
    resolved = templates.resolve_template("tax-calculator-controller")
    policy = resolved["policy"]
    assert policy["readable_roots"] == ["/mnt/c/Dev/Tax Calculator"]
    assert policy["writable_roots"] == ["/mnt/c/Dev/Tax Calculator"]
    assert resolved["allowed_branches"] == ["feat/projection-architecture-discovery"]
    assert resolved["baseline_required"] is True
    assert resolved["max_duration_seconds"] == 2 * 60 * 60


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
        # No verb set here ever grants arbitrary command execution or owner
        # mode; only filesystem read/edit, git commit, and test execution.
        for verb_list in verbs.values():
            assert "run_command" not in verb_list
            assert "force_push" not in verb_list
            assert "reset_hard" not in verb_list


def test_maximum_duration_bounded_for_every_active_template():
    for name in templates.active_template_names():
        resolved = templates.resolve_template(name)
        assert 0 < resolved["max_duration_seconds"] <= 4 * 60 * 60


def test_unknown_template_rejected():
    with pytest.raises(templates.UnknownPolicyTemplateError):
        templates.resolve_template("does-not-exist")


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
