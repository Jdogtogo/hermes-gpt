"""Named operator-session policy templates for hermes-gpt.

A remote MCP client (ChatGPT) may only ever name a template — it can never
submit raw policy JSON or arbitrary filesystem roots. Templates resolve
locally to an exact, immutable policy snapshot that gets shown to the human
approver (Telegram/localhost) before any session is created.
"""

from __future__ import annotations

import copy
from typing import Any

_FOUR_HOURS = 4 * 60 * 60

POLICY_TEMPLATES: dict[str, dict[str, Any]] = {
    "sandbox": {
        "active": True,
        "description": "Disposable standalone sandbox repository. Safe default for routine testing.",
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": ["/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch"],
            "writable_roots": ["/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch"],
            "verbs": {"filesystem": ["read", "edit"], "git": ["commit"], "tests": ["run"]},
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": None,  # any branch within the sandbox repo
        "baseline_required": False,
    },
    "hermes-gpt-operator-maintenance": {
        "active": True,
        "description": "Maintenance access to the operator profile's own source worktree.",
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": ["/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"],
            "writable_roots": ["/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"],
            "service_units": ["hermes-gpt-chatgpt-operator.service"],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["commit"],
                "services": ["restart"],
                "tests": ["run"],
            },
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": ["codex/operator-session-chatgpt-20260713"],
        "baseline_required": False,
    },
    "tax-calculator-controller": {
        "active": True,
        "description": (
            "Tightly scoped maintenance access to the Tax Calculator repository "
            "for reviewed line-ending repair and subsequent controlled development."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": ["/mnt/c/Dev/Tax Calculator"],
            "writable_roots": ["/mnt/c/Dev/Tax Calculator"],
            "hard_denied_paths": [
                "/mnt/c/Dev/Tax Calculator/.claude",
                "/mnt/c/Dev/Tax Calculator/powerautomate_flow_rebuild",
            ],
            "verbs": {"filesystem": ["read", "edit"], "git": ["commit"], "tests": ["run"]},
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": ["feat/projection-architecture-discovery"],
        "baseline_required": True,
    },
    "hermes-context-maintenance": {
        "active": True,
        "description": (
            "Allow ChatGPT's Hermes operator to inspect and maintain the native Hermes Agent "
            "context system and OpsBrain without granting unrestricted owner-level access."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": [
                "/home/jfroh/.hermes/hermes-agent",
                "/home/jfroh/.hermes/ops-brain",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/hermes-agent",
                "/home/jfroh/.hermes/ops-brain",
            ],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/hermes-agent/.env",
                "/home/jfroh/.hermes/hermes-agent/.env.*",
                "/home/jfroh/.hermes/hermes-agent/credentials",
                "/home/jfroh/.hermes/hermes-agent/*/credentials",
                "/home/jfroh/.hermes/hermes-agent/*/API keys",
                "/home/jfroh/.hermes/hermes-agent/*/OAuth tokens",
                "/home/jfroh/.hermes/hermes-agent/*/authentication databases",
                "/home/jfroh/.hermes/hermes-agent/*/secret stores",
                "/home/jfroh/.hermes/hermes-agent/*/private keys",
                "/home/jfroh/.hermes/hermes-agent/*/SSH material",
                "/home/jfroh/.hermes/hermes-agent/*/.git/config",
                "/home/jfroh/.hermes/hermes-agent/*/runtime session databases",
                "/home/jfroh/.hermes/hermes-agent/*/operator approval databases",
                "/home/jfroh/.hermes/hermes-agent/*/operator policy/session state",
                "/home/jfroh/.hermes/ops-brain/.env",
                "/home/jfroh/.hermes/ops-brain/.env.*",
                "/home/jfroh/.hermes/ops-brain/credentials",
                "/home/jfroh/.hermes/ops-brain/*/credentials",
                "/home/jfroh/.hermes/ops-brain/*/API keys",
                "/home/jfroh/.hermes/ops-brain/*/OAuth tokens",
                "/home/jfroh/.hermes/ops-brain/*/authentication databases",
                "/home/jfroh/.hermes/ops-brain/*/secret stores",
                "/home/jfroh/.hermes/ops-brain/*/private keys",
                "/home/jfroh/.hermes/ops-brain/*/SSH material",
                "/home/jfroh/.hermes/ops-brain/*/.git/config",
                "/home/jfroh/.hermes/ops-brain/*/runtime session databases",
                "/home/jfroh/.hermes/ops-brain/*/operator approval databases",
                "/home/jfroh/.hermes/ops-brain/*/operator policy/session state",
            ],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["commit"],
                "tests": ["run"],
            },
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": None,
        "baseline_required": False,
    },
}


class UnknownPolicyTemplateError(ValueError):
    pass


class InactivePolicyTemplateError(ValueError):
    pass


def resolve_template(name: str) -> dict[str, Any]:
    """Return a deep-copied resolved template, or raise if unknown/inactive.

    Never accepts caller-supplied roots/verbs — only ever a name from
    POLICY_TEMPLATES. Raises before any session or approval request is
    created, so an inactive template can never reach a human approver.
    Returns a deep copy so a caller mutating the result (e.g. appending to
    readable_roots) can never corrupt the module-level registry for later
    callers in the same process.
    """
    template = POLICY_TEMPLATES.get(name)
    if template is None:
        raise UnknownPolicyTemplateError(f"Unknown policy template: {name!r}.")
    if not template.get("active", False):
        raise InactivePolicyTemplateError(
            f"Policy template {name!r} is defined but not yet activated."
        )
    return copy.deepcopy(template)


def active_template_names() -> list[str]:
    return sorted(name for name, t in POLICY_TEMPLATES.items() if t.get("active", False))