"""Named operator-session policy templates for hermes-gpt.

A remote MCP client (ChatGPT) may only ever name a template — it can never
submit raw policy JSON or arbitrary filesystem roots. Templates resolve
locally to an exact, immutable policy snapshot that gets shown to the human
approver (Telegram/localhost) before any session is created.
"""

from __future__ import annotations

import copy
from typing import Any

# Seconds. A template's max_duration_seconds bounds both the initial
# requested duration and (transitively, via operator_sessions'
# MAX_SESSION_DURATION_SECONDS) how far extensions can push expiry.
_TWO_HOURS = 2 * 60 * 60
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
            "verbs": {"filesystem": ["read", "edit"], "git": ["commit"], "tests": ["run"]},
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
            "verbs": {"filesystem": ["read", "edit"], "git": ["commit"], "tests": ["run"]},
        },
        "max_duration_seconds": _TWO_HOURS,
        "allowed_branches": ["feat/projection-architecture-discovery"],
        "baseline_required": True,
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
