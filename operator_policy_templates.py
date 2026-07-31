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
_TEN_HOURS = 10 * 60 * 60

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
            "allowed_profiles": [
                "default",
                "backend-eng",
                "hy3-free-test",
                "nvidia-live-test",
                "gemini-live-test",
                "ollama-live-test",
                "gemini-flash",
                "planner-glm52",
                "coder-deepseek-v4-pro",
                "coder-deepseek-v4-flash",
                "worker-nemotron-super",
                "multimodal-kimi-k26",
                "vision-nemotron-omni",
            ],
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
    "tax-calculator-antigravity-review": {
        "active": True,
        "description": (
            "Fixed, read-only Antigravity review of the approved Projections Calculator commits. "
            "Allows test execution and fixed Hermes evidence output, but no Tax Calculator source edits, Git writes, or service changes."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["antigravity-operator"],
            "readable_roots": [
                "/mnt/c/Dev/Tax Calculator",
                "/home/jfroh/.hermes/ops-brain/evidence/runtime/projections-calculator-antigravity-review",
                "/home/jfroh/.hermes/ops-brain/evidence/projections-calculator-independent-review-2026-07-31.md",
                "/home/jfroh/.hermes/ops-brain/evidence/projections-calculator-independent-review-2026-07-31.yaml",
                "/home/jfroh/.gemini/antigravity-cli/settings.json",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/ops-brain/evidence/runtime/projections-calculator-antigravity-review",
                "/home/jfroh/.hermes/ops-brain/evidence/projections-calculator-independent-review-2026-07-31.md",
                "/home/jfroh/.hermes/ops-brain/evidence/projections-calculator-independent-review-2026-07-31.yaml",
                "/home/jfroh/.gemini/antigravity-cli/settings.json",
            ],
            "hard_denied_paths": [
                "/mnt/c/Dev/Tax Calculator/.env",
                "/mnt/c/Dev/Tax Calculator/.env.*",
                "/mnt/c/Dev/Tax Calculator/**/credentials",
                "/mnt/c/Dev/Tax Calculator/**/API keys",
                "/mnt/c/Dev/Tax Calculator/**/OAuth tokens",
                "/mnt/c/Dev/Tax Calculator/**/authentication databases",
                "/mnt/c/Dev/Tax Calculator/**/secret stores",
                "/mnt/c/Dev/Tax Calculator/**/private keys",
                "/mnt/c/Dev/Tax Calculator/**/SSH material",
                "/mnt/c/Dev/Tax Calculator/**/.git/config",
                "/mnt/c/Dev/Tax Calculator/**/runtime session databases",
                "/mnt/c/Dev/Tax Calculator/**/operator approval databases",
                "/mnt/c/Dev/Tax Calculator/**/operator policy/session state",
            ],
            "verbs": {
                "filesystem": ["read", "edit"],
                "tests": ["run"],
            },
        },
        "max_duration_seconds": _TEN_HOURS,
        "allowed_branches": None,
        "baseline_required": False,
    },
    "hermes-approval-web-maintenance": {
        "active": True,
        "description": "Bootstrap maintenance access for the localhost approval web service only.",
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": ["/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"],
            "writable_roots": ["/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"],
            "service_units": ["hermes-gpt-approval-web.service"],
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
    "hermes-antigravity-pilot": {
        "active": True,
        "description": (
            "Narrow execution access for the live-qualified Antigravity managed-agent "
            "adapter and bounded overnight evidence logging."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default", "backend-eng"],
            "readable_roots": [
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent",
                "/home/jfroh/.hermes/ops-brain",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent",
                "/home/jfroh/.hermes/ops-brain",
            ],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/.env",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/.env.*",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/credentials",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/API keys",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/OAuth tokens",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/authentication databases",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/secret stores",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/private keys",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/SSH material",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/.git/config",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/runtime session databases",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/operator approval databases",
                "/home/jfroh/.hermes/worktrees/antigravity-managed-agent/**/operator policy/session state",
                "/home/jfroh/.hermes/ops-brain/.env",
                "/home/jfroh/.hermes/ops-brain/.env.*",
                "/home/jfroh/.hermes/ops-brain/**/credentials",
                "/home/jfroh/.hermes/ops-brain/**/API keys",
                "/home/jfroh/.hermes/ops-brain/**/OAuth tokens",
                "/home/jfroh/.hermes/ops-brain/**/authentication databases",
                "/home/jfroh/.hermes/ops-brain/**/secret stores",
                "/home/jfroh/.hermes/ops-brain/**/private keys",
                "/home/jfroh/.hermes/ops-brain/**/SSH material",
                "/home/jfroh/.hermes/ops-brain/**/.git/config",
                "/home/jfroh/.hermes/ops-brain/**/runtime session databases",
                "/home/jfroh/.hermes/ops-brain/**/operator approval databases",
                "/home/jfroh/.hermes/ops-brain/**/operator policy/session state",
            ],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["commit"],
                "tests": ["run"],
            },
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": ["feat/antigravity-managed-agent"],
        "baseline_required": False,
    },
    "hermes-overnight-maintenance": {
        "active": True,
        "description": (
            "Extended, human-approved overnight maintenance across controlled Hermes "
            "worktrees, routing configuration, model profiles, and OpsBrain evidence."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": [
                "/home/jfroh/.hermes/hermes-agent",
                "/home/jfroh/.hermes/worktrees",
                "/home/jfroh/.hermes/ops-brain",
                "/home/jfroh/.hermes/profiles",
                "/home/jfroh/.hermes/model-routing-migration",
                "/home/jfroh/.hermes/config.yaml",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/worktrees",
                "/home/jfroh/.hermes/ops-brain",
                "/home/jfroh/.hermes/profiles",
                "/home/jfroh/.hermes/model-routing-migration",
                "/home/jfroh/.hermes/config.yaml",
            ],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/.env",
                "/home/jfroh/.hermes/.env.*",
                "/home/jfroh/.hermes/auth",
                "/home/jfroh/.hermes/auth.json",
                "/home/jfroh/.hermes/credentials",
                "/home/jfroh/.hermes/**/credentials",
                "/home/jfroh/.hermes/**/API keys",
                "/home/jfroh/.hermes/**/OAuth tokens",
                "/home/jfroh/.hermes/**/authentication databases",
                "/home/jfroh/.hermes/**/secret stores",
                "/home/jfroh/.hermes/**/private keys",
                "/home/jfroh/.hermes/**/SSH material",
                "/home/jfroh/.hermes/**/.git/config",
                "/home/jfroh/.hermes/**/runtime session databases",
                "/home/jfroh/.hermes/**/operator approval databases",
                "/home/jfroh/.hermes/**/operator policy/session state",
                "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt",
                "/home/jfroh/.hermes/worktrees/hermes-operator-telegram-approval",
                "/home/jfroh/.hermes/worktrees/overnight-operator-session-policy",
                "/home/jfroh/.hermes/worktrees/*operator*",
            ],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["commit"],
                "tests": ["run"],
            },
        },
        "max_duration_seconds": _TEN_HOURS,
        "allowed_branches": None,
        "baseline_required": False,
    },
    "hermes-model-routing-migration": {
        "active": True,
        "description": (
            "Narrowly scoped access to audit, back up, configure, test, and migrate "
            "Hermes native model routing while preserving LiteLLM as rollback."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": [
                "/home/jfroh/.hermes/config.yaml",
                "/home/jfroh/.hermes/profiles",
                "/home/jfroh/.hermes/model-routing-migration",
                "/home/jfroh/.hermes/hermes-agent",
                "/mnt/c/Users/jfroh/.litellm/config.yaml",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/config.yaml",
                "/home/jfroh/.hermes/profiles",
                "/home/jfroh/.hermes/model-routing-migration",
            ],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/.env",
                "/home/jfroh/.hermes/.env.*",
                "/home/jfroh/.hermes/auth.json",
                "/home/jfroh/.hermes/credentials",
                "/home/jfroh/.hermes/**/credentials",
                "/home/jfroh/.hermes/**/API keys",
                "/home/jfroh/.hermes/**/OAuth tokens",
                "/home/jfroh/.hermes/**/secret stores",
                "/home/jfroh/.hermes/**/private keys",
                "/mnt/c/Users/jfroh/.litellm/.env",
                "/mnt/c/Users/jfroh/.litellm/.env.*",
                "/mnt/c/Users/jfroh/.litellm/auth.json",
                "/mnt/c/Users/jfroh/.litellm/start_litellm.ps1",
            ],
            "service_units": ["hermes-gateway.service"],
            "verbs": {
                "filesystem": ["read", "edit"],
                "services": ["restart"],
                "tests": ["run"],
            },
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": None,
        "baseline_required": False,
    },
    "hermes-governance-inventory": {
        "active": True,
        "description": "Read-only inventory of Hermes governance, memory, skills, Kanban, and cron state.",
        "policy": {
            "level": "read_only",
            "apply_mode": "dry_run",
            "readable_roots": [
                "/home/jfroh/.hermes/SOUL.md",
                "/home/jfroh/.hermes/memories",
                "/home/jfroh/.hermes/skills",
                "/home/jfroh/.hermes/kanban.db",
                "/home/jfroh/.hermes/kanban/boards",
                "/home/jfroh/.hermes/cron",
                "/home/jfroh/.hermes/ops-brain",
            ],
            "writable_roots": [],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/.env",
                "/home/jfroh/.hermes/.env.*",
                "/home/jfroh/.hermes/auth",
                "/home/jfroh/.hermes/auth.json",
                "/home/jfroh/.hermes/credentials",
                "/home/jfroh/.hermes/**/credentials",
                "/home/jfroh/.hermes/**/API keys",
                "/home/jfroh/.hermes/**/OAuth tokens",
                "/home/jfroh/.hermes/**/authentication databases",
                "/home/jfroh/.hermes/**/secret stores",
                "/home/jfroh/.hermes/**/private keys",
                "/home/jfroh/.hermes/**/SSH material",
                "/home/jfroh/.hermes/**/runtime session databases",
                "/home/jfroh/.hermes/**/operator approval databases",
                "/home/jfroh/.hermes/**/operator policy/session state",
            ],
            "verbs": {"filesystem": ["read"]},
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": None,
        "baseline_required": False,
    },
    "hermes-governance-maintenance": {
        "active": True,
        "description": (
            "Controlled maintenance of Hermes governance, memory, skills, cron, Kanban, "
            "OpsBrain, and delegation policy without access to secrets or runtime authority state."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": [
                "/home/jfroh/.hermes/SOUL.md",
                "/home/jfroh/.hermes/memories",
                "/home/jfroh/.hermes/skills",
                "/home/jfroh/.hermes/cron",
                "/home/jfroh/.hermes/kanban.db",
                "/home/jfroh/.hermes/kanban/boards",
                "/home/jfroh/.hermes/ops-brain",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/SOUL.md",
                "/home/jfroh/.hermes/memories",
                "/home/jfroh/.hermes/skills",
                "/home/jfroh/.hermes/cron",
                "/home/jfroh/.hermes/kanban/boards",
                "/home/jfroh/.hermes/ops-brain",
            ],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/.env",
                "/home/jfroh/.hermes/.env.*",
                "/home/jfroh/.hermes/auth",
                "/home/jfroh/.hermes/auth.json",
                "/home/jfroh/.hermes/credentials",
                "/home/jfroh/.hermes/**/credentials",
                "/home/jfroh/.hermes/**/API keys",
                "/home/jfroh/.hermes/**/OAuth tokens",
                "/home/jfroh/.hermes/**/authentication databases",
                "/home/jfroh/.hermes/**/secret stores",
                "/home/jfroh/.hermes/**/private keys",
                "/home/jfroh/.hermes/**/SSH material",
                "/home/jfroh/.hermes/**/.git/config",
                "/home/jfroh/.hermes/**/runtime session databases",
                "/home/jfroh/.hermes/**/operator approval databases",
                "/home/jfroh/.hermes/**/operator policy/session state",
                "/home/jfroh/.hermes/kanban.db",
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