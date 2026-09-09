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
    "hermes-contained-maintenance-standing": {
        "active": True,
        "description": (
            "Durable standing authority for contained, reversible maintenance in the "
            "dedicated maintenance worktree. No network, services, deployment, deletion, "
            "credentials, client data, financial data, force operations, or external communication."
        ),
        "standing_authority_eligible": True,
        "risk_tier": 1,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default", "hy3-free-test", "nvidia-live-test"],
            "readable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt/standing-maintenance-clean"
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt/standing-maintenance-clean"
            ],
            "egress_hosts": [],
            "service_units": [],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["commit"],
                "tests": ["run"],
            },
            "containment_strength": "container",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": True,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "none",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": False,
            "has_deployment": False,
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": ["codex/operator-session-chatgpt-20260713"],
        "baseline_required": True,
    },
    "hermes-mission-control-standing": {
        "active": True,
        "description": (
            "Durable low-risk standing authority for routine Mission Control synchronization. "
            "Read access is limited to core non-client OpsBrain governance documents and write "
            "access is limited to the Mission Control and Hermes Stabilization project records. "
            "No network, services, Git mutation, deployment, credentials, client data, financial "
            "data, runtime authority state, or external communication."
        ),
        "standing_authority_eligible": True,
        "risk_tier": 1,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [
                "/home/jfroh/.hermes/ops-brain/projects/mission-control.md",
                "/home/jfroh/.hermes/ops-brain/projects/hermes-stabilization-sprint.md",
                "/home/jfroh/.hermes/ops-brain/projects/hermes-approval-framework.md",
                "/home/jfroh/.hermes/ops-brain/projects/handover-task-packet-template.md",
                "/home/jfroh/.hermes/ops-brain/runbooks/mission-control-operating-model.md",
                "/home/jfroh/.hermes/ops-brain/SCHEMA.md",
                "/home/jfroh/.hermes/ops-brain/DESIGN.md",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/ops-brain/projects/mission-control.md",
                "/home/jfroh/.hermes/ops-brain/projects/hermes-stabilization-sprint.md",
            ],
            "egress_hosts": [],
            "service_units": [],
            "hard_denied_paths": [
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
            "verbs": {"filesystem": ["read", "edit"]},
            "containment_strength": "container",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": True,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "none",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": False,
            "has_deployment": False,
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": None,
        "baseline_required": False,
    },
    "hermes-governed-kanban-standing": {
        "active": True,
        "description": (
            "Durable low-risk standing authority for the dedicated Hermes Stabilization "
            "Kanban board. It may read OpsBrain and may read and edit only that named board directory, but cannot "
            "touch the default kanban.db, other boards, services, network, repositories, "
            "credentials, client/financial data, releases, or runtime authority state."
        ),
        "standing_authority_eligible": True,
        "risk_tier": 1,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [
                "/home/jfroh/.hermes/kanban/boards/hermes-stabilization",
                "/home/jfroh/.hermes/ops-brain",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/kanban/boards/hermes-stabilization"
            ],
            "egress_hosts": [],
            "service_units": [],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/kanban.db",
                "/home/jfroh/.hermes/kanban/current",
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
            "verbs": {"filesystem": ["read", "edit"]},
            "containment_strength": "container",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": True,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "none",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": False,
            "has_deployment": False,
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": None,
        "baseline_required": False,
    },
    "hermes-canonical-preservation-integration": {
        "active": True,
        "description": (
            "Bounded task authority to integrate the reviewed preservation commit into a new clean "
            "standalone integration clone. The dirty canonical working tree is read-only; no release, "
            "service, network, credential, destructive Git, or canonical working-tree writes are granted."
        ),
        "risk_tier": 2,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default", "hy3-free-test", "nvidia-live-test"],
            "readable_roots": [
                "/home/jfroh/hermes-gpt",
                "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt/.release-preservation",
                "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration",
                "/home/jfroh/.hermes/ops-brain/projects/mission-control.md",
                "/home/jfroh/.hermes/ops-brain/projects/hermes-stabilization-sprint.md",
                "/home/jfroh/.hermes/ops-brain/evidence/hermes-stabilization-remaining-work-2026-08-07.md",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration",
                "/home/jfroh/.hermes/ops-brain/projects/mission-control.md",
                "/home/jfroh/.hermes/ops-brain/projects/hermes-stabilization-sprint.md",
                "/home/jfroh/.hermes/ops-brain/evidence/hermes-stabilization-remaining-work-2026-08-07.md",
            ],
            "egress_hosts": [],
            "service_units": [],
            "hard_denied_paths": [
                "/home/jfroh/hermes-gpt/.env",
                "/home/jfroh/hermes-gpt/.env.*",
                "/home/jfroh/hermes-gpt/**/credentials",
                "/home/jfroh/hermes-gpt/**/API keys",
                "/home/jfroh/hermes-gpt/**/OAuth tokens",
                "/home/jfroh/hermes-gpt/**/secret stores",
                "/home/jfroh/hermes-gpt/**/private keys",
                "/home/jfroh/.hermes/.env",
                "/home/jfroh/.hermes/.env.*",
                "/home/jfroh/.hermes/auth",
                "/home/jfroh/.hermes/auth.json",
                "/home/jfroh/.hermes/credentials",
                "/home/jfroh/.hermes/releases/v018-live",
                "/home/jfroh/.hermes/releases/v019",
            ],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["commit"],
                "tests": ["run"],
            },
            "containment_strength": "container",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": False,
            "untracked_delete_protected": True,
            "version_controlled_rollback": True,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "none",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": False,
            "has_deployment": False,
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": ["mission-control/preservation-integration"],
        "baseline_required": True,
    },
    "hermes-claude-desktop-restart": {
        "active": True,
        "description": (
            "Fixed-purpose restart of the already-running Windows Claude Desktop application. "
            "No arbitrary process names, executable paths, shell commands, GUI automation, or file access."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [],
            "writable_roots": [],
            "verbs": {"applications": ["restart"]},
            "containment_strength": "process",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": False,
            "has_deployment": False,
        },
        "max_duration_seconds": 30 * 60,
        "allowed_branches": None,
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
                "coder-deepseek-v4-pro",
                "coder-deepseek-v4-flash",
                "worker-nemotron-super",
                "multimodal-kimi-k26",
                "vision-nemotron-omni",
            ],
            "readable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt",
                "/home/jfroh/.hermes/ops-brain/antigravity/runtime",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt",
                "/home/jfroh/.hermes/ops-brain/antigravity/runtime",
            ],
            "service_units": [
                "hermes-gpt-chatgpt-operator.service",
                "hermes-gpt-approval-web.service",
            ],
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
    "hermes-github-cli-install": {
        "active": True,
        "description": (
            "One-purpose authority to install a portable GitHub CLI only inside the clean Controller "
            "integration worktree. GitHub release egress is fixed and no authentication, credential access, "
            "system package manager, sudo, service, routing, OpsBrain, or unrelated filesystem authority is granted."
        ),
        "risk_tier": 3,
        "standing_authority_eligible": False,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration",
            ],
            "egress_hosts": ["github.com", "release-assets.githubusercontent.com"],
            "service_units": [],
            "verbs": {
                "filesystem": ["read", "edit"],
                "tests": ["run"],
            },
            "containment_strength": "process",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": True,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "none",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": True,
            "has_deployment": False,
        },
        "max_duration_seconds": 60 * 60,
        "allowed_branches": ["mission-control/preservation-integration"],
        "baseline_required": True,
    },
    "hermes-github-release-auth": {
        "active": True,
        "description": (
            "One-purpose authority for the fixed GitHub release OAuth device broker. The caller may start, "
            "complete, inspect status, or clear only the fixed release-auth state; bearer tokens and device_code "
            "remain opaque and are never exposed through generic filesystem tools or tool output."
        ),
        "risk_tier": 3,
        "standing_authority_eligible": False,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration/logs/.release-tools/gh-auth",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration/logs/.release-tools/gh-auth",
            ],
            "egress_hosts": ["github.com", "api.github.com"],
            "service_units": [],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration/logs/.release-tools/gh-auth",
            ],
            "verbs": {
                "github_release_auth": ["start", "complete", "status", "clear"],
            },
            "containment_strength": "process",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": False,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "none",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": True,
            "has_deployment": False,
        },
        "max_duration_seconds": 60 * 60,
        "allowed_branches": ["mission-control/preservation-integration"],
        "baseline_required": True,
    },
    "hermes-controller-release": {
        "active": True,
        "description": (
            "One-purpose authority to publish the exact clean ChatGPT Controller HEAD to the "
            "configured GitHub origin on the fixed Controller branch. No force-push, arbitrary "
            "remote, arbitrary branch, filesystem mutation, service change, credentials, or other "
            "network operation is granted."
        ),
        "risk_tier": 3,
        "standing_authority_eligible": False,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration",
            ],
            "writable_roots": [],
            "egress_hosts": ["github.com"],
            "service_units": [],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/worktrees/hermes-canonical-preservation-integration/logs/.release-tools/gh-auth",
            ],
            "verbs": {"git": ["push"]},
            "containment_strength": "process",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": True,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "release",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": True,
            "has_deployment": True,
        },
        "max_duration_seconds": 60 * 60,
        "allowed_branches": ["mission-control/preservation-integration"],
        "baseline_required": True,
    },
    "hermes-opsbrain-release": {
        "active": True,
        "description": (
            "One-purpose authority for canonical OpsBrain publication. The canonical checkout is read-only; "
            "all validation occurs in a bounded disposable scratch clone. The remote is fixed to github.com, "
            "the repository and master branch are fixed in code, and publication requires exact local/remote "
            "SHAs plus an atomic expected-SHA compare-and-swap. No general Git push, arbitrary repository, "
            "arbitrary branch, service, credential, provider-routing, or unrelated filesystem authority is granted."
        ),
        "risk_tier": 3,
        "standing_authority_eligible": False,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [
                "/home/jfroh/.hermes/ops-brain",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/ops-brain-publish-scratch",
            ],
            "egress_hosts": ["github.com"],
            "service_units": [],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/ops-brain/.env",
                "/home/jfroh/.hermes/ops-brain/.env.*",
                "/home/jfroh/.hermes/ops-brain/**/credentials",
                "/home/jfroh/.hermes/ops-brain/**/API keys",
                "/home/jfroh/.hermes/ops-brain/**/OAuth tokens",
                "/home/jfroh/.hermes/ops-brain/**/authentication databases",
                "/home/jfroh/.hermes/ops-brain/**/secret stores",
                "/home/jfroh/.hermes/ops-brain/**/private keys",
                "/home/jfroh/.hermes/ops-brain/**/SSH material",
            ],
            "verbs": {
                "opsbrain": ["preflight", "release"],
            },
            "containment_strength": "process",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": True,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "release",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": True,
            "has_deployment": True,
        },
        "max_duration_seconds": 60 * 60,
        "allowed_branches": ["master"],
        "baseline_required": True,
    },
    "hermes-exec-first-safe-model": {
        "active": True,
        "description": (
            "One-purpose authority for the fixed hermes-exec first-safe free-model acceptance. "
            "The connector egress is fixed to hermes-exec; the trusted worker then performs exactly "
            "two zero-cost API-key-authenticated model calls from the dedicated first-safe profile. "
            "No arbitrary remote command, host, path, model, service, Git write, OAuth flow, or "
            "broader routing capability is granted."
        ),
        "risk_tier": 3,
        "standing_authority_eligible": False,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt/.release-preservation",
            ],
            "writable_roots": [],
            "egress_hosts": ["hermes-exec"],
            "service_units": [],
            "hard_denied_paths": [
                "/home/jfroh/.ssh",
                "/home/jfroh/.hermes/.env",
                "/home/jfroh/.hermes/.env.*",
                "/home/jfroh/.hermes/auth",
                "/home/jfroh/.hermes/auth.json",
                "/home/jfroh/.hermes/credentials",
                "/home/jfroh/.hermes/**/credentials",
                "/home/jfroh/.hermes/**/API keys",
                "/home/jfroh/.hermes/**/OAuth tokens",
                "/home/jfroh/.hermes/**/secret stores",
                "/home/jfroh/.hermes/**/private keys",
                "/home/jfroh/.hermes/**/SSH material",
            ],
            "verbs": {
                "filesystem": ["edit"],
                "tests": ["run"],
                # Fixed-purpose, read-only inspection of the single Mission
                # Control coordination lease record. Mission Control must
                # verify it holds the lease before invoking the fixed VM
                # operation. Deliberately NOT filesystem:read: this capability
                # takes no path input, enumerates nothing and writes nothing,
                # so the policy keeps a zero general local read/write surface.
                "mission_control": ["lease_status"],
            },
            "containment_strength": "vm",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": False,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "config",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": False,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": False,
            "has_deployment": False,
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": None,
        "baseline_required": False,
    },
    "hermes-exec-first-safe-provision": {
        "active": True,
        "description": (
            "One-purpose PRE-LIVE authority for fixed trusted provisioning of the dedicated "
            "first-safe profile on jfroh@hermes-exec. The connector only records/verifies a bounded "
            "intent; the trusted host worker may quarantine only the exact profile-local auth.json by "
            "non-content rename, then create the approved sparse profile config after the target-local "
            "private profile .env already exists with the expected key name. No secret value is read or "
            "returned, and no model/API call, arbitrary command, service, Git, OAuth, "
            "Cloudflare, cron, cutover or WSL-retirement capability is granted."
        ),
        "risk_tier": 3,
        "standing_authority_eligible": False,
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [
                "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt/.release-preservation",
            ],
            "writable_roots": [],
            "egress_hosts": ["hermes-exec"],
            "service_units": [],
            "hard_denied_paths": [
                "/home/jfroh/.ssh",
                "/home/jfroh/.hermes/.env",
                "/home/jfroh/.hermes/.env.*",
                "/home/jfroh/.hermes/auth",
                "/home/jfroh/.hermes/auth.json",
                "/home/jfroh/.hermes/credentials",
                "/home/jfroh/.hermes/**/credentials",
                "/home/jfroh/.hermes/**/API keys",
                "/home/jfroh/.hermes/**/OAuth tokens",
                "/home/jfroh/.hermes/**/secret stores",
                "/home/jfroh/.hermes/**/private keys",
                "/home/jfroh/.hermes/**/SSH material",
            ],
            "verbs": {
                "filesystem": ["read", "edit"],
                "tests": ["run"],
                "mission_control": ["lease_status"],
            },
            "containment_strength": "vm",
            "containment_verified": True,
            "bounded_roots_verified": True,
            "branch_guard_verified": True,
            "baseline_guard_verified": True,
            "single_writer_verified": True,
            "untracked_delete_protected": True,
            "version_controlled_rollback": False,
            "deliverable_verification_required": True,
            "deliverable_verification_verified": False,
            "data_sensitivity": "internal",
            "production_effect": "config",
            "paid_route_change": "none",
            "has_secret_access": False,
            "has_credential_access": True,
            "has_client_identifiable_data": False,
            "has_financial_data": False,
            "has_external_communication": False,
            "has_deployment": False,
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": None,
        "baseline_required": False,
    },
    "hermes-routing-v019-release": {
        "active": True,
        "description": (
            "Fixed, human-approved promotion of routing-policy-resolver into main and immutable v019. "
            "No arbitrary branches, tags, release paths, deployment, credentials, or service changes."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": [
                "/home/jfroh/.hermes/worktrees/routing-policy-resolver",
                "/home/jfroh/.hermes/worktrees/routing-v019-main",
                "/home/jfroh/.hermes/hermes-agent",
                "/home/jfroh/.hermes/releases/v018-live",
                "/home/jfroh/.hermes/releases/v019",
                "/home/jfroh/.hermes/ops-brain/projects/mission-control.md",
                "/home/jfroh/.hermes/ops-brain/projects/hermes-stabilization-sprint.md",
                "/home/jfroh/.hermes/ops-brain/evidence/routing-v019-promotion-2026-08-06.md",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/worktrees/routing-v019-main",
                "/home/jfroh/.hermes/ops-brain/projects/mission-control.md",
                "/home/jfroh/.hermes/ops-brain/projects/hermes-stabilization-sprint.md",
                "/home/jfroh/.hermes/ops-brain/evidence/routing-v019-promotion-2026-08-06.md",
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
                "/home/jfroh/.hermes/**/secret stores",
                "/home/jfroh/.hermes/**/private keys",
                "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt",
                "/home/jfroh/.hermes/worktrees/*operator*",
            ],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["release"],
                "tests": ["run"],
            },
        },
        "max_duration_seconds": _FOUR_HOURS,
        "allowed_branches": None,
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
    "hermes-windows-stale-backend-cleanup": {
        "active": True,
        "description": (
            "Task-bound cleanup authority for the retired Windows Hermes/LiteLLM duplicate only. "
            "Allows evidence backup/quarantine and disabling its known autostart launchers while preserving WSL Hermes as authoritative."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["default"],
            "readable_roots": [
                "/mnt/c/Users/jfroh/.hermes",
                "/mnt/c/Users/jfroh/.litellm",
                "/mnt/c/Users/jfroh/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/HermesLiteLLM.vbs",
                "/mnt/c/Users/jfroh/Desktop/Hermes Desktop.lnk",
                "/mnt/c/Users/jfroh/OneDrive/Desktop/Hermes Desktop.lnk",
                "/mnt/c/Users/jfroh/Launch-Hermes-Desktop.ps1",
                "/home/jfroh/.hermes/model-routing-migration",
            ],
            "writable_roots": [
                "/mnt/c/Users/jfroh/.hermes",
                "/mnt/c/Users/jfroh/.litellm",
                "/mnt/c/Users/jfroh/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/HermesLiteLLM.vbs",
                "/home/jfroh/.hermes/model-routing-migration",
            ],
            "hard_denied_paths": [
                "/home/jfroh/.hermes/config.yaml",
                "/home/jfroh/.hermes/.env",
                "/home/jfroh/.hermes/.env.*",
                "/home/jfroh/.hermes/auth.json",
                "/home/jfroh/.hermes/profiles",
                "/home/jfroh/.hermes/ops-brain",
                "/home/jfroh/.hermes/memories",
                "/home/jfroh/.hermes/skills",
            ],
            "verbs": {
                "filesystem": ["read", "edit"],
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
    "jb-mailbox-canonical-asset-reconciliation": {
        "active": True,
        "description": (
            "Read-only reconciliation of the recovered JB Mailbox Triage implementation "
            "foundation against canonical OpsBrain specifications, with narrowly scoped "
            "evidence and project-record writes only."
        ),
        "policy": {
            "level": "workspace",
            "apply_mode": "direct",
            "allowed_profiles": ["backend-eng"],
            "readable_roots": [
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage",
                "/home/jfroh/.hermes/ops-brain",
            ],
            "writable_roots": [
                "/home/jfroh/.hermes/ops-brain/evidence",
                "/home/jfroh/.hermes/ops-brain/projects/jb-mailbox-triage-dashboard.md",
            ],
            "hard_denied_paths": [
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/.env",
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/.env.*",
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/**/credentials",
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/**/API keys",
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/**/OAuth tokens",
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/**/authentication databases",
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/**/secret stores",
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/**/private keys",
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/**/SSH material",
                "/mnt/c/Users/jfroh/OneDrive - The Trustee for JP and LA FROHNERT PTY LIMITED/Exit/Externally Share Client Folders/Documents/New project/practice-hub-jv-email-triage/**/.git/config",
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
