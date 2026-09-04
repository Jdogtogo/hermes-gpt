"""Fixtures for shadow resolver testing - OpsBrain reconciliation case."""

from dataclasses import dataclass
from typing import Any

from .capability_vocabulary import CapabilityAtom, RiskClass, compose_capability


@dataclass(frozen=True)
class AuthorityForecast:
    """Authority Forecast - from Authority Layer spec section 5.

    What the task objectively requires before execution.
    """
    objective: str
    logical_task_id: str
    readable_roots: tuple[str, ...]
    writable_roots: tuple[str, ...]
    required_verbs: dict[str, list[str]]  # family -> [actions]
    service_units: tuple[str, ...] = ()
    egress_hosts: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    rollback_approach: str = ""
    requested_expiry: str = "completion"


@dataclass(frozen=True)
class AuthorityEnvelope:
    """Authority Envelope - the resolved immutable authority from current mechanism.

    From Authority Layer spec section 4 (Authority Envelope).
    """
    envelope_id: str
    mission_id: str
    policy_template: str
    readable_roots: tuple[str, ...]
    writable_roots: tuple[str, ...]
    verbs: dict[str, list[str]]
    service_units: tuple[str, ...]
    risk_class: RiskClass
    evidence_requirements: tuple[str, ...]
    rollback_requirements: tuple[str, ...]
    expires_at: int
    parent_envelope_id: str | None = None


class OpsBrainReconciliationFixture:
    """The 2026-09-05 OpsBrain reconciliation as the primary acceptance fixture.

    Required task authority (from designs/mission-control-authority-architecture-v2-2026-09-05.md):
    - read /home/jfroh/.hermes/ops-brain
    - edit only an exact allow-list of OpsBrain files
    - run the OpsBrain validator
    - create an exact-file local Git commit on the approved repository/branch
    - no push
    - no service restart
    - no config mutation
    - no routing mutation
    - no profile mutation
    - no credentials
    - no destructive actions
    - no external communication
    """

    # The exact files that were staged for the reconciliation
    RECONCILIATION_FILES = (
        "designs/multi-agent-mission-control-dashboard-v0.1.md",
        "designs/multi-agent-mission-control-dashboard-v0.2.md",
        "designs/multi-agent-mission-control-dashboard-v0.3.md",
        "evidence/opsbrain-reconciliation-2026-09-05.md",
        "ideas/voice-brain-query.md",
        "projects/hermes-governed-computer-use-integration.md",
        "projects/hermes-nightly-health-drift-evidence-audit.md",
        "projects/mission-control-task-bound-authority.md",
        "projects/morning-mission-control-authority-window.md",
        "projects/packet-hermes-computer-use-host-diagnostics-003.md",
        "projects/packet-hermes-computer-use-hy3-discovery-001.md",
        "projects/packet-hermes-computer-use-runtime-diagnostics-002.md",
        "projects/project-kernel-template.md",
        "runbooks/hermes-approval-and-delegation-preflight.md",
        "runbooks/mission-control-execution-engine.md",
        "runbooks/mission-control-operating-model.md",
    )

    @classmethod
    def forecast(cls) -> AuthorityForecast:
        """The Authority Forecast for the OpsBrain reconciliation task."""
        return AuthorityForecast(
            objective="Reconcile canonical OpsBrain state and commit exact reviewed reconciliation files",
            logical_task_id="opsbrain-reconciliation-2026-09-05",
            readable_roots=(
                "/home/jfroh/.hermes/ops-brain",
            ),
            writable_roots=(
                "/home/jfroh/.hermes/ops-brain",
            ),
            required_verbs={
                "read": ["file"],
                "write": ["file", "patch"],
                "execute": ["validator", "test"],
                "git": ["stage", "commit"],
            },
            service_units=(),
            egress_hosts=(),
            evidence_requirements=(
                "changed-file manifest",
                "diff or commit identifier",
                "validation report",
            ),
            rollback_approach="git reset --hard HEAD~1 (exact local commit only, no push)",
            requested_expiry="completion",
        )

    @classmethod
    def required_capabilities(cls) -> list[CapabilityAtom]:
        """The exact capability atoms required for this task."""
        forecast = cls.forecast()
        caps = []

        # Read OpsBrain
        for root in forecast.readable_roots:
            caps.append(compose_capability("read", "file", root, {}))

        # Write exact OpsBrain files (allow-list)
        for file in cls.RECONCILIATION_FILES:
            caps.append(compose_capability("write", "file", f"{forecast.writable_roots[0]}/{file}", {}))

        # Run validator
        caps.append(compose_capability("execute", "validator", "opsbrain-validator", {}))

        # Git stage exact files
        caps.append(compose_capability("git", "stage", "ops-brain-repo", {"files": "exact_allow_list"}))

        # Git commit exact files, no push
        caps.append(compose_capability("git", "commit", "ops-brain-repo", {
            "files": "exact_allow_list",
            "branch": "master",
            "no_push": True,
        }))

        return caps

    @classmethod
    def risk_class(cls) -> RiskClass:
        """R1 - Reversible workspace change (exact local commit, no push)."""
        return RiskClass.R1

    @classmethod
    def current_template_hermes_gpt_operator_maintenance(cls) -> dict[str, Any]:
        """Current template: hermes-gpt-operator-maintenance (from operator_policy_templates.py)."""
        return {
            "name": "hermes-gpt-operator-maintenance",
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
            "risk_class": "high",  # coarse metadata
            "risk_tier": 3,
        }

    @classmethod
    def current_template_hermes_overnight_maintenance(cls) -> dict[str, Any]:
        """Current template: hermes-overnight-maintenance (from operator_policy_templates.py)."""
        return {
            "name": "hermes-overnight-maintenance",
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
            "service_units": [],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["commit"],
                "tests": ["run"],
            },
            "risk_class": "high",
            "risk_tier": 3,
        }

    @classmethod
    def current_template_hermes_governance_maintenance(cls) -> dict[str, Any]:
        """Current template: hermes-governance-maintenance (from operator_policy_templates.py)."""
        return {
            "name": "hermes-governance-maintenance",
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
            "service_units": [],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["commit"],
                "tests": ["run"],
            },
            "risk_class": "high",
            "risk_tier": 3,
        }

    @classmethod
    def all_current_templates(cls) -> dict[str, dict[str, Any]]:
        """All relevant current templates for comparison."""
        return {
            "hermes-gpt-operator-maintenance": cls.current_template_hermes_gpt_operator_maintenance(),
            "hermes-overnight-maintenance": cls.current_template_hermes_overnight_maintenance(),
            "hermes-governance-maintenance": cls.current_template_hermes_governance_maintenance(),
        }