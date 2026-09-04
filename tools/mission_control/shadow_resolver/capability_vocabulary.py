"""Capability vocabulary for Mission Control Authority Architecture v2.

Reuses the existing R0-R4 risk classes and Authority Layer specification.
Does NOT introduce a second risk taxonomy or authority store.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class RiskClass(str, Enum):
    """Existing R0-R4 risk classes from architecture/hermes-authority-layer-specification.md."""

    R0 = "R0"  # Read-only observation
    R1 = "R1"  # Reversible workspace change
    R2 = "R2"  # Operational change
    R3 = "R3"  # High-impact change
    R4 = "R4"  # Prohibited through ordinary authority


@dataclass(frozen=True)
class CapabilityAtom:
    """Atomic capability: verb + target + constraints.

    Example: git.commit(repo=/home/jfroh/.hermes/ops-brain, files=[...], branch=master, no_push=true)
    """

    family: str  # read, write, execute, git, delegate, network, service, external_action, credential, security_boundary, spend, destructive
    verb: str
    target: str
    constraints: dict[str, Any]

    def to_string(self) -> str:
        """Human-readable capability string."""
        constraints_str = ", ".join(f"{k}={v}" for k, v in sorted(self.constraints.items()))
        return f"{self.family}.{self.verb}({self.target}" + (f", {constraints_str}" if constraints_str else "") + ")"

    def __str__(self) -> str:
        return self.to_string()


# Capability families from design doc section 5.1
CAPABILITY_FAMILIES = {
    "read": ["file", "project", "runtime", "config", "status", "evidence"],
    "write": ["file", "patch", "create"],
    "execute": ["validator", "test", "script", "tool"],
    "git": ["stage", "commit", "push"],
    "delegate": ["start", "resume", "cancel"],
    "network": ["web", "api"],
    "service": ["status", "reload", "restart"],
    "external_action": ["send", "publish", "message", "invite", "create"],
    "credential": ["add", "change", "revoke", "authenticate"],
    "security_boundary": ["firewall", "tunnel", "iam", "approval_policy", "safe_root"],
    "spend": ["paid_usage", "purchase"],
    "destructive": ["delete", "irreversible_overwrite", "destructive_migration", "history_rewrite"],
}


# Risk class mapping for capability atoms (section 5.2)
RISK_CLASS_MAPPING: dict[str, RiskClass] = {
    # R0 - Read-only observation
    "read.file": RiskClass.R0,
    "read.project": RiskClass.R0,
    "read.runtime": RiskClass.R0,
    "read.config": RiskClass.R0,
    "read.status": RiskClass.R0,
    "read.evidence": RiskClass.R0,
    # R1 - Reversible workspace change
    "write.file": RiskClass.R1,
    "write.patch": RiskClass.R1,
    "write.create": RiskClass.R1,
    "execute.validator": RiskClass.R1,
    "execute.test": RiskClass.R1,
    "execute.script": RiskClass.R1,
    "git.stage": RiskClass.R1,
    "git.commit": RiskClass.R1,
    # R2 - Operational change
    "git.push": RiskClass.R2,
    "service.restart": RiskClass.R2,
    "service.reload": RiskClass.R2,
    "execute.tool": RiskClass.R2,
    "delegate.start": RiskClass.R2,
    "network.api": RiskClass.R2,
    # R3 - High-impact change
    "external_action.send": RiskClass.R3,
    "external_action.publish": RiskClass.R3,
    "credential.add": RiskClass.R3,
    "credential.change": RiskClass.R3,
    "security_boundary.approval_policy": RiskClass.R3,
    "security_boundary.safe_root": RiskClass.R3,
    "spend.paid_usage": RiskClass.R3,
    # R4 - Prohibited
    "credential.revoke": RiskClass.R4,
    "credential.authenticate": RiskClass.R4,
    "destructive.delete": RiskClass.R4,
    "destructive.irreversible_overwrite": RiskClass.R4,
    "destructive.destructive_migration": RiskClass.R4,
    "destructive.history_rewrite": RiskClass.R4,
    "security_boundary.firewall": RiskClass.R4,
    "security_boundary.tunnel": RiskClass.R4,
    "security_boundary.iam": RiskClass.R4,
    "spend.purchase": RiskClass.R4,
}


# Hard denied paths - from Authority Layer spec and operator_policy.py
HARD_DENIED_PATHS = (
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.docker",
    "~/.azure",
    "~/.cloudflared",
    "~/.hermes/mcp-tokens",
    "~/.hermes/auth",
    "~/.hermes/.env",
    "~/.hermes/auth.json",
    # Additional from operator_policy_templates.py
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
    "/home/jfroh/.hermes/**/.git/config",
    "/home/jfroh/.hermes/**/runtime session databases",
    "/home/jfroh/.hermes/**/operator approval databases",
    "/home/jfroh/.hermes/**/operator policy/session state",
)


# Standing read roots - from operator_policy.py STANDING_READ_ONLY_ROOTS
STANDING_READ_ROOTS = (
    "/home/jfroh/.hermes/SOUL.md",
    "/home/jfroh/.hermes/memories",
    "/home/jfroh/.hermes/skills",
    "/home/jfroh/.hermes/kanban.db",
    "/home/jfroh/.hermes/kanban/boards",
    "/home/jfroh/.hermes/cron",
    "/home/jfroh/.hermes/ops-brain",
)


def compose_capability(family: str, verb: str, target: str, constraints: dict[str, Any] | None = None) -> CapabilityAtom:
    """Compose a capability atom from parts."""
    return CapabilityAtom(
        family=family,
        verb=verb,
        target=target,
        constraints=constraints or {},
    )


def decompose_template(template_name: str, template: dict[str, Any]) -> list[CapabilityAtom]:
    """Decompose a named policy template into capability atoms.

    This is the inverse of what the shadow resolver does - it shows what
    capabilities a template actually grants.
    """
    atoms = []

    # Filesystem read
    for root in template.get("readable_roots", []):
        atoms.append(CapabilityAtom(
            family="read",
            verb="file",
            target=root,
            constraints={},
        ))

    # Filesystem write/edit
    for root in template.get("writable_roots", []):
        atoms.append(CapabilityAtom(
            family="write",
            verb="file",
            target=root,
            constraints={},
        ))

    # Verbs
    verbs = template.get("verbs", {})
    for family, actions in verbs.items():
        if isinstance(actions, list):
            for action in actions:
                # Map to capability families
                if family == "filesystem":
                    if action in ("read", "edit"):
                        pass  # Already covered by readable/writable roots
                elif family == "git":
                    if action == "commit":
                        atoms.append(CapabilityAtom(
                            family="git",
                            verb="commit",
                            target="repository",
                            constraints={"files": "exact_allow_list"},
                        ))
                    elif action == "push":
                        atoms.append(CapabilityAtom(
                            family="git",
                            verb="push",
                            target="repository",
                            constraints={},
                        ))
                    elif action == "release":
                        atoms.append(CapabilityAtom(
                            family="git",
                            verb="push",
                            target="repository",
                            constraints={"type": "release"},
                        ))
                elif family == "tests":
                    if action == "run":
                        atoms.append(CapabilityAtom(
                            family="execute",
                            verb="test",
                            target="validator",
                            constraints={},
                        ))
                elif family == "services":
                    if action == "restart":
                        atoms.append(CapabilityAtom(
                            family="service",
                            verb="restart",
                            target="systemd_unit",
                            constraints={"units": template.get("service_units", [])},
                        ))
                elif family == "network":
                    if action == "web":
                        atoms.append(CapabilityAtom(
                            family="network",
                            verb="web",
                            target="internet",
                            constraints={},
                        ))
                elif family == "applications":
                    if action == "restart":
                        atoms.append(CapabilityAtom(
                            family="service",
                            verb="restart",
                            target="application",
                            constraints={},
                        ))

    return atoms


def classify_risk(atoms: list[CapabilityAtom]) -> RiskClass:
    """Classify the overall risk class of a set of capability atoms.

    Returns the highest risk class present.
    """
    risk_order = [RiskClass.R0, RiskClass.R1, RiskClass.R2, RiskClass.R3, RiskClass.R4]
    max_risk = RiskClass.R0

    for atom in atoms:
        key = f"{atom.family}.{atom.verb}"
        atom_risk = RISK_CLASS_MAPPING.get(key, RiskClass.R0)
        if risk_order.index(atom_risk) > risk_order.index(max_risk):
            max_risk = atom_risk

    return max_risk


def check_hard_denies(atoms: list[CapabilityAtom]) -> list[str]:
    """Check if any capability atom violates hard denies."""
    import os
    violations = []

    # Expand ~ in denied paths
    expanded_denied = [os.path.expanduser(d) for d in HARD_DENIED_PATHS]

    for atom in atoms:
        target = os.path.expanduser(atom.target)
        for denied in expanded_denied:
            # Simple path containment check
            if denied in target or target in denied:
                violations.append(f"Hard deny: {atom} targets denied path {denied}")

    return violations