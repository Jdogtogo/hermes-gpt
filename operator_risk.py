"""Deterministic risk classification for governed Hermes operator authority.

The classifier separates authorization risk from ordinary elapsed time.  It is
computed entirely from locally verified facts.  Caller assertions are not
trusted unless the policy/session construction path has first converted them
into immutable ``RiskFactors``.

RiskClass maps to the user-facing tier model as follows:

* LOW: Tier 0 read-only/status, or Tier 1 contained reversible maintenance.
* MATERIAL: Tier 2 bounded work requiring one task-bound approval bundle.
* HIGH: Tier 3 material/irreversible boundary requiring explicit approval.
* PROHIBITED: not approvable through the standing/bundle pathway.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


RISK_BASED_AUTHORITY_ENABLED_ENV = "HERMES_GPT_RISK_BASED_AUTHORITY_ENABLED"
DEFAULT_FEATURE_FLAG = False


def risk_based_authority_enabled() -> bool:
    value = os.environ.get(RISK_BASED_AUTHORITY_ENABLED_ENV, "").strip().lower()
    return value in {"1", "true", "yes", "on", "enabled"}


class RiskClass(str, Enum):
    LOW = "low"
    MATERIAL = "material"
    HIGH = "high"
    PROHIBITED = "prohibited"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskClass):
            return NotImplemented
        return risk_rank(self) < risk_rank(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, RiskClass):
            return NotImplemented
        return risk_rank(self) <= risk_rank(other)


_RISK_RANK: dict[RiskClass, int] = {
    RiskClass.LOW: 0,
    RiskClass.MATERIAL: 1,
    RiskClass.HIGH: 2,
    RiskClass.PROHIBITED: 3,
}


def risk_rank(value: RiskClass) -> int:
    """Return a stable severity rank independent of Enum/string ordering."""
    return _RISK_RANK[value]


class ContainmentStrength(str, Enum):
    NONE = "none"
    PROCESS_ISOLATION = "process"
    CONTAINER = "container"
    VM = "vm"
    AIR_GAPPED = "air_gapped"


_CONTAINMENT_RANK: dict[ContainmentStrength, int] = {
    ContainmentStrength.NONE: 0,
    ContainmentStrength.PROCESS_ISOLATION: 1,
    ContainmentStrength.CONTAINER: 2,
    ContainmentStrength.VM: 3,
    ContainmentStrength.AIR_GAPPED: 4,
}


class EgressClass(str, Enum):
    NONE = "none"
    LOOPBACK_ONLY = "loopback"
    PRIVATE_NETWORK = "private"
    ALLOWLISTED_HOSTS = "allowlisted"
    UNRESTRICTED = "unrestricted"


class DataSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CLIENT_IDENTIFIABLE = "client_id"
    FINANCIAL = "financial"
    CREDENTIALS = "credentials"
    REGULATED = "regulated"


class ProductionEffect(str, Enum):
    NONE = "none"
    READ_ONLY = "read_only"
    CONFIG_CHANGE = "config"
    SERVICE_RESTART = "restart"
    DEPLOYMENT = "deployment"
    DATA_MUTATION = "data_mutation"


class PaidRouteChange(str, Enum):
    NONE = "none"
    MODEL_CHANGE = "model"
    PROVIDER_CHANGE = "provider"
    VOLUME_CHANGE = "volume"


@dataclass(frozen=True)
class RiskFactors:
    # Scope and verbs.
    roots: tuple[Path, ...] = ()
    writable_roots: tuple[Path, ...] = ()
    root_expansion: bool = False
    verbs: tuple[str, ...] = ()
    has_write: bool = False
    has_delete: bool = False
    has_force_push: bool = False
    has_service_restart: bool = False
    has_deployment: bool = False

    # Network and production effects.
    egress_class: EgressClass = EgressClass.NONE
    egress_hosts: tuple[str, ...] = ()
    production_effect: ProductionEffect = ProductionEffect.NONE
    service_units: tuple[str, ...] = ()

    # Data and external effects.
    data_sensitivity: DataSensitivity = DataSensitivity.PUBLIC
    has_secret_access: bool = False
    has_credential_access: bool = False
    has_client_identifiable_data: bool = False
    has_financial_data: bool = False
    has_external_communication: bool = False
    external_comm_destinations: tuple[str, ...] = ()
    paid_route_change: PaidRouteChange = PaidRouteChange.NONE

    # Technical containment.
    containment_strength: ContainmentStrength = ContainmentStrength.NONE
    containment_weakened: bool = False
    hard_denies_present: bool = False
    bounded_roots_verified: bool = False
    containment_verified: bool = False
    branch_guard_verified: bool = False
    baseline_guard_verified: bool = False
    single_writer_verified: bool = False
    untracked_delete_protected: bool = False
    version_controlled_rollback: bool = False
    deliverable_verification_required: bool = False
    deliverable_verification_verified: bool = False

    # Policy binding.
    policy_template: str | None = None
    policy_template_hash: str | None = None
    policy_template_version: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "roots": [str(p) for p in self.roots],
            "writable_roots": [str(p) for p in self.writable_roots],
            "root_expansion": self.root_expansion,
            "verbs": list(self.verbs),
            "has_write": self.has_write,
            "has_delete": self.has_delete,
            "has_force_push": self.has_force_push,
            "has_service_restart": self.has_service_restart,
            "has_deployment": self.has_deployment,
            "egress_class": self.egress_class.value,
            "egress_hosts": list(self.egress_hosts),
            "production_effect": self.production_effect.value,
            "service_units": list(self.service_units),
            "data_sensitivity": self.data_sensitivity.value,
            "has_secret_access": self.has_secret_access,
            "has_credential_access": self.has_credential_access,
            "has_client_identifiable_data": self.has_client_identifiable_data,
            "has_financial_data": self.has_financial_data,
            "has_external_communication": self.has_external_communication,
            "external_comm_destinations": list(self.external_comm_destinations),
            "paid_route_change": self.paid_route_change.value,
            "containment_strength": self.containment_strength.value,
            "containment_weakened": self.containment_weakened,
            "hard_denies_present": self.hard_denies_present,
            "bounded_roots_verified": self.bounded_roots_verified,
            "containment_verified": self.containment_verified,
            "branch_guard_verified": self.branch_guard_verified,
            "baseline_guard_verified": self.baseline_guard_verified,
            "single_writer_verified": self.single_writer_verified,
            "untracked_delete_protected": self.untracked_delete_protected,
            "version_controlled_rollback": self.version_controlled_rollback,
            "deliverable_verification_required": self.deliverable_verification_required,
            "deliverable_verification_verified": self.deliverable_verification_verified,
            "policy_template": self.policy_template,
            "policy_template_hash": self.policy_template_hash,
            "policy_template_version": self.policy_template_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RiskFactors":
        """Losslessly restore factors from their canonical representation."""
        return cls(
            roots=tuple(Path(p) for p in data.get("roots", [])),
            writable_roots=tuple(Path(p) for p in data.get("writable_roots", [])),
            root_expansion=bool(data.get("root_expansion", False)),
            verbs=tuple(str(v) for v in data.get("verbs", [])),
            has_write=bool(data.get("has_write", False)),
            has_delete=bool(data.get("has_delete", False)),
            has_force_push=bool(data.get("has_force_push", False)),
            has_service_restart=bool(data.get("has_service_restart", False)),
            has_deployment=bool(data.get("has_deployment", False)),
            egress_class=EgressClass(data.get("egress_class", EgressClass.NONE.value)),
            egress_hosts=tuple(str(v) for v in data.get("egress_hosts", [])),
            production_effect=ProductionEffect(data.get("production_effect", ProductionEffect.NONE.value)),
            service_units=tuple(str(v) for v in data.get("service_units", [])),
            data_sensitivity=DataSensitivity(data.get("data_sensitivity", DataSensitivity.PUBLIC.value)),
            has_secret_access=bool(data.get("has_secret_access", False)),
            has_credential_access=bool(data.get("has_credential_access", False)),
            has_client_identifiable_data=bool(data.get("has_client_identifiable_data", False)),
            has_financial_data=bool(data.get("has_financial_data", False)),
            has_external_communication=bool(data.get("has_external_communication", False)),
            external_comm_destinations=tuple(str(v) for v in data.get("external_comm_destinations", [])),
            paid_route_change=PaidRouteChange(data.get("paid_route_change", PaidRouteChange.NONE.value)),
            containment_strength=ContainmentStrength(
                data.get("containment_strength", ContainmentStrength.NONE.value)
            ),
            containment_weakened=bool(data.get("containment_weakened", False)),
            hard_denies_present=bool(data.get("hard_denies_present", False)),
            bounded_roots_verified=bool(data.get("bounded_roots_verified", False)),
            containment_verified=bool(data.get("containment_verified", False)),
            branch_guard_verified=bool(data.get("branch_guard_verified", False)),
            baseline_guard_verified=bool(data.get("baseline_guard_verified", False)),
            single_writer_verified=bool(data.get("single_writer_verified", False)),
            untracked_delete_protected=bool(data.get("untracked_delete_protected", False)),
            version_controlled_rollback=bool(data.get("version_controlled_rollback", False)),
            deliverable_verification_required=bool(
                data.get("deliverable_verification_required", False)
            ),
            deliverable_verification_verified=bool(
                data.get("deliverable_verification_verified", False)
            ),
            policy_template=data.get("policy_template"),
            policy_template_hash=data.get("policy_template_hash"),
            policy_template_version=data.get("policy_template_version"),
        )

    def compute_hash(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def tier1_invariants_satisfied(self) -> bool:
        """Whether reversible maintenance has all standing-authority controls.

        Deliverable verification must be required as a completion gate.  It is
        deliberately not required to be *already verified* before execution.
        """
        return all(
            (
                self.bounded_roots_verified,
                self.containment_verified,
                self.branch_guard_verified,
                self.baseline_guard_verified,
                self.single_writer_verified,
                self.untracked_delete_protected,
                self.version_controlled_rollback,
                self.deliverable_verification_required,
            )
        ) and _CONTAINMENT_RANK[self.containment_strength] >= _CONTAINMENT_RANK[
            ContainmentStrength.CONTAINER
        ]


@dataclass(frozen=True)
class RiskReason:
    factor: str
    detail: str
    severity: RiskClass


@dataclass(frozen=True)
class RiskDecision:
    risk_class: RiskClass
    reasons: tuple[RiskReason, ...]
    factors_hash: str
    standing_authority_eligible: bool
    authority_bundle_eligible: bool
    requires_human_approval: bool
    prohibited_reasons: tuple[str, ...] = ()

    @property
    def tier(self) -> int | None:
        return {
            RiskClass.LOW: 0,
            RiskClass.MATERIAL: 2,
            RiskClass.HIGH: 3,
            RiskClass.PROHIBITED: None,
        }[self.risk_class]

    def summary(self) -> str:
        labels = {
            RiskClass.LOW: "LOW risk - standing authority eligible",
            RiskClass.MATERIAL: "MATERIAL risk - task-bound authority bundle required",
            RiskClass.HIGH: "HIGH risk - explicit human approval at the material boundary",
            RiskClass.PROHIBITED: "PROHIBITED - unavailable through this authority pathway",
        }
        details = [f"{r.factor}: {r.detail}" for r in self.reasons]
        details.extend(f"PROHIBITED: {value}" for value in self.prohibited_reasons)
        suffix = "; ".join(details) if details else "no material risk factors"
        return f"{labels[self.risk_class]}. Reasons: {suffix}"


def _has_normal_commit(factors: RiskFactors) -> bool:
    return "git:commit" in factors.verbs


def _has_test_execution(factors: RiskFactors) -> bool:
    return "tests:run" in factors.verbs


def _has_reversible_maintenance(factors: RiskFactors) -> bool:
    return factors.has_write or _has_normal_commit(factors) or _has_test_execution(factors)


def classify_risk(factors: RiskFactors) -> RiskDecision:
    reasons: list[RiskReason] = []
    prohibited: list[str] = []

    # Fail-closed boundaries that this standing/bundle subsystem never grants.
    if factors.has_secret_access or factors.has_credential_access or factors.data_sensitivity == DataSensitivity.CREDENTIALS:
        prohibited.append("Secret or credential access requested")
        reasons.append(RiskReason("secrets", "Direct secret or credential access", RiskClass.PROHIBITED))
    if factors.egress_class == EgressClass.UNRESTRICTED:
        prohibited.append("Unrestricted network egress")
        reasons.append(RiskReason("egress", "Unrestricted network egress", RiskClass.PROHIBITED))
    if factors.paid_route_change != PaidRouteChange.NONE:
        prohibited.append("Paid route change")
        reasons.append(RiskReason("paid_route", "Paid route change affecting cost", RiskClass.PROHIBITED))
    if factors.root_expansion:
        prohibited.append("Root expansion beyond approved policy")
        reasons.append(RiskReason("roots", "Roots expanded beyond the approved policy", RiskClass.PROHIBITED))
    if factors.containment_weakened:
        prohibited.append("Containment weaker than the approved baseline")
        reasons.append(RiskReason("containment", "Containment weakened", RiskClass.PROHIBITED))

    if prohibited:
        return RiskDecision(
            risk_class=RiskClass.PROHIBITED,
            reasons=tuple(reasons),
            factors_hash=factors.compute_hash(),
            standing_authority_eligible=False,
            authority_bundle_eligible=False,
            requires_human_approval=True,
            prohibited_reasons=tuple(prohibited),
        )

    # Tier 3 boundaries. These require explicit approval and are never standing.
    if factors.has_service_restart or factors.production_effect == ProductionEffect.SERVICE_RESTART:
        reasons.append(RiskReason("service", "Service restart capability", RiskClass.HIGH))
    if factors.has_force_push:
        reasons.append(RiskReason("git", "Force push capability", RiskClass.HIGH))
    if factors.has_delete:
        reasons.append(RiskReason("filesystem", "Recursive or destructive delete capability", RiskClass.HIGH))
    if factors.has_deployment or factors.production_effect in {
        ProductionEffect.CONFIG_CHANGE,
        ProductionEffect.DEPLOYMENT,
        ProductionEffect.DATA_MUTATION,
        ProductionEffect.READ_ONLY,
    }:
        reasons.append(
            RiskReason(
                "production",
                f"Production effect: {factors.production_effect.value}",
                RiskClass.HIGH,
            )
        )
    if factors.egress_class in {EgressClass.PRIVATE_NETWORK, EgressClass.ALLOWLISTED_HOSTS}:
        reasons.append(RiskReason("egress", f"Network egress: {factors.egress_class.value}", RiskClass.HIGH))
    if factors.has_external_communication:
        reasons.append(RiskReason("external", "External communication capability", RiskClass.HIGH))
    if factors.has_client_identifiable_data or factors.data_sensitivity in {
        DataSensitivity.CLIENT_IDENTIFIABLE,
        DataSensitivity.REGULATED,
    }:
        reasons.append(RiskReason("data", "Client-identifiable or regulated data", RiskClass.HIGH))
    if factors.has_financial_data or factors.data_sensitivity == DataSensitivity.FINANCIAL:
        reasons.append(RiskReason("data", "Financial data", RiskClass.HIGH))
    if factors.containment_strength in {
        ContainmentStrength.NONE,
        ContainmentStrength.PROCESS_ISOLATION,
    }:
        reasons.append(
            RiskReason(
                "containment",
                f"Insufficient containment: {factors.containment_strength.value}",
                RiskClass.HIGH,
            )
        )

    # Tier 2 versus Tier 1 reversible maintenance.
    maintenance = _has_reversible_maintenance(factors)
    if maintenance:
        tier1_ready = (
            factors.tier1_invariants_satisfied()
            and factors.egress_class == EgressClass.NONE
            and factors.production_effect == ProductionEffect.NONE
            and not factors.has_service_restart
            and not factors.has_deployment
            and not factors.has_delete
            and not factors.has_force_push
            and not factors.has_external_communication
            and not factors.has_client_identifiable_data
            and not factors.has_financial_data
        )
        if tier1_ready:
            reasons.append(
                RiskReason(
                    "contained_maintenance",
                    "Contained reversible maintenance with all standing-authority invariants",
                    RiskClass.LOW,
                )
            )
        else:
            reasons.append(
                RiskReason(
                    "maintenance",
                    "Write, test or normal-commit capability without every Tier 1 invariant",
                    RiskClass.MATERIAL,
                )
            )

    if factors.egress_class == EgressClass.LOOPBACK_ONLY:
        reasons.append(RiskReason("egress", "Loopback-only network egress", RiskClass.MATERIAL))

    risk_class = RiskClass.LOW
    if reasons:
        risk_class = max((reason.severity for reason in reasons), key=risk_rank)

    return RiskDecision(
        risk_class=risk_class,
        reasons=tuple(reasons),
        factors_hash=factors.compute_hash(),
        standing_authority_eligible=risk_class == RiskClass.LOW,
        authority_bundle_eligible=risk_class in {RiskClass.LOW, RiskClass.MATERIAL},
        requires_human_approval=risk_class in {RiskClass.MATERIAL, RiskClass.HIGH},
        prohibited_reasons=(),
    )


def _enum_or_default(enum_type: type[Enum], value: Any, default: Enum) -> Enum:
    try:
        return enum_type(value)  # type: ignore[call-arg]
    except (TypeError, ValueError):
        return default


def compute_risk_factors_from_session(
    snapshot: dict[str, Any],
    *,
    template_baseline: dict[str, Any] | None = None,
) -> RiskFactors:
    """Compute immutable factors from a locally resolved session/policy snapshot."""
    verbs_map = snapshot.get("verbs", {}) or {}
    verb_list = tuple(
        f"{resource}:{action}"
        for resource, actions in verbs_map.items()
        if isinstance(actions, list)
        for action in actions
    )

    readable_roots = tuple(Path(p) for p in snapshot.get("readable_roots", []))
    writable_roots = tuple(Path(p) for p in snapshot.get("writable_roots", []))

    root_expansion = False
    containment_weakened = False
    if template_baseline is not None:
        approved_writable = {str(Path(p)) for p in template_baseline.get("writable_roots", [])}
        root_expansion = not {str(p) for p in writable_roots}.issubset(approved_writable)
        approved_strength = _enum_or_default(
            ContainmentStrength,
            template_baseline.get("containment_strength", ContainmentStrength.NONE.value),
            ContainmentStrength.NONE,
        )
    else:
        approved_strength = ContainmentStrength.NONE

    egress_hosts = tuple(str(v) for v in snapshot.get("egress_hosts", []))
    if not egress_hosts:
        egress_class = EgressClass.NONE
    elif any(host in {"*", "0.0.0.0", "::", "any"} for host in egress_hosts):
        egress_class = EgressClass.UNRESTRICTED
    elif all(host in {"localhost", "127.0.0.1", "::1", "[::1]"} for host in egress_hosts):
        egress_class = EgressClass.LOOPBACK_ONLY
    else:
        configured_egress = snapshot.get("egress_class")
        egress_class = _enum_or_default(
            EgressClass,
            configured_egress,
            EgressClass.ALLOWLISTED_HOSTS,
        )

    containment_strength = _enum_or_default(
        ContainmentStrength,
        snapshot.get("containment_strength", ContainmentStrength.NONE.value),
        ContainmentStrength.NONE,
    )
    if template_baseline is not None:
        containment_weakened = _CONTAINMENT_RANK[containment_strength] < _CONTAINMENT_RANK[approved_strength]

    service_units = tuple(str(v) for v in snapshot.get("service_units", []))
    has_service_restart = "services:restart" in verb_list or "service:restart" in verb_list
    production_effect = _enum_or_default(
        ProductionEffect,
        snapshot.get(
            "production_effect",
            ProductionEffect.SERVICE_RESTART.value if has_service_restart and service_units else ProductionEffect.NONE.value,
        ),
        ProductionEffect.NONE,
    )

    paid_route_change = _enum_or_default(
        PaidRouteChange,
        snapshot.get("paid_route_change", PaidRouteChange.NONE.value),
        PaidRouteChange.NONE,
    )
    data_sensitivity = _enum_or_default(
        DataSensitivity,
        snapshot.get("data_sensitivity", DataSensitivity.PUBLIC.value),
        DataSensitivity.PUBLIC,
    )

    # Hard-denied paths demonstrate a guardrail. They do not imply requested access.
    hard_denies_present = bool(snapshot.get("hard_denied_paths", []))

    return RiskFactors(
        roots=readable_roots,
        writable_roots=writable_roots,
        root_expansion=root_expansion,
        verbs=verb_list,
        has_write="filesystem:edit" in verb_list or "filesystem:write" in verb_list,
        has_delete="filesystem:recursive_delete" in verb_list or "filesystem:delete" in verb_list,
        has_force_push="git:force_push" in verb_list,
        has_service_restart=has_service_restart,
        has_deployment=bool(snapshot.get("has_deployment", False)) or "deployment:apply" in verb_list,
        egress_class=egress_class,
        egress_hosts=egress_hosts,
        production_effect=production_effect,
        service_units=service_units,
        data_sensitivity=data_sensitivity,
        has_secret_access=bool(snapshot.get("has_secret_access", False)),
        has_credential_access=bool(snapshot.get("has_credential_access", False)),
        has_client_identifiable_data=bool(snapshot.get("has_client_identifiable_data", False)),
        has_financial_data=bool(snapshot.get("has_financial_data", False)),
        has_external_communication=bool(snapshot.get("has_external_communication", False)),
        external_comm_destinations=tuple(
            str(v) for v in snapshot.get("external_comm_destinations", [])
        ),
        paid_route_change=paid_route_change,
        containment_strength=containment_strength,
        containment_weakened=containment_weakened,
        hard_denies_present=hard_denies_present,
        bounded_roots_verified=bool(snapshot.get("bounded_roots_verified", False)),
        containment_verified=bool(snapshot.get("containment_verified", False)),
        branch_guard_verified=bool(snapshot.get("branch_guard_verified", False)),
        baseline_guard_verified=bool(snapshot.get("baseline_guard_verified", False)),
        single_writer_verified=bool(snapshot.get("single_writer_verified", False)),
        untracked_delete_protected=bool(snapshot.get("untracked_delete_protected", False)),
        version_controlled_rollback=bool(snapshot.get("version_controlled_rollback", False)),
        deliverable_verification_required=bool(
            snapshot.get("deliverable_verification_required", False)
        ),
        deliverable_verification_verified=bool(
            snapshot.get("deliverable_verification_verified", False)
        ),
        policy_template=snapshot.get("policy_template"),
        policy_template_hash=snapshot.get("snapshot_hash") or snapshot.get("policy_template_hash"),
        policy_template_version=int(snapshot.get("version", snapshot.get("policy_template_version", 1))),
    )


@dataclass(frozen=True)
class EscalationResult:
    escalated: bool
    from_class: RiskClass
    to_class: RiskClass
    changed_factors: tuple[str, ...]
    new_prohibited: tuple[str, ...] = ()

    def summary(self) -> str:
        if not self.escalated:
            return f"No escalation (remains {self.from_class.value})"
        text = f"ESCALATED: {self.from_class.value} -> {self.to_class.value}"
        if self.changed_factors:
            text += f". Changed: {', '.join(self.changed_factors)}"
        if self.new_prohibited:
            text += f". New prohibited: {', '.join(self.new_prohibited)}"
        return text


def check_escalation(current: RiskFactors, proposed: RiskFactors) -> EscalationResult:
    current_decision = classify_risk(current)
    proposed_decision = classify_risk(proposed)
    escalated = risk_rank(proposed_decision.risk_class) > risk_rank(current_decision.risk_class)
    if not escalated:
        return EscalationResult(
            escalated=False,
            from_class=current_decision.risk_class,
            to_class=proposed_decision.risk_class,
            changed_factors=(),
        )
    before = current.to_dict()
    after = proposed.to_dict()
    changed = tuple(key for key in after if after.get(key) != before.get(key))
    return EscalationResult(
        escalated=True,
        from_class=current_decision.risk_class,
        to_class=proposed_decision.risk_class,
        changed_factors=changed,
        new_prohibited=proposed_decision.prohibited_reasons,
    )
