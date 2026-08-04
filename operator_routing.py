"""Deterministic free-only routing and bounded cross-provider recovery.

This module adapts the accepted staging router in
``/home/jfroh/.hermes/model-routing-migration`` (evidence:
``ops-brain/evidence/hermes-live-provider-routing-pilot-2026-08-02.md``) into
the live delegated-worker path. It deliberately keeps the staging semantics:

* provider eligibility is policy driven, not OpenRouter-default;
* static configuration entries are hints, never automatically routable;
* free-only routing with a zero price ceiling and no paid fallback;
* one bounded alternate attempt by default, preferring a different provider;
* every attempt carries a unique identity and a predecessor reference.

The module owns no credentials, performs no network access and reads only
non-secret routing control state. Credentials stay in the profile ``.env`` that
the delegated runtime links read-only.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Canonical policy
# ---------------------------------------------------------------------------

#: Canonical provider eligibility and selection priority. This ordering is the
#: accepted policy and is not re-derived from configuration file ordering.
CANONICAL_PROVIDER_ORDER: tuple[str, ...] = (
    "nvidia",
    "openrouter",
    "gemini",
    "nous",
    "ollama",
)

#: Bounded recovery. One cross-provider alternate attempt by default. This is
#: configurable but never unbounded: the resolver refuses to walk the whole
#: provider list.
DEFAULT_MAX_ALTERNATE_ATTEMPTS = 1
MAX_ALTERNATE_ATTEMPTS_CEILING = 3

ROUTING_CONTROL_ENV = "HERMES_OPERATOR_ROUTING_CONTROL"
DEFAULT_ROUTING_CONTROL_PATH = Path(__file__).resolve().parent / "routing_control.json"

#: Marker a worker must emit to turn "apply produced no changes" into a
#: legitimate no-change result. A bare no-op is a recoverable model failure.
NO_CHANGE_JUSTIFICATION_PREFIX = "HERMES_NO_CHANGE_JUSTIFICATION:"

_PROVIDER_ALIASES: dict[str, str] = {
    "nvidia": "nvidia",
    "nvidia_direct": "nvidia",
    "nvidia-direct": "nvidia",
    "nim": "nvidia",
    "openrouter": "openrouter",
    "open_router": "openrouter",
    "gemini": "gemini",
    "gemini_direct": "gemini",
    "gemini-direct": "gemini",
    "google": "gemini",
    "googleai": "gemini",
    "nous": "nous",
    "nousresearch": "nous",
    "nous_research": "nous",
    "ollama": "ollama",
    "local": "ollama",
}


class RoutingError(ValueError):
    """Raised when routing cannot produce a usable, policy-compliant primary."""


class RecoveryClass(str, Enum):
    """What a delegated attempt outcome permits the controller to do next."""

    SUCCESS = "success"
    #: A model/provider defect. Eligible for one bounded alternate attempt.
    MODEL_RECOVERABLE = "model_recoverable"
    #: Deterministic work that a governed operator path may finish directly.
    OPERATOR_ESCALATION = "operator_escalation"
    #: Never retry on another model. Permission, tool policy or evidence gaps.
    FAIL_CLOSED = "fail_closed"


class FailureClass(str, Enum):
    """Concrete unusable-response classifications."""

    COMPLETED = "completed"
    EMPTY_RESPONSE = "empty_response"
    PROVIDER_FALLBACK_RESPONSE = "provider_fallback_response"
    REASONING_ONLY = "reasoning_only"
    PLANNING_LOOP = "planning_loop"
    NO_CHANGE_UNJUSTIFIED = "no_change_unjustified"
    NO_CHANGE_JUSTIFIED = "no_change_justified"
    RATE_LIMIT = "rate_limit"
    TRANSIENT_PROVIDER_FAILURE = "transient_provider_failure"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_CONFIGURATION = "provider_configuration"
    DEADLINE_EXHAUSTED = "deadline_exhausted"
    EVIDENCE_FAILURE = "evidence_failure"
    PERMISSION_FAILURE = "permission_failure"
    TOOL_POLICY_FAILURE = "tool_policy_failure"
    PROCESS_FAILURE = "process_failure"


#: Only these classes may consume the bounded alternate attempt.
_RECOVERABLE = frozenset(
    {
        FailureClass.EMPTY_RESPONSE,
        FailureClass.PROVIDER_FALLBACK_RESPONSE,
        FailureClass.REASONING_ONLY,
        FailureClass.PLANNING_LOOP,
        FailureClass.NO_CHANGE_UNJUSTIFIED,
        FailureClass.RATE_LIMIT,
        FailureClass.TRANSIENT_PROVIDER_FAILURE,
        FailureClass.PROVIDER_UNAVAILABLE,
    }
)

#: These never trigger a blind model fallback.
_FAIL_CLOSED = frozenset(
    {
        FailureClass.PERMISSION_FAILURE,
        FailureClass.TOOL_POLICY_FAILURE,
        FailureClass.EVIDENCE_FAILURE,
        FailureClass.PROVIDER_CONFIGURATION,
        FailureClass.DEADLINE_EXHAUSTED,
        FailureClass.PROCESS_FAILURE,
    }
)


def normalise_provider(value: Any) -> str:
    """Map a raw provider string onto a canonical lane name."""
    text = str(value or "").strip().lower()
    return _PROVIDER_ALIASES.get(text, text)


def normalise_model(value: Any) -> str:
    """Normalise a model id so aliases of one model compare equal.

    ``nvidia/x:free`` and ``nvidia/x`` are the same underlying model, so one
    cannot be presented as diversification for the other.
    """
    text = str(value or "").strip().lower()
    for suffix in (":free", ":nitro", ":beta", ":extended"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
    return text


# ---------------------------------------------------------------------------
# Routing control surface (non-secret)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderControl:
    """Non-secret qualification state for one provider lane."""

    lane: str
    eligible: bool = False
    quarantined: bool = True
    reason: str = "no qualification record"
    free_tier_only: bool = True
    qualified_models: tuple[str, ...] = ()
    evidence_ref: str = ""

    def qualifies(self, model: str) -> bool:
        return normalise_model(model) in {normalise_model(m) for m in self.qualified_models}


@dataclass(frozen=True)
class RoutingControl:
    """Parsed routing control surface."""

    free_only: bool = True
    max_alternate_attempts: int = DEFAULT_MAX_ALTERNATE_ATTEMPTS
    provider_order: tuple[str, ...] = CANONICAL_PROVIDER_ORDER
    require_qualified_primary: bool = False
    #: Offer every qualified route from this control surface as an alternate,
    #: not only routes a config file happens to list. Without this a profile
    #: whose fallback list names one provider can never reach a genuinely
    #: different provider, which is the defect this integration exists to fix.
    include_qualified_routes: bool = True
    providers: dict[str, ProviderControl] = field(default_factory=dict)
    source_path: str = ""

    def control_for(self, lane: str) -> ProviderControl:
        return self.providers.get(lane, ProviderControl(lane=lane))

    def qualified_routes(self) -> list["RouteCandidate"]:
        """Every currently qualified, non-quarantined route, canonically ordered."""
        routes: list[RouteCandidate] = []
        for lane in self.provider_order:
            provider_control = self.control_for(lane)
            if provider_control.quarantined or not provider_control.eligible:
                continue
            for model in provider_control.qualified_models:
                routes.append(RouteCandidate(provider=lane, model=model, origin="control"))
        return routes


def _control_path() -> Path:
    override = os.environ.get(ROUTING_CONTROL_ENV, "").strip()
    return Path(override) if override else DEFAULT_ROUTING_CONTROL_PATH


def load_routing_control(path: Path | None = None) -> RoutingControl:
    """Load the reviewed, non-secret routing control surface.

    A missing or malformed control surface fails closed to "nothing is
    qualified" rather than silently promoting stale configuration.
    """
    target = Path(path) if path is not None else _control_path()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return RoutingControl(source_path=str(target))
    if not isinstance(raw, dict):
        return RoutingControl(source_path=str(target))

    order = tuple(
        normalise_provider(item)
        for item in raw.get("provider_order", CANONICAL_PROVIDER_ORDER)
        if normalise_provider(item)
    ) or CANONICAL_PROVIDER_ORDER

    limit = raw.get("max_alternate_attempts", DEFAULT_MAX_ALTERNATE_ATTEMPTS)
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_ALTERNATE_ATTEMPTS
    limit = max(0, min(MAX_ALTERNATE_ATTEMPTS_CEILING, limit))

    providers: dict[str, ProviderControl] = {}
    for name, value in (raw.get("providers") or {}).items():
        lane = normalise_provider(name)
        if not lane or not isinstance(value, dict):
            continue
        models = value.get("qualified_models") or []
        providers[lane] = ProviderControl(
            lane=lane,
            eligible=bool(value.get("eligible", False)),
            quarantined=bool(value.get("quarantined", not value.get("eligible", False))),
            reason=str(value.get("reason") or ""),
            free_tier_only=bool(value.get("free_tier_only", True)),
            qualified_models=tuple(str(item) for item in models if str(item).strip()),
            evidence_ref=str(value.get("evidence_ref") or ""),
        )

    return RoutingControl(
        free_only=bool(raw.get("free_only", True)),
        max_alternate_attempts=limit,
        provider_order=order,
        require_qualified_primary=bool(raw.get("require_qualified_primary", False)),
        include_qualified_routes=bool(raw.get("include_qualified_routes", True)),
        providers=providers,
        source_path=str(target),
    )


# ---------------------------------------------------------------------------
# Route candidates
# ---------------------------------------------------------------------------


@dataclass
class RouteCandidate:
    """One concrete provider/model route."""

    provider: str
    model: str
    origin: str = "global"  # task | profile | global
    base_url: str = ""
    paid: bool = False

    @property
    def lane(self) -> str:
        return normalise_provider(self.provider)

    @property
    def key(self) -> tuple[str, str]:
        """Underlying-route identity used for de-duplication."""
        return (self.lane, normalise_model(self.model))

    def priority(self, order: tuple[str, ...]) -> int:
        try:
            return order.index(self.lane)
        except ValueError:
            return len(order)

    def to_runtime_dict(self) -> dict[str, Any]:
        # Hermes reads the primary model from either ``model`` or ``default``
        # depending on config vintage, so emit both to stay compatible.
        entry: dict[str, Any] = {
            "provider": self.provider,
            "model": self.model,
            "default": self.model,
        }
        if self.base_url:
            entry["base_url"] = self.base_url
        return entry

    def to_fallback_dict(self) -> dict[str, Any]:
        """Fallback chain entries use the provider/model pair only."""
        entry: dict[str, Any] = {"provider": self.provider, "model": self.model}
        if self.base_url:
            entry["base_url"] = self.base_url
        return entry

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "lane": self.lane,
            "model": self.model,
            "normalised_model": normalise_model(self.model),
            "origin": self.origin,
        }


def _candidate_from_mapping(value: Any, origin: str) -> RouteCandidate | None:
    """Build a candidate from a config mapping, rejecting malformed entries."""
    if not isinstance(value, dict):
        return None
    provider = value.get("provider")
    model = value.get("model") or value.get("default") or value.get("name")
    if not str(provider or "").strip() or not str(model or "").strip():
        return None
    price_fields = (
        value.get("input_per_million"),
        value.get("output_per_million"),
        value.get("price"),
    )
    paid = any(
        isinstance(item, (int, float)) and float(item) > 0.0 for item in price_fields
    ) or bool(value.get("paid", False))
    return RouteCandidate(
        provider=str(provider).strip(),
        model=str(model).strip(),
        origin=origin,
        base_url=str(value.get("base_url") or "").strip(),
        paid=paid,
    )


def _fallback_candidates(config: Any, origin: str) -> list[RouteCandidate]:
    """Read a ``fallback_providers`` list, skipping malformed entries.

    Keys such as ``fallback_providers[0]`` that some historic writers left in
    the root config are ignored: only the real list is read.
    """
    if not isinstance(config, dict):
        return []
    raw = config.get("fallback_providers")
    if not isinstance(raw, list):
        return []
    candidates: list[RouteCandidate] = []
    for item in raw:
        candidate = _candidate_from_mapping(item, origin)
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _primary_candidate(config: Any, origin: str) -> RouteCandidate | None:
    if not isinstance(config, dict):
        return None
    return _candidate_from_mapping(config.get("model"), origin)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


@dataclass
class ExcludedRoute:
    provider: str
    model: str
    reason: str

    def to_audit_dict(self) -> dict[str, Any]:
        return {"provider": self.provider, "model": self.model, "reason": self.reason}


@dataclass
class ResolvedRouting:
    """Complete routing configuration materialised into a delegated runtime."""

    primary: RouteCandidate
    alternates: list[RouteCandidate] = field(default_factory=list)
    excluded: list[ExcludedRoute] = field(default_factory=list)
    free_only: bool = True
    max_alternate_attempts: int = DEFAULT_MAX_ALTERNATE_ATTEMPTS
    provider_order: tuple[str, ...] = CANONICAL_PROVIDER_ORDER
    deadline_seconds: int = 0
    control_source: str = ""

    def runtime_fallback_providers(self) -> list[dict[str, Any]]:
        """Ordered fallback chain, primary excluded, capped by the retry limit."""
        return [item.to_fallback_dict() for item in self.alternates[: self.max_alternate_attempts]]

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "primary": self.primary.to_audit_dict(),
            "alternates": [item.to_audit_dict() for item in self.alternates],
            "eligible_alternate_count": len(self.alternates),
            "excluded": [item.to_audit_dict() for item in self.excluded],
            "free_only": self.free_only,
            "max_alternate_attempts": self.max_alternate_attempts,
            "provider_order": list(self.provider_order),
            "deadline_seconds": self.deadline_seconds,
            "control_source": self.control_source,
        }


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _eligibility_failure(
    candidate: RouteCandidate, control: RoutingControl, *, require_qualified: bool
) -> str:
    """Return an exclusion reason, or "" when the candidate is eligible."""
    provider_control = control.control_for(candidate.lane)
    if candidate.lane not in control.provider_order:
        return f"provider lane {candidate.lane!r} is outside the canonical provider order"
    if control.free_only and candidate.paid:
        return "paid route rejected by free-only policy"
    if provider_control.quarantined or not provider_control.eligible:
        return provider_control.reason or f"provider lane {candidate.lane!r} is quarantined"
    if require_qualified and not provider_control.qualifies(candidate.model):
        return "model has no current account-specific qualification record"
    return ""


def resolve_routing(
    *,
    hermes_root: Path,
    profile: str,
    profile_home: Path,
    task_routing: dict[str, Any] | None = None,
    control: RoutingControl | None = None,
    deadline_seconds: int = 0,
) -> ResolvedRouting:
    """Resolve the complete routing configuration for one delegated task.

    Precedence, highest first:

    1. task-specific routing supplied by the caller;
    2. profile-specific routing from ``<profile_home>/config.yaml``;
    3. global defaults from ``<hermes_root>/config.yaml``.

    The primary is taken from the highest precedence level that declares one.
    Alternates are accumulated across all three levels in that same order, then
    filtered to eligible, free, canonically-ordered routes that differ from the
    primary's underlying provider/model.
    """
    control = control or load_routing_control()
    task_routing = task_routing or {}

    profile_config = _load_yaml(Path(profile_home) / "config.yaml")
    # The ``default`` profile home *is* the Hermes root, so its config would
    # otherwise be read at two precedence levels and appear as a self-duplicate.
    same_file = Path(profile_home).resolve(strict=False) == Path(hermes_root).resolve(strict=False)
    global_config = {} if same_file else _load_yaml(Path(hermes_root) / "config.yaml")

    # --- primary: first declared level wins, no duplicate primaries ---------
    primary = (
        _primary_candidate(task_routing, "task")
        or _primary_candidate(profile_config, "profile")
        or _primary_candidate(global_config, "global")
    )
    if primary is None:
        raise RoutingError(
            f"no usable model configuration for profile {profile!r}: "
            f"checked task routing, {profile_home}/config.yaml and {hermes_root}/config.yaml"
        )

    excluded: list[ExcludedRoute] = []

    # A quarantined or paid primary always fails closed. Nous and Ollama stay
    # ineligible here until their independent qualification gates pass.
    primary_failure = _eligibility_failure(
        primary, control, require_qualified=control.require_qualified_primary
    )
    primary_control = control.control_for(primary.lane)
    if primary_failure and (
        primary_control.quarantined
        or not primary_control.eligible
        or (control.free_only and primary.paid)
        or control.require_qualified_primary
    ):
        raise RoutingError(
            f"primary route {primary.provider}/{primary.model} is not eligible: {primary_failure}"
        )

    # --- alternates: accumulate in precedence order, then gate --------------
    ordered_sources = [
        *_fallback_candidates(task_routing, "task"),
        *_fallback_candidates(profile_config, "profile"),
        *_fallback_candidates(global_config, "global"),
    ]
    if control.include_qualified_routes:
        # Configured fallback lists are frequently single-provider, which cannot
        # satisfy "a fallback must use a genuinely different provider". The
        # reviewed control surface supplies the remaining qualified routes.
        ordered_sources.extend(control.qualified_routes())

    seen: set[tuple[str, str]] = {primary.key}
    eligible: list[RouteCandidate] = []
    for candidate in ordered_sources:
        if candidate.key in seen:
            reason = (
                "duplicate of the primary route; a profile alias of the same "
                "underlying provider/model is not diversification"
                if candidate.key == primary.key
                else "duplicate of an earlier alternate"
            )
            excluded.append(ExcludedRoute(candidate.provider, candidate.model, reason))
            continue
        seen.add(candidate.key)
        failure = _eligibility_failure(candidate, control, require_qualified=True)
        if failure:
            excluded.append(ExcludedRoute(candidate.provider, candidate.model, failure))
            continue
        eligible.append(candidate)

    # Canonical provider order decides selection priority, not file order.
    eligible.sort(key=lambda item: item.priority(control.provider_order))

    return ResolvedRouting(
        primary=primary,
        alternates=eligible,
        excluded=excluded,
        free_only=control.free_only,
        max_alternate_attempts=control.max_alternate_attempts,
        provider_order=control.provider_order,
        deadline_seconds=int(deadline_seconds or 0),
        control_source=control.source_path,
    )


def select_alternate(
    resolved: ResolvedRouting,
    *,
    failed_routes: list[RouteCandidate] | None = None,
    attempts_used: int = 0,
) -> RouteCandidate | None:
    """Return the highest-priority eligible route not already attempted.

    Returns ``None`` once the configured alternate-attempt limit is spent, so
    recovery stays bounded instead of walking the whole provider list.
    """
    if attempts_used >= resolved.max_alternate_attempts:
        return None
    attempted = {resolved.primary.key}
    attempted_lanes = {resolved.primary.lane}
    for route in failed_routes or []:
        attempted.add(route.key)
        attempted_lanes.add(route.lane)
    remaining = [item for item in resolved.alternates if item.key not in attempted]
    # A genuinely different provider is preferred over another model on a lane
    # that has already failed.
    for candidate in remaining:
        if candidate.lane not in attempted_lanes:
            return candidate
    return remaining[0] if remaining else None


# ---------------------------------------------------------------------------
# Attempt identity
# ---------------------------------------------------------------------------


def new_attempt_identity(
    *,
    logical_work_id: str,
    route: RouteCandidate,
    attempt_number: int,
    predecessor_attempt_id: str | None = None,
) -> dict[str, Any]:
    """Mint a unique attempt identity carrying its predecessor and work id."""
    return {
        "attempt_id": "da_" + uuid.uuid4().hex,
        "attempt_number": int(attempt_number),
        "predecessor_attempt_id": predecessor_attempt_id,
        "logical_work_id": logical_work_id,
        "provider": route.provider,
        "provider_lane": route.lane,
        "model": route.model,
    }


# ---------------------------------------------------------------------------
# Unusable-response classification
# ---------------------------------------------------------------------------

_RATE_LIMIT_MARKERS = (
    "429",
    "rate limit",
    "rate-limit",
    "too many requests",
    "quota exceeded",
    "resource_exhausted",
)
_UNAVAILABLE_MARKERS = (
    "503",
    "service unavailable",
    "provider unavailable",
    "connection refused",
    "connection reset",
    "no healthy upstream",
)
_TRANSIENT_MARKERS = ("500", "502", "504", "bad gateway", "gateway timeout", "upstream error")
_EMPTY_MARKERS = (
    "no reply: the model returned empty content",
    "model returned empty content",
    "try `continue`, switch model/provider",
)
_PERMISSION_MARKERS = (
    "permission denied",
    "not permitted",
    "authority was withdrawn",
    "operator session expired",
    "policy denied",
    "forbidden",
)
_TOOL_POLICY_MARKERS = (
    "tool is not available",
    "toolset is not available",
    "unknown tool",
    "tool not allowed",
    "tool policy",
)
_PLANNING_MARKERS = (
    "i will now",
    "next, i will",
    "let me plan",
    "here is my plan",
    "i plan to",
    "first, i need to",
)


def _contains(haystack: str, markers: tuple[str, ...]) -> bool:
    return any(marker in haystack for marker in markers)


def classify_outcome(
    *,
    status: str,
    rc: int,
    stdout: str,
    stderr: str,
    mode: str,
    changed_files: list[str] | None,
    final_answer: str | None,
    final_answer_reason: str = "",
    tool_progress: bool | None = None,
) -> tuple[FailureClass, RecoveryClass, str]:
    """Classify one delegated attempt outcome.

    Returns ``(failure_class, recovery_class, human_reason)``. Only genuine
    model/provider defects map to :attr:`RecoveryClass.MODEL_RECOVERABLE`;
    permission, tool-policy and evidence gaps always fail closed so a bad
    authority never triggers a blind walk across providers.
    """
    combined = f"{stdout or ''}\n{stderr or ''}".lower()
    changed_files = changed_files or []

    # Authority and policy failures must never consume a model alternate.
    if status == "blocked" or _contains(combined, _PERMISSION_MARKERS):
        return (
            FailureClass.PERMISSION_FAILURE,
            RecoveryClass.FAIL_CLOSED,
            "authority or permission failure; model fallback is not applicable",
        )
    if _contains(combined, _TOOL_POLICY_MARKERS):
        return (
            FailureClass.TOOL_POLICY_FAILURE,
            RecoveryClass.FAIL_CLOSED,
            "tool policy failure; model fallback is not applicable",
        )
    if "provider resolver returned an empty api key" in combined:
        return (
            FailureClass.PROVIDER_CONFIGURATION,
            RecoveryClass.FAIL_CLOSED,
            "provider credential configuration is incomplete",
        )
    if status == "timed_out" or rc == 124:
        return (
            FailureClass.DEADLINE_EXHAUSTED,
            RecoveryClass.OPERATOR_ESCALATION,
            "delegated attempt exceeded its bounded execution timeout",
        )

    # Provider transport failures are bounded-recoverable on another provider.
    if _contains(combined, _RATE_LIMIT_MARKERS):
        return (
            FailureClass.RATE_LIMIT,
            RecoveryClass.MODEL_RECOVERABLE,
            "provider returned a rate-limit response",
        )
    if _contains(combined, _UNAVAILABLE_MARKERS):
        return (
            FailureClass.PROVIDER_UNAVAILABLE,
            RecoveryClass.MODEL_RECOVERABLE,
            "provider lane was unavailable",
        )
    if _contains(combined, _TRANSIENT_MARKERS):
        return (
            FailureClass.TRANSIENT_PROVIDER_FAILURE,
            RecoveryClass.MODEL_RECOVERABLE,
            "provider returned a transient upstream failure",
        )
    if _contains(combined, _EMPTY_MARKERS):
        return (
            FailureClass.EMPTY_RESPONSE,
            RecoveryClass.MODEL_RECOVERABLE,
            "model produced an explicit empty-response failure",
        )
    if not combined.strip():
        return (
            FailureClass.EMPTY_RESPONSE,
            RecoveryClass.MODEL_RECOVERABLE,
            "process exited cleanly but produced no output",
        )
    if "fallback" in combined:
        return (
            FailureClass.PROVIDER_FALLBACK_RESPONSE,
            RecoveryClass.MODEL_RECOVERABLE,
            "provider returned a fallback response",
        )
    if rc != 0:
        return (
            FailureClass.PROCESS_FAILURE,
            RecoveryClass.FAIL_CLOSED,
            f"process exited with return code {rc}",
        )

    # Reasoning-only: output exists but no usable final answer was produced.
    if not final_answer:
        return (
            FailureClass.REASONING_ONLY,
            RecoveryClass.MODEL_RECOVERABLE,
            f"model produced no usable final answer ({final_answer_reason or 'not_found'})",
        )

    if mode == "apply" and not changed_files:
        if NO_CHANGE_JUSTIFICATION_PREFIX.lower() in (final_answer or "").lower():
            return (
                FailureClass.NO_CHANGE_JUSTIFIED,
                RecoveryClass.SUCCESS,
                "apply task reported an explicitly justified no-change result",
            )
        if tool_progress is False and _contains((final_answer or "").lower(), _PLANNING_MARKERS):
            return (
                FailureClass.PLANNING_LOOP,
                RecoveryClass.MODEL_RECOVERABLE,
                "apply worker planned repeatedly without executing tools",
            )
        return (
            FailureClass.NO_CHANGE_UNJUSTIFIED,
            RecoveryClass.MODEL_RECOVERABLE,
            "apply task produced no workspace changes and no valid no-change justification",
        )

    return (
        FailureClass.COMPLETED,
        RecoveryClass.SUCCESS,
        "substantive output and required workspace evidence were produced",
    )


def is_recoverable(failure: FailureClass) -> bool:
    return failure in _RECOVERABLE


def is_fail_closed(failure: FailureClass) -> bool:
    return failure in _FAIL_CLOSED
