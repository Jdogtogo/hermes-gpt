"""Mission Control Authority Architecture v2 — Phase 2 Shadow Resolver & Phase 3 Pilot.

Trusted deterministic capability resolver that maps Authority Forecasts into
candidate Authority Envelopes without changing live authorization.

Phase 2: SHADOW MODE implementation - compares resolver output against current templates.
Phase 3: MINIMUM LIVE ACTIVATION SEAM - exact R1 pilot grant via capability composition.
"""

from .resolver import ShadowResolver, ShadowComparison, CapabilityAtom, RiskClass, run_shadow_comparison
from .fixtures import OpsBrainReconciliationFixture, AuthorityForecast, AuthorityEnvelope
from .capability_vocabulary import (
    CAPABILITY_FAMILIES,
    RISK_CLASS_MAPPING,
    HARD_DENIED_PATHS,
    STANDING_READ_ROOTS,
    compose_capability,
    decompose_template,
    classify_risk,
    check_hard_denies,
)
from .capability_composition import (
    CapabilityComposer,
    ResolvedAuthorityBundle,
    create_pilot_forecast,
    create_pilot_grant,
    get_pilot_policy_template_name,
)
from .pilot_template import (
    PILOT_TEMPLATE_NAME,
    PILOT_TEMPLATE,
    is_pilot_enabled,
    get_pilot_template,
)
from .pilot_mcp_tool import hermes_operator_phase3_r1_pilot_request

__all__ = [
    # Phase 2 Shadow Resolver
    "ShadowResolver",
    "ShadowComparison",
    "CapabilityAtom",
    "RiskClass",
    "OpsBrainReconciliationFixture",
    "AuthorityForecast",
    "AuthorityEnvelope",
    "run_shadow_comparison",
    "CAPABILITY_FAMILIES",
    "RISK_CLASS_MAPPING",
    "HARD_DENIED_PATHS",
    "STANDING_READ_ROOTS",
    "compose_capability",
    "decompose_template",
    "classify_risk",
    "check_hard_denies",
    # Phase 3 Pilot
    "CapabilityComposer",
    "ResolvedAuthorityBundle",
    "create_pilot_forecast",
    "create_pilot_grant",
    "get_pilot_policy_template_name",
    "PILOT_TEMPLATE_NAME",
    "PILOT_TEMPLATE",
    "is_pilot_enabled",
    "get_pilot_template",
    "hermes_operator_phase3_r1_pilot_request",
]