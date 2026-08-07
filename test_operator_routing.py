"""Routing, fallback-inheritance and bounded-recovery tests.

Covers the acceptance matrix for delegated runtime fallback inheritance:
materialisation, canonical provider order, free-only policy, provider
quarantine gates and behavioural recovery classification.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import operator_routing as routing


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _control(**overrides) -> routing.RoutingControl:
    """A permissive control surface where every lane is qualified.

    Used to test ordering and precedence independently of the shipped
    quarantine decisions, which are asserted separately.
    """
    providers = {
        "nvidia": routing.ProviderControl(
            lane="nvidia",
            eligible=True,
            quarantined=False,
            qualified_models=("nvidia/nemotron-3-ultra-550b-a55b",),
        ),
        "openrouter": routing.ProviderControl(
            lane="openrouter",
            eligible=True,
            quarantined=False,
            qualified_models=(
                "nvidia/nemotron-3-ultra-550b-a55b:free",
                "cohere/north-mini-code:free",
            ),
        ),
        "gemini": routing.ProviderControl(
            lane="gemini",
            eligible=True,
            quarantined=False,
            qualified_models=("gemini-3.5-flash-lite",),
        ),
        "nous": routing.ProviderControl(
            lane="nous",
            eligible=True,
            quarantined=False,
            qualified_models=("tencent/hy3:free",),
        ),
        "ollama": routing.ProviderControl(
            lane="ollama",
            eligible=True,
            quarantined=False,
            qualified_models=("qwen2.5:7b-instruct",),
        ),
    }
    defaults = {
        "free_only": True,
        "max_alternate_attempts": 1,
        "provider_order": routing.CANONICAL_PROVIDER_ORDER,
        # Off by default so each case exercises exactly the configured routes;
        # control-supplied routes have their own dedicated tests below.
        "include_qualified_routes": False,
        "providers": providers,
        "source_path": "test-control",
    }
    defaults.update(overrides)
    return routing.RoutingControl(**defaults)


def _write(root: Path, name: str, payload: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return root


def _resolve(tmp_path, *, profile_config, global_config=None, task_routing=None, control=None):
    profile_home = _write(tmp_path / "profile", "config.yaml", profile_config)
    hermes_root = _write(tmp_path / "hermes", "config.yaml", global_config or {})
    return routing.resolve_routing(
        hermes_root=hermes_root,
        profile="testing",
        profile_home=profile_home,
        task_routing=task_routing,
        control=control or _control(),
    )


NVIDIA = {"provider": "nvidia", "model": "nvidia/nemotron-3-ultra-550b-a55b"}
OR_NEMOTRON = {"provider": "openrouter", "model": "nvidia/nemotron-3-ultra-550b-a55b:free"}
OR_COHERE = {"provider": "openrouter", "model": "cohere/north-mini-code:free"}
GEMINI = {"provider": "gemini", "model": "gemini-3.5-flash-lite"}
NOUS = {"provider": "nous", "model": "tencent/hy3:free"}
OLLAMA = {"provider": "ollama", "model": "qwen2.5:7b-instruct"}


# ---------------------------------------------------------------------------
# Fallback materialisation
# ---------------------------------------------------------------------------


def test_no_fallback_configured_yields_empty_chain(tmp_path):
    resolved = _resolve(tmp_path, profile_config={"model": OR_NEMOTRON})
    assert resolved.primary.model == OR_NEMOTRON["model"]
    assert resolved.alternates == []
    assert resolved.runtime_fallback_providers() == []


def test_single_fallback_is_materialised(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON, "fallback_providers": [NVIDIA]},
    )
    assert [item.lane for item in resolved.alternates] == ["nvidia"]
    assert resolved.runtime_fallback_providers() == [
        {"provider": "nvidia", "model": "nvidia/nemotron-3-ultra-550b-a55b"}
    ]


def test_multiple_fallbacks_are_ordered_canonically(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={
            "model": OR_NEMOTRON,
            # Deliberately declared out of canonical order.
            "fallback_providers": [OLLAMA, GEMINI, NVIDIA],
        },
    )
    assert [item.lane for item in resolved.alternates] == ["nvidia", "gemini", "ollama"]


def test_profile_fallback_takes_precedence_over_global(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON, "fallback_providers": [NVIDIA]},
        global_config={"model": GEMINI, "fallback_providers": [OR_COHERE]},
    )
    # Both are collected, but the profile entry is seen first.
    assert resolved.primary.origin == "profile"
    origins = {item.lane: item.origin for item in resolved.alternates}
    assert origins["nvidia"] == "profile"
    assert origins["openrouter"] == "global"


def test_global_fallback_is_inherited_when_profile_declares_none(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON},
        global_config={"fallback_providers": [NVIDIA, OR_COHERE]},
    )
    assert [item.origin for item in resolved.alternates] == ["global", "global"]
    assert [item.lane for item in resolved.alternates] == ["nvidia", "openrouter"]


def test_task_routing_outranks_profile_and_global_for_the_primary(tmp_path):
    """Precedence picks the primary; canonical order ranks the alternates.

    Task > profile > global decides *which* routes are in play. Once eligible,
    alternates are ranked by the canonical provider order, not by which
    configuration level contributed them.
    """
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON, "fallback_providers": [OR_COHERE]},
        global_config={"model": GEMINI, "fallback_providers": [OLLAMA]},
        task_routing={"model": NVIDIA, "fallback_providers": [GEMINI]},
    )
    assert resolved.primary.origin == "task"
    assert resolved.primary.lane == "nvidia"
    # All three levels contribute alternates.
    assert {item.origin for item in resolved.alternates} == {"task", "profile", "global"}
    # Ranking is canonical: OpenRouter, then Gemini, then Ollama.
    assert [item.lane for item in resolved.alternates] == ["openrouter", "gemini", "ollama"]


def test_duplicate_primary_is_removed_from_the_fallback_chain(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON, "fallback_providers": [OR_NEMOTRON, NVIDIA]},
    )
    assert [item.lane for item in resolved.alternates] == ["nvidia"]
    reasons = [item.reason for item in resolved.excluded]
    assert any("duplicate of the primary route" in reason for reason in reasons)


def test_same_model_alias_is_not_diversification(tmp_path):
    """``model`` and ``model:free`` are one underlying route, not two."""
    resolved = _resolve(
        tmp_path,
        profile_config={
            "model": OR_NEMOTRON,
            "fallback_providers": [
                {"provider": "openrouter", "model": "nvidia/nemotron-3-ultra-550b-a55b"},
            ],
        },
    )
    assert resolved.alternates == []
    assert any("not diversification" in item.reason for item in resolved.excluded)


def test_malformed_fallback_entries_are_rejected(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={
            "model": OR_NEMOTRON,
            "fallback_providers": [
                "not-a-mapping",
                {"provider": "nvidia"},          # missing model
                {"model": "orphaned"},           # missing provider
                {"provider": "", "model": ""},   # empty
                NVIDIA,
            ],
        },
    )
    assert [item.lane for item in resolved.alternates] == ["nvidia"]


def test_bracketed_config_keys_are_ignored(tmp_path):
    """Historic writers left ``fallback_providers[0]`` scalar keys behind."""
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON},
        global_config={
            "fallback_providers": [NVIDIA],
            "fallback_providers[0]": {"provider": "ollama", "model": "ghost"},
            "fallback_providers[1]": {"provider": "nous", "model": "ghost"},
        },
    )
    assert [item.lane for item in resolved.alternates] == ["nvidia"]


def test_missing_primary_raises(tmp_path):
    with pytest.raises(routing.RoutingError):
        _resolve(tmp_path, profile_config={"agent": {}})


# ---------------------------------------------------------------------------
# Routing order and policy
# ---------------------------------------------------------------------------


def test_canonical_provider_order_is_the_accepted_policy():
    assert routing.CANONICAL_PROVIDER_ORDER == (
        "nvidia",
        "openrouter",
        "gemini",
        "nous",
        "ollama",
    )


@pytest.mark.parametrize(
    "earlier,later",
    [
        (NVIDIA, OR_COHERE),   # NVIDIA precedes OpenRouter
        (OR_COHERE, GEMINI),   # OpenRouter precedes Gemini
        (GEMINI, NOUS),        # Gemini precedes Nous
        (NOUS, OLLAMA),        # Nous precedes qualified Ollama
    ],
)
def test_canonical_priority_pairs(tmp_path, earlier, later):
    resolved = _resolve(
        tmp_path,
        profile_config={
            "model": {"provider": "openrouter", "model": "some/other-primary:free"},
            # Declared worst-first to prove file order does not decide priority.
            "fallback_providers": [later, earlier],
        },
        control=_control(
            providers={
                **_control().providers,
                "openrouter": routing.ProviderControl(
                    lane="openrouter",
                    eligible=True,
                    quarantined=False,
                    qualified_models=(
                        "some/other-primary:free",
                        "cohere/north-mini-code:free",
                    ),
                ),
            }
        ),
    )
    lanes = [item.lane for item in resolved.alternates]
    assert lanes.index(routing.normalise_provider(earlier["provider"])) < lanes.index(
        routing.normalise_provider(later["provider"])
    )


def test_paid_route_is_always_rejected(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={
            "model": OR_NEMOTRON,
            "fallback_providers": [
                {**NVIDIA, "paid": True},
                {"provider": "gemini", "model": "gemini-3.5-flash-lite", "input_per_million": 1.5},
            ],
        },
    )
    assert resolved.alternates == []
    assert all("paid route rejected" in item.reason for item in resolved.excluded)


def test_paid_planner_glm52_openrouter_route_is_rejected(tmp_path):
    """The real planner profile model must never pass the free-only gate."""
    with pytest.raises(routing.RoutingError) as exc:
        _resolve(
            tmp_path,
            profile_config={"model": {"provider": "openrouter", "model": "z-ai/glm-5.2"}},
            control=_control(require_qualified_primary=True),
        )
    assert "not explicitly proven free" in str(exc.value)


def test_unprobed_route_is_rejected(tmp_path):
    """A model with no current qualification record cannot be an alternate."""
    resolved = _resolve(
        tmp_path,
        profile_config={
            "model": OR_NEMOTRON,
            "fallback_providers": [{"provider": "nvidia", "model": "nvidia/never-probed"}],
        },
    )
    assert resolved.alternates == []
    assert any("no current Hermes-Agent qualification" in i.reason for i in resolved.excluded)


def test_lane_outside_canonical_order_is_rejected(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={
            "model": OR_NEMOTRON,
            "fallback_providers": [{"provider": "some-unknown-vendor", "model": "x"}],
        },
    )
    assert resolved.alternates == []
    assert any("outside the canonical provider order" in i.reason for i in resolved.excluded)


# --- shipped control surface gates -----------------------------------------


def _shipped() -> routing.RoutingControl:
    return routing.load_routing_control(routing.DEFAULT_ROUTING_CONTROL_PATH)


def test_shipped_control_qualifies_fresh_ollama_qwen():
    control = _shipped().control_for("ollama")
    assert control.eligible is True
    assert control.quarantined is False
    assert control.qualified_models == ("qwen2.5:7b-instruct",)
    assert "fresh host qualification" in control.reason.lower()


def test_shipped_control_qualifies_free_tencent_hy3_on_nous():
    control = _shipped().control_for("nous")
    assert control.eligible is True
    assert control.quarantined is False
    assert control.qualified_models == ("tencent/hy3:free",)
    assert "task-local auth staging" in control.reason.lower()
    assert "tencent/hy3:free" in control.reason.lower()


def test_shipped_control_preserves_nous_and_ollama_as_discovered_records():
    """Quarantine must not erase the provider records from configuration."""
    raw = json.loads(routing.DEFAULT_ROUTING_CONTROL_PATH.read_text(encoding="utf-8"))
    for lane in ("nous", "ollama"):
        assert lane in raw["providers"]
        assert raw["providers"][lane]["discovered_models"]


def test_shipped_control_is_free_only_and_bounded():
    control = _shipped()
    assert control.free_only is True
    assert control.max_alternate_attempts == 3
    assert control.max_alternate_attempts <= routing.MAX_ALTERNATE_ATTEMPTS_CEILING
    assert control.provider_order == routing.CANONICAL_PROVIDER_ORDER


def test_shipped_control_includes_qualified_agent_routes_but_excludes_direct_only_ollama(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON, "fallback_providers": [OLLAMA, NOUS, NVIDIA]},
        control=_shipped(),
    )
    lanes = [item.lane for item in resolved.alternates]
    assert lanes[0] == "nvidia"
    assert "ollama" not in lanes
    assert "nous" in lanes
    ollama = _shipped().control_for("ollama")
    assert ollama.direct_inference_models == ("qwen2.5:7b-instruct",)
    assert ollama.agent_qualification_explicit is True
    assert ollama.agent_qualified_models == ()


def test_unqualified_ollama_model_is_not_added_as_automatic_route(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={
            "model": OR_NEMOTRON,
            "fallback_providers": [{"provider": "ollama", "model": "llama3.1:8b"}],
        },
        control=_shipped(),
    )
    assert all(
        not (item.lane == "ollama" and item.model == "llama3.1:8b")
        for item in resolved.alternates
    )


def test_missing_control_surface_fails_closed(tmp_path):
    control = routing.load_routing_control(tmp_path / "absent.json")
    assert control.providers == {}
    assert control.control_for("openrouter").eligible is False


def test_malformed_control_surface_fails_closed(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    assert routing.load_routing_control(path).providers == {}


def test_alternate_attempt_limit_is_clamped(tmp_path):
    path = tmp_path / "control.json"
    path.write_text(json.dumps({"max_alternate_attempts": 99}), encoding="utf-8")
    assert (
        routing.load_routing_control(path).max_alternate_attempts
        == routing.MAX_ALTERNATE_ATTEMPTS_CEILING
    )


# ---------------------------------------------------------------------------
# Bounded alternate selection
# ---------------------------------------------------------------------------


def test_alternate_selection_stops_at_the_configured_limit(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON, "fallback_providers": [NVIDIA, GEMINI]},
    )
    first = routing.select_alternate(resolved, attempts_used=0)
    assert first is not None and first.lane == "nvidia"
    # One alternate is the default budget: recovery does not walk the list.
    assert routing.select_alternate(resolved, failed_routes=[first], attempts_used=1) is None


def test_alternate_selection_skips_already_failed_routes(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON, "fallback_providers": [NVIDIA, GEMINI]},
        control=_control(max_alternate_attempts=2),
    )
    first = routing.select_alternate(resolved, attempts_used=0)
    second = routing.select_alternate(resolved, failed_routes=[first], attempts_used=1)
    assert first.lane == "nvidia"
    assert second.lane == "gemini"


def test_retry_exhaustion_returns_none(tmp_path):
    resolved = _resolve(tmp_path, profile_config={"model": OR_NEMOTRON})
    assert routing.select_alternate(resolved, attempts_used=0) is None


def test_alternate_prefers_a_different_provider_over_a_same_lane_model(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={
            "model": OR_NEMOTRON,
            # OpenRouter is the failing lane; a second OpenRouter model is not
            # genuine diversification while another provider remains eligible.
            "fallback_providers": [OR_COHERE, GEMINI],
        },
    )
    alternate = routing.select_alternate(resolved, attempts_used=0)
    assert alternate.lane == "gemini"


# --- control-surface supplied alternates ------------------------------------


def test_control_surface_supplies_a_cross_provider_alternate(tmp_path):
    """A single-provider fallback list must still reach another provider."""
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON, "fallback_providers": [OR_COHERE]},
        control=_shipped(),
    )
    alternate = routing.select_alternate(resolved, attempts_used=0)
    assert alternate is not None
    assert alternate.lane == "nvidia"
    assert alternate.origin == "control"
    assert alternate.lane != resolved.primary.lane


def test_control_supplied_routes_include_only_qualified_lanes(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON},
        control=_shipped(),
    )
    lanes = {item.lane for item in resolved.alternates}
    assert "ollama" not in lanes
    assert "nous" in lanes
    assert lanes <= {"nvidia", "openrouter", "gemini", "nous"}


def test_control_supplied_routes_are_canonically_ordered(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": {"provider": "openrouter", "model": "some/primary:free"}},
        control=_shipped(),
    )
    lanes = [item.lane for item in resolved.alternates]
    assert resolved.primary.lane == "nvidia"
    assert lanes == sorted(lanes, key=routing.CANONICAL_PROVIDER_ORDER.index)
    assert "ollama" not in lanes


def test_control_supplied_routes_never_duplicate_the_primary(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": NVIDIA},
        control=_shipped(),
    )
    assert all(item.key != resolved.primary.key for item in resolved.alternates)
    # The failing NVIDIA lane must not be offered as its own alternate.
    alternate = routing.select_alternate(resolved, attempts_used=0)
    assert alternate.lane != "nvidia"


def test_include_qualified_routes_can_be_disabled(tmp_path):
    resolved = _resolve(
        tmp_path,
        profile_config={"model": OR_NEMOTRON},
        control=_control(include_qualified_routes=False),
    )
    assert resolved.alternates == []


def test_attempt_identity_is_unique_and_records_ancestry():
    route = routing.RouteCandidate(provider="nvidia", model="nvidia/x")
    first = routing.new_attempt_identity(
        logical_work_id="lw_1", route=route, attempt_number=2, predecessor_attempt_id="da_prev"
    )
    second = routing.new_attempt_identity(
        logical_work_id="lw_1", route=route, attempt_number=2, predecessor_attempt_id="da_prev"
    )
    assert first["attempt_id"] != second["attempt_id"]
    assert first["attempt_id"].startswith("da_")
    assert first["predecessor_attempt_id"] == "da_prev"
    assert first["logical_work_id"] == "lw_1"
    assert first["provider_lane"] == "nvidia"


# ---------------------------------------------------------------------------
# Behavioural recovery classification
# ---------------------------------------------------------------------------


def _classify(**overrides):
    payload = {
        "status": "running",
        "rc": 0,
        "stdout": "",
        "stderr": "",
        "mode": "apply",
        "changed_files": [],
        "final_answer": None,
        "final_answer_reason": "",
        "tool_progress": None,
    }
    payload.update(overrides)
    return routing.classify_outcome(**payload)


def test_empty_response_is_bounded_recoverable():
    failure, recovery, _ = _classify(stdout="No reply: the model returned empty content")
    assert failure is routing.FailureClass.EMPTY_RESPONSE
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE
    assert routing.is_recoverable(failure)


def test_no_output_at_all_is_bounded_recoverable():
    failure, recovery, _ = _classify(stdout="", stderr="")
    assert failure is routing.FailureClass.EMPTY_RESPONSE
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE


def test_reasoning_only_response_is_bounded_recoverable():
    failure, recovery, reason = _classify(
        stdout="Thinking about the problem in detail.\nMore reasoning.",
        final_answer=None,
        final_answer_reason="unstructured_ambiguous",
    )
    assert failure is routing.FailureClass.REASONING_ONLY
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE
    assert "no usable final answer" in reason


def test_rate_limit_is_bounded_recoverable():
    failure, recovery, _ = _classify(stderr="HTTP 429 quota exceeded for free tier")
    assert failure is routing.FailureClass.RATE_LIMIT
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE


def test_budget_exhaustion_is_bounded_recoverable_before_generic_403_permission_handling():
    failure, recovery, _ = _classify(stderr="HTTP 403: monthly budget limit exceeded")
    assert failure is routing.FailureClass.PROVIDER_BUDGET_EXHAUSTED
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE


def test_agent_context_capability_mismatch_is_bounded_recoverable():
    failure, recovery, _ = _classify(
        stderr="model context window 32768 is smaller than minimum required 64000"
    )
    assert failure is routing.FailureClass.PROVIDER_CAPABILITY_MISMATCH
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE


def test_provider_unavailable_is_bounded_recoverable():
    failure, recovery, _ = _classify(stderr="503 service unavailable")
    assert failure is routing.FailureClass.PROVIDER_UNAVAILABLE
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE


def test_transient_upstream_failure_is_bounded_recoverable():
    failure, recovery, _ = _classify(stderr="502 bad gateway")
    assert failure is routing.FailureClass.TRANSIENT_PROVIDER_FAILURE
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE


def test_permission_failure_does_not_trigger_model_fallback():
    failure, recovery, _ = _classify(status="blocked", stdout="permission denied")
    assert failure is routing.FailureClass.PERMISSION_FAILURE
    assert recovery is routing.RecoveryClass.FAIL_CLOSED
    assert not routing.is_recoverable(failure)


def test_tool_policy_failure_does_not_trigger_model_fallback():
    failure, recovery, _ = _classify(stdout="tool is not available in this toolset")
    assert failure is routing.FailureClass.TOOL_POLICY_FAILURE
    assert recovery is routing.RecoveryClass.FAIL_CLOSED


def test_missing_credentials_fail_closed():
    failure, recovery, _ = _classify(
        stderr="provider resolver returned an empty api key"
    )
    assert failure is routing.FailureClass.PROVIDER_CONFIGURATION
    assert recovery is routing.RecoveryClass.FAIL_CLOSED


def test_deadline_exhaustion_escalates_rather_than_refetching_a_model():
    failure, recovery, _ = _classify(rc=124, stdout="partial work")
    assert failure is routing.FailureClass.DEADLINE_EXHAUSTED
    assert recovery is routing.RecoveryClass.OPERATOR_ESCALATION
    assert not routing.is_recoverable(failure)


def test_apply_no_change_without_justification_is_recoverable():
    failure, recovery, _ = _classify(
        stdout="Reviewed everything.", final_answer="Reviewed everything.", changed_files=[]
    )
    assert failure is routing.FailureClass.NO_CHANGE_UNJUSTIFIED
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE


def test_apply_no_change_with_explicit_justification_is_accepted():
    answer = (
        "The target already contains the requested value.\n"
        f"{routing.NO_CHANGE_JUSTIFICATION_PREFIX} config.yaml line 12 already reads "
        "'enabled: true'; no edit is required."
    )
    failure, recovery, _ = _classify(stdout=answer, final_answer=answer, changed_files=[])
    assert failure is routing.FailureClass.NO_CHANGE_JUSTIFIED
    assert recovery is routing.RecoveryClass.SUCCESS


def test_planning_loop_is_detected_separately_from_a_plain_no_op():
    answer = "I will now inspect the repository and then I plan to update the file."
    failure, recovery, _ = _classify(
        stdout=answer, final_answer=answer, changed_files=[], tool_progress=False
    )
    assert failure is routing.FailureClass.PLANNING_LOOP
    assert recovery is routing.RecoveryClass.MODEL_RECOVERABLE


def test_substantive_apply_result_completes():
    failure, recovery, _ = _classify(
        stdout="Updated the record.",
        final_answer="Updated the record.",
        changed_files=["project.md"],
    )
    assert failure is routing.FailureClass.COMPLETED
    assert recovery is routing.RecoveryClass.SUCCESS


def test_read_only_mode_does_not_require_changed_files():
    failure, recovery, _ = _classify(
        mode="read_only", stdout="The answer is 4.", final_answer="The answer is 4."
    )
    assert failure is routing.FailureClass.COMPLETED
    assert recovery is routing.RecoveryClass.SUCCESS


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("NVIDIA", "nvidia"),
        ("nvidia_direct", "nvidia"),
        ("google", "gemini"),
        ("gemini_direct", "gemini"),
        ("nousresearch", "nous"),
        ("local", "ollama"),
    ],
)
def test_provider_alias_normalisation(raw, expected):
    assert routing.normalise_provider(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("nvidia/X:free", "nvidia/x"),
        ("nvidia/x", "nvidia/x"),
        (" Cohere/North:nitro ", "cohere/north"),
    ],
)
def test_model_alias_normalisation(raw, expected):
    assert routing.normalise_model(raw) == expected
