"""Tests for the immutable FIRST_SAFE acceptance specification module."""

from __future__ import annotations

import inspect
import json

import pytest

import operator_hermes_exec_model as spec


def _payload(model: str | None = None, reason: str = "single_model_catalog_zero_price") -> dict:
    selected = model or spec.APPROVED_MODEL
    calls = [
        {
            "call": number,
            "ok": True,
            "model": selected,
            "provider": spec.APPROVED_PROVIDER,
            "estimated_cost_usd": 0.0,
            "actual_cost_usd": 0.0,
            "cost_status": ["known"],
            "api_call_count": 1,
            "cooldown_rotation_events": 0,
        }
        for number in (1, 2)
    ]
    return {
        "success": True,
        "changed": True,
        "profile": spec.REMOTE_PROFILE,
        "previous_default": "",
        "resulting_default": selected,
        "selected_model": selected,
        "selection_reason": reason,
        "provider": spec.APPROVED_PROVIDER,
        "base_url": spec.OPENROUTER_BASE_URL,
        "catalog_price": {"prompt": 0.0, "completion": 0.0},
        "guard": {"kind": spec.GUARD_KIND, "all_passed": True, "checks": {name: True for name in spec.REQUIRED_GUARD_CHECKS}},
        "calls": calls,
        "total_acceptance_calls": 2,
        "total_estimated_cost_usd": 0.0,
        "total_actual_cost_usd": 0.0,
        "cooldown_rotation_events": 0,
        "changed_key": "model.default",
        "broader_routing_changed": False,
        "git_status_unchanged": True,
        "sibling_profiles_unchanged": True,
        "root_provider_state_absent_before_after": True,
        "shared_nous_state_absent_before_after": True,
        "api_key_auth_only": True,
        "oauth_used": False,
        "ambient_provider_env_inherited": False,
    }


# --- no executor lives here anymore -----------------------------------------

def test_specification_module_exposes_no_executor():
    assert not hasattr(spec, "hermes_exec_first_safe_model")
    assert not hasattr(spec, "_run_fixed_remote")
    assert not hasattr(spec, "_ssh_argv")
    source = inspect.getsource(spec)
    # subprocess appears only inside the quoted REMOTE_PROGRAM; the host module
    # itself deliberately exposes no transport or executor primitive.
    assert not hasattr(spec, "subprocess")
    for forbidden in ("SSH_BINARY", "SSH_KEY", "SSH_TARGET", "REMOTE_PYTHON"):
        assert not hasattr(spec, forbidden), forbidden


def test_fixed_plan_is_entirely_constant_and_fail_closed():
    first = spec.fixed_plan()
    assert first == spec.fixed_plan()
    assert first["host"] == "hermes-exec"
    assert first["remote_runtime_user"] == "jfroh"
    assert first["linux_home"] == "/home/jfroh"
    assert first["hermes_root"] == "/home/jfroh/.hermes"
    assert first["profile"] == "first-safe"
    assert first["profile_home"] == "/home/jfroh/.hermes/profiles/first-safe"
    assert first["config"] == "/home/jfroh/.hermes/profiles/first-safe/config.yaml"
    assert first["change_only"] == "model.default"
    assert first["provider"] == "openrouter"
    assert first["approved_model"] == "cohere/north-mini-code:free"
    assert first["model_fallbacks"] == []
    assert first["base_url"] == "https://openrouter.ai/api/v1"
    assert first["api_key_auth_only"] is True
    assert first["oauth_allowed"] is False
    assert first["root_provider_state_required_absent"] is True
    assert first["shared_nous_state_required_absent"] is True
    assert first["ambient_provider_env_inherited"] is False
    assert first["acceptance_calls"] == 2
    assert first["guard_kind"] == spec.GUARD_KIND
    assert first["guard_required_checks"] == list(spec.REQUIRED_GUARD_CHECKS)
    assert first["required_cost_usd_each"] == 0.0
    assert first["required_cooldown_rotation_events"] == 0
    assert first["shell"] is False
    assert first["arbitrary_remote_command_surface"] is False


def test_remote_program_contains_no_legacy_target_or_fallback_route():
    program = spec.REMOTE_PROGRAM
    assert 'LINUX_HOME=Path("/home/jfroh")' in program
    assert 'ROOT=LINUX_HOME/".hermes"' in program
    assert 'PROFILE_NAME="first-safe"' in program
    assert 'PROFILE_HOME=ROOT/"profiles"/PROFILE_NAME' in program
    assert 'cohere/north-mini-code:free' in program
    assert 'sanitized_env' in program
    assert 'pwd.getpwuid(os.geteuid())' in program
    assert 'identity.pw_name!="jfroh"' in program
    assert 'ROOT_AUTH' in program and 'ROOT_SHARED_NOUS' in program
    assert 'sibling_snapshot' in program
    assert 'OPENROUTER_API_KEY' in program
    assert '/home/hermes' not in program
    assert 'sudo -n -u hermes' not in program
    assert 'nvidia/nemotron' not in program
    assert 'z-ai/glm-5.2' not in program


def test_remote_program_purges_ambient_credentials_and_binds_profile(monkeypatch):
    import os

    monkeypatch.setenv("OPENROUTER_API_KEY", "ambient-must-not-survive")
    monkeypatch.setenv("NVIDIA_API_KEY", "ambient-must-not-survive")
    namespace = {"__name__": "first_safe_non_live_test"}
    exec(compile(spec.REMOTE_PROGRAM, "<first-safe-remote>", "exec"), namespace, namespace)

    assert "OPENROUTER_API_KEY" not in os.environ
    assert "NVIDIA_API_KEY" not in os.environ
    assert os.environ["HOME"] == "/home/jfroh"
    assert os.environ["HERMES_HOME"] == "/home/jfroh/.hermes/profiles/first-safe"
    assert os.environ["HERMES_SHARED_AUTH_DIR"] == "/home/jfroh/.hermes/profiles/first-safe/shared"
    child_env = namespace["sanitized_env"]()
    assert "OPENROUTER_API_KEY" not in child_env
    assert "NVIDIA_API_KEY" not in child_env
    assert child_env["HERMES_HOME"] == "/home/jfroh/.hermes/profiles/first-safe"


def test_remote_program_sparse_config_rewrite_changes_only_model_default():
    namespace = {"__name__": "first_safe_non_live_test"}
    exec(compile(spec.REMOTE_PROGRAM, "<first-safe-remote>", "exec"), namespace, namespace)
    before = (
        "model:\n"
        "  provider: openrouter\n"
        "  default: \"\"\n"
        "  base_url: https://openrouter.ai/api/v1\n"
        "fallback_providers: []\n"
        "providers: {}\n"
        "credential_pool_strategies: {}\n"
    )
    previous, after = namespace["replace_default"](before, spec.APPROVED_MODEL)
    assert previous == ""
    assert after.replace("  default: cohere/north-mini-code:free\n", "  default: \"\"\n") == before
    namespace["validate_static_profile_config"](after)


def test_embedded_runtime_guard_is_self_contained_and_named():
    namespace = {"__name__": "first_safe_non_live_test"}
    exec(compile(spec.REMOTE_PROGRAM, "<first-safe-remote>", "exec"), namespace, namespace)
    config = (
        "model:\n"
        "  provider: openrouter\n"
        "  default: \n"
        "  base_url: https://openrouter.ai/api/v1\n"
        "fallback_providers: []\n"
        "providers: {}\n"
        "credential_pool_strategies: {}\n"
    )
    guard = namespace["run_guard"](
        spec.APPROVED_MODEL,
        {"prompt": 0.0, "completion": 0.0},
        config,
    )
    assert guard == {
        "kind": spec.GUARD_KIND,
        "all_passed": True,
        "checks": {name: True for name in spec.REQUIRED_GUARD_CHECKS},
    }
    assert "test_openrouter_free_only_guard.py" not in spec.REMOTE_PROGRAM
    assert '"-m","pytest"' not in spec.REMOTE_PROGRAM

    with pytest.raises(SystemExit):
        namespace["run_guard"](
            spec.APPROVED_MODEL,
            {"prompt": 0.01, "completion": 0.0},
            config,
        )


def test_profile_auth_metadata_accepts_env_reference_and_rejects_oauth_or_persisted_secret(tmp_path):
    namespace = {"__name__": "first_safe_non_live_test"}
    exec(compile(spec.REMOTE_PROGRAM, "<first-safe-remote>", "exec"), namespace, namespace)
    auth = tmp_path / "auth.json"
    label = "OPENROUTER_" + "API_KEY"
    source = "env:" + label

    def write_entry(entry):
        auth.write_text(json.dumps({
            "version": 1,
            "providers": {},
            "credential_pool": {"openrouter": [entry]},
        }), encoding="utf-8")
        auth.chmod(0o600)

    entry = {
        "id": "env-openrouter",
        "label": label,
        "auth_type": "api_key",
        "priority": 0,
        "source": source,
        "secret_fingerprint": "sha256:" + ("a" * 16),
        "request_count": 1,
    }
    write_entry(entry)
    result = namespace["validate_profile_auth_metadata"](auth)
    assert result["present"] is True
    assert result["entry_count"] == 1
    assert result["oauth_present"] is False
    assert result["secret_persisted"] is False

    bad_oauth = dict(entry); bad_oauth["auth_type"] = "oauth"
    write_entry(bad_oauth)
    with pytest.raises(SystemExit):
        namespace["validate_profile_auth_metadata"](auth)

    bad_secret = dict(entry); bad_secret["access_" + "token"] = "sk" + "-or-test-value"
    write_entry(bad_secret)
    with pytest.raises(SystemExit):
        namespace["validate_profile_auth_metadata"](auth)


def test_spec_hash_is_stable_and_covers_the_program_text(monkeypatch):
    baseline = spec.spec_hash()
    assert baseline == spec.spec_hash()
    monkeypatch.setattr(spec, "REMOTE_PROGRAM", spec.REMOTE_PROGRAM + "\n# tampered\n")
    assert spec.spec_hash() != baseline


def test_spec_hash_changes_if_the_approved_model_changes(monkeypatch):
    baseline = spec.spec_hash()
    monkeypatch.setattr(spec, "APPROVED_MODEL", "some/other-model:free")
    assert spec.spec_hash() != baseline


# --- acceptance invariants --------------------------------------------------

def test_valid_payload_passes():
    spec.validate_acceptance_payload(_payload())


@pytest.mark.parametrize(
    "field,value",
    [
        ("success", False),
        ("profile", "maintenance"),
        ("provider", "nvidia"),
        ("base_url", "https://example.invalid"),
        ("total_acceptance_calls", 1),
        ("total_acceptance_calls", 3),
        ("total_estimated_cost_usd", 0.01),
        ("total_actual_cost_usd", 0.01),
        ("cooldown_rotation_events", 1),
        ("selected_model", "anthropic/claude-opus-4.6"),
        ("resulting_default", "anthropic/claude-opus-4.6"),
        ("selection_reason", "fallback_selected"),
        ("changed_key", "model.provider"),
        ("broader_routing_changed", True),
        ("git_status_unchanged", False),
        ("sibling_profiles_unchanged", False),
        ("root_provider_state_absent_before_after", False),
        ("shared_nous_state_absent_before_after", False),
        ("api_key_auth_only", False),
        ("oauth_used", True),
        ("ambient_provider_env_inherited", True),
    ],
)
def test_invariant_violations_are_rejected(field, value):
    payload = _payload()
    payload[field] = value
    with pytest.raises(RuntimeError):
        spec.validate_acceptance_payload(payload)


def test_runtime_guard_requires_exact_named_check_set_all_true():
    payload = _payload()
    payload["guard"]["checks"]["catalog_prompt_zero"] = False
    with pytest.raises(RuntimeError, match="runtime free-only guard"):
        spec.validate_acceptance_payload(payload)

    payload = _payload()
    payload["guard"]["checks"]["unexpected_check"] = True
    with pytest.raises(RuntimeError, match="check-set drift"):
        spec.validate_acceptance_payload(payload)

    payload = _payload()
    payload["guard"]["kind"] = "wrong-guard"
    with pytest.raises(RuntimeError, match="runtime free-only guard"):
        spec.validate_acceptance_payload(payload)


def test_per_call_route_cost_and_count_are_enforced():
    cases = []
    p = _payload(); p["calls"][0]["api_call_count"] = 2; cases.append(p)
    p = _payload(); p["calls"][0]["provider"] = "nvidia"; cases.append(p)
    p = _payload(); p["calls"][0]["model"] = "other/model:free"; cases.append(p)
    p = _payload(); p["calls"][0]["actual_cost_usd"] = 0.01; cases.append(p)
    p = _payload(); p["calls"] = p["calls"][:1]; cases.append(p)
    for payload in cases:
        with pytest.raises(RuntimeError):
            spec.validate_acceptance_payload(payload)


# --- evidence projection ----------------------------------------------------

def test_bounded_evidence_drops_anything_not_allow_listed():
    payload = _payload()
    payload["raw_stdout"] = "debug1: Offering public key /home/jfroh/.ssh/id_rsa"
    payload["OPENROUTER_API_KEY"] = "sk-or-v1-should-never-appear"
    payload["stderr"] = "transport failure"
    evidence = spec.bounded_evidence(payload)

    assert "raw_stdout" not in evidence
    assert "OPENROUTER_API_KEY" not in evidence
    assert "stderr" not in evidence
    assert set(evidence) <= set(spec.EVIDENCE_KEYS) | {"host", "config"}
    serialized = json.dumps(evidence)
    assert "sk-or-v1" not in serialized
    assert "id_rsa" not in serialized

    assert evidence["selected_model"] == spec.APPROVED_MODEL
    assert evidence["profile"] == spec.REMOTE_PROFILE
    assert evidence["provider"] == spec.APPROVED_PROVIDER
    assert evidence["guard"]["kind"] == spec.GUARD_KIND
    assert evidence["guard"]["all_passed"] is True
    assert evidence["guard"]["checks"] == {name: True for name in spec.REQUIRED_GUARD_CHECKS}
    assert evidence["total_acceptance_calls"] == 2
    assert evidence["total_estimated_cost_usd"] == 0.0
    assert evidence["total_actual_cost_usd"] == 0.0
    assert evidence["cooldown_rotation_events"] == 0
    assert evidence["changed_key"] == "model.default"
    assert evidence["broader_routing_changed"] is False
    assert evidence["git_status_unchanged"] is True
    assert evidence["sibling_profiles_unchanged"] is True
    assert evidence["root_provider_state_absent_before_after"] is True
    assert evidence["shared_nous_state_absent_before_after"] is True
    assert evidence["api_key_auth_only"] is True
    assert evidence["oauth_used"] is False
    assert evidence["ambient_provider_env_inherited"] is False
    assert len(evidence["calls"]) == 2
    for entry in evidence["calls"]:
        assert entry["estimated_cost_usd"] == 0.0
        assert entry["actual_cost_usd"] == 0.0
        assert entry["api_call_count"] == 1
        assert entry["cost_status"] == ["known"]


def test_extract_result_requires_exactly_one_structured_line():
    line = "HERMES_EXEC_FIRST_SAFE_MODEL_JSON=" + json.dumps(_payload())
    assert spec.extract_result("noise\n" + line + "\nmore noise")["success"] is True
    with pytest.raises(RuntimeError, match="exactly one structured result"):
        spec.extract_result("no structured output here")
    with pytest.raises(RuntimeError, match="exactly one structured result"):
        spec.extract_result(line + "\n" + line)
    with pytest.raises(RuntimeError, match="invalid structured JSON"):
        spec.extract_result("HERMES_EXEC_FIRST_SAFE_MODEL_JSON={not json")
