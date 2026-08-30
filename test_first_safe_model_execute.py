from __future__ import annotations

import inspect
import json
from types import SimpleNamespace

import first_safe_worker as worker
import operator_first_safe as first_safe


VALID_INTENT = "fsi_ABCDEFGHIJKLMNOP"


def test_execute_only_accepts_opaque_intent_id():
    assert list(inspect.signature(first_safe.hermes_first_safe_model_execute).parameters) == ["intent_id"]


def test_execute_rejects_injection_before_authority_lease_or_worker(monkeypatch):
    called = {"authority": False, "lease": False, "worker": False}

    def fail_authority(*, for_mutation):
        called["authority"] = True
        raise AssertionError("authority must not be reached")

    def fail_lease():
        called["lease"] = True
        raise AssertionError("lease must not be reached")

    def fail_worker(*, execute, intent_id):
        called["worker"] = True
        raise AssertionError("worker must not run")

    monkeypatch.setattr(first_safe, "_require_first_safe_authority", fail_authority)
    monkeypatch.setattr(first_safe, "_require_mission_control_lease", fail_lease)
    monkeypatch.setattr(worker, "claim_and_run", fail_worker)

    result = json.loads(first_safe.hermes_first_safe_model_execute("fsi_bad;rm -rf /"))
    assert result["success"] is False
    assert result["code"] == "FIRST_SAFE_EXECUTE_ERROR"
    assert called == {"authority": False, "lease": False, "worker": False}


def test_execute_orders_authority_then_live_lease_then_fixed_worker(monkeypatch):
    calls: list[object] = []

    def authority(*, for_mutation):
        calls.append(("authority", for_mutation))
        return SimpleNamespace(level="workspace", apply_mode="direct")

    def lease():
        calls.append("lease")
        return {"success": True, "has_lease": True, "owner": "chatgpt-mission-control"}

    def claim_and_run(*, execute, intent_id):
        calls.append(("worker", execute, intent_id))
        return {
            "success": True,
            "intent_id": intent_id,
            "evidence": {"changed": True, "selected_model": "cohere/north-mini-code:free"},
        }

    monkeypatch.setattr(first_safe, "_require_first_safe_authority", authority)
    monkeypatch.setattr(first_safe, "_require_mission_control_lease", lease)
    monkeypatch.setattr(worker, "claim_and_run", claim_and_run)
    monkeypatch.setattr(first_safe.op, "audit_record", lambda **kwargs: None)

    result = json.loads(first_safe.hermes_first_safe_model_execute(VALID_INTENT))
    assert result["success"] is True
    assert result["intent_id"] == VALID_INTENT
    assert result["state"] == first_safe.STATE_COMPLETED
    assert result["policy_template"] == first_safe.POLICY_TEMPLATE
    assert result["evidence"]["selected_model"] == "cohere/north-mini-code:free"
    assert calls == [
        ("authority", True),
        "lease",
        ("worker", True, VALID_INTENT),
    ]


def test_execute_surfaces_worker_failure_without_claiming_success(monkeypatch):
    monkeypatch.setattr(
        first_safe,
        "_require_first_safe_authority",
        lambda *, for_mutation: SimpleNamespace(level="workspace", apply_mode="direct"),
    )
    monkeypatch.setattr(
        first_safe,
        "_require_mission_control_lease",
        lambda: {"success": True, "has_lease": True, "owner": "chatgpt-mission-control"},
    )
    monkeypatch.setattr(
        worker,
        "claim_and_run",
        lambda *, execute, intent_id: {
            "success": False,
            "error": "AUTHORITY_REVALIDATION_FAILED",
            "detail": "intent binding no longer matches live authority",
            "intent_id": intent_id,
        },
    )

    result = json.loads(first_safe.hermes_first_safe_model_execute(VALID_INTENT))
    assert result["success"] is False
    assert result["code"] == "FIRST_SAFE_EXECUTE_ERROR"
    assert "AUTHORITY_REVALIDATION_FAILED" in result["error"]


def test_execute_source_exposes_no_operational_parameters():
    source = inspect.getsource(first_safe.hermes_first_safe_model_execute)
    for forbidden in (
        "host: str",
        "user: str",
        "command: str",
        "script: str",
        "model: str",
        "api_key: str",
        "path: str",
        "credential: str",
    ):
        assert forbidden not in source
    assert "claim_and_run(execute=True, intent_id=token)" in source
    assert "_require_mission_control_lease()" in source
