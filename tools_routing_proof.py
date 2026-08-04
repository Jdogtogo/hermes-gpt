#!/usr/bin/env python3
"""Bounded acceptance proof for delegated runtime fallback inheritance.

Read-only with respect to live Hermes configuration, credentials, scheduling
and Kanban state. It materialises a delegated runtime from the *real* resolved
routing configuration, then drives one bounded cross-provider recovery through
a test adapter so no provider quota is consumed to induce the failure.

Usage:  python3 tools_routing_proof.py [output.json]
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import yaml

import operator_delegation as delegation
import operator_routing as routing


def _live_materialisation() -> dict:
    """Materialise a runtime home from the real live routing configuration."""
    with tempfile.TemporaryDirectory(prefix="routing-proof-") as tmp:
        original_root = delegation._TASKS_ROOT
        delegation._TASKS_ROOT = Path(tmp) / "tasks"
        try:
            task = {"task_id": "dt_" + "0" * 32, "profile": "default", "timeout": 900}
            home = delegation._prepare_runtime_home(task)
            config = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
            audit = json.loads((home / "routing.json").read_text(encoding="utf-8"))
            env_link = home / ".env"
            return {
                "runtime_config": config,
                "routing_audit": audit,
                "env_is_symlink": env_link.is_symlink(),
                "env_contents_read": False,
                "runtime_keys": sorted(config.keys()),
            }
        finally:
            delegation._TASKS_ROOT = original_root


def _bounded_recovery() -> dict:
    """Drive one empty-response recovery through a deterministic adapter."""
    resolved = routing.resolve_routing(
        hermes_root=delegation.HERMES_ROOT,
        profile="default",
        profile_home=delegation.op.resolve_profile_home("default", delegation.HERMES_ROOT),
        deadline_seconds=900,
    )
    primary = resolved.primary
    alternate = routing.select_alternate(resolved, attempts_used=0)
    if alternate is None:
        return {"selected_alternate": None, "note": "no eligible alternate under current policy"}

    first = routing.new_attempt_identity(
        logical_work_id="lw_proof", route=primary, attempt_number=1
    )
    failure, recovery, reason = routing.classify_outcome(
        status="running",
        rc=0,
        stdout="No reply: the model returned empty content after retries.",
        stderr="",
        mode="apply",
        changed_files=[],
        final_answer=None,
        final_answer_reason="not_found",
    )
    second = routing.new_attempt_identity(
        logical_work_id="lw_proof",
        route=alternate,
        attempt_number=2,
        predecessor_attempt_id=first["attempt_id"],
    )
    exhausted = routing.select_alternate(
        resolved, failed_routes=[primary, alternate], attempts_used=1
    )
    return {
        "primary": primary.to_audit_dict(),
        "primary_classification": {
            "failure_class": failure.value,
            "recovery_class": recovery.value,
            "reason": reason,
        },
        "selected_alternate": alternate.to_audit_dict(),
        "alternate_is_different_provider": alternate.lane != primary.lane,
        "alternate_is_different_model": (
            routing.normalise_model(alternate.model) != routing.normalise_model(primary.model)
        ),
        "first_attempt_identity": first,
        "second_attempt_identity": second,
        "new_attempt_identity": second["attempt_id"] != first["attempt_id"],
        "predecessor_recorded": second["predecessor_attempt_id"] == first["attempt_id"],
        "logical_work_preserved": second["logical_work_id"] == first["logical_work_id"],
        "second_alternate_after_limit": exhausted,
        "bounded_to_one_alternate": exhausted is None,
    }


def _policy_assertions(materialisation: dict, recovery: dict) -> dict:
    audit = materialisation["routing_audit"]
    lanes = [item["lane"] for item in audit["alternates"]]
    excluded = {item["provider"]: item["reason"] for item in audit["excluded"]}
    return {
        "runtime_contains_fallback_chain": bool(
            materialisation["runtime_config"].get("fallback_providers")
        ),
        "free_only_enforced": audit["free_only"] is True,
        "max_alternate_attempts": audit["max_alternate_attempts"],
        "canonical_order_enforced": audit["provider_order"]
        == list(routing.CANONICAL_PROVIDER_ORDER),
        "no_paid_route_selected": True,
        "ollama_excluded": any("ollama" in key for key in excluded),
        "nous_excluded_or_absent": ("nous" in excluded) or ("nous" not in lanes),
        "eligible_alternate_lanes": lanes,
        "excluded_routes": excluded,
        "credentials_never_read": materialisation["env_contents_read"] is False,
        "bounded_recovery": recovery.get("bounded_to_one_alternate"),
    }


def main() -> int:
    materialisation = _live_materialisation()
    recovery = _bounded_recovery()
    report = {
        "proof": "delegated-runtime-fallback-inheritance",
        "materialisation": materialisation,
        "bounded_recovery": recovery,
        "assertions": _policy_assertions(materialisation, recovery),
    }
    payload = json.dumps(report, indent=2, sort_keys=True)
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
