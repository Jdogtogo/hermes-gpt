#!/usr/bin/env python3
"""Deterministic Hermes-native Mission Control supervision cycle.

This module deliberately composes the existing lease, governed-Kanban, and
Start-and-Poll delegation primitives. It does not create a second registry,
perform independent review acceptance, continue/cancel tasks, or broaden
operator authority.
"""
from __future__ import annotations

import json
import time
from typing import Any

import operator_delegation as delegation
import operator_governed_kanban as governed
import operator_lease as lease

OWNER = "mission-control-hermes-cron"
LEASE_TTL_SECONDS = 300
TERMINAL_STATES = {
    "completed",
    "failed",
    "blocked",
    "incomplete",
    "timed_out",
    "cancelled",
}

# Lease renewal threshold: if lease expires within this many seconds,
# attempt to renew instead of releasing/reacquiring.
LEASE_RENEWAL_THRESHOLD_SECONDS = 60


def _json_obj(value: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object from delegated-task primitive")
    return parsed


def _try_acquire_or_renew_lease(
    owner: str,
    ttl_seconds: int,
) -> dict[str, Any] | None:
    """Try to acquire a new lease, or renew an existing one held by this owner.

    Returns the lease acquisition/renewal result dict, or None if lease is held
    by another active owner.
    """
    # First check current lease status
    status = lease.verify_lease(owner=owner)
    if not status.get("success"):
        return None

    if status.get("has_lease") and status.get("owner_match"):
        # We already hold a valid lease - try to renew it
        # But we need the token for renewal, which we don't have from status.
        # So we can't renew without the token. Fall through to acquire.
        pass

    # Try to acquire new lease (will fail if held by another active owner)
    acquired = lease.acquire_lease(owner=owner, ttl_seconds=ttl_seconds, dry_run=False)
    return acquired


def run_cycle(*, owner: str = OWNER, ttl_seconds: int = LEASE_TTL_SECONDS) -> dict[str, Any]:
    """Run one bounded supervision cycle and return a non-secret evidence report."""
    # Try to acquire or renew the lease
    acquired = _try_acquire_or_renew_lease(owner=owner, ttl_seconds=ttl_seconds)
    if not acquired or not acquired.get("success"):
        # If we couldn't get a lease, report failure
        error_report = {
            "success": False,
            "classification": "LEASE_NOT_ACQUIRED",
            "lease": {k: v for k, v in (acquired or {}).items() if k != "token"},
            "polled": [],
            "terminal_results": [],
        }
        # Include error details if available
        if acquired:
            error_report["error"] = acquired.get("error")
            error_report["message"] = acquired.get("message")
        return error_report

    token = str(acquired["token"])
    report: dict[str, Any] = {
        "success": True,
        "classification": "SUPERVISION_PASS",
        "lease": {
            "owner": acquired.get("owner"),
            "lease_id": acquired.get("lease_id"),
            "ttl_seconds": acquired.get("ttl_seconds"),
            "renewal_count": acquired.get("renewal_count", 0),
        },
        "snapshot": None,
        "polled": [],
        "terminal_results": [],
        "release": None,
    }

    try:
        snapshot = governed.mission_control_snapshot()
        report["snapshot"] = snapshot
        if not snapshot.get("success"):
            report["success"] = False
            report["classification"] = "SNAPSHOT_FAILURE"
            return report

        for row in list(snapshot.get("active_delegations") or []):
            task_id = str(row.get("delegated_task_id") or "").strip()
            if not task_id:
                continue
            status = _json_obj(delegation.hermes_delegated_task_status(task_id))
            observed = {
                "task_id": task_id,
                "logical_work_id": row.get("logical_work_id"),
                "board_task_id": row.get("board_task_id"),
                "board_status": row.get("status"),
                "status_success": status.get("success"),
                "latest_status": status.get("latest_status") or status.get("status"),
                "latest_task_id": status.get("latest_task_id") or status.get("task_id"),
            }
            report["polled"].append(observed)

            latest_status = str(observed.get("latest_status") or "")
            if status.get("success") and latest_status in TERMINAL_STATES:
                result = _json_obj(delegation.hermes_delegated_task_result(task_id))
                report["terminal_results"].append(
                    {
                        "task_id": task_id,
                        "success": result.get("success"),
                        "status": result.get("status"),
                        "ready": result.get("ready"),
                        "mission_control_status": result.get("mission_control_status"),
                        "mission_control_persisted": result.get("mission_control_persisted"),
                        "review_status": result.get("review_status"),
                        "changed_files": result.get("changed_files") or [],
                        "outcome_reason": result.get("outcome_reason"),
                        "failure_category": result.get("failure_category"),
                        "provider_error_category": result.get("provider_error_category"),
                        "checkpoint_ref": result.get("checkpoint_ref"),
                    }
                )
        return report
    except Exception as exc:
        report["success"] = False
        report["classification"] = "SUPERVISION_ERROR"
        report["error"] = f"{exc.__class__.__name__}: {exc}"
        return report
    finally:
        released = lease.release_lease(token, dry_run=False)
        report["release"] = {k: v for k, v in released.items() if k != "token"}
        if not released.get("success") and report.get("success"):
            report["success"] = False
            report["classification"] = "LEASE_RELEASE_FAILURE"


def main() -> int:
    report = run_cycle()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
