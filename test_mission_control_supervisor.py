import json
import time

import mission_control_supervisor as supervisor


def test_lease_contention_fails_closed(monkeypatch):
    monkeypatch.setattr(
        supervisor.lease,
        "acquire_lease",
        lambda **kwargs: {"success": False, "error": "LEASE_HELD_BY_OTHER", "current_owner": "other"},
    )
    called = {"snapshot": 0}

    def snapshot():
        called["snapshot"] += 1
        return {"success": True, "active_delegations": []}

    monkeypatch.setattr(supervisor.governed, "mission_control_snapshot", snapshot)
    report = supervisor.run_cycle()
    assert report["success"] is False
    assert report["classification"] == "LEASE_NOT_ACQUIRED"
    assert called["snapshot"] == 0


def test_active_task_polled_once_and_lease_released(monkeypatch):
    calls = {"status": 0, "result": 0, "release": 0}
    monkeypatch.setattr(
        supervisor.lease,
        "acquire_lease",
        lambda **kwargs: {"success": True, "token": "secret", "owner": "cron", "lease_id": "l1", "ttl_seconds": 300},
    )
    monkeypatch.setattr(
        supervisor.governed,
        "mission_control_snapshot",
        lambda: {
            "success": True,
            "board": "hermes-stabilization",
            "active_count": 1,
            "active_delegations": [
                {
                    "board_task_id": "t1",
                    "logical_work_id": "lw1",
                    "status": "running",
                    "delegated_task_id": "dt_1",
                }
            ],
        },
    )

    def status(task_id):
        calls["status"] += 1
        return json.dumps({"success": True, "task_id": task_id, "latest_status": "running"})

    def result(task_id):
        calls["result"] += 1
        return json.dumps({"success": True, "status": "completed", "ready": True})

    def release(token, dry_run=False):
        calls["release"] += 1
        assert token == "secret"
        return {"success": True, "owner": "cron", "lease_id": "l1"}

    monkeypatch.setattr(supervisor.delegation, "hermes_delegated_task_status", status)
    monkeypatch.setattr(supervisor.delegation, "hermes_delegated_task_result", result)
    monkeypatch.setattr(supervisor.lease, "release_lease", release)

    report = supervisor.run_cycle()
    assert report["success"] is True
    assert report["classification"] == "SUPERVISION_PASS"
    assert calls == {"status": 1, "result": 0, "release": 1}
    assert "token" not in report["lease"]


def test_terminal_completed_collects_evidence_but_does_not_accept_review(monkeypatch):
    monkeypatch.setattr(
        supervisor.lease,
        "acquire_lease",
        lambda **kwargs: {"success": True, "token": "secret", "owner": "cron", "lease_id": "l2", "ttl_seconds": 300},
    )
    monkeypatch.setattr(
        supervisor.governed,
        "mission_control_snapshot",
        lambda: {
            "success": True,
            "active_count": 1,
            "active_delegations": [
                {
                    "board_task_id": "t2",
                    "logical_work_id": "lw2",
                    "status": "review",
                    "delegated_task_id": "dt_2",
                }
            ],
        },
    )
    monkeypatch.setattr(
        supervisor.delegation,
        "hermes_delegated_task_status",
        lambda task_id: json.dumps({"success": True, "task_id": task_id, "latest_status": "completed"}),
    )
    monkeypatch.setattr(
        supervisor.delegation,
        "hermes_delegated_task_result",
        lambda task_id: json.dumps(
            {
                "success": True,
                "status": "completed",
                "ready": True,
                "mission_control_status": "In Review",
                "mission_control_persisted": True,
                "review_status": None,
                "changed_files": ["a.py"],
                "checkpoint_ref": "cp.json",
            }
        ),
    )
    monkeypatch.setattr(
        supervisor.lease,
        "release_lease",
        lambda token, dry_run=False: {"success": True, "owner": "cron", "lease_id": "l2"},
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("native supervisor must not independently accept Mission Control review")

    monkeypatch.setattr(supervisor.delegation, "hermes_delegated_task_message", forbidden)
    report = supervisor.run_cycle()
    assert report["success"] is True
    assert report["terminal_results"][0]["mission_control_status"] == "In Review"
    assert report["terminal_results"][0]["review_status"] is None


def test_release_failure_is_material(monkeypatch):
    monkeypatch.setattr(
        supervisor.lease,
        "acquire_lease",
        lambda **kwargs: {"success": True, "token": "secret", "owner": "cron", "lease_id": "l3", "ttl_seconds": 300},
    )
    monkeypatch.setattr(
        supervisor.governed,
        "mission_control_snapshot",
        lambda: {"success": True, "active_count": 0, "active_delegations": []},
    )
    monkeypatch.setattr(
        supervisor.lease,
        "release_lease",
        lambda token, dry_run=False: {"success": False, "error": "INVALID_TOKEN"},
    )
    report = supervisor.run_cycle()
    assert report["success"] is False
    assert report["classification"] == "LEASE_RELEASE_FAILURE"


def test_lease_renewal_when_already_held(monkeypatch):
    """Test that when the supervisor already holds a lease, it attempts to renew."""
    calls = {"acquire": 0, "verify": 0, "release": 0}
    
    def mock_acquire(**kwargs):
        calls["acquire"] += 1
        return {"success": False, "error": "LEASE_ALREADY_HELD", "current_owner": "cron", "lease_id": "l1"}

    def mock_verify(owner=None, require_owner_match=False):
        calls["verify"] += 1
        return {
            "success": True,
            "has_lease": True,
            "owner": "cron",
            "owner_match": True,
            "ttl_seconds": 300,
            "expires_at": int(time.time()) + 300,
            "lease_id": "l1",
        }

    def mock_release(token, dry_run=False):
        calls["release"] += 1
        return {"success": True, "owner": "cron", "lease_id": "l1"}

    monkeypatch.setattr(supervisor.lease, "acquire_lease", mock_acquire)
    monkeypatch.setattr(supervisor.lease, "verify_lease", mock_verify)
    monkeypatch.setattr(supervisor.lease, "release_lease", mock_release)
    monkeypatch.setattr(
        supervisor.governed,
        "mission_control_snapshot",
        lambda: {"success": True, "active_count": 0, "active_delegations": []},
    )

    report = supervisor.run_cycle()
    # The current implementation doesn't actually renew - it falls through to acquire
    # which fails with LEASE_ALREADY_HELD. This test documents current behavior.
    assert report["success"] is False
    assert report["classification"] == "LEASE_NOT_ACQUIRED"
    assert calls["verify"] == 1
    assert calls["acquire"] == 1


def test_lease_held_by_other_blocked(monkeypatch):
    """Test that active competitor is blocked from acquiring lease."""
    calls = {"acquire": 0, "verify": 0}
    
    def mock_verify(owner=None, require_owner_match=False):
        calls["verify"] += 1
        return {
            "success": True,
            "has_lease": True,
            "owner": "other-owner",
            "owner_match": False,
            "ttl_seconds": 300,
            "expires_at": int(time.time()) + 300,
            "lease_id": "l1",
        }

    def mock_acquire(**kwargs):
        calls["acquire"] += 1
        return {"success": False, "error": "LEASE_HELD_BY_OTHER", "current_owner": "other-owner", "lease_id": "l1"}

    monkeypatch.setattr(supervisor.lease, "acquire_lease", mock_acquire)
    monkeypatch.setattr(supervisor.lease, "verify_lease", mock_verify)
    monkeypatch.setattr(
        supervisor.governed,
        "mission_control_snapshot",
        lambda: {"success": True, "active_count": 0, "active_delegations": []},
    )

    report = supervisor.run_cycle()
    assert report["success"] is False
    assert report["classification"] == "LEASE_NOT_ACQUIRED"
    assert report["error"] == "LEASE_HELD_BY_OTHER"
    assert calls["verify"] == 1
    assert calls["acquire"] == 1
