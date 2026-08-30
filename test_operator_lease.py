from __future__ import annotations

import multiprocessing as mp
import time
from pathlib import Path

import pytest

import operator_lease as lease


class _Policy:
    session_id = "test-session"
    level = "workspace"
    apply_mode = "direct"

    @staticmethod
    def current_oauth_identity():
        return ("test-user", None)


def _configure(tmp_path: Path, monkeypatch) -> None:
    state_dir = tmp_path / "leases"
    monkeypatch.setattr(lease, "_LEASE_STATE_DIR", state_dir)
    monkeypatch.setattr(lease, "_LEASE_STATE_PATH", state_dir / "mission-control-lease.json")
    monkeypatch.setattr(lease, "_LEASE_LOCK_PATH", state_dir / "mission-control-lease.lock")
    monkeypatch.setattr(lease, "_require_operator_authority", lambda **kwargs: _Policy())
    # Lease status authorizes separately (narrow mission_control:lease_status,
    # or the legacy broad filesystem:read). These lifecycle tests are not about
    # that split, so they stand in for a broadly-authorized caller -- which is
    # the behaviour they were written against, including expired-record reaping.
    monkeypatch.setattr(lease, "_require_lease_status_authority", lambda: (_Policy(), True))
    monkeypatch.setattr(lease.op_policy, "audit_record", lambda **kwargs: None)


def _contender(owner: str, start, out) -> None:
    start.wait()
    out.put(lease.acquire_lease(owner=owner, ttl_seconds=60))


def test_cross_process_acquire_has_exactly_one_winner(tmp_path, monkeypatch):
    _configure(tmp_path, monkeypatch)
    ctx = mp.get_context("fork")
    start = ctx.Event()
    out = ctx.Queue()
    p1 = ctx.Process(target=_contender, args=("owner-a", start, out))
    p2 = ctx.Process(target=_contender, args=("owner-b", start, out))
    p1.start(); p2.start(); start.set()
    r1 = out.get(timeout=5); r2 = out.get(timeout=5)
    p1.join(5); p2.join(5)
    assert p1.exitcode == 0 and p2.exitcode == 0
    winners = [r for r in (r1, r2) if r["success"]]
    losers = [r for r in (r1, r2) if not r["success"]]
    assert len(winners) == 1
    assert len(losers) == 1
    assert losers[0]["error"] == "LEASE_HELD_BY_OTHER"


def test_release_requires_token_and_allows_reacquire(tmp_path, monkeypatch):
    _configure(tmp_path, monkeypatch)
    first = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert first["success"]
    bad = lease.release_lease("wrong-token")
    assert not bad["success"] and bad["error"] == "INVALID_TOKEN"
    status = lease.verify_lease(owner="owner-a", require_owner_match=True)
    assert status["success"] and status["has_lease"] and status["owner_match"]
    released = lease.release_lease(first["token"])
    assert released["success"]
    second = lease.acquire_lease(owner="owner-b", ttl_seconds=60)
    assert second["success"]


def test_expired_lease_can_be_reacquired(tmp_path, monkeypatch):
    _configure(tmp_path, monkeypatch)
    now = int(time.time())
    lease._write_lease_state(lease.LeaseState("owner-a", "token-a", now - 120, now - 1, "old"))
    result = lease.acquire_lease(owner="owner-b", ttl_seconds=60)
    assert result["success"]
    status = lease.verify_lease(owner="owner-b", require_owner_match=True)
    assert status["success"] and status["owner_match"]


def test_same_owner_cannot_replace_live_lease(tmp_path, monkeypatch):
    _configure(tmp_path, monkeypatch)

    first = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    second = lease.acquire_lease(owner="owner-a", ttl_seconds=60)

    assert first["success"] is True
    assert second["success"] is False
    assert second["error"] == "LEASE_ALREADY_HELD"
    persisted = lease._read_lease_state()
    assert persisted is not None
    assert persisted.owner == "owner-a"
    assert persisted.lease_id == first["lease_id"]
    assert persisted.token == first["token"]


def test_verify_lease_token_accepts_only_current_bearer(tmp_path, monkeypatch):
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    good = lease.verify_lease_token(acquired["token"])
    bad = lease.verify_lease_token("wrong-token")

    assert good["success"] is True
    assert good["owner"] == "owner-a"
    assert good["lease_id"] == acquired["lease_id"]
    assert "token" not in good
    assert bad["success"] is False
    assert bad["error"] == "INVALID_LEASE_TOKEN"
    assert "token" not in bad


def test_acquire_audit_failure_rolls_back_created_lease(tmp_path, monkeypatch):
    _configure(tmp_path, monkeypatch)

    def fail_audit(**kwargs):
        assert kwargs["level"] == "workspace"
        assert kwargs["apply_mode"] == "direct"
        assert kwargs["dry_run"] is False
        assert kwargs["success"] is True
        raise RuntimeError("forced audit failure")

    monkeypatch.setattr(lease.op_policy, "audit_record", fail_audit)

    with pytest.raises(RuntimeError, match="forced audit failure"):
        lease.acquire_lease(owner="owner-a", ttl_seconds=60)

    assert lease._read_lease_state() is None
    status = lease.verify_lease(owner="owner-a", require_owner_match=True)
    assert status["success"] and not status["has_lease"]
