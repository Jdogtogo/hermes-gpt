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


# =============================================================================
# REGRESSION TESTS FOR RENEW/HANDOFF (per checkpoint requirements)
# =============================================================================

def test_renew_lease_normal_operation(tmp_path, monkeypatch):
    """Test normal lease renewal - extends expiry, increments renewal_count, preserves token."""
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]
    token = acquired["token"]
    original_expires = acquired["expires_at"]
    original_renewal_count = 0

    # Renew the lease
    renewed = lease.renew_lease(token=token, ttl_seconds=120)
    assert renewed["success"]
    assert renewed["owner"] == "owner-a"
    assert renewed["renewal_count"] == 1
    assert renewed["expires_at"] > original_expires
    assert renewed["expires_at"] == acquired["issued_at"] + 120  # renew extends from now
    assert renewed["ttl_seconds"] == 120

    # Verify the token still works
    verified = lease.verify_lease_token(token)
    assert verified["success"]
    assert verified["renewal_count"] == 1
    assert verified["expires_at"] == renewed["expires_at"]


def test_renew_lease_max_renewals_enforced(tmp_path, monkeypatch):
    """Test that max renewals (12) is enforced - must reacquire after limit."""
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]
    token = acquired["token"]

    # Renew up to max (12 times)
    for i in range(1, lease.MAX_RENEWALS + 1):
        renewed = lease.renew_lease(token=token, ttl_seconds=60)
        assert renewed["success"]
        assert renewed["renewal_count"] == i

    # 13th renewal should fail
    failed = lease.renew_lease(token=token, ttl_seconds=60)
    assert not failed["success"]
    assert failed["error"] == "MAX_RENEWALS_REACHED"
    assert failed["renewal_count"] == lease.MAX_RENEWALS
    assert failed["max_renewals"] == lease.MAX_RENEWALS


def test_renew_lease_rejects_expired_lease(tmp_path, monkeypatch):
    """Test that renew fails on expired lease."""
    _configure(tmp_path, monkeypatch)

    now = int(time.time())
    # Create an expired lease
    lease._write_lease_state(lease.LeaseState(
        owner="owner-a",
        token="token-a",
        issued_at=now - 120,
        expires_at=now - 60,  # expired 60 seconds ago
        lease_id="expired-lease"
    ))

    result = lease.renew_lease(token="token-a", ttl_seconds=60)
    assert not result["success"]
    assert result["error"] == "LEASE_EXPIRED"


def test_renew_lease_rejects_wrong_token(tmp_path, monkeypatch):
    """Test that renew fails with invalid token."""
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]

    result = lease.renew_lease(token="wrong-token", ttl_seconds=60)
    assert not result["success"]
    assert result["error"] == "INVALID_TOKEN"


def test_renew_lease_dry_run_does_not_persist(tmp_path, monkeypatch):
    """Test that dry_run=true validates but does not persist changes."""
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]
    token = acquired["token"]
    original_expires = acquired["expires_at"]
    original_renewal_count = 0

    # Dry-run renewal
    renewed = lease.renew_lease(token=token, ttl_seconds=120, dry_run=True)
    assert renewed["success"]
    assert renewed["dry_run"] is True
    assert renewed["renewal_count"] == 1
    assert renewed["expires_at"] > original_expires

    # Verify actual state unchanged
    state = lease._read_lease_state()
    assert state is not None
    assert state.expires_at == original_expires
    assert state.renewal_count == original_renewal_count


def test_handoff_lease_normal_operation(tmp_path, monkeypatch):
    """Test normal lease handoff - transfers ownership, resets renewal_count, preserves token."""
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]
    token = acquired["token"]
    original_issued = acquired["issued_at"]
    original_lease_id = acquired["lease_id"]

    # Handoff to new owner
    handed_off = lease.handoff_lease(token=token, new_owner="owner-b")
    assert handed_off["success"]
    assert handed_off["owner"] == "owner-b"
    assert handed_off["previous_owner"] == "owner-a"
    assert handed_off["renewal_count"] == 0  # Reset on handoff
    assert handed_off["issued_at"] == original_issued  # Preserved
    assert handed_off["lease_id"] == original_lease_id  # Preserved
    assert handed_off["expires_at"] > original_issued  # Extended by default TTL

    # Verify new owner can use token
    verified = lease.verify_lease_token(token)
    assert verified["success"]
    assert verified["owner"] == "owner-b"
    assert verified["renewal_count"] == 0


def test_handoff_lease_rejects_same_owner(tmp_path, monkeypatch):
    """Test that handoff fails when new_owner == current owner."""
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]
    token = acquired["token"]

    # Try to handoff to same owner
    result = lease.handoff_lease(token=token, new_owner="owner-a")
    assert not result["success"]
    assert result["error"] == "SAME_OWNER"
    assert result["current_owner"] == "owner-a"


def test_handoff_lease_rejects_wrong_token(tmp_path, monkeypatch):
    """Test that handoff fails with invalid token."""
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]

    result = lease.handoff_lease(token="wrong-token", new_owner="owner-b")
    assert not result["success"]
    assert result["error"] == "INVALID_TOKEN"


def test_handoff_lease_rejects_expired_lease(tmp_path, monkeypatch):
    """Test that handoff fails on expired lease."""
    _configure(tmp_path, monkeypatch)

    now = int(time.time())
    # Create an expired lease
    lease._write_lease_state(lease.LeaseState(
        owner="owner-a",
        token="token-a",
        issued_at=now - 120,
        expires_at=now - 60,  # expired
        lease_id="expired-lease"
    ))

    result = lease.handoff_lease(token="token-a", new_owner="owner-b")
    assert not result["success"]
    assert result["error"] == "LEASE_EXPIRED"


def test_handoff_lease_dry_run_does_not_persist(tmp_path, monkeypatch):
    """Test that dry_run=true validates but does not persist changes."""
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]
    token = acquired["token"]
    original_owner = "owner-a"
    original_renewal_count = 0

    # Dry-run handoff
    handed_off = lease.handoff_lease(token=token, new_owner="owner-b", dry_run=True)
    assert handed_off["success"]
    assert handed_off["dry_run"] is True
    assert handed_off["owner"] == "owner-b"
    assert handed_off["renewal_count"] == 0

    # Verify actual state unchanged
    state = lease._read_lease_state()
    assert state is not None
    assert state.owner == original_owner
    assert state.renewal_count == original_renewal_count


def test_release_requires_correct_token(tmp_path, monkeypatch):
    """Test that release fails with wrong token (wrong-token release refusal)."""
    _configure(tmp_path, monkeypatch)

    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]
    token = acquired["token"]

    # Try to release with wrong token
    result = lease.release_lease("wrong-token")
    assert not result["success"]
    assert result["error"] == "INVALID_TOKEN"

    # Verify lease still exists
    status = lease.verify_lease(owner="owner-a", require_owner_match=True)
    assert status["success"]
    assert status["has_lease"]
    assert status["owner_match"]


def test_stale_abandoned_lease_can_be_reacquired(tmp_path, monkeypatch):
    """Test that stale/abandoned (expired) lease can be reacquired by new owner."""
    _configure(tmp_path, monkeypatch)

    now = int(time.time())
    # Create an expired lease (stale/abandoned)
    lease._write_lease_state(lease.LeaseState(
        owner="owner-a",
        token="token-a",
        issued_at=now - 3600,
        expires_at=now - 60,  # expired 60 seconds ago
        lease_id="stale-lease"
    ))

    # New owner can acquire
    result = lease.acquire_lease(owner="owner-b", ttl_seconds=60)
    assert result["success"]
    assert result["owner"] == "owner-b"

    # Verify old lease is gone
    status = lease.verify_lease(owner="owner-b", require_owner_match=True)
    assert status["success"]
    assert status["has_lease"]
    assert status["owner_match"]
    assert status["owner"] == "owner-b"


def test_active_competitor_blocked_from_acquire(tmp_path, monkeypatch):
    """Test that active competitor is blocked from acquiring a live lease."""
    _configure(tmp_path, monkeypatch)

    # Owner-a acquires lease
    acquired = lease.acquire_lease(owner="owner-a", ttl_seconds=60)
    assert acquired["success"]

    # Owner-b tries to acquire (should be blocked)
    result = lease.acquire_lease(owner="owner-b", ttl_seconds=60)
    assert not result["success"]
    assert result["error"] == "LEASE_HELD_BY_OTHER"
    assert result["current_owner"] == "owner-a"

    # Original owner-a still holds lease
    status = lease.verify_lease(owner="owner-a", require_owner_match=True)
    assert status["success"]
    assert status["has_lease"]
    assert status["owner_match"]
