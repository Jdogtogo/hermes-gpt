"""Tests for persistent single-writer worktree ownership."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import operator_worktree_lock as locks


def test_claim_assert_and_release(tmp_path):
    state = tmp_path / "state"
    worktree = tmp_path / "repo"
    worktree.mkdir()
    claimed = locks.claim_writer_locks("sa_one", (worktree,), root=state, now=100)
    assert len(claimed) == 1
    assert claimed[0].authority_id == "sa_one"
    locks.assert_writer_locks("sa_one", (worktree,), root=state)
    assert locks.release_writer_locks("sa_one", (worktree,), root=state) == 1
    with pytest.raises(locks.WriterLockMissingError):
        locks.assert_writer_locks("sa_one", (worktree,), root=state)


def test_second_writer_is_rejected_without_overwrite(tmp_path):
    state = tmp_path / "state"
    worktree = tmp_path / "repo"
    worktree.mkdir()
    locks.claim_writer_locks("sa_one", (worktree,), root=state, now=100)
    with pytest.raises(locks.WriterLockConflictError, match="already owned"):
        locks.claim_writer_locks("ab_two", (worktree,), root=state, now=200)
    locks.assert_writer_locks("sa_one", (worktree,), root=state)


def test_multi_root_claim_rolls_back_partial_claim_on_conflict(tmp_path):
    state = tmp_path / "state"
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    locks.claim_writer_locks("existing", (second,), root=state, now=100)
    with pytest.raises(locks.WriterLockConflictError):
        locks.claim_writer_locks("new", (first, second), root=state, now=200)
    assert not locks.lock_path(first, root=state).exists()
    locks.assert_writer_locks("existing", (second,), root=state)


def test_reentrant_claim_survives_later_conflict(tmp_path):
    state = tmp_path / "state"
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    locks.claim_writer_locks("owner", (first,), root=state, now=100)
    locks.claim_writer_locks("other", (second,), root=state, now=100)
    with pytest.raises(locks.WriterLockConflictError):
        locks.claim_writer_locks("owner", (first, second), root=state, now=200)
    locks.assert_writer_locks("owner", (first,), root=state)
    locks.assert_writer_locks("other", (second,), root=state)


def test_wrong_owner_cannot_release(tmp_path):
    state = tmp_path / "state"
    worktree = tmp_path / "repo"
    worktree.mkdir()
    locks.claim_writer_locks("owner", (worktree,), root=state)
    with pytest.raises(locks.WriterLockConflictError, match="Refusing to release"):
        locks.release_writer_locks("other", (worktree,), root=state)
    locks.assert_writer_locks("owner", (worktree,), root=state)


def test_malformed_lock_fails_closed(tmp_path):
    state = tmp_path / "state"
    worktree = tmp_path / "repo"
    worktree.mkdir()
    path = locks.lock_path(worktree, root=state)
    path.parent.mkdir(parents=True)
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(locks.WriterLockError, match="malformed or unreadable"):
        locks.claim_writer_locks("new", (worktree,), root=state)


def test_lock_payload_contains_no_repository_content(tmp_path):
    state = tmp_path / "state"
    worktree = tmp_path / "repo"
    worktree.mkdir()
    locks.claim_writer_locks("sa_one", (worktree,), root=state, now=123)
    payload = json.loads(locks.lock_path(worktree, root=state).read_text(encoding="utf-8"))
    assert payload == {
        "authority_id": "sa_one",
        "claimed_at": 123,
        "worktree": str(worktree.resolve()),
    }
