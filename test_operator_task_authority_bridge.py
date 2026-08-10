"""Integration regressions for Task-Bound Authority v2 and the real session broker.

These tests use the production operator_sessions / OperatorPolicy / delegation
code against an isolated temporary session root. They prove the module-level
resolver is actually bridged to the existing human approval path rather than
operating as a parallel authority system.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import operator_delegation as delegation
import operator_policy as op
import operator_policy_templates as templates
import operator_sessions as sessions
import operator_task_authority as tba
import server


@pytest.fixture
def session_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "sessions"
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(root))
    for name in [
        op.OPERATOR_ENABLED_ENV,
        op.OPERATOR_LEVEL_ENV,
        op.OPERATOR_APPLY_MODE_ENV,
        op.OPERATOR_ALLOWED_PATHS_ENV,
        op.OWNER_ACK_ENV,
    ]:
        monkeypatch.delenv(name, raising=False)
    yield root


def _request(root: Path, *, task: str, template: str = "sandbox", now: int | None = None):
    resolved = templates.resolve_template(template)
    return sessions.request_session(
        policy_template=template,
        resolved_policy=resolved["policy"],
        requested_duration_seconds=1800,
        reason=f"[task:{task}] contained maintenance proof",
        root=root,
        now=now,
    )


def test_real_session_pending_request_is_deduplicated(session_env):
    first = _request(session_env, task="bridge-pending-dedupe")
    second = _request(session_env, task="bridge-pending-dedupe")
    assert second == first
    pending = sessions.list_pending_session_requests(root=session_env)
    assert [item["request_id"] for item in pending] == [first]
    info = sessions.session_request_info(first, root=session_env)
    assert info["logical_task_id"] == "bridge-pending-dedupe"
    assert info["request_identity"]


def test_unrelated_real_session_requests_coexist(session_env):
    first = _request(session_env, task="bridge-unrelated-a", template="sandbox")
    second = _request(
        session_env,
        task="bridge-unrelated-b",
        template="hermes-gpt-operator-maintenance",
    )
    pending = sessions.list_pending_session_requests(root=session_env)
    assert {item["request_id"] for item in pending} == {first, second}


def test_material_scope_change_for_same_task_supersedes_only_that_task(session_env):
    now = int(time.time())
    first = _request(session_env, task="bridge-scope-change", template="sandbox", now=now)
    second = _request(
        session_env,
        task="bridge-scope-change",
        template="hermes-gpt-operator-maintenance",
        now=now + 1,
    )
    assert second != first
    pending = sessions.list_pending_session_requests(root=session_env)
    assert [item["request_id"] for item in pending] == [second]
    with pytest.raises(ValueError, match="already superseded"):
        sessions.approve_session_request(first, root=session_env, now=now + 2)


def test_human_approval_mints_task_authority_and_survives_old_timer(session_env):
    now = int(time.time())
    request_id = _request(session_env, task="bridge-timer", now=now)
    record = sessions.approve_session_request(
        request_id,
        decided_by="telegram:justin",
        root=session_env,
        now=now + 1,
    )
    state = tba.task_status("bridge-timer", root=session_env, now=now + 2)
    assert state["valid"] is True
    assert state["authority_source"] == "task_bound"
    assert state["effective_authority_ids"] == [request_id]

    immediate = sessions.resolve_effective_authority(now=now + 2)
    assert immediate.is_active is True
    assert immediate.status == "task_bound"
    assert immediate.authority_kind == "task_bound"
    assert immediate.logical_task_id == "bridge-timer"
    assert immediate.session_id == record.session_id
    assert immediate.expires_at == state["hard_expires_at"]

    # The legacy session has expired, but the logical task has not.
    later = sessions.resolve_effective_authority(now=record.expires_at + 1)
    assert later.is_active is True
    assert later.status == "task_bound"
    assert later.logical_task_id == "bridge-timer"
    assert later.expires_at > record.expires_at


def test_task_hard_ceiling_still_fails_closed(session_env):
    now = int(time.time())
    request_id = _request(session_env, task="bridge-hard-expiry", now=now)
    sessions.approve_session_request(request_id, root=session_env, now=now + 1)
    expired = sessions.resolve_effective_authority(
        now=now + 1 + tba.HARD_TASK_LIFETIME_SECONDS + 1
    )
    assert expired.is_active is False
    assert expired.status == "task_bound_inactive"


def test_completion_invalidates_task_without_falling_back_to_live_session(session_env):
    now = int(time.time())
    request_id = _request(session_env, task="bridge-complete", now=now)
    record = sessions.approve_session_request(request_id, root=session_env, now=now + 1)
    assert record.expires_at > now + 2

    tba.complete_task("bridge-complete", actor="test", root=session_env)
    closed = sessions.resolve_effective_authority(now=now + 2)
    assert closed.is_active is False
    assert closed.status == "task_bound_inactive"
    assert "completed" in (closed.failure_reason or "")


def test_controller_completion_surface_invalidates_task_and_requires_fresh_request(session_env):
    now = int(time.time())
    request_id = _request(session_env, task="bridge-controller-complete", now=now)
    sessions.approve_session_request(request_id, root=session_env, now=now + 1)

    response = json.loads(server.hermes_operator_task_complete())
    assert response["success"] is True
    assert response["completed"] is True
    assert response["logical_task_id"] == "bridge-controller-complete"
    assert response["task_authority"]["task_state"] == "completed"
    assert response["task_authority"]["valid"] is False

    closed = sessions.resolve_effective_authority(now=now + 2)
    assert closed.is_active is False
    assert closed.status == "task_bound_inactive"
    assert "completed" in (closed.failure_reason or "")

    replacement = _request(session_env, task="bridge-controller-complete", now=now + 3)
    assert replacement != request_id
    replacement_info = sessions.session_request_info(replacement, root=session_env)
    assert replacement_info["status"] == "pending"


def test_stale_client_revoke_transport_can_complete_named_active_task(session_env):
    now = int(time.time())
    request_id = _request(session_env, task="bridge-compat-complete", now=now)
    sessions.approve_session_request(request_id, root=session_env, now=now + 1)

    response = json.loads(
        server.hermes_operator_session_revoke("task:bridge-compat-complete")
    )
    assert response["success"] is True
    assert response["completed"] is True
    assert response["compatibility_path"] is True
    assert response["task_authority"]["task_state"] == "completed"
    assert response["task_authority"]["valid"] is False

    closed = sessions.resolve_effective_authority(now=now + 2)
    assert closed.is_active is False
    assert closed.status == "task_bound_inactive"


def test_source_session_revoke_revokes_task_authority(session_env):
    now = int(time.time())
    request_id = _request(session_env, task="bridge-revoke", now=now)
    record = sessions.approve_session_request(request_id, root=session_env, now=now + 1)
    assert sessions.revoke_session(record.session_id, root=session_env, now=now + 2) is True
    state = tba.task_status("bridge-revoke", root=session_env, now=now + 2)
    assert state["valid"] is False
    assert state["task_state"] == "revoked"


def test_task_specific_resolution_is_independent_of_active_pointer(session_env):
    now = int(time.time())
    req_a = _request(session_env, task="bridge-pointer-a", now=now)
    rec_a = sessions.approve_session_request(req_a, root=session_env, now=now + 1)
    req_b = _request(session_env, task="bridge-pointer-b", now=now + 2)
    rec_b = sessions.approve_session_request(req_b, root=session_env, now=now + 3)
    assert rec_a.session_id != rec_b.session_id

    # Default resolution follows the latest active pointer (task B).
    default = sessions.resolve_effective_authority(now=now + 4)
    assert default.logical_task_id == "bridge-pointer-b"

    # A delegated worker carrying task A's id resolves task A directly, even
    # though the global pointer now names task B.
    task_a = sessions.resolve_effective_authority(task_id="bridge-pointer-a", now=now + 4)
    assert task_a.is_active is True
    assert task_a.logical_task_id == "bridge-pointer-a"
    assert task_a.session_id == rec_a.session_id


def test_operator_policy_and_delegation_capture_same_task_lifecycle(session_env):
    now = int(time.time())
    request_id = _request(session_env, task="bridge-delegation", now=now)
    record = sessions.approve_session_request(request_id, root=session_env, now=now + 1)

    policy = op.OperatorPolicy(logical_task_id="bridge-delegation")
    assert policy.authority_kind == "task_bound"
    assert policy.logical_task_id == "bridge-delegation"
    assert policy.session_status == "task_bound"
    assert policy.expires_at > record.expires_at

    envelope = delegation._capture_authority_envelope(
        policy,
        profile="default",
        workdir=Path(policy.readable_roots[0]),
        mode="apply",
        allow_web=False,
        max_turns=10,
        timeout=120,
    )
    assert envelope["authority_kind"] == "task_bound"
    assert envelope["logical_task_id"] == "bridge-delegation"
    assert envelope["session_id"] == record.session_id
    assert envelope["expires_at"] == policy.expires_at


def test_material_boundaries_remain_outside_task_bridge(session_env):
    now = int(time.time())
    request_id = _request(session_env, task="bridge-material", now=now)
    sessions.approve_session_request(request_id, root=session_env, now=now + 1)
    state = tba.task_status("bridge-material", root=session_env, now=now + 2)
    assert state["valid"] is True

    envelope = sessions.task_envelope_from_policy(
        policy_template="sandbox",
        resolved_policy=templates.resolve_template("sandbox")["policy"],
    )
    for boundary in (
        tba.material_boundary(paid_routing=True),
        tba.material_boundary(paths=("~/.hermes/auth/token.json",)),
        tba.material_boundary(network_security=True),
        tba.material_boundary(release_deploy=True),
    ):
        resolution = tba.resolve(
            task_id="bridge-material",
            envelope=envelope,
            policy_class="sandbox",
            boundary=boundary,
            root=session_env,
        )
        assert resolution.approval_required is True
        assert resolution.state == "blocked"


def test_legacy_approved_request_can_be_bound_without_duplicate_approval(session_env):
    now = int(time.time())
    request_id = _request(session_env, task="bridge-upgrade", now=now)
    record = sessions.approve_session_request(request_id, root=session_env, now=now + 1)

    # Simulate a pre-v2 approved row: keep the approved session and human
    # decision, but remove the v2 binding and task authority records.
    import sqlite3
    with sqlite3.connect(sessions.db_path(session_env)) as connection:
        connection.execute(
            "UPDATE session_creation_requests SET logical_task_id=NULL, request_identity=NULL "
            "WHERE request_id=?",
            (request_id,),
        )
        connection.commit()
    with sqlite3.connect(session_env / tba.TASK_DB_NAME) as connection:
        connection.execute("DELETE FROM task_authorities WHERE task_id=?", ("bridge-upgrade",))
        connection.commit()

    # The first normal sidecar resolution performs the one-time migration
    # from the already-approved legacy row. No second approval/request exists.
    migrated = sessions.resolve_effective_authority(now=now + 2)
    assert migrated.status == "task_bound"
    assert migrated.logical_task_id == "bridge-upgrade"
    assert migrated.session_id == record.session_id
    assert migrated.source_request_id == request_id

    pending = sessions.list_pending_session_requests(root=session_env)
    assert pending == []

    after = sessions.resolve_effective_authority(now=record.expires_at + 1)
    assert after.status == "task_bound"
    assert after.logical_task_id == "bridge-upgrade"
    assert after.is_active is True
