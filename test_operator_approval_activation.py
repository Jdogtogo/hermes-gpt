"""Regression tests for approval -> live-authority activation.

Pins the repair for the observed failure: a session request that a human
genuinely approved (locally, via the Telegram resolve endpoint) produced an
approved session record, a stored resulting_session_id and an updated active
pointer -- and then never became the effective authority, because
resolve_effective_authority() rejected the approved snapshot as malformed and
OperatorPolicy silently fell back to the standing authority. Live evidence:
request sr_26389838 (template hermes-exec-first-safe-model, decided_by
telegram:..., resulting session ops_2jKN...), whose immutable snapshot grants
workspace level with a deliberately empty writable_roots list.

Two things were wrong and both are covered here:

* the "workspace level implies writable roots" integrity check could not tell
  a snapshot that LOST its roots from a template that deliberately grants a
  zero-local-write surface, so it rejected a legitimate policy; and
* that invariant lived only in the resolver, so an incoherent policy passed
  request and approval silently, consumed a human approval, minted a session
  and moved the active pointer before failing closed on the next call.

The full required lifecycle -- pending request -> human approval -> approved
session record -> resulting_session_id -> active pointer -> effective
authority -> live status, with no operator restart -- is asserted end to end.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import operator_lease as lease
import operator_policy as op
import operator_policy_templates as templates
import operator_sessions as sessions
import operator_task_authority as task_authority


# The registered template whose approval failed to activate in production: it
# deliberately grants workspace-tier verbs with NO local write surface.
ZERO_WRITE_TEMPLATE = "hermes-exec-first-safe-model"


@pytest.fixture
def session_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root = tmp_path / "sessions"
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(root))
    monkeypatch.delenv(sessions.ACTIVE_SESSION_ID_ENV, raising=False)
    for name in [
        op.OPERATOR_ENABLED_ENV, op.OPERATOR_LEVEL_ENV, op.OPERATOR_APPLY_MODE_ENV,
        op.OPERATOR_ALLOWED_PATHS_ENV, op.OWNER_ACK_ENV,
    ]:
        monkeypatch.delenv(name, raising=False)
    lease_dir = tmp_path / "leases"
    lease_path = lease_dir / "mission-control-lease.json"
    monkeypatch.setattr(lease, "_LEASE_STATE_DIR", lease_dir)
    monkeypatch.setattr(lease, "_LEASE_STATE_PATH", lease_path)
    monkeypatch.setattr(lease, "_LEASE_LOCK_PATH", lease_dir / "mission-control-lease.lock")
    lease_dir.mkdir(parents=True, exist_ok=True)
    now = lease._now()
    lease_path.write_text(json.dumps({
        "owner": "chatgpt-mission-control",
        "token": "fixture-token-never-returned",
        "issued_at": now,
        "expires_at": now + 3600,
        "lease_id": "fixture-approval-lease",
    }), encoding="utf-8")
    op.set_audit_log_override(tmp_path / "audit.jsonl")
    yield root
    op.set_audit_log_override(None)


def _session_count(root: Path) -> int:
    with sqlite3.connect(sessions.db_path(root)) as connection:
        return int(connection.execute("SELECT COUNT(*) FROM operator_sessions").fetchone()[0])


def _request_row(root: Path, request_id: str) -> dict:
    with sqlite3.connect(sessions.db_path(root)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM session_creation_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
    return dict(row) if row is not None else {}


def _incoherent_policy() -> dict:
    """Workspace level with no writable roots under a template this deployment
    does not register -- i.e. roots that cannot be vouched for as deliberate."""
    return {
        "policy_template": "phantom-template",
        "level": "workspace",
        "apply_mode": "direct",
        "readable_roots": ["/tmp"],
        "writable_roots": [],
        "verbs": {"filesystem": ["edit"]},
    }


def _request_zero_write_session(root: Path, *, now: int = 2_000_000_000, request_id: str = "sr_zerowrite") -> str:
    resolved = templates.resolve_template(ZERO_WRITE_TEMPLATE)
    return sessions.request_session(
        policy_template=ZERO_WRITE_TEMPLATE,
        resolved_policy=resolved["policy"],
        requested_duration_seconds=3600,
        reason="[task:activation-regression] prove approval activates authority",
        root=root,
        now=now,
        request_id=request_id,
    )


# ---------------------------------------------------------------------------
# 1. A pending request grants nothing.
# ---------------------------------------------------------------------------

def test_pending_request_grants_no_authority(session_env):
    request_id = _request_zero_write_session(session_env)

    assert _session_count(session_env) == 0
    assert not sessions._active_pointer_path(session_env).exists()
    authority = sessions.resolve_effective_authority(now=2_000_000_001)
    assert authority.is_active is False
    assert authority.status == "none_configured"
    assert authority.level == "read_only"
    assert authority.apply_mode == "dry_run"
    assert _request_row(session_env, request_id)["status"] == "pending"


# ---------------------------------------------------------------------------
# 2-6. The complete lifecycle, through the exact function the localhost page
# and the Telegram resolve endpoint both call.
# ---------------------------------------------------------------------------

def test_approval_activates_zero_local_write_session_end_to_end(session_env, monkeypatch):
    """The production regression, start to finish.

    Before the fix this approval produced an approved record, a stored
    resulting_session_id and an updated pointer, and then resolved to
    status='malformed' / is_active=False on the very next call.
    """
    request_id = _request_zero_write_session(session_env)

    # A long-lived process that has ALREADY resolved authority before approval:
    # what it sees after approval is the "no restart required" property.
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(session_env))
    before = op.OperatorPolicy()
    assert before.session_status == "none_configured"
    assert before.level == "read_only"

    record = sessions.approve_session_request(
        request_id, decided_by="telegram:8595123783", root=session_env, now=2_000_000_010,
    )

    # 2. Exactly one session was created.
    assert _session_count(session_env) == 1

    # 3. The approved request stores resulting_session_id (and the task binding).
    row = _request_row(session_env, request_id)
    assert row["status"] == "approved"
    assert row["decided_by"] == "telegram:8595123783"
    assert row["decided_at"] == 2_000_000_010
    assert row["resulting_session_id"] == record.session_id
    assert str(row["logical_task_id"]).strip()

    # 4. The active pointer was updated to that session.
    pointer = sessions._active_pointer_path(session_env)
    assert pointer.is_file()
    assert pointer.read_text(encoding="utf-8").strip() == record.session_id

    # 5. resolve_effective_authority() returns the new task-bound authority NOW.
    authority = sessions.resolve_effective_authority(now=2_000_000_011)
    assert authority.is_active is True
    assert authority.status == "task_bound"
    assert authority.authority_kind == "task_bound"
    assert authority.session_id == record.session_id
    assert authority.policy_template == ZERO_WRITE_TEMPLATE
    assert authority.logical_task_id == row["logical_task_id"]
    assert authority.source_request_id == request_id
    assert authority.level == "workspace"
    assert authority.apply_mode == "direct"
    # The zero-local-write surface is preserved, not quietly widened.
    assert authority.writable_roots == []

    # 6. The already-running process reconstructs the new authority with no
    # restart: a freshly constructed OperatorPolicy in the SAME process sees it.
    after = op.OperatorPolicy()
    assert after.session_status == "task_bound"
    assert after.session_id == record.session_id
    assert after.policy_template == ZERO_WRITE_TEMPLATE
    assert after.level == "workspace"
    assert after.writable_roots == []
    # ... and still cannot write anywhere locally, because there are no roots.
    assert after.allowed_paths == [Path(p) for p in authority.readable_roots]


def test_status_surface_reports_the_dedicated_session_not_standing(session_env, monkeypatch):
    """The reported symptom: status kept naming the standing authority."""
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(session_env))
    request_id = _request_zero_write_session(session_env)
    record = sessions.approve_session_request(
        request_id, decided_by="localhost", root=session_env, now=2_000_000_010,
    )

    policy = op.OperatorPolicy()
    assert policy.authority_kind == "task_bound"
    assert policy.session_status != "standing"
    assert policy.session_id == record.session_id

    summary = policy.to_summary()
    assert summary["session_status"] == "task_bound"
    assert summary["session_id"] == record.session_id
    assert summary["session_failure_reason"] is None


# ---------------------------------------------------------------------------
# 7. Approval surface and MCP server on different session roots.
# ---------------------------------------------------------------------------

def test_divergent_session_roots_are_detectable_and_fail_closed(tmp_path, monkeypatch):
    """An approval recorded under one root must never silently grant authority
    to a component resolving a different root -- and the divergence must be
    readable off each component rather than having to be inferred."""
    approver_root = tmp_path / "approver-sessions"
    server_root = tmp_path / "server-sessions"
    lease_dir = tmp_path / "leases"
    lease_path = lease_dir / "mission-control-lease.json"
    monkeypatch.setattr(lease, "_LEASE_STATE_DIR", lease_dir)
    monkeypatch.setattr(lease, "_LEASE_STATE_PATH", lease_path)
    monkeypatch.setattr(lease, "_LEASE_LOCK_PATH", lease_dir / "mission-control-lease.lock")
    lease_dir.mkdir(parents=True, exist_ok=True)
    lease_now = lease._now()
    lease_path.write_text(json.dumps({
        "owner": "chatgpt-mission-control",
        "token": "fixture-token-never-returned",
        "issued_at": lease_now,
        "expires_at": lease_now + 3600,
        "lease_id": "fixture-divergent-root-lease",
    }), encoding="utf-8")
    for name in [
        op.OPERATOR_ENABLED_ENV, op.OPERATOR_LEVEL_ENV, op.OPERATOR_APPLY_MODE_ENV,
        op.OPERATOR_ALLOWED_PATHS_ENV, op.OWNER_ACK_ENV,
    ]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv(sessions.ACTIVE_SESSION_ID_ENV, raising=False)

    # The approval surface approves against ITS root.
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(approver_root))
    request_id = _request_zero_write_session(approver_root)
    record = sessions.approve_session_request(
        request_id, decided_by="localhost", root=approver_root, now=2_000_000_010,
    )
    approver_binding = sessions.session_deployment_binding()
    assert approver_binding["session_root"] == str(approver_root)
    assert approver_binding["active_session_id"] == record.session_id

    # The MCP server resolves a DIFFERENT root: no authority, and it says so.
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(server_root))
    server_binding = sessions.session_deployment_binding()
    assert server_binding["session_root"] == str(server_root)
    assert server_binding["active_session_id"] is None
    assert server_binding["session_root"] != approver_binding["session_root"]
    assert server_binding["db_path"] != approver_binding["db_path"]
    assert server_binding["active_pointer_path"] != approver_binding["active_pointer_path"]

    authority = sessions.resolve_effective_authority(now=2_000_000_011)
    assert authority.is_active is False
    assert authority.level == "read_only"
    assert authority.apply_mode == "dry_run"
    assert authority.failure_reason

    # Even a stale startup-time env id pointing at the other root's session
    # cannot re-grant it: the session simply does not exist in this store.
    monkeypatch.setenv(sessions.ACTIVE_SESSION_ID_ENV, record.session_id)
    stale = sessions.resolve_effective_authority(now=2_000_000_011)
    assert stale.is_active is False
    assert stale.status == "missing"
    assert stale.pointed_session_id == record.session_id
    assert op.OperatorPolicy().level == "read_only"


# ---------------------------------------------------------------------------
# 9. Duplicate approval.
# ---------------------------------------------------------------------------

def test_duplicate_approval_is_rejected_and_creates_no_second_session(session_env):
    request_id = _request_zero_write_session(session_env)
    record = sessions.approve_session_request(request_id, root=session_env, now=2_000_000_010)
    assert _session_count(session_env) == 1

    with pytest.raises(ValueError, match="already approved"):
        sessions.approve_session_request(request_id, root=session_env, now=2_000_000_011)

    assert _session_count(session_env) == 1
    pointer = sessions._active_pointer_path(session_env)
    assert pointer.read_text(encoding="utf-8").strip() == record.session_id


# ---------------------------------------------------------------------------
# 10. Approval failure leaves no partial authority.
# ---------------------------------------------------------------------------

def test_task_authority_failure_leaves_no_partial_authority(session_env, monkeypatch):
    request_id = _request_zero_write_session(session_env)

    def _boom(**_kwargs):
        raise RuntimeError("task authority store unavailable")

    monkeypatch.setattr(task_authority, "grant_external_approval", _boom)
    with pytest.raises(RuntimeError, match="task authority store unavailable"):
        sessions.approve_session_request(request_id, root=session_env, now=2_000_000_010)

    # The pointer was never moved, the request was never spent, and no live
    # authority exists.
    assert not sessions._active_pointer_path(session_env).exists()
    assert _request_row(session_env, request_id)["status"] == "pending"
    assert _request_row(session_env, request_id)["resulting_session_id"] is None
    authority = sessions.resolve_effective_authority(now=2_000_000_011)
    assert authority.is_active is False


def test_incoherent_policy_is_refused_before_a_human_is_asked(session_env):
    """The approval-consuming failure mode: refuse at REQUEST time."""
    with pytest.raises(sessions.SessionPolicyInvariantError, match="could never become live"):
        sessions.request_session(
            policy_template="phantom-template",
            resolved_policy=_incoherent_policy(),
            requested_duration_seconds=3600,
            reason="[task:incoherent] should never reach a human",
            root=session_env,
            now=2_000_000_000,
        )
    assert sessions.list_pending_session_requests(root=session_env) == []


def test_incoherent_snapshot_approval_fails_atomically_and_keeps_request_pending(session_env, monkeypatch):
    """If such a request already exists (recorded by older code), approving it
    must not consume the approval, mint a session, or move the pointer."""
    # Bypass the request-time guard to simulate a row written before the fix.
    monkeypatch.setattr(sessions, "snapshot_authority_defect", lambda policy: None)
    request_id = sessions.request_session(
        policy_template="phantom-template",
        resolved_policy=_incoherent_policy(),
        requested_duration_seconds=3600,
        reason="[task:legacy-incoherent] recorded before the fix",
        root=session_env,
        now=2_000_000_000,
        request_id="sr_legacy",
    )
    monkeypatch.undo()

    with pytest.raises(sessions.SessionPolicyInvariantError, match="remains pending and unspent"):
        sessions.approve_session_request(request_id, decided_by="localhost", root=session_env, now=2_000_000_010)

    assert _session_count(session_env) == 0
    assert not sessions._active_pointer_path(session_env).exists()
    row = _request_row(session_env, request_id)
    assert row["status"] == "pending"
    assert row["resulting_session_id"] is None
    assert row["decided_by"] is None


def test_create_session_refuses_an_unresolvable_approved_snapshot(session_env):
    """Final chokepoint: no caller can persist approved-but-unresolvable."""
    with pytest.raises(sessions.SessionPolicyInvariantError, match="can never become the effective authority"):
        sessions.create_session(_incoherent_policy(), root=session_env, approval_state="approved")

    # A not-yet-approved record is still allowed; the invariant binds approval.
    pending = sessions.create_session(
        _incoherent_policy(), root=session_env, approval_state="pending",
    )
    assert pending.approval_state == "pending"


def test_snapshot_defect_distinguishes_deliberate_from_lost_write_roots():
    """The discriminator itself: only the LOCAL template registry can say that
    an empty write surface is the approved design."""
    registered = templates.resolve_template(ZERO_WRITE_TEMPLATE)["policy"]
    assert registered["level"] == "workspace"
    assert registered["writable_roots"] == []
    assert sessions.snapshot_authority_defect(
        {**registered, "policy_template": ZERO_WRITE_TEMPLATE}
    ) is None

    # Same shape, template this deployment cannot vouch for -> fails closed.
    assert sessions.snapshot_authority_defect(_incoherent_policy()) is not None
    # Same shape, no template at all -> fails closed.
    assert sessions.snapshot_authority_defect(
        {**registered, "policy_template": None}
    ) is not None
    # A registered template that DOES declare write roots, with the roots
    # missing from the snapshot, is still the drift the check was written for.
    maintenance = templates.resolve_template("hermes-gpt-operator-maintenance")["policy"]
    assert maintenance["writable_roots"]
    assert sessions.snapshot_authority_defect(
        {**maintenance, "policy_template": "hermes-gpt-operator-maintenance", "writable_roots": []}
    ) is not None


# ---------------------------------------------------------------------------
# 8. Standing authority behaviour is untouched by all of the above.
# ---------------------------------------------------------------------------

def test_standing_authority_remains_the_fallback_only_when_no_session_is_live(session_env, monkeypatch):
    """Session and standing authority stay non-composable: a live task-bound
    session is reported as itself, and standing is consulted only when no
    session authority resolves -- never merged with one."""
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(session_env))
    calls: list[str | None] = []

    def _spy(standing_authority_id=None):
        calls.append(standing_authority_id)
        return None, None, None, "no standing authority configured"

    monkeypatch.setattr(op, "_resolve_standing_policy_snapshot", _spy)

    # No session yet -> standing is consulted.
    assert op.OperatorPolicy().level == "read_only"
    assert len(calls) == 1

    request_id = _request_zero_write_session(session_env)
    sessions.approve_session_request(request_id, decided_by="localhost", root=session_env, now=2_000_000_010)

    # Live session -> standing is NOT consulted at all, so the two authorities
    # can never be combined.
    policy = op.OperatorPolicy()
    assert policy.authority_kind == "task_bound"
    assert len(calls) == 1


def test_hermes_exec_gate_accepts_task_bound_authority(session_env, monkeypatch):
    """The second production blocker: the fixed-purpose tool's gate predated
    Task-Bound Authority v2 and required session_status == 'active', which a
    healthy v2 session never reports."""
    # The gate moved to operator_first_safe when FIRST_SAFE was split into
    # prepare/verify and execution left the connector path; the property under
    # test -- a task_bound session satisfies it -- is unchanged.
    import operator_first_safe as first_safe

    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(session_env))
    request_id = _request_zero_write_session(session_env)
    sessions.approve_session_request(request_id, decided_by="localhost", root=session_env, now=2_000_000_010)
    assert op.OperatorPolicy().session_status == "task_bound"

    policy = first_safe._require_first_safe_authority(for_mutation=True)
    assert policy.session_status == "task_bound"
    assert policy.policy_template == "hermes-exec-first-safe-model"
    assert first_safe.spec.fixed_plan()["arbitrary_remote_command_surface"] is False
