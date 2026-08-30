"""Regression tests for narrow Mission Control lease verification under the
hermes-exec-first-safe-model authority.

Mission Control must verify it holds the coordination lease before invoking the
fixed-purpose VM operation. Under the FIRST_SAFE session that failed with
"Verb filesystem:read is not granted by this Operator Session", because
operator_lease._require_operator_authority() gated every lease operation --
including the read-only status report -- behind the broad filesystem:read verb.

The repair gives the fixed-purpose status operation its own narrow capability,
mission_control:lease_status, and grants exactly that (and nothing else) to the
FIRST_SAFE template. These tests pin both halves: the lease check works, and
nothing about FIRST_SAFE's local read/write surface moved.

Everything here runs against REAL resolved policies and REAL approved sessions
in an isolated session root -- no stubbed OperatorPolicy -- because the whole
claim under test is what the authorization layer actually does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import operator_lease as lease
import operator_policy as op
import operator_policy_templates as templates
import operator_risk as risk
import operator_sessions as sessions
import operator_workspace as ows

FIRST_SAFE = "hermes-exec-first-safe-model"
MAINTENANCE = "hermes-gpt-operator-maintenance"


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
    # Every test in this module uses an isolated lease store because FIRST_SAFE
    # approval itself now requires a live Mission Control lease.
    state_dir = tmp_path / "leases"
    monkeypatch.setattr(lease, "_LEASE_STATE_DIR", state_dir)
    monkeypatch.setattr(lease, "_LEASE_STATE_PATH", state_dir / "mission-control-lease.json")
    monkeypatch.setattr(lease, "_LEASE_LOCK_PATH", state_dir / "mission-control-lease.lock")
    op.set_audit_log_override(tmp_path / "audit.jsonl")
    yield root
    op.set_audit_log_override(None)


@pytest.fixture
def lease_state(session_env) -> Path:
    """Return the already-isolated lease record path."""
    return lease._LEASE_STATE_PATH


def _approve(root: Path, template: str, *, now: int = 2_000_000_000) -> sessions.SessionRecord:
    """Request + approve a real session through the same function the localhost
    page and the Telegram resolve endpoint call."""
    if template == FIRST_SAFE:
        _seed_live_lease(lease._LEASE_STATE_PATH)
    resolved = templates.resolve_template(template)
    request_id = sessions.request_session(
        policy_template=template,
        resolved_policy=resolved["policy"],
        requested_duration_seconds=3600,
        reason=f"[task:lease-capability-{template}] regression fixture",
        root=root,
        now=now,
    )
    return sessions.approve_session_request(
        request_id, decided_by="localhost", root=root, now=now + 1,
    )


def _seed_live_lease(path: Path, *, owner: str = "chatgpt-mission-control", ttl: int = 3600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = lease._now()
    path.write_text(json.dumps({
        "owner": owner,
        "token": "fixture-token-never-returned",
        "issued_at": now,
        "expires_at": now + ttl,
        "lease_id": "fixture-lease-id",
    }), encoding="utf-8")


def _request_first_safe(root: Path, *, now: int = 2_000_000_000) -> str:
    resolved = templates.resolve_template(FIRST_SAFE)
    return sessions.request_session(
        policy_template=FIRST_SAFE,
        resolved_policy=resolved["policy"],
        requested_duration_seconds=3600,
        reason="[task:first-safe-approval-lease-gate] regression fixture",
        root=root,
        now=now,
    )


# ---------------------------------------------------------------------------
# A. Approval cannot outrun the Mission Control lease.
# ---------------------------------------------------------------------------

def test_first_safe_approval_without_lease_fails_closed_and_stays_pending(session_env, lease_state):
    lease_state.unlink(missing_ok=True)
    request_id = _request_first_safe(session_env)

    with pytest.raises(PermissionError, match="requires an existing Mission Control lease"):
        sessions.approve_session_request(
            request_id, decided_by="localhost", root=session_env, now=2_000_000_001,
        )

    pending = {item["request_id"] for item in sessions.list_pending_session_requests(root=session_env)}
    assert request_id in pending
    authority = sessions.resolve_effective_authority(now=2_000_000_002)
    assert authority.is_active is False
    assert authority.session_id is None


def test_first_safe_approval_rejects_wrong_or_expired_lease(session_env, lease_state):
    request_id = _request_first_safe(session_env)

    _seed_live_lease(lease_state, owner="someone-else")
    with pytest.raises(PermissionError, match="current owner is different"):
        sessions.approve_session_request(
            request_id, decided_by="localhost", root=session_env, now=2_000_000_001,
        )

    _seed_live_lease(lease_state, ttl=-1)
    with pytest.raises(PermissionError, match="current lease is expired"):
        sessions.approve_session_request(
            request_id, decided_by="localhost", root=session_env, now=2_000_000_002,
        )

    pending = {item["request_id"] for item in sessions.list_pending_session_requests(root=session_env)}
    assert request_id in pending


def test_first_safe_approval_with_live_mission_control_lease_succeeds(session_env, lease_state):
    _seed_live_lease(lease_state)
    request_id = _request_first_safe(session_env)
    record = sessions.approve_session_request(
        request_id, decided_by="localhost", root=session_env, now=2_000_000_001,
    )

    assert record.approval_state == "approved"
    authority = sessions.resolve_effective_authority(now=2_000_000_002)
    assert authority.is_active is True
    assert authority.session_id == record.session_id
    assert authority.policy_template == FIRST_SAFE
    assert authority.writable_roots == []


# ---------------------------------------------------------------------------
# B. Narrow lease status works under FIRST_SAFE authority.
# ---------------------------------------------------------------------------

def test_first_safe_authority_can_read_lease_status(session_env, lease_state):
    _approve(session_env, FIRST_SAFE)
    _seed_live_lease(lease_state)

    policy = op.OperatorPolicy()
    assert policy.policy_template == FIRST_SAFE
    assert policy.session_status == "task_bound"
    assert policy.has_verb("mission_control", "lease_status") is True
    assert policy.has_verb("filesystem", "read") is False

    result = json.loads(lease.hermes_mission_control_lease_status(owner="chatgpt-mission-control"))
    assert result["success"] is True, result
    assert result["has_lease"] is True
    assert result["owner"] == "chatgpt-mission-control"
    assert result["owner_match"] is True
    assert result["lease_id"] == "fixture-lease-id"
    assert result["ttl_seconds"] > 0
    # The release token is never disclosed.
    assert "token" not in json.dumps(result)


def test_lease_status_reports_only_fixed_coordination_state(session_env, lease_state):
    _approve(session_env, FIRST_SAFE)
    _seed_live_lease(lease_state)
    result = json.loads(lease.hermes_mission_control_lease_status())

    assert set(result) <= {
        "success", "has_lease", "owner", "owner_match", "ttl_seconds",
        "expires_at", "issued_at", "lease_id", "requested_owner",
    }
    # No path parameter exists to abuse: the tool's whole signature is an
    # optional owner string and a boolean, and the record it reads is a module
    # constant, not an argument.
    import inspect
    params = inspect.signature(lease.hermes_mission_control_lease_status).parameters
    assert list(params) == ["owner", "require_owner_match"]
    assert lease._LEASE_STATE_PATH.parent == lease._LEASE_STATE_DIR
    source = inspect.getsource(lease.verify_lease)
    assert "_LEASE_STATE_PATH" not in source, "status must not compute its own path"
    assert "open(" not in source and "read_text" not in source


def test_narrow_capability_caller_never_writes(session_env, lease_state):
    """An expired record must not be unlinked by a zero-write authority."""
    _approve(session_env, FIRST_SAFE)
    _seed_live_lease(lease_state, ttl=-10)  # already expired
    assert lease_state.exists()

    result = json.loads(lease.hermes_mission_control_lease_status())
    assert result["success"] is True
    assert result["has_lease"] is False
    assert result["was_expired"] is True
    assert result["expired_record_reaped"] is False
    # The one incidental write lease status can otherwise perform did not happen.
    assert lease_state.exists()


def test_broad_legacy_caller_still_reaps_expired_records(session_env, lease_state):
    """Templates granting filesystem:read keep the pre-existing behaviour."""
    _approve(session_env, MAINTENANCE)
    _seed_live_lease(lease_state, ttl=-10)
    assert op.OperatorPolicy().has_verb("filesystem", "read") is True

    result = json.loads(lease.hermes_mission_control_lease_status())
    assert result["was_expired"] is True
    assert result["expired_record_reaped"] is True
    assert not lease_state.exists()


# ---------------------------------------------------------------------------
# B. General file read remains denied.
# ---------------------------------------------------------------------------

def test_first_safe_cannot_read_arbitrary_files(session_env, lease_state, tmp_path):
    _approve(session_env, FIRST_SAFE)
    target = tmp_path / "secret-ish.txt"
    target.write_text("should never be readable", encoding="utf-8")

    out = json.loads(ows.hermes_workspace_read(path=str(target)))
    assert out.get("success") is not True

    # Also inside the one readable root the template does declare, and against
    # the operator's own source tree, and against genuinely sensitive paths.
    for candidate in (
        "/home/jfroh/.hermes/.env",
        "/home/jfroh/.ssh/id_rsa",
        "/home/jfroh/.hermes/ops-brain",
        str(lease_state),
    ):
        denied = json.loads(ows.hermes_workspace_read(path=candidate))
        assert denied.get("success") is not True, candidate


def test_first_safe_read_surface_is_exactly_its_declared_readable_root(session_env, tmp_path):
    """Honest boundary, pinned so it cannot drift.

    FIRST_SAFE declares one readable root (the operator release tree) in the
    immutable snapshot the human approves, and read authority in this operator
    is expressed by readable_roots -- not by the filesystem:read verb, which a
    handful of tools use as a separate coarse marker. So reads INSIDE that one
    declared root are permitted and reads outside it are not. Adding
    mission_control:lease_status changed neither side of that line.
    """
    _approve(session_env, FIRST_SAFE)
    policy = op.OperatorPolicy()
    declared = [str(p) for p in policy.readable_roots]
    assert declared == [
        "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt/.release-preservation"
    ]

    inside = Path(declared[0]) / "operator_policy.py"
    if inside.is_file():
        allowed = json.loads(ows.hermes_workspace_read(path=str(inside)))
        assert allowed.get("success") is True, (
            "in-root reads are part of the approved FIRST_SAFE snapshot; if this "
            "ever fails the template's readable_roots changed"
        )

    outside = tmp_path / "outside.txt"
    outside.write_text("nope", encoding="utf-8")
    for candidate in (str(outside), "/home/jfroh/.hermes/.env", "/home/jfroh/.ssh/id_rsa",
                      "/home/jfroh/.hermes/config.yaml", "/home/jfroh/.hermes/ops-brain"):
        denied = json.loads(ows.hermes_workspace_read(path=candidate))
        assert denied.get("success") is not True, candidate


def test_search_files_honours_session_readable_roots(session_env, tmp_path, monkeypatch):
    """hermes_search_files was the one registered read tool with no operator
    guard at all: it searched and returned file content from anywhere on the
    host regardless of the session's readable roots."""
    import server

    _approve(session_env, FIRST_SAFE)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "notes.txt").write_text("findme", encoding="utf-8")

    with pytest.raises(Exception) as excinfo:
        server.hermes_search_files(pattern="findme", target="content", path=str(outside))
    assert "readable root" in str(excinfo.value).lower() or "denied" in str(excinfo.value).lower()


def test_first_safe_policy_metadata_grants_no_filesystem_read(session_env):
    _approve(session_env, FIRST_SAFE)
    policy = op.OperatorPolicy()

    assert "read" not in policy.verbs.get("filesystem", [])
    assert policy.verbs == {
        "filesystem": ["edit"],
        "tests": ["run"],
        "mission_control": ["lease_status"],
    }
    with pytest.raises(PermissionError, match="filesystem:read"):
        policy.require_verb("filesystem", "read")
    # The narrow capability is not a filesystem verb and cannot be spent as one.
    with pytest.raises(PermissionError):
        policy.require_read_path("/home/jfroh/.hermes/.env")


# ---------------------------------------------------------------------------
# C/D. FIRST_SAFE policy invariants unchanged by this repair.
# ---------------------------------------------------------------------------

def test_first_safe_template_invariants_hold(session_env):
    resolved = templates.resolve_template(FIRST_SAFE)
    policy = resolved["policy"]

    assert policy["writable_roots"] == []
    assert policy["level"] == "workspace"
    assert policy["apply_mode"] == "direct"
    assert policy["allowed_profiles"] == ["default"]
    assert policy["egress_hosts"] == ["hermes-exec"]
    assert policy["paid_route_change"] == "none"
    assert policy["has_secret_access"] is False
    assert policy["has_credential_access"] is False
    assert policy["has_client_identifiable_data"] is False
    assert policy["has_financial_data"] is False
    assert policy["has_external_communication"] is False
    assert resolved["risk_tier"] == 3
    assert resolved["standing_authority_eligible"] is False

    # ... and the approved session carries them through unchanged.
    record = _approve(session_env, FIRST_SAFE)
    assert record.policy["writable_roots"] == []
    assert op.OperatorPolicy().writable_roots == []


def test_first_safe_risk_classification_is_unchanged_by_the_new_capability():
    """mission_control:lease_status must be inert to risk: it is not a write,
    delete, commit, force-push, deployment or service verb."""
    normalized = sessions.normalize_policy(
        {**templates.resolve_template(FIRST_SAFE)["policy"], "policy_template": FIRST_SAFE}
    )
    factors = risk.compute_risk_factors_from_session(normalized, template_baseline=normalized)
    decision = risk.classify_risk(factors)

    assert "mission_control:lease_status" in factors.verbs
    assert decision.risk_class == risk.RiskClass.HIGH
    assert decision.tier == 3
    assert decision.standing_authority_eligible is False
    assert factors.has_delete is False
    assert factors.has_force_push is False

    # The precise claim: the new verb is inert to risk. Classify the identical
    # policy with the capability stripped and require every risk-bearing factor
    # and the whole decision to be unchanged. (has_write stays True either way
    # -- it comes from the pre-existing filesystem:edit token the fixed remote
    # operation needs, not from anything added here.)
    without = dict(normalized)
    without["verbs"] = {k: v for k, v in normalized["verbs"].items() if k != "mission_control"}
    bare = risk.compute_risk_factors_from_session(without, template_baseline=without)
    baseline = risk.classify_risk(bare)

    assert "mission_control:lease_status" not in bare.verbs
    assert (baseline.risk_class, baseline.tier) == (decision.risk_class, decision.tier)
    assert baseline.standing_authority_eligible == decision.standing_authority_eligible
    for field in (
        "has_write", "has_delete", "has_force_push", "has_service_restart",
        "has_deployment", "egress_class", "writable_roots", "roots",
        "root_expansion",
    ):
        assert getattr(bare, field) == getattr(factors, field), field


# ---------------------------------------------------------------------------
# E. Lease status grants no authority.
# ---------------------------------------------------------------------------

def test_reading_lease_status_changes_no_authority(session_env, lease_state):
    record = _approve(session_env, FIRST_SAFE)
    _seed_live_lease(lease_state)

    def snapshot() -> dict:
        authority = sessions.resolve_effective_authority()
        policy = op.OperatorPolicy()
        return {
            "session_id": authority.session_id,
            "status": authority.status,
            "authority_kind": authority.authority_kind,
            "logical_task_id": authority.logical_task_id,
            "level": policy.level,
            "apply_mode": policy.apply_mode,
            "writable_roots": [str(p) for p in policy.writable_roots],
            "readable_roots": [str(p) for p in policy.readable_roots],
            "verbs": policy.verbs,
            "snapshot_hash": policy.snapshot_hash,
            "pointer": sessions._active_pointer_path(session_env).read_text(encoding="utf-8").strip(),
        }

    before = snapshot()
    result = json.loads(lease.hermes_mission_control_lease_status(owner="chatgpt-mission-control"))
    assert result["success"] is True and result["has_lease"] is True
    after = snapshot()

    assert before == after
    assert after["session_id"] == record.session_id
    assert after["writable_roots"] == []


# ---------------------------------------------------------------------------
# F. Other lease lifecycle operations stay governed and stay out of reach.
# ---------------------------------------------------------------------------

def test_first_safe_cannot_acquire_or_release_the_lease(session_env, lease_state):
    _approve(session_env, FIRST_SAFE)
    _seed_live_lease(lease_state)
    before = lease_state.read_text(encoding="utf-8")

    acquired = json.loads(lease.hermes_mission_control_lease_acquire(owner="first-safe"))
    assert acquired.get("success") is not True
    released = json.loads(lease.hermes_mission_control_lease_release(token="fixture-token-never-returned"))
    assert released.get("success") is not True

    # Holding the narrow inspection capability changed nothing about the lease.
    assert lease_state.read_text(encoding="utf-8") == before


def test_narrow_capability_alone_does_not_reach_the_mutation_guard(session_env):
    """The acquire/release/token-verify path is pinned to the broad verb, so
    'may check the lease' can never be spent as 'may take the lease'."""
    _approve(session_env, FIRST_SAFE)
    with pytest.raises(PermissionError, match="filesystem:read"):
        lease._require_operator_authority(mutate=False)
    with pytest.raises(PermissionError, match="filesystem:read"):
        lease._require_operator_authority(mutate=True)

    # Whereas the status path is authorized, and reports it used the narrow one.
    policy, may_reap = lease._require_lease_status_authority()
    assert policy.policy_template == FIRST_SAFE
    assert may_reap is False


def test_maintenance_authority_retains_full_lease_lifecycle(session_env, lease_state):
    """No template that could previously drive the lease lost anything."""
    _approve(session_env, MAINTENANCE)
    acquired = json.loads(lease.hermes_mission_control_lease_acquire(owner="chatgpt-mission-control"))
    assert acquired["success"] is True, acquired
    status = json.loads(lease.hermes_mission_control_lease_status(owner="chatgpt-mission-control"))
    assert status["success"] is True and status["owner_match"] is True
    released = json.loads(lease.hermes_mission_control_lease_release(token=acquired["token"]))
    assert released["success"] is True, released


# ---------------------------------------------------------------------------
# The capability primitive itself.
# ---------------------------------------------------------------------------

def test_require_any_verb_accepts_either_and_reports_which(session_env):
    _approve(session_env, FIRST_SAFE)
    narrow = op.OperatorPolicy()
    assert narrow.require_any_verb(
        [lease.LEASE_STATUS_CAPABILITY, lease.LEASE_STATUS_LEGACY_CAPABILITY]
    ) == lease.LEASE_STATUS_CAPABILITY

    with pytest.raises(PermissionError, match="None of the required capabilities"):
        narrow.require_any_verb([("filesystem", "read"), ("git", "push")])


def test_no_other_template_gained_the_narrow_capability():
    """The grant is confined to the two dedicated FIRST_SAFE gates only."""
    holders = {
        name for name in templates.active_template_names()
        if "lease_status" in templates.resolve_template(name)["policy"]
        .get("verbs", {}).get("mission_control", [])
    }
    assert holders == {FIRST_SAFE, "hermes-exec-first-safe-provision"}


# ---------------------------------------------------------------------------
# Prior repair (OPERATOR_APPROVAL_ACTIVATION_REPAIRED) still holds.
# ---------------------------------------------------------------------------

def test_zero_write_snapshot_still_activates_without_restart(session_env):
    before = op.OperatorPolicy()
    assert before.session_status == "none_configured"

    record = _approve(session_env, FIRST_SAFE)

    after = op.OperatorPolicy()
    assert after.session_status == "task_bound"
    assert after.session_id == record.session_id
    assert after.policy_template == FIRST_SAFE
    assert after.writable_roots == []
    assert sessions.snapshot_authority_defect(
        {**templates.resolve_template(FIRST_SAFE)["policy"], "policy_template": FIRST_SAFE}
    ) is None


def test_first_safe_tool_gate_still_accepts_task_bound(session_env):
    # The gate moved to operator_first_safe with the prepare/verify split; the
    # property under test -- task_bound satisfies FIRST_SAFE -- is unchanged.
    import operator_first_safe as first_safe

    _approve(session_env, FIRST_SAFE)
    assert op.OperatorPolicy().session_status == "task_bound"
    policy = first_safe._require_first_safe_authority(for_mutation=True)
    assert policy.session_status == "task_bound"
    assert policy.policy_template == FIRST_SAFE
