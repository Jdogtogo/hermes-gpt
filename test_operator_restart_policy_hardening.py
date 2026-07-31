"""Regression tests for the operator-service-restart policy hardening.

Context: docs/OPERATOR_RESTART_INVESTIGATION.md. A stale approval-web writer
process (pre-``policy_template`` persistence) minted approved sessions whose
snapshots lacked ``policy_template``; the freshly-deployed operator server then
rejected ``hermes_operator_service_restart`` because its gate required that
field. The hardening:

  1. create_session refuses to persist an *approved* snapshot with no
     policy_template (SessionPolicyInvariantError), and approve_session_request
     asserts the same at the approval boundary;
  2. OperatorPolicy exposes policy_template sourced from the SAME snapshot as
     level/verbs/service_units, so the restart gate reads one authoritative
     resolution rather than a second, independently-resolved lookup.

These tests exercise the real request -> approve -> resolve -> restart paths.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

import operator_policy as op
import operator_policy_templates as templates
import operator_sessions as sessions
import operator_workspace as ows

MAINTENANCE = "hermes-gpt-operator-maintenance"
OPERATOR_UNIT = "hermes-gpt-chatgpt-operator.service"
APPROVAL_WEB_MAINTENANCE = "hermes-approval-web-maintenance"
APPROVAL_WEB_UNIT = "hermes-gpt-approval-web.service"


@pytest.fixture
def session_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "sessions"
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(root))
    for name in [
        op.OPERATOR_ENABLED_ENV,
        op.OPERATOR_LEVEL_ENV,
        op.OPERATOR_APPLY_MODE_ENV,
        op.OPERATOR_ALLOWED_PATHS_ENV,
        op.OWNER_ACK_ENV,
        sessions.ACTIVE_SESSION_ID_ENV,
    ]:
        monkeypatch.delenv(name, raising=False)
    op.set_audit_log_override(tmp_path / "audit.jsonl")
    yield root
    op.set_audit_log_override(None)


def _fail_runner(*args, **kwargs):
    pytest.fail("systemd runner must not be called on a denied/dry-run restart")


def _request_and_approve(root: Path, template: str, *, decided_by: str, minutes: int = 60):
    """Mirror server.hermes_operator_session_request then the human approval
    (Telegram / localhost / break-glass CLI all converge on
    approve_session_request, differing only in decided_by)."""
    resolved = templates.resolve_template(template)
    capped = min(max(60, minutes * 60), resolved["max_duration_seconds"])
    request_id = sessions.request_session(
        policy_template=template,
        resolved_policy=resolved["policy"],
        requested_duration_seconds=capped,
        reason="restart-policy-hardening regression",
        root=root,
    )
    return sessions.approve_session_request(request_id, decided_by=decided_by, root=root)


def _write_stale_writer_session(root: Path, workspace: Path, *, session_id: str = "ops-stale-legacy") -> str:
    """Reproduce what a STALE writer process left in the live DB: an approved,
    workspace-level session that grants services:restart for the operator unit,
    but whose canonical snapshot has NO policy_template key at all. Deliberately
    bypasses create_session (whose new invariant would refuse to write this) so
    we can prove the NEW reader/gate fail-closes on legacy data."""
    policy = {
        "level": "workspace",
        "apply_mode": "direct",
        "readable_roots": [str(workspace)],
        "writable_roots": [str(workspace)],
        "service_units": [OPERATOR_UNIT],
        "verbs": {"filesystem": ["read", "edit"], "services": ["restart"], "tests": ["run"]},
    }
    normalized = sessions.normalize_policy(policy)
    normalized.pop("policy_template", None)  # the stale-writer omission
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    now = int(time.time())
    created, expires = now - 60, now + 3600  # currently valid (reader uses real now)
    with sessions._connect(root) as con:
        con.execute(
            "INSERT OR IGNORE INTO policy_snapshots(snapshot_hash, canonical_json, created_at) VALUES (?, ?, ?)",
            (digest, canonical, created),
        )
        con.execute(
            "INSERT INTO operator_sessions(session_id, snapshot_hash, created_at, expires_at, revoked_at, approval_state) "
            "VALUES (?, ?, ?, ?, NULL, 'approved')",
            (session_id, digest, created, expires),
        )
    sessions._write_active_pointer(session_id, root=root)
    return session_id


# 1. Normal Telegram approval -------------------------------------------------

def test_normal_telegram_approval_binds_policy_template_and_allows_restart(session_root):
    record = _request_and_approve(session_root, MAINTENANCE, decided_by="telegram:8595123783")
    assert record.policy["policy_template"] == MAINTENANCE

    authority = sessions.resolve_effective_authority()
    assert authority.is_active is True
    assert authority.policy_template == MAINTENANCE

    out = ows.hermes_operator_service_restart(
        dry_run=True, runner=_fail_runner,
        systemd_run_binary="/usr/bin/systemd-run", systemctl_binary="/usr/bin/systemctl",
    )
    parsed = json.loads(out)
    assert parsed["success"] is True
    assert parsed["plan"]["would_schedule_restart"] is True
    assert parsed["plan"]["service_unit"] == OPERATOR_UNIT


# 2. Localhost / break-glass approval ----------------------------------------

def test_localhost_break_glass_approval_binds_policy_template(session_root):
    # The localhost approval page and the break-glass CLI both call
    # approve_session_request; only decided_by differs from Telegram.
    record = _request_and_approve(session_root, MAINTENANCE, decided_by="local-cli")
    assert record.policy["policy_template"] == MAINTENANCE

    policy = op.OperatorPolicy()
    assert policy.session_status == "active"
    assert policy.session_id == record.session_id
    assert policy.policy_template == MAINTENANCE  # single authoritative source


# 3. Missing policy_template --------------------------------------------------

def test_missing_policy_template_is_refused_at_approval(session_root):
    resolved = templates.resolve_template(MAINTENANCE)
    request_id = sessions.request_session(
        policy_template="",  # unbound request (e.g. produced by a stale writer)
        resolved_policy=resolved["policy"],
        requested_duration_seconds=3600,
        reason="unbound",
        root=session_root,
    )
    with pytest.raises(sessions.SessionPolicyInvariantError):
        sessions.approve_session_request(request_id, decided_by="telegram:8595123783", root=session_root)
    # No authority may have been minted by the failed approval.
    assert sessions.active_session() is None


def test_missing_policy_template_is_refused_at_creation(session_root, tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    with pytest.raises(sessions.SessionPolicyInvariantError):
        sessions.create_session(
            {
                "level": "workspace",
                "apply_mode": "direct",
                "readable_roots": [str(workspace)],
                "writable_roots": [str(workspace)],
                "verbs": {"filesystem": ["read", "edit"]},
            },
            root=session_root,
            session_id="ops-unbound",
        )


# 4. Stale writer / new reader version mismatch -------------------------------

def test_stale_writer_snapshot_is_denied_by_new_reader(session_root, tmp_path):
    workspace = tmp_path / "ws"
    workspace.mkdir()
    _write_stale_writer_session(session_root, workspace)

    # The NEW reader sees an active, workspace-level session -- but with no
    # bound template (exactly the incident's split-brain shape).
    authority = sessions.resolve_effective_authority()
    assert authority.is_active is True
    assert authority.level == "workspace"
    assert authority.policy_template is None

    # Ordinary workspace authority still resolves (why workspace edits kept
    # working during the incident)...
    policy = op.OperatorPolicy()
    policy.require_level("workspace")  # must not raise
    assert policy.policy_template is None

    # ...but the restart gate fail-closes on the unbound legacy snapshot.
    out = ows.hermes_operator_service_restart(
        dry_run=True, runner=_fail_runner,
        systemd_run_binary="/usr/bin/systemd-run", systemctl_binary="/usr/bin/systemctl",
    )
    parsed = json.loads(out)
    assert parsed["success"] is False
    assert "policy template" in parsed["error"].lower()


# 5. Maintenance-policy restart allowed --------------------------------------

def test_maintenance_policy_restart_allowed_schedules_exact_unit(session_root):
    _request_and_approve(session_root, MAINTENANCE, decided_by="telegram:8595123783")
    captured = {}

    def fake_runner(argv, timeout=120, workdir=None):
        captured["argv"] = argv
        captured["timeout"] = timeout
        return (0, "Running timer as unit", "")

    out = ows.hermes_operator_service_restart(
        dry_run=False, runner=fake_runner,
        systemd_run_binary="/usr/bin/systemd-run", systemctl_binary="/usr/bin/systemctl",
    )
    parsed = json.loads(out)
    assert parsed["success"] is True
    assert parsed["scheduled"] is True
    assert captured["timeout"] == 30
    assert captured["argv"][0] == "/usr/bin/systemd-run"
    assert captured["argv"][-4:] == ["/usr/bin/systemctl", "--user", "restart", OPERATOR_UNIT]


# 6. Non-maintenance-policy restart denied ------------------------------------

def test_non_maintenance_policy_restart_denied(session_root):
    # A perfectly valid, template-bound session -- but bound to the wrong
    # template. The gate must reject on the template VALUE, not merely on the
    # field being present.
    record = _request_and_approve(session_root, "sandbox", decided_by="telegram:8595123783")
    assert record.policy["policy_template"] == "sandbox"

    out = ows.hermes_operator_service_restart(
        dry_run=False, runner=_fail_runner,
        systemd_run_binary="/usr/bin/systemd-run", systemctl_binary="/usr/bin/systemctl",
    )
    parsed = json.loads(out)
    assert parsed["success"] is False
    assert "policy template" in parsed["error"].lower()


# 7. Approval-web bootstrap restart -------------------------------------------

def test_approval_web_maintenance_schedules_exact_unit(session_root):
    _request_and_approve(
        session_root,
        APPROVAL_WEB_MAINTENANCE,
        decided_by="telegram:8595123783",
    )
    captured = {}

    def fake_runner(argv, timeout=120, workdir=None):
        captured["argv"] = argv
        captured["timeout"] = timeout
        return (0, "Running timer as unit", "")

    out = ows.hermes_approval_web_service_restart(
        dry_run=False,
        runner=fake_runner,
        systemd_run_binary="/usr/bin/systemd-run",
        systemctl_binary="/usr/bin/systemctl",
    )
    parsed = json.loads(out)
    assert parsed["success"] is True
    assert parsed["scheduled"] is True
    assert captured["timeout"] == 30
    assert captured["argv"][-4:] == [
        "/usr/bin/systemctl",
        "--user",
        "restart",
        APPROVAL_WEB_UNIT,
    ]


def test_operator_maintenance_cannot_restart_approval_web(session_root):
    _request_and_approve(session_root, MAINTENANCE, decided_by="telegram:8595123783")
    out = ows.hermes_approval_web_service_restart(
        dry_run=False,
        runner=_fail_runner,
        systemd_run_binary="/usr/bin/systemd-run",
        systemctl_binary="/usr/bin/systemctl",
    )
    parsed = json.loads(out)
    assert parsed["success"] is False
    assert APPROVAL_WEB_MAINTENANCE in parsed["error"]
