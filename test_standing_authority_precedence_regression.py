"""Regression tests for operation-level standing/session authority selection."""

from __future__ import annotations

import copy
import json
import time

import pytest

import operator_delegation as op_delegation
import operator_manifest
import operator_policy as op_policy
import operator_policy_templates as op_templates
import operator_sessions as op_sessions
import operator_standing_authority as op_standing
import server


@pytest.fixture
def precedence_env(tmp_path, monkeypatch):
    session_root = tmp_path / "sessions"
    standing_root = tmp_path / "standing-work"
    session_work = tmp_path / "session-work"
    standing_root.mkdir()
    session_work.mkdir()

    monkeypatch.setenv(op_sessions.SESSION_ROOT_ENV, str(session_root))
    monkeypatch.setenv("HERMES_GPT_RISK_BASED_AUTHORITY_ENABLED", "1")
    monkeypatch.delenv(op_sessions.ACTIVE_SESSION_ID_ENV, raising=False)
    monkeypatch.delenv(op_policy.OPERATOR_ENABLED_ENV, raising=False)
    monkeypatch.delenv(op_policy.OPERATOR_LEVEL_ENV, raising=False)
    monkeypatch.delenv(op_policy.OPERATOR_APPLY_MODE_ENV, raising=False)
    monkeypatch.setattr(op_policy, "profile_exists", lambda profile, hermes_root: True)

    original_resolve = op_templates.resolve_template

    def resolve(name: str):
        resolved = copy.deepcopy(original_resolve(name))
        if name == "hermes-contained-maintenance-standing":
            resolved["policy"]["readable_roots"] = [str(standing_root)]
            resolved["policy"]["writable_roots"] = [str(standing_root)]
        elif name == "hermes-canonical-preservation-integration":
            resolved["policy"]["readable_roots"] = [str(session_work)]
            resolved["policy"]["writable_roots"] = [str(session_work)]
            # Deliberately give the session a capability standing does not have,
            # so the test can prove permissions are not composed across sources.
            resolved["policy"]["verbs"].setdefault("network", []).append("web")
        return resolved

    monkeypatch.setattr(op_templates, "resolve_template", resolve)
    yield session_root, standing_root, session_work


def _approve(root, template, *, mode="session", now=1_000):
    response = json.loads(
        server.hermes_operator_session_request(
            policy_template=template,
            requested_duration_minutes=30,
            reason="precedence regression",
            authority_mode=mode,
        )
    )
    assert response["success"] is True
    return op_sessions.approve_session_request(
        response["request_id"], decided_by="telegram:test", root=root, now=now
    )


def _approve_both(env):
    root, standing_root, session_work = env
    now = int(time.time())
    _approve(root, "hermes-contained-maintenance-standing", mode="standing", now=now - 10)
    session = _approve(root, "hermes-canonical-preservation-integration", mode="session", now=now)
    return root, standing_root, session_work, session


def test_standing_candidate_materialises_while_unrelated_session_is_active(precedence_env):
    _, standing_root, _, _ = _approve_both(precedence_env)
    effective = op_policy.OperatorPolicy()
    standing = op_policy.OperatorPolicy(authority_preference="standing")

    assert effective.path_authority_source == "session_snapshot"
    assert standing.path_authority_source == "standing_policy_snapshot"
    standing.require_write_path(standing_root)


def test_low_risk_standing_task_is_selected_before_unrelated_active_session(precedence_env):
    _, standing_root, _, _ = _approve_both(precedence_env)
    selected = op_delegation._select_delegation_policy(
        profile="default",
        workdir=standing_root,
        mode="apply",
        allow_web=False,
    )
    assert selected.path_authority_source == "standing_policy_snapshot"
    assert selected.session_status == "standing"


def test_active_session_still_authorizes_its_own_scoped_work(precedence_env):
    _, _, session_work, session = _approve_both(precedence_env)
    selected = op_delegation._select_delegation_policy(
        profile="default",
        workdir=session_work,
        mode="apply",
        allow_web=False,
    )
    assert selected.path_authority_source == "session_snapshot"
    assert selected.session_id == session.session_id


def test_no_mixed_authority_composition_for_standing_path_plus_session_network(precedence_env):
    _, standing_root, _, _ = _approve_both(precedence_env)
    with pytest.raises(PermissionError, match="No single approved authority"):
        op_delegation._select_delegation_policy(
            profile="default",
            workdir=standing_root,
            mode="read_only",
            allow_web=True,
        )


def test_material_capability_not_in_standing_requires_other_authority(precedence_env):
    _, standing_root, _, _ = _approve_both(precedence_env)
    standing = op_policy.OperatorPolicy(authority_preference="standing")
    with pytest.raises(PermissionError):
        standing.require_verb("network", "web")
    with pytest.raises(PermissionError):
        standing.require_verb("services", "restart")


def test_standing_revalidation_ignores_unrelated_session_replacement(precedence_env):
    root, standing_root, _, _ = _approve_both(precedence_env)
    standing = op_policy.OperatorPolicy(authority_preference="standing")
    envelope = op_delegation._capture_authority_envelope(
        standing,
        profile="default",
        workdir=standing_root,
        mode="apply",
        allow_web=False,
        max_turns=5,
        timeout=60,
    )
    task = {"authority": envelope, "profile": "default", "workdir": str(standing_root), "mode": "apply"}
    op_delegation._require_task_authority(task)

    # Revoke remains an immediate hard stop.
    assert op_standing.revoke_standing_authority(
        standing.session_id,
        revoked_by="telegram:test",
        reason="regression revoke",
        root=root,
        now=3_000,
    ) is True
    with pytest.raises(PermissionError):
        op_delegation._require_task_authority(task)


def test_public_tool_manifest_remains_41_tools():
    assert operator_manifest.EXPECTED_TOOL_COUNT == 41
    assert len(operator_manifest.CANONICAL_TOOL_NAMES) == 41
