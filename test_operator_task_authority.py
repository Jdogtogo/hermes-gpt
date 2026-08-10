"""Task-Bound Authority v2 regression suite.

Proves the 13 required behaviours. Every test uses an isolated tmp root so
no live operator state is touched.
"""

from __future__ import annotations

import pytest

import operator_task_authority as tba


@pytest.fixture()
def root(tmp_path):
    return tmp_path / "opsroot"


def kanban_envelope(base, *, commit=True, test=True):
    return tba.derive_envelope(
        task_class="hermes_agent_kanban_ui",
        writable_files=(str(base / "ui" / "Board.tsx"),),
        needs_test=test,
        needs_commit=commit,
    )


def grant(root, task_id, envelope, policy_class="contained"):
    res = tba.resolve(task_id=task_id, envelope=envelope,
                      policy_class=policy_class, root=root)
    assert res.approval_required
    return tba.approve_request(res.request_id, approved_by="justin", root=root)


# 1. Direct contained maintenance reuses correct standing/task authority.
def test_direct_contained_maintenance_reuses_authority(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("kanban-cleanup", worktree=str(tmp_path))
    grant(root, task, env)
    res = tba.resolve(task_id=task, envelope=env, policy_class="contained", root=root)
    assert res.approval_required is False
    assert res.authority_source == "task_bound"


# 2. Delegated maintenance uses the SAME resolution path.
def test_delegated_worker_uses_same_resolver(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("kanban-cleanup", worktree=str(tmp_path))
    grant(root, task, env)
    # A delegated worker resolves the identical logical task id.
    delegated = tba.resolve(task_id=task, envelope=env,
                            policy_class="contained", root=root)
    assert delegated.approval_required is False
    assert delegated.authority_source == "task_bound"
    assert delegated.effective_authority_ids


# 3. Equivalent pending request is NOT duplicated.
def test_equivalent_pending_request_not_duplicated(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("dedupe", worktree=str(tmp_path))
    first = tba.resolve(task_id=task, envelope=env, policy_class="c", root=root)
    second = tba.resolve(task_id=task, envelope=env, policy_class="c", root=root)
    assert first.request_id == second.request_id
    assert "not duplicated" in second.selection_reason
    # And the first was NOT superseded merely by re-sending.
    assert second.state == "pending_approval"


# 4. Equivalent approved authority is reused.
def test_equivalent_approved_authority_reused(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("reuse", worktree=str(tmp_path))
    grant(root, task, env)
    again = tba.resolve(task_id=task, envelope=env, policy_class="contained", root=root)
    assert again.approval_required is False


# 5. Scope-changing request may supersede safely.
def test_material_scope_change_supersedes(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("scope", worktree=str(tmp_path))
    grant(root, task, env)
    wider = tba.derive_envelope(
        task_class="hermes_agent_kanban_ui",
        writable_files=(str(tmp_path / "ui" / "Board.tsx"),
                        str(tmp_path / "other" / "Deep.tsx")),
        needs_test=True, needs_commit=True,
    )
    res = tba.resolve(task_id=task, envelope=wider, policy_class="contained", root=root)
    assert res.approval_required is True
    assert "scope materially changed" in res.selection_reason
    assert res.missing_capability


# 6. Task authority does not vanish mid-task due only to a 30-minute timer.
def test_authority_survives_thirty_minute_timer(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("longtask", worktree=str(tmp_path))
    authority = grant(root, task, env)
    later = authority.created_at + 31 * 60  # past the old 1800s session expiry
    valid, reason = authority.is_valid(now=later)
    assert valid is True, reason
    res = tba.resolve(task_id=task, envelope=env, policy_class="contained",
                      now=later, root=root)
    assert res.approval_required is False
    assert res.authority_source == "task_bound"


# 6b. Hard safety lifetime still bounds the task.
def test_hard_safety_lifetime_still_enforced(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("hardlife", worktree=str(tmp_path))
    authority = grant(root, task, env)
    beyond = authority.created_at + tba.HARD_TASK_LIFETIME_SECONDS + 1
    valid, reason = authority.is_valid(now=beyond)
    assert valid is False
    assert "hard safety lifetime" in reason

# 7. Task completion / revocation invalidates authority.
def test_completion_and_revocation_invalidate(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("finish", worktree=str(tmp_path))
    grant(root, task, env)
    tba.complete_task(task, root=root)
    res = tba.resolve(task_id=task, envelope=env, policy_class="contained", root=root)
    assert res.approval_required is True

    task2 = tba.make_task_id("revokeme", worktree=str(tmp_path))
    grant(root, task2, env)
    tba.revoke_task(task2, root=root)
    assert tba.task_status(task2, root=root)["valid"] is False

    task3 = tba.make_task_id("cancelme", worktree=str(tmp_path))
    grant(root, task3, env)
    tba.cancel_task(task3, root=root)
    assert tba.task_status(task3, root=root)["task_state"] == "cancelled"


# 8. Independent authorities are NEVER unioned.
def test_authorities_never_unioned(root, tmp_path):
    a = tba.derive_envelope(task_class="hermes_agent_kanban_ui",
                            writable_files=(str(tmp_path / "a" / "x.tsx"),))
    b = tba.derive_envelope(task_class="hermes_agent_kanban_ui",
                            writable_files=(str(tmp_path / "b" / "y.tsx"),),
                            needs_commit=True)
    want = tba.derive_envelope(
        task_class="hermes_agent_kanban_ui",
        writable_files=(str(tmp_path / "a" / "x.tsx"), str(tmp_path / "b" / "y.tsx")),
        needs_commit=True,
    )
    task = tba.make_task_id("union", worktree=str(tmp_path))
    res = tba.resolve(task_id=task, envelope=want, policy_class="c",
                      standing_candidates=(("sa_A", a), ("sa_B", b)), root=root)
    # Neither standing authority is INDEPENDENTLY sufficient -> approval.
    assert res.approval_required is True
    assert res.authority_source == "none"

    # But one genuinely sufficient standing authority IS selected alone.
    res2 = tba.resolve(task_id=task, envelope=a, policy_class="c",
                       standing_candidates=(("sa_A", a), ("sa_B", b)), root=root)
    assert res2.authority_source == "standing"
    assert res2.effective_authority_ids == ("sa_A",)


# 9. Secrets remain blocked.
@pytest.mark.parametrize("secret", [
    "~/.ssh/id_rsa", "~/.aws/credentials", "~/.hermes/auth/token.json",
    "~/.hermes/.env", "~/.gnupg/secring.gpg",
])
def test_secrets_remain_blocked(root, tmp_path, secret):
    assert tba.is_hard_denied(secret) is True
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("secret", worktree=str(tmp_path))
    grant(root, task, env)
    boundary = tba.material_boundary(paths=(secret,))
    assert boundary == "secrets"
    res = tba.resolve(task_id=task, envelope=env, policy_class="c",
                      boundary=boundary, root=root)
    assert res.approval_required is True
    assert res.missing_capability == "secrets"
    assert res.state == "blocked"


# 10. Paid routes remain blocked.
def test_paid_routes_blocked(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("paid", worktree=str(tmp_path))
    grant(root, task, env)
    boundary = tba.material_boundary(paid_routing=True)
    res = tba.resolve(task_id=task, envelope=env, policy_class="c",
                      boundary=boundary, root=root)
    assert res.approval_required is True
    assert res.missing_capability == "paid_routing"


# 11. Network / release / host mutation remain blocked.
@pytest.mark.parametrize("kwargs,expected", [
    ({"network_security": True}, "network_security"),
    ({"release_deploy": True}, "release_deploy"),
    ({"host_install": True}, "host_install"),
    ({"destructive": True}, "destructive"),
    ({"repo_reset": True}, "repo_reset"),
    ({"budget_change": True}, "budget"),
])
def test_material_mutations_blocked(root, tmp_path, kwargs, expected):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("material", worktree=str(tmp_path))
    grant(root, task, env)
    boundary = tba.material_boundary(**kwargs)
    assert boundary == expected
    res = tba.resolve(task_id=task, envelope=env, policy_class="c",
                      boundary=boundary, root=root)
    assert res.approval_required is True


# 12. Explicit task-bound operator restart works only where declared.
def test_task_bound_restart_only_where_declared(root, tmp_path):
    # Not declared -> derivation refuses (least privilege).
    with pytest.raises(tba.TaskAuthorityError):
        tba.derive_envelope(
            task_class="hermes_agent_kanban_ui",
            writable_files=(str(tmp_path / "a.tsx"),),
            service_units=("hermes-gpt-chatgpt-operator.service",),
        )
    # Declared -> allowed, and bound to that exact unit.
    env = tba.derive_envelope(
        task_class="task_bound_operator_restart",
        writable_files=(str(tmp_path / "a.py"),),
        service_units=("hermes-gpt-chatgpt-operator.service",),
    )
    assert env.verbs["service"] == ("restart",)
    task = tba.make_task_id("restart", worktree=str(tmp_path))
    grant(root, task, env)
    res = tba.resolve(task_id=task, envelope=env, policy_class="c", root=root)
    assert res.approval_required is False

    other = tba.derive_envelope(
        task_class="task_bound_operator_restart",
        writable_files=(str(tmp_path / "a.py"),),
        service_units=("hermes-gateway.service",),
    )
    res2 = tba.resolve(task_id=task, envelope=other, policy_class="c", root=root)
    assert res2.approval_required is True  # undeclared unit -> new approval


# 13. Dirty unrelated repository files cannot leak into a commit.
def test_undeclared_root_blocked(root, tmp_path):
    declared = (str(tmp_path / "worktree"),)
    boundary = tba.material_boundary(
        paths=(str(tmp_path / "elsewhere" / "dirty.py"),),
        declared_roots=declared,
    )
    assert boundary == "undeclared_root"
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("dirty", worktree=str(tmp_path))
    grant(root, task, env)
    res = tba.resolve(task_id=task, envelope=env, policy_class="c",
                      boundary=boundary, root=root)
    assert res.approval_required is True
    assert res.missing_capability == "undeclared_root"


# Observability surface.
def test_task_authority_explanation_surface(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("observe", worktree=str(tmp_path))
    grant(root, task, env)
    out = tba.explain(task_id=task, envelope=env, policy_class="c", root=root)
    assert out["label"] == "TASK_AUTHORITY"
    for key in ("logical_task_id", "authority_source", "effective_authority_ids",
                "roots", "verbs", "task_state", "hard_expires_at",
                "selection_reason", "approval_required", "missing_capability"):
        assert key in out
    assert out["approval_required"] is False


def test_audit_evidence_is_append_only(root, tmp_path):
    env = kanban_envelope(tmp_path)
    task = tba.make_task_id("audit", worktree=str(tmp_path))
    grant(root, task, env)
    tba.complete_task(task, root=root)
    lines = (root / tba.TASK_AUDIT_NAME).read_text().strip().splitlines()
    events = [__import__("json").loads(line)["event"] for line in lines]
    assert "request_created" in events
    assert "task_authority_granted" in events
    assert "task_completed" in events
