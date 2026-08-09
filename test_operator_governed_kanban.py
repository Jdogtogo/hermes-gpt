from __future__ import annotations

import json
from types import SimpleNamespace

import operator_governed_kanban as gk


class FakePolicy:
    session_id = "sa_board"
    readable_roots = [gk.BOARD_ROOT]
    writable_roots = [gk.BOARD_ROOT]
    egress_hosts = []
    git_remotes = []
    service_units = []
    verbs = {"filesystem": ["read", "edit"]}

    def require_enabled(self):
        return None

    def require_level(self, level):
        assert level == "workspace"

    def require_mutation(self, dry_run):
        assert dry_run is False

    def require_read_path(self, path):
        assert str(path).startswith(str(gk.BOARD_ROOT))

    def require_write_path(self, path):
        assert str(path).startswith(str(gk.BOARD_ROOT))

    def require_verb(self, resource, verb):
        assert (resource, verb) == ("filesystem", "edit")


class FakeConn:
    def __init__(self, kb):
        self.kb = kb

    def close(self):
        return None


class FakeKanban:
    def __init__(self):
        self.tasks = {}
        self.comments = {}
        self.task_links = []
        self.created_board = None
        self.counter = 0

    def create_board(self, slug, **kwargs):
        self.created_board = (slug, kwargs)
        return {"slug": slug}

    def connect(self, *, board=None):
        assert board == gk.BOARD_SLUG
        return FakeConn(self)

    def create_task(self, conn, **kwargs):
        key = kwargs.get("idempotency_key")
        for task in self.tasks.values():
            if getattr(task, "idempotency_key", None) == key and task.status != "archived":
                return task.id
        self.counter += 1
        task_id = f"t_{self.counter:08x}"
        status = "blocked" if kwargs.get("initial_status") == "blocked" else "ready"
        task = SimpleNamespace(
            id=task_id,
            title=kwargs["title"],
            body=kwargs.get("body"),
            assignee=kwargs.get("assignee"),
            status=status,
            priority=kwargs.get("priority", 0),
            workspace_path=kwargs.get("workspace_path"),
            started_at=None,
            idempotency_key=key,
        )
        self.tasks[task_id] = task
        self.comments[task_id] = []
        return task_id

    def list_tasks(self, conn, *, assignee=None, status=None, limit=None, **kwargs):
        values = [
            task
            for task in self.tasks.values()
            if (assignee is None or task.assignee == assignee)
            and (status is None or task.status == status)
        ]
        values.sort(key=lambda task: (-task.priority, task.id))
        return values[:limit] if limit else values

    def list_comments(self, conn, task_id):
        return self.comments[task_id]

    def add_comment(self, conn, task_id, author, body):
        self.comments[task_id].append(SimpleNamespace(author=author, body=body))
        return len(self.comments[task_id])

    def claim_task(self, conn, task_id, **kwargs):
        task = self.tasks[task_id]
        if task.status != "ready":
            return None
        task.status = "running"
        task.started_at = 100
        return task

    def complete_task(self, conn, task_id, **kwargs):
        self.tasks[task_id].status = "done"
        self.tasks[task_id].result = kwargs.get("result")
        self.tasks[task_id].metadata = kwargs.get("metadata")
        return True

    def block_task(self, conn, task_id, *, reason=None, kind=None, **kwargs):
        self.tasks[task_id].status = "blocked"
        self.tasks[task_id].block_reason = reason
        self.tasks[task_id].block_kind = kind
        return True

    def unblock_task(self, conn, task_id):
        task = self.tasks[task_id]
        if task.status != "blocked":
            return False
        task.status = "ready"
        return True


def _reset_state(monkeypatch, kb):
    monkeypatch.setattr(gk, "_KANBAN_MODULE_OVERRIDE", kb)
    monkeypatch.setattr(gk, "_select_board_policy", lambda: FakePolicy())
    gk._STATE.update(
        {
            "started": False,
            "status": "not_started",
            "board_authority_id": None,
            "last_tick_at": None,
            "last_error": None,
            "counts": {},
            "seeded_task_ids": [],
        }
    )


def test_seed_uses_named_board_and_blocks_material_boundaries(monkeypatch):
    kb = FakeKanban()
    _reset_state(monkeypatch, kb)

    result = gk.dispatch_once()

    assert kb.created_board[0] == "hermes-stabilization"
    assert len(kb.tasks) == len(gk.SEED_TASKS)
    assert all(task.assignee == gk.ASSIGNEE for task in kb.tasks.values())
    boundary_titles = {
        item["title"] for item in gk.SEED_TASKS if item["kind"] == "boundary"
    }
    boundary_tasks = [task for task in kb.tasks.values() if task.title in boundary_titles]
    assert boundary_tasks
    assert all(task.status == "blocked" for task in boundary_tasks)
    assert result["board"] == "hermes-stabilization"
    assert result["board_authority_id"] == "sa_board"
    assert result["counts"]["blocked"] == len(boundary_tasks)


def test_ready_card_is_forecast_then_queued_through_governed_delegation(monkeypatch):
    kb = FakeKanban()
    _reset_state(monkeypatch, kb)
    calls = []

    monkeypatch.setattr(
        gk.op_delegation,
        "hermes_delegate_task_forecast",
        lambda **kwargs: json.dumps({"success": True, "granted": True}),
    )

    def fake_delegate(**kwargs):
        calls.append(kwargs)
        return json.dumps({"success": True, "task_id": "dt_governed"})

    monkeypatch.setattr(gk.op_delegation, "hermes_delegate_task", fake_delegate)
    monkeypatch.setattr(
        gk.op_delegation,
        "hermes_delegated_task_result",
        lambda task_id: json.dumps({"success": True, "ready": False, "task_id": task_id}),
    )

    result = gk.dispatch_once()

    assert calls
    assert calls[0]["workdir"] == str(gk.CLEAN_MAINTENANCE_WORKTREE)
    running = [task for task in kb.tasks.values() if task.status == "running"]
    assert len(running) == 1
    assert gk._delegation_marker(kb.comments[running[0].id]) == "dt_governed"
    assert result["counts"]["running"] == 1


def test_running_card_completes_from_delegated_evidence(monkeypatch):
    kb = FakeKanban()
    _reset_state(monkeypatch, kb)
    ids = gk._ensure_board_and_seed(kb, FakePolicy())
    delegate_task = next(
        task for task in kb.tasks.values() if gk._decode_packet(task.body) is not None
    )
    delegate_task.status = "running"
    delegate_task.started_at = 100
    kb.add_comment(None, delegate_task.id, gk.CREATED_BY, "governed-delegation-task-id=dt_done")

    monkeypatch.setattr(
        gk.op_delegation,
        "hermes_delegated_task_result",
        lambda task_id: json.dumps(
            {
                "success": True,
                "ready": True,
                "task_id": task_id,
                "final_answer": "Verified governed completion.",
                "changed_files": [],
                "returncode": 0,
                "authority": {"session_id": "sa_contained"},
            }
        ),
    )
    monkeypatch.setattr(
        gk.op_delegation,
        "hermes_delegate_task_forecast",
        lambda **kwargs: json.dumps({"success": True, "granted": True}),
    )
    monkeypatch.setattr(
        gk.op_delegation,
        "hermes_delegate_task",
        lambda **kwargs: json.dumps({"success": True, "task_id": "dt_next"}),
    )

    gk.dispatch_once()

    assert kb.tasks[delegate_task.id].status == "done"
    assert kb.tasks[delegate_task.id].metadata["delegated_task_id"] == "dt_done"
    assert kb.tasks[delegate_task.id].metadata["authority_id"] == "sa_contained"


def test_forecast_denial_blocks_instead_of_bypassing_authority(monkeypatch):
    kb = FakeKanban()
    _reset_state(monkeypatch, kb)
    monkeypatch.setattr(
        gk.op_delegation,
        "hermes_delegate_task_forecast",
        lambda **kwargs: json.dumps(
            {
                "success": True,
                "granted": False,
                "denial": {"safe_message": "bounded approval required"},
            }
        ),
    )
    monkeypatch.setattr(
        gk.op_delegation,
        "hermes_delegate_task",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("must not delegate")),
    )

    gk.dispatch_once()

    blocked = [
        task
        for task in kb.tasks.values()
        if task.status == "blocked" and gk._decode_packet(task.body) is not None
    ]
    assert blocked
    assert "Approval required" in blocked[0].block_reason
    assert blocked[0].block_kind == "capability"


def test_latest_block_reason_reads_canonical_block_event_payload():
    task = SimpleNamespace(id="t_event", block_reason=None)

    class EventConn:
        def execute(self, sql, params):
            assert "kind = 'blocked'" in sql
            assert params == ("t_event",)

            class Cursor:
                def fetchone(self):
                    return (json.dumps({"reason": "originating standing authority is no longer active", "kind": "transient"}),)

            return Cursor()

    assert gk._latest_block_reason(EventConn(), task) == "originating standing authority is no longer active"


def test_recover_fixed_authority_block_retries_once_and_preserves_real_boundaries(monkeypatch):
    kb = FakeKanban()
    _reset_state(monkeypatch, kb)
    gk._ensure_board_and_seed(kb, FakePolicy())

    delegate_tasks = [
        task for task in kb.tasks.values() if gk._decode_packet(task.body) is not None
    ]
    assert len(delegate_tasks) == 2
    retryable = delegate_tasks[0]
    other_blocked = delegate_tasks[1]
    retryable.status = "blocked"
    retryable.block_reason = "originating standing authority is no longer active"
    retryable.block_kind = "transient"
    other_blocked.status = "blocked"
    other_blocked.block_reason = "Approval required: bounded approval required"
    other_blocked.block_kind = "capability"

    boundary_tasks = [
        task for task in kb.tasks.values() if gk._decode_packet(task.body) is None
    ]
    assert boundary_tasks
    assert all(task.status == "blocked" for task in boundary_tasks)

    conn = kb.connect(board=gk.BOARD_SLUG)
    gk._recover_fixed_authority_blocks(kb, conn)
    conn.close()

    assert retryable.status == "ready"
    assert other_blocked.status == "blocked"
    assert all(task.status == "blocked" for task in boundary_tasks)
    assert any(
        comment.body == "governed-fixed-authority-retry=v2"
        for comment in kb.comments[retryable.id]
    )

    retryable.status = "blocked"
    retryable.block_reason = "originating standing authority is no longer active"
    conn = kb.connect(board=gk.BOARD_SLUG)
    gk._recover_fixed_authority_blocks(kb, conn)
    conn.close()
    assert retryable.status == "blocked"


def test_seed_sync_normalizes_delegate_todo_to_ready_without_unblocking_boundaries(monkeypatch):
    kb = FakeKanban()
    _reset_state(monkeypatch, kb)
    ids = gk._ensure_board_and_seed(kb, FakePolicy())

    delegate = next(task for task in kb.tasks.values() if gk._decode_packet(task.body) is not None)
    boundary = next(task for task in kb.tasks.values() if gk._decode_packet(task.body) is None)
    delegate.status = "todo"
    boundary.status = "blocked"
    kb.task_links.append(("t_stale_parent", delegate.id))

    delegate_item = next(item for item in gk.SEED_TASKS if item["kind"] == "delegate" and item["title"] == delegate.title)
    boundary_item = next(item for item in gk.SEED_TASKS if item["kind"] == "boundary" and item["title"] == boundary.title)
    conn = kb.connect(board=gk.BOARD_SLUG)
    gk._sync_seed_record(kb, conn, delegate.id, delegate_item, gk._encode_packet(delegate_item["packet"]))
    gk._sync_seed_record(kb, conn, boundary.id, boundary_item, str(boundary_item["reason"]))
    conn.close()

    assert delegate.status == "ready"
    assert boundary.status == "blocked"
    assert kb.task_links == []
    assert any(
        comment.body == "governed-seed-todo-normalized=v1"
        for comment in kb.comments[delegate.id]
    )
