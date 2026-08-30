"""Governed Kanban bridge for low-risk Hermes operator work.

The native Hermes Kanban dispatcher intentionally launches ordinary profile
workers. Those workers run with the user's normal OS authority, so maintenance
cards that must stay inside the Hermes-GPT operator approval model use a
separate, non-spawnable lane instead.

This bridge owns exactly one named board (``hermes-stabilization``). It creates
and mutates that board only when a dedicated standing authority independently
covers the board directory. Ready cards assigned to ``controller-governed`` are
claimed here and submitted through :mod:`operator_delegation`, which performs
its own least-privilege standing/session authority selection. Permissions are
never unioned between the board mutation and delegated execution operations.
"""
from __future__ import annotations

import importlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

import operator_policy as op_policy
import operator_standing_authority as op_standing
import operator_delegation as op_delegation

BOARD_SLUG = "hermes-stabilization"
BOARD_NAME = "Hermes Stabilization"
BOARD_ROOT = Path.home() / ".hermes" / "kanban" / "boards" / BOARD_SLUG
ASSIGNEE = "controller-governed"
PACKET_PREFIX = "HERMES_CONTROLLER_PACKET_V1\n"
POLL_SECONDS = 60
CLAIM_TTL_SECONDS = 2 * 60 * 60
CREATED_BY = "hermes-gpt-governed-kanban"
CLEAN_MAINTENANCE_WORKTREE = (
    Path.home()
    / ".hermes"
    / "worktrees"
    / "hermes-gpt-operator-session-chatgpt"
    / "standing-maintenance-clean"
)

# The seed list is deliberately small and auditable. Low-risk cards are normal
# governed delegation packets. Material/host-level follow-ups are represented
# on the same board as blocked boundaries rather than being silently executed.
SEED_TASKS: tuple[dict[str, Any], ...] = (
    {
        "key": "hermes-stabilization-live-delegation-smoke-v1",
        "title": "Verify governed delegated-provider smoke",
        "priority": 100,
        "kind": "delegate",
        "packet": {
            "prompt": (
                "Perform a read-only governed smoke test in this repository. "
                "Read operator_delegation.py and confirm that the current source "
                "contains the least-privilege multi-standing authority resolver. "
                "Make no changes. Return a concise evidence statement ending with "
                "HERMES_GOVERNED_KANBAN_SMOKE_OK."
            ),
            "workdir": str(CLEAN_MAINTENANCE_WORKTREE),
            "mode": "read_only",
            "profile": "default",
            "max_turns": 12,
            "timeout": 600,
            "allow_web": False,
        },
    },
    {
        "key": "hermes-stabilization-pytest-baseline-triage-v1",
        "title": "Triage broad operator pytest baseline",
        "priority": 90,
        "kind": "delegate",
        "packet": {
            "prompt": (
                "Investigate the broad repository pytest baseline without changing files. "
                "Known evidence: authority/delegation/security regression suites pass "
                "325/325 in this clean maintenance checkout, while an earlier full-suite "
                "run had failures concentrated in bridge-worker and environment/runtime-"
                "dependent tests. Inspect the repository tests and implementation to "
                "classify likely environment-dependent/pre-existing failure groups versus "
                "credible regressions. Produce a prioritized, testable triage plan and do "
                "not claim any failing test is fixed."
            ),
            "workdir": str(CLEAN_MAINTENANCE_WORKTREE),
            "mode": "read_only",
            "profile": "default",
            "max_turns": 24,
            "timeout": 1200,
            "allow_web": False,
        },
    },
    {
        "key": "hermes-stabilization-config-drift-review-v1",
        "title": "Routing · Confirm free-first provider order",
        "priority": 79,
        "kind": "boundary",
        "reason": "Promote the approved order NVIDIA direct → Nous → OpenRouter free → Gemini direct → Ollama into live routing configuration.",
        "approval_policy_template": "hermes-model-routing-migration",
    },
    {
        "key": "hermes-routing-nvidia-glm52-v1",
        "title": "Routing · Verify GLM 5.2 on NVIDIA direct",
        "priority": 78,
        "kind": "boundary",
        "reason": "Verify z-ai/glm-5.2 remains a free NVIDIA-direct route and is not routed through paid OpenRouter.",
        "approval_policy_template": "hermes-model-routing-migration",
    },
    {
        "key": "hermes-routing-nous-hy3-v1",
        "title": "Routing · Verify Nous HY3 free",
        "priority": 77,
        "kind": "boundary",
        "reason": "Verify tencent/hy3:free remains qualified through Nous and stays ahead of OpenRouter and Gemini in fallback priority.",
        "approval_policy_template": "hermes-model-routing-migration",
    },
    {
        "key": "hermes-routing-openrouter-free-only-v1",
        "title": "Routing · Verify OpenRouter is free-only",
        "priority": 76,
        "kind": "boundary",
        "reason": "Confirm OpenRouter can only use explicitly free-qualified routes and cannot silently fall through to paid models.",
        "approval_policy_template": "hermes-model-routing-migration",
    },
    {
        "key": "hermes-routing-gemini-quota-schema-v1",
        "title": "Routing · Verify Gemini quota schema",
        "priority": 75,
        "kind": "delegate",
        "packet": {
            "prompt": (
                "Read operator_routing.py and routing_control.json only. Confirm Gemini has a machine-readable "
                "rate-limit schema with unknown hard RPM/TPM/RPD ceilings left unset, a 300-second HTTP 429 "
                "cooldown, a 3600-second quota-exhaustion cooldown, and Retry-After support recorded. Make no "
                "changes. End with HERMES_GEMINI_RATE_LIMIT_SCHEMA_OK."
            ),
            "workdir": str(CLEAN_MAINTENANCE_WORKTREE),
            "mode": "read_only",
            "profile": "default",
            "max_turns": 12,
            "timeout": 600,
            "allow_web": False,
        },
    },
    {
        "key": "hermes-routing-planner-glm52-v2",
        "title": "Routing · Review stale planner-glm52 mapping",
        "priority": 74,
        "kind": "boundary",
        "reason": "Inspect and remove or correct the stale planner-glm52 process-profile mapping without removing the valid NVIDIA-direct GLM 5.2 model route.",
        "approval_policy_template": "hermes-model-routing-migration",
    },
    {
        "key": "hermes-environment-active-pipeline-v1",
        "title": "Environment · Review Active-Pipeline hint",
        "priority": 73,
        "kind": "boundary",
        "reason": "Review the stale Active-Pipeline:Financial-Automation-V2 environment hint and change it only if live evidence confirms drift.",
        "approval_policy_template": "hermes-model-routing-migration",
    },
    {
        "key": "hermes-agents-antigravity-long-horizon-v1",
        "title": "Agents · Confirm Antigravity long-horizon role",
        "priority": 72,
        "kind": "delegate",
        "packet": {
            "prompt": (
                "Inspect the Antigravity and long-horizon delegation integration in this repository. Confirm how "
                "Antigravity participates as a governed long-horizon agent/reviewer separate from the provider "
                "fallback chain, identify any remaining integration gap, and make no changes. End with "
                "HERMES_ANTIGRAVITY_LONG_HORIZON_REVIEW_OK."
            ),
            "workdir": str(CLEAN_MAINTENANCE_WORKTREE),
            "mode": "read_only",
            "profile": "default",
            "max_turns": 20,
            "timeout": 900,
            "allow_web": False,
        },
    },
    {
        "key": "hermes-routing-final-smoke-v1",
        "title": "Routing · Run final live routing smoke",
        "priority": 71,
        "kind": "boundary",
        "reason": "After approved configuration changes, run live free-route smoke tests and record final provider/model evidence.",
        "approval_policy_template": "hermes-model-routing-migration",
    },
    {
        "key": "hermes-stabilization-computer-use-decision-v1",
        "title": "Decide whether computer-use and cua-driver are required",
        "priority": 60,
        "kind": "boundary",
        "reason": (
            "Host capability boundary: cua-driver is not installed. Installation or host "
            "configuration must remain a separately reviewed host-level action; no install "
            "is authorized by the Kanban standing authority."
        ),
    },
    {
        "key": "hermes-stabilization-agent-update-review-v1",
        "title": "Review one-commit Hermes Agent update",
        "priority": 50,
        "kind": "boundary",
        "reason": (
            "Upstream-update boundary: Hermes Agent reports one commit available. Review "
            "and update of the agent checkout is outside the contained maintenance standing "
            "authority and must not be performed silently."
        ),
    },
)

_LOCK = threading.RLock()
_STARTED = False
_THREAD: threading.Thread | None = None
_KANBAN_MODULE_OVERRIDE: Any | None = None
_STATE: dict[str, Any] = {
    "started": False,
    "board": BOARD_SLUG,
    "lane": ASSIGNEE,
    "status": "not_started",
    "board_authority_id": None,
    "last_tick_at": None,
    "last_error": None,
    "counts": {},
    "seeded_task_ids": [],
}


def _kb() -> Any:
    if _KANBAN_MODULE_OVERRIDE is not None:
        return _KANBAN_MODULE_OVERRIDE
    return importlib.import_module("hermes_cli.kanban_db")


def _board_policy_score(policy: op_policy.OperatorPolicy) -> tuple[int, ...]:
    verbs = sum(len(v) for v in policy.verbs.values())
    roots = [*policy.readable_roots, *policy.writable_roots]
    return (
        len(policy.egress_hosts) + len(policy.git_remotes) + len(policy.service_units),
        verbs,
        len(policy.writable_roots),
        len(policy.readable_roots),
        len(roots),
        -sum(len(Path(root).parts) for root in roots),
    )


def _select_board_policy() -> op_policy.OperatorPolicy | None:
    candidates: list[op_policy.OperatorPolicy] = []
    try:
        authorities = op_standing.list_standing_authorities()
    except Exception:
        authorities = []
    for authority in authorities:
        authority_id = str(getattr(authority, "authority_id", "") or "")
        if not authority_id:
            continue
        try:
            policy = op_policy.OperatorPolicy(
                authority_preference="standing",
                standing_authority_id=authority_id,
            )
            policy.require_enabled()
            policy.require_level("workspace")
            policy.require_mutation(dry_run=False)
            policy.require_read_path(BOARD_ROOT)
            policy.require_write_path(BOARD_ROOT)
            policy.require_verb("filesystem", "edit")
        except Exception:
            continue
        candidates.append(policy)
    if not candidates:
        return None
    return min(candidates, key=_board_policy_score)


MISSION_CONTROL_CREATED_BY = "hermes-gpt-mission-control"
MISSION_CONTROL_KEY_PREFIX = "mission-control:"
DELEGATION_MARKER_PREFIX = "governed-delegation-task-id="


def _select_board_read_policy() -> op_policy.OperatorPolicy | None:
    candidates: list[op_policy.OperatorPolicy] = []
    try:
        authorities = op_standing.list_standing_authorities()
    except Exception:
        authorities = []
    for authority in authorities:
        authority_id = str(getattr(authority, "authority_id", "") or "")
        if not authority_id:
            continue
        try:
            policy = op_policy.OperatorPolicy(
                authority_preference="standing",
                standing_authority_id=authority_id,
            )
            policy.require_enabled()
            policy.require_level("workspace")
            policy.require_read_path(BOARD_ROOT)
        except Exception:
            continue
        candidates.append(policy)
    if not candidates:
        return None
    return min(candidates, key=_board_policy_score)


def _mission_control_key(logical_work_id: str) -> str:
    return MISSION_CONTROL_KEY_PREFIX + logical_work_id


def _board_status_to_mission_control(status: str | None) -> str | None:
    return {
        "running": "In Progress",
        "review": "In Review",
        "done": "Completed",
        "blocked": "On Hold",
    }.get(str(status or ""))


def record_mission_control_task(task: dict[str, Any], *, event: str) -> bool:
    """Upsert one delegated logical task into the existing governed board."""
    policy = _select_board_policy()
    if policy is None:
        return False
    try:
        policy.require_write_path(BOARD_ROOT)
        kb = _kb()
        conn = kb.connect(board=BOARD_SLUG)
    except Exception:
        return False
    try:
        logical_work_id = str(task.get("logical_work_id") or task.get("task_id") or "").strip()
        delegated_id = str(task.get("task_id") or "").strip()
        if not logical_work_id or not delegated_id:
            return False
        card_id = kb.create_task(
            conn,
            title=f"Delegated Hermes task {logical_work_id}",
            body="Mission Control delegated execution record. Prompt content is intentionally not stored.",
            assignee=ASSIGNEE,
            created_by=MISSION_CONTROL_CREATED_BY,
            workspace_kind="dir",
            workspace_path=str(task.get("workdir") or "") or None,
            priority=0,
            idempotency_key=_mission_control_key(logical_work_id),
            initial_status="running",
            board=BOARD_SLUG,
        )
        marker = DELEGATION_MARKER_PREFIX + delegated_id
        comments = kb.list_comments(conn, card_id)
        if not comments or str(getattr(comments[-1], "body", "") or "") != marker:
            if not any(str(getattr(c, "body", "") or "") == marker for c in comments):
                kb.add_comment(conn, card_id, MISSION_CONTROL_CREATED_BY, marker)

        worker_status = str(task.get("status") or "")
        review_status = str(task.get("review_status") or "")
        if worker_status == "completed":
            desired = "done" if review_status == "accepted" else "review"
        elif worker_status in op_delegation.TERMINAL_STATES:
            desired = "blocked"
        else:
            desired = "running"

        if desired == "blocked":
            reason = str(
                task.get("outcome_reason")
                or task.get("failure_category")
                or f"Delegated task ended in {worker_status or 'terminal'} state"
            )[:2000]
            current = kb.get_task(conn, card_id) if hasattr(kb, "get_task") else getattr(conn, "kb", None).tasks.get(card_id)
            if getattr(current, "status", None) != "blocked":
                kb.block_task(conn, card_id, reason=reason, kind="capability" if task.get("failure_category") == "permission" else "transient")
        elif hasattr(conn, "kb") and hasattr(conn.kb, "tasks"):
            card = conn.kb.tasks[card_id]
            if card.status != "done" or desired == "done":
                card.status = desired
                if desired == "done":
                    card.result = str(task.get("review_summary") or task.get("outcome_reason") or "Mission Control review accepted")
        else:
            now = int(time.time())
            with kb.write_txn(conn):
                if desired == "done":
                    conn.execute(
                        "UPDATE tasks SET status='done', completed_at=?, result=? WHERE id=?",
                        (now, str(task.get("review_summary") or task.get("outcome_reason") or "Mission Control review accepted")[:8000], card_id),
                    )
                else:
                    conn.execute(
                        "UPDATE tasks SET status=?, completed_at=NULL WHERE id=? AND status!='done'",
                        (desired, card_id),
                    )
        lifecycle = f"mission-control-event={event};worker-status={worker_status};review-status={review_status or 'pending'}"
        comments = kb.list_comments(conn, card_id)
        if not comments or str(getattr(comments[-1], "body", "") or "") != lifecycle:
            kb.add_comment(conn, card_id, MISSION_CONTROL_CREATED_BY, lifecycle)
        return True
    except Exception:
        return False
    finally:
        conn.close()


def _mission_control_rows_read_only() -> tuple[list[dict[str, Any]], dict[str, int]]:
    if _KANBAN_MODULE_OVERRIDE is not None:
        kb = _KANBAN_MODULE_OVERRIDE
        conn = kb.connect(board=BOARD_SLUG)
        try:
            tasks = [t for t in kb.list_tasks(conn, assignee=ASSIGNEE) if str(getattr(t, "idempotency_key", "") or "").startswith(MISSION_CONTROL_KEY_PREFIX)]
            rows = []
            counts: dict[str, int] = {}
            for task in tasks:
                status = str(task.status)
                counts[status] = counts.get(status, 0) + 1
                comments = kb.list_comments(conn, task.id)
                delegated_id = _delegation_marker(comments)
                rows.append({"board_task_id": task.id, "title": task.title, "status": status, "delegated_task_id": delegated_id, "logical_work_id": str(task.idempotency_key)[len(MISSION_CONTROL_KEY_PREFIX):]})
            return rows, counts
        finally:
            conn.close()

    policy = _select_board_read_policy()
    db_path = BOARD_ROOT / "kanban.db"
    if policy is None or not db_path.is_file():
        return [], {}
    policy.require_read_path(db_path)
    uri = f"file:{db_path}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        task_rows = conn.execute(
            "SELECT id,title,status,idempotency_key FROM tasks WHERE assignee=? AND idempotency_key LIKE ?",
            (ASSIGNEE, MISSION_CONTROL_KEY_PREFIX + "%"),
        ).fetchall()
        rows: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        for row in task_rows:
            status = str(row["status"])
            counts[status] = counts.get(status, 0) + 1
            marker = conn.execute(
                "SELECT body FROM task_comments WHERE task_id=? AND body LIKE ? ORDER BY id DESC LIMIT 1",
                (row["id"], DELEGATION_MARKER_PREFIX + "%"),
            ).fetchone()
            delegated_id = None
            if marker:
                delegated_id = str(marker[0])[len(DELEGATION_MARKER_PREFIX):].strip() or None
            if delegated_id and delegated_id.startswith("dt_"):
                try:
                    if not op_delegation._task_path(delegated_id).is_file():
                        delegated_id = None
                except Exception:
                    delegated_id = None
            key = str(row["idempotency_key"] or "")
            rows.append({"board_task_id": row["id"], "title": row["title"], "status": status, "delegated_task_id": delegated_id, "logical_work_id": key[len(MISSION_CONTROL_KEY_PREFIX):]})
    return rows, counts


def mission_control_task_status(logical_work_id: str) -> str | None:
    rows, _ = _mission_control_rows_read_only()
    for row in rows:
        if row.get("logical_work_id") == logical_work_id:
            return _board_status_to_mission_control(str(row.get("status") or ""))
    return None


def mission_control_snapshot() -> dict[str, Any]:
    try:
        rows, counts = _mission_control_rows_read_only()
        active = [row for row in rows if row.get("status") in {"running", "review"} and row.get("delegated_task_id")]
        return {
            "success": True,
            "board": BOARD_SLUG,
            "counts": counts,
            "active_delegations": active,
            "active_count": len(active),
        }
    except Exception as exc:
        return {
            "success": False,
            "board": BOARD_SLUG,
            "counts": {},
            "active_delegations": [],
            "active_count": 0,
            "error": f"{exc.__class__.__name__}: {exc}",
        }


def _encode_packet(packet: dict[str, Any]) -> str:
    return PACKET_PREFIX + json.dumps(packet, sort_keys=True, separators=(",", ":"))


def _decode_packet(body: str | None) -> dict[str, Any] | None:
    text = str(body or "")
    if not text.startswith(PACKET_PREFIX):
        return None
    try:
        value = json.loads(text[len(PACKET_PREFIX) :])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _delegation_marker(comments: list[Any]) -> str | None:
    prefix = "governed-delegation-task-id="
    for comment in reversed(comments):
        body = str(getattr(comment, "body", "") or "")
        if body.startswith(prefix):
            value = body[len(prefix) :].strip()
            return value or None
    return None


def _sync_seed_record(kb: Any, conn: Any, task_id: str, item: dict[str, Any], body: str) -> None:
    """Refresh one known governed seed card without replacing its durable ID/history."""
    workspace_path = str(CLEAN_MAINTENANCE_WORKTREE) if item["kind"] == "delegate" else None
    # Unit-test fake path; production uses the same SQL shape as Hermes' dashboard updater.
    if hasattr(conn, "kb") and hasattr(conn.kb, "tasks"):
        task = conn.kb.tasks.get(task_id)
        if task is not None:
            task.title = item["title"]
            task.body = body
            task.assignee = ASSIGNEE
            task.priority = int(item["priority"])
            task.workspace_path = workspace_path
    else:
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET title = ?, body = ?, assignee = ?, priority = ?, "
                "workspace_kind = 'dir', workspace_path = ? WHERE id = ?",
                (item["title"], body, ASSIGNEE, int(item["priority"]), workspace_path, task_id),
            )
            conn.execute(
                "INSERT INTO task_events (task_id, kind, payload, created_at) VALUES (?, 'edited', ?, ?)",
                (task_id, json.dumps({"source": CREATED_BY, "seed_schema": 1}), int(time.time())),
            )

    task = kb.get_task(conn, task_id) if hasattr(kb, "get_task") else getattr(conn, "kb", None).tasks.get(task_id)
    if task is None:
        return
    if item["kind"] == "delegate":
        # Canonical governed seed delegate cards have no parent dependencies.
        # Older persisted versions may retain task_links from previous schemas;
        # remove only inbound links for this exact seeded delegate ID.
        if hasattr(conn, "kb") and hasattr(conn.kb, "task_links"):
            conn.kb.task_links = [link for link in conn.kb.task_links if link[1] != task_id]
        elif not (hasattr(conn, "kb") and hasattr(conn.kb, "tasks")):
            with kb.write_txn(conn):
                conn.execute("DELETE FROM task_links WHERE child_id = ?", (task_id,))
    if item["kind"] == "delegate" and task.status == "todo":
        if hasattr(conn, "kb") and hasattr(conn.kb, "tasks"):
            task.status = "ready"
            task.started_at = None
        else:
            with kb.write_txn(conn):
                conn.execute(
                    "UPDATE tasks SET status='ready', started_at=NULL, completed_at=NULL, "
                    "claim_lock=NULL, claim_expires=NULL, current_run_id=NULL WHERE id=?",
                    (task_id,),
                )
        kb.add_comment(conn, task_id, CREATED_BY, "governed-seed-todo-normalized=v1")
    elif item["kind"] == "delegate" and task.status in {"blocked", "archived"}:
        reason = _latest_block_reason(conn, task)
        known_stale = (
            task.status == "archived"
            or "controller-governed card has no valid governed delegation packet" in reason
            or "originating standing authority is no longer active" in reason
        )
        marker = "governed-seed-migration=v1"
        comments = kb.list_comments(conn, task_id)
        already = any(str(getattr(c, "body", "") or "") == marker for c in comments)
        if known_stale and not already:
            if task.status == "blocked":
                kb.unblock_task(conn, task_id)
            else:
                if hasattr(conn, "kb") and hasattr(conn.kb, "tasks"):
                    task.status = "ready"
                    task.started_at = None
                else:
                    with kb.write_txn(conn):
                        conn.execute(
                            "UPDATE tasks SET status='ready', started_at=NULL, completed_at=NULL, "
                            "claim_lock=NULL, claim_expires=NULL, current_run_id=NULL WHERE id=?",
                            (task_id,),
                        )
            kb.add_comment(conn, task_id, CREATED_BY, marker)
    elif item["kind"] == "boundary" and task.status != "blocked":
        kb.block_task(conn, task_id, reason=str(item["reason"]), kind="capability")


def _ensure_board_and_seed(kb: Any, policy: op_policy.OperatorPolicy) -> list[str]:
    policy.require_write_path(BOARD_ROOT)
    kb.create_board(
        BOARD_SLUG,
        name=BOARD_NAME,
        description=(
            "Governed Hermes stabilization work. Cards on controller-governed are "
            "dispatched only through Hermes-GPT operator authority and evidence gates."
        ),
        default_workdir=str(CLEAN_MAINTENANCE_WORKTREE),
    )
    conn = kb.connect(board=BOARD_SLUG)
    ids: list[str] = []
    try:
        for item in SEED_TASKS:
            if item["kind"] == "delegate":
                body = _encode_packet(item["packet"])
                initial_status = "running"  # ignored for ordinary no-parent cards -> ready
            else:
                body = str(item["reason"])
                initial_status = "blocked"
            task_id = kb.create_task(
                conn,
                title=item["title"],
                body=body,
                assignee=ASSIGNEE,
                created_by=CREATED_BY,
                workspace_kind="dir",
                workspace_path=(
                    str(CLEAN_MAINTENANCE_WORKTREE)
                    if item["kind"] == "delegate"
                    else None
                ),
                priority=int(item["priority"]),
                idempotency_key=item["key"],
                initial_status=initial_status,
                board=BOARD_SLUG,
            )
            _sync_seed_record(kb, conn, task_id, item, body)
            ids.append(task_id)
            if item["kind"] == "boundary":
                existing = kb.list_comments(conn, task_id)
                marker = "governed-boundary="
                if not any(str(getattr(c, "body", "")).startswith(marker) for c in existing):
                    detail = item["reason"]
                    template = item.get("approval_policy_template")
                    if template:
                        detail += f" Approval policy template: {template}."
                    kb.add_comment(conn, task_id, CREATED_BY, marker + detail)
        return ids
    finally:
        conn.close()


def _queue_ready_task(kb: Any, conn: Any, task: Any) -> None:
    packet = _decode_packet(getattr(task, "body", None))
    if packet is None:
        kb.block_task(
            conn,
            task.id,
            reason="controller-governed card has no valid governed delegation packet",
            kind="capability",
        )
        return
    claimed = kb.claim_task(
        conn,
        task.id,
        ttl_seconds=CLAIM_TTL_SECONDS,
        claimer=ASSIGNEE,
    )
    if claimed is None:
        return

    forecast = json.loads(
        op_delegation.hermes_delegate_task_forecast(
            workdir=str(packet["workdir"]),
            mode=str(packet.get("mode", "read_only")),
            profile=str(packet.get("profile", "default")),
            max_turns=int(packet.get("max_turns", 30)),
            timeout=int(packet.get("timeout", 1800)),
            allow_web=bool(packet.get("allow_web", False)),
        )
    )
    if not forecast.get("success") or not forecast.get("granted"):
        reason = (
            forecast.get("denial", {}).get("safe_message")
            or forecast.get("safe_message")
            or "no approved authority completely covers this card"
        )
        kb.block_task(conn, task.id, reason=f"Approval required: {reason}", kind="capability")
        return

    queued = json.loads(
        op_delegation.hermes_delegate_task(
            prompt=str(packet["prompt"]),
            workdir=str(packet["workdir"]),
            mode=str(packet.get("mode", "read_only")),
            profile=str(packet.get("profile", "default")),
            max_turns=int(packet.get("max_turns", 30)),
            timeout=int(packet.get("timeout", 1800)),
            allow_web=bool(packet.get("allow_web", False)),
        )
    )
    if not queued.get("success"):
        kb.block_task(
            conn,
            task.id,
            reason=queued.get("safe_message") or "governed delegation could not be queued",
            kind="transient",
        )
        return
    delegated_id = str(queued.get("task_id") or "")
    if not delegated_id:
        kb.block_task(conn, task.id, reason="delegation returned no task id", kind="transient")
        return
    kb.add_comment(conn, task.id, CREATED_BY, f"governed-delegation-task-id={delegated_id}")


def _latest_block_reason(conn: Any, task: Any) -> str:
    """Return the canonical most-recent blocked reason for a Kanban task."""
    direct = str(getattr(task, "block_reason", "") or "")
    if direct:
        return direct
    try:
        row = conn.execute(
            "SELECT payload FROM task_events WHERE task_id = ? AND kind = 'blocked' ORDER BY id DESC LIMIT 1",
            (task.id,),
        ).fetchone()
        if row is None:
            return ""
        raw = row[0] if not hasattr(row, "keys") else row["payload"]
        payload = json.loads(str(raw or "{}"))
        return str(payload.get("reason") or "") if isinstance(payload, dict) else ""
    except Exception:
        return ""


def _seeded_task_diagnostics(kb: Any, conn: Any) -> list[dict[str, Any]]:
    """Return safe board-state diagnostics for the fixed governed seed cards."""
    rows: list[dict[str, Any]] = []
    seeded_keys = {str(item["key"]) for item in SEED_TASKS}
    for task in kb.list_tasks(conn, assignee=ASSIGNEE, limit=20):
        if str(getattr(task, "idempotency_key", "") or "") not in seeded_keys:
            continue
        latest_kind = ""
        latest_payload: dict[str, Any] = {}
        try:
            event = conn.execute(
                "SELECT kind, payload FROM task_events WHERE task_id = ? ORDER BY id DESC LIMIT 1",
                (task.id,),
            ).fetchone()
            if event is not None:
                if hasattr(event, "keys"):
                    latest_kind = str(event["kind"] or "")
                    raw_payload = event["payload"]
                else:
                    latest_kind = str(event[0] or "")
                    raw_payload = event[1]
                parsed = json.loads(str(raw_payload or "{}"))
                if isinstance(parsed, dict):
                    latest_payload = parsed
        except Exception:
            pass
        rows.append(
            {
                "task_id": str(task.id),
                "title": str(getattr(task, "title", "") or ""),
                "status": str(getattr(task, "status", "") or ""),
                "latest_event_kind": latest_kind,
                "latest_reason": str(latest_payload.get("reason") or "")[:500],
                "latest_summary": str(latest_payload.get("summary") or "")[:500],
            }
        )
    return rows


def _recover_fixed_authority_blocks(kb: Any, conn: Any) -> None:
    """Retry only cards blocked by the now-fixed standing-pointer bug.

    This is intentionally not a generic transient/capability auto-unblocker.
    It recognizes one historical failure signature, retries each matching card
    at most once, and leaves all genuine approval/material boundaries blocked.
    """
    retry_marker = "governed-fixed-authority-retry=v2"
    for task in kb.list_tasks(conn, assignee=ASSIGNEE, status="blocked", limit=20):
        if _decode_packet(getattr(task, "body", None)) is None:
            continue
        reason = _latest_block_reason(conn, task)
        if "originating standing authority is no longer active" not in reason:
            continue
        comments = kb.list_comments(conn, task.id)
        if any(str(getattr(comment, "body", "") or "") == retry_marker for comment in comments):
            continue
        if kb.unblock_task(conn, task.id):
            kb.add_comment(conn, task.id, CREATED_BY, retry_marker)


def _reconcile_running_task(kb: Any, conn: Any, task: Any) -> None:
    comments = kb.list_comments(conn, task.id)
    delegated_id = _delegation_marker(comments)
    if not delegated_id:
        started_at = int(getattr(task, "started_at", 0) or 0)
        if started_at and int(time.time()) - started_at > 180:
            kb.block_task(
                conn,
                task.id,
                reason="governed card was claimed but no delegated task id was recorded",
                kind="transient",
            )
        return
    status = json.loads(op_delegation.hermes_delegated_task_status(delegated_id))
    if not status.get("success"):
        return
    latest_status = str(status.get("latest_status") or status.get("status") or "")
    if latest_status not in op_delegation.TERMINAL_STATES:
        return
    result = json.loads(op_delegation.hermes_delegated_task_result(delegated_id))
    if not result.get("ready"):
        return
    if result.get("success"):
        final_answer = str(result.get("final_answer") or "").strip()
        if result.get("review_status") == "accepted":
            if hasattr(conn, "kb") and hasattr(conn.kb, "tasks"):
                task.status = "done"
                task.result = final_answer[:8000]
            else:
                with kb.write_txn(conn):
                    conn.execute(
                        "UPDATE tasks SET status='done', completed_at=?, result=? WHERE id=?",
                        (int(time.time()), final_answer[:8000], task.id),
                    )
        else:
            if hasattr(conn, "kb") and hasattr(conn.kb, "tasks"):
                task.status = "review"
                task.result = final_answer[:8000]
            else:
                with kb.write_txn(conn):
                    conn.execute(
                        "UPDATE tasks SET status='review', completed_at=NULL, result=? WHERE id=?",
                        (final_answer[:8000], task.id),
                    )
            kb.add_comment(conn, task.id, CREATED_BY, "mission-control-review-required=v1")
        return
    failure = str(result.get("failure_category") or "")
    kind = "capability" if failure in {"permission", "provider_configuration"} else "transient"
    reason = str(result.get("outcome_reason") or result.get("stderr") or "governed delegated task failed")
    kb.block_task(conn, task.id, reason=reason[:2000], kind=kind)


def dispatch_once() -> dict[str, Any]:
    now = int(time.time())
    policy = _select_board_policy()
    with _LOCK:
        _STATE["last_tick_at"] = now
    if policy is None:
        with _LOCK:
            _STATE.update(
                {
                    "status": "waiting_for_board_authority",
                    "board_authority_id": None,
                    "last_error": None,
                    "counts": {},
                }
            )
        return status_snapshot()

    try:
        kb = _kb()
        seeded = _ensure_board_and_seed(kb, policy)
        conn = kb.connect(board=BOARD_SLUG)
        try:
            _recover_fixed_authority_blocks(kb, conn)
            for task in kb.list_tasks(conn, assignee=ASSIGNEE, status="running", limit=10):
                _reconcile_running_task(kb, conn, task)
            # One new claim per tick keeps execution serial and makes each card's
            # authority/evidence trail easy to audit.
            ready = kb.list_tasks(conn, assignee=ASSIGNEE, status="ready", limit=1)
            if ready:
                _queue_ready_task(kb, conn, ready[0])
            counts: dict[str, int] = {}
            for status in ("triage", "todo", "scheduled", "ready", "running", "blocked", "review", "done"):
                counts[status] = len(kb.list_tasks(conn, assignee=ASSIGNEE, status=status))
            diagnostics = _seeded_task_diagnostics(kb, conn)
        finally:
            conn.close()
        with _LOCK:
            _STATE.update(
                {
                    "status": "active",
                    "board_authority_id": policy.session_id,
                    "last_error": None,
                    "counts": counts,
                    "seeded_task_ids": seeded,
                    "tasks": diagnostics,
                }
            )
    except Exception as exc:
        with _LOCK:
            _STATE.update(
                {
                    "status": "error",
                    "board_authority_id": policy.session_id,
                    "last_error": f"{exc.__class__.__name__}: {exc}",
                }
            )
    return status_snapshot()


def _loop() -> None:
    while True:
        try:
            dispatch_once()
        except Exception as exc:  # pragma: no cover - outer defensive loop
            with _LOCK:
                _STATE.update(
                    {
                        "status": "error",
                        "last_error": f"{exc.__class__.__name__}: {exc}",
                        "last_tick_at": int(time.time()),
                    }
                )
        time.sleep(POLL_SECONDS)


def start_dispatcher() -> None:
    global _STARTED, _THREAD
    # Unit tests construct multiple FastMCP servers in one process. Do not leak
    # a real background board thread from those fixtures; dedicated bridge tests
    # invoke dispatch_once() directly with a fake kanban module.
    if os.environ.get("PYTEST_CURRENT_TEST") and _KANBAN_MODULE_OVERRIDE is None:
        return
    with _LOCK:
        if _STARTED:
            return
        _STARTED = True
        _STATE["started"] = True
        _STATE["status"] = "starting"
        _THREAD = threading.Thread(
            target=_loop,
            daemon=True,
            name="hermes-governed-kanban",
        )
        _THREAD.start()


def status_snapshot() -> dict[str, Any]:
    with _LOCK:
        return json.loads(json.dumps(_STATE))
