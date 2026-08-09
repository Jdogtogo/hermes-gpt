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
        "title": "Review routing and environment configuration drift",
        "priority": 70,
        "kind": "boundary",
        "reason": (
            "Material configuration scope: review planner-glm52 in the process profile "
            "allowlist and the stale Active-Pipeline environment hint under the existing "
            "hermes-model-routing-migration policy. No autonomous standing grant covers "
            "those live configuration roots."
        ),
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
    result = json.loads(op_delegation.hermes_delegated_task_result(delegated_id))
    if not result.get("ready"):
        return
    if result.get("success"):
        final_answer = str(result.get("final_answer") or result.get("stdout") or "").strip()
        metadata = {
            "delegated_task_id": delegated_id,
            "authority_id": (result.get("authority") or {}).get("session_id"),
            "changed_files": result.get("changed_files") or [],
            "returncode": result.get("returncode"),
        }
        kb.complete_task(
            conn,
            task.id,
            result=final_answer[:8000],
            summary=(final_answer.splitlines()[0][:400] if final_answer else "Governed task completed"),
            metadata=metadata,
        )
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
