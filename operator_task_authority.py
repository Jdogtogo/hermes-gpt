"""Task-Bound Authority v2 (TASK_AUTHORITY).

One logical task -> one stable work-package id -> one least-privilege
authority envelope -> execution, with approval required only at genuine
material boundaries.

Design rules enforced here:
  * default deny / fail closed
  * least privilege (narrow derived envelope, never a broad template)
  * NO authority union: exactly one source is selected and returned
  * immutable audit evidence (append-only jsonl)
  * task/worktree containment
  * hard-denied secret paths preserved (inherited, never removed)
  * task lifetime is bound to the LOGICAL TASK, not a 30-minute session timer
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TASK_DB_NAME = "task_authorities.sqlite3"
TASK_AUDIT_NAME = "task_authority_audit.jsonl"

# Hard safety lifetime. A logical task may outlive a routine session timer,
# but never this. 8h is the absolute ceiling.
HARD_TASK_LIFETIME_SECONDS = 8 * 60 * 60

# Secret / credential roots that are ALWAYS denied, regardless of task scope.
HARD_DENIED_PATHS = (
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.docker", "~/.azure",
    "~/.cloudflared", "~/.hermes/mcp-tokens", "~/.hermes/auth",
    "~/.hermes/.env", "~/.hermes/auth.json",
)

# Material boundaries: ALWAYS human-gated, never covered by a task authority.
MATERIAL_BOUNDARIES = (
    "secrets", "paid_routing", "budget", "network_security",
    "host_install", "release_deploy", "destructive", "repo_reset",
    "undeclared_root",
)

TERMINAL_STATES = {"completed", "cancelled", "revoked"}


class TaskAuthorityError(ValueError):
    """Raised on task-authority integrity violations."""


@dataclass(frozen=True)
class TaskEnvelope:
    """The narrow, derived capability envelope for one logical task."""

    readable_roots: tuple[str, ...] = ()
    writable_roots: tuple[str, ...] = ()
    verbs: dict[str, tuple[str, ...]] = field(default_factory=dict)
    service_units: tuple[str, ...] = ()
    task_class: str = "generic"

    def canonical(self) -> dict[str, Any]:
        return {
            "readable_roots": sorted(self.readable_roots),
            "writable_roots": sorted(self.writable_roots),
            "verbs": {k: sorted(v) for k, v in sorted(self.verbs.items())},
            "service_units": sorted(self.service_units),
            "task_class": self.task_class,
        }

    def capability_hash(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class TaskAuthority:
    task_id: str
    envelope: TaskEnvelope
    source: str            # task_bound | standing | session | approved_request
    source_id: str | None
    state: str             # active | completed | cancelled | revoked
    created_at: int
    hard_expires_at: int
    policy_class: str

    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def is_valid(self, *, now: int | None = None) -> tuple[bool, str | None]:
        current = int(time.time() if now is None else now)
        if self.state in TERMINAL_STATES:
            return False, f"task {self.task_id} is {self.state}"
        if current >= self.hard_expires_at:
            return False, (
                f"task {self.task_id} exceeded hard safety lifetime "
                f"({HARD_TASK_LIFETIME_SECONDS}s)"
            )
        return True, None


def _root(root: Path | None = None) -> Path:
    if root is not None:
        return Path(root)
    env = os.environ.get("HERMES_GPT_OPERATOR_SESSION_ROOT", "").strip()
    if env:
        return Path(env)
    return Path.home() / ".hermes" / "operator-sessions" / "default"


def _db_path(root: Path | None = None) -> Path:
    return _root(root) / TASK_DB_NAME


def _audit_path(root: Path | None = None) -> Path:
    return _root(root) / TASK_AUDIT_NAME


def _connect(root: Path | None = None) -> sqlite3.Connection:
    path = _db_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    _initialize(connection)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return connection


def _initialize(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS task_authorities ("
        "task_id TEXT PRIMARY KEY, envelope_json TEXT NOT NULL, "
        "capability_hash TEXT NOT NULL, source TEXT NOT NULL, "
        "source_id TEXT, state TEXT NOT NULL, created_at INTEGER NOT NULL, "
        "hard_expires_at INTEGER NOT NULL, policy_class TEXT NOT NULL, "
        "request_identity TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS task_requests ("
        "request_id TEXT PRIMARY KEY, request_identity TEXT NOT NULL, "
        "task_id TEXT NOT NULL, envelope_json TEXT NOT NULL, "
        "status TEXT NOT NULL, created_at INTEGER NOT NULL, "
        "decided_at INTEGER, decided_by TEXT)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_req_identity ON task_requests(request_identity)"
    )
    connection.commit()


def audit(event: str, payload: dict[str, Any], *, root: Path | None = None) -> None:
    """Append-only, secret-free audit evidence."""
    record = {"ts": int(time.time()), "event": event, **payload}
    path = _audit_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

# ---------------------------------------------------------------------------
# 2. Logical task identity
# ---------------------------------------------------------------------------

def make_task_id(logical_name: str, *, worktree: str | None = None) -> str:
    """Stable logical work-package id. Same logical work -> same id, so a
    task survives process restarts and session timers."""
    basis = f"{logical_name.strip().lower()}|{(worktree or '').strip().rstrip('/')}"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    return f"task_{digest}"


def request_identity(task_id: str, envelope: TaskEnvelope, policy_class: str) -> str:
    """Deterministic request identity: task id + capability set + roots +
    policy class. Two equivalent asks produce the SAME identity, so they are
    de-duplicated instead of superseding one another."""
    basis = json.dumps(
        {
            "task_id": task_id,
            "capability": envelope.capability_hash(),
            "policy_class": policy_class,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "ri_" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# 5. Narrow task capability derivation
# ---------------------------------------------------------------------------

# 6. Expected task classes. Each is a NARROW envelope, not a broad template.
TASK_CLASSES: dict[str, dict[str, Any]] = {
    "hermes_gpt_contained_maintenance": {
        "verbs": {"fs": ("read", "write"), "git": ("commit",), "test": ("run",)},
        "requires_worktree": True,
    },
    "hermes_agent_kanban_ui": {
        "verbs": {"fs": ("read", "write"), "git": ("commit",), "test": ("run",)},
        "requires_worktree": True,
    },
    "hermes_stabilization_board": {
        "verbs": {"fs": ("read", "write"), "git": ("commit",), "test": ("run",)},
        "requires_worktree": True,
    },
    "mission_control_opsbrain": {
        "verbs": {"fs": ("read", "write"), "git": ("commit",)},
        "requires_worktree": False,
    },
    "free_routing_qualification": {
        "verbs": {"fs": ("read",), "routing": ("read",)},
        "requires_worktree": False,
    },
    "task_bound_operator_restart": {
        "verbs": {"fs": ("read", "write"), "service": ("restart",)},
        "requires_worktree": True,
    },
    "generic": {"verbs": {"fs": ("read",)}, "requires_worktree": False},
}


def derive_envelope(
    *,
    task_class: str,
    files: tuple[str, ...] = (),
    writable_files: tuple[str, ...] = (),
    needs_test: bool = False,
    needs_commit: bool = False,
    service_units: tuple[str, ...] = (),
) -> TaskEnvelope:
    """Derive the NARROWEST envelope that satisfies the declared operation.

    Editing one Kanban UI file + running its test + an isolated commit yields
    exactly those roots and verbs -- never blanket write access to all of
    Hermes Agent.
    """
    spec = TASK_CLASSES.get(task_class)
    if spec is None:
        raise TaskAuthorityError(f"unknown task class {task_class!r}")

    allowed = spec["verbs"]
    verbs: dict[str, tuple[str, ...]] = {}

    if files or writable_files:
        verbs["fs"] = ("read",)
    if writable_files:
        if "write" not in allowed.get("fs", ()):  # least privilege
            raise TaskAuthorityError(f"task class {task_class!r} may not write")
        verbs["fs"] = ("read", "write")
    if needs_test:
        if "run" not in allowed.get("test", ()):
            raise TaskAuthorityError(f"task class {task_class!r} may not run tests")
        verbs["test"] = ("run",)
    if needs_commit:
        if "commit" not in allowed.get("git", ()):
            raise TaskAuthorityError(f"task class {task_class!r} may not commit")
        verbs["git"] = ("commit",)
    if service_units:
        if "restart" not in allowed.get("service", ()):
            raise TaskAuthorityError(
                f"task class {task_class!r} may not restart services; "
                "declare task class 'task_bound_operator_restart'"
            )
        verbs["service"] = ("restart",)
    if not verbs:
        verbs = {"fs": ("read",)}

    readable = tuple(sorted({*files, *writable_files}))
    return TaskEnvelope(
        readable_roots=readable,
        writable_roots=tuple(sorted(set(writable_files))),
        verbs=verbs,
        service_units=tuple(sorted(set(service_units))),
        task_class=task_class,
    )


def envelope_from_policy(policy: dict[str, Any], *, task_class: str) -> TaskEnvelope:
    """Adapt one already-resolved immutable operator policy snapshot into a
    task envelope without broadening it.

    This bridge is intentionally mechanical: roots, verbs, and service units
    are copied from the approved snapshot exactly (after deterministic
    normalization). The existing operator risk gate remains the approval
    boundary; this function never grants authority by itself.
    """
    raw_verbs = policy.get("verbs") if isinstance(policy.get("verbs"), dict) else {}
    verbs: dict[str, tuple[str, ...]] = {}
    for name, actions in sorted(raw_verbs.items()):
        if not isinstance(name, str) or not isinstance(actions, (list, tuple)):
            continue
        normalized = tuple(sorted({str(action).strip() for action in actions if str(action).strip()}))
        if normalized:
            verbs[name] = normalized
    return TaskEnvelope(
        readable_roots=tuple(sorted({str(p) for p in policy.get("readable_roots", []) if str(p).strip()})),
        writable_roots=tuple(sorted({str(p) for p in policy.get("writable_roots", []) if str(p).strip()})),
        verbs=verbs,
        service_units=tuple(sorted({str(u) for u in policy.get("service_units", []) if str(u).strip()})),
        task_class=task_class,
    )


def _expand(path: str) -> Path:
    return Path(os.path.expanduser(path))


def is_hard_denied(path: str) -> bool:
    """Secret/credential paths are denied even inside an active task."""
    try:
        target = _expand(path).resolve()
    except Exception:
        return True
    for denied in HARD_DENIED_PATHS:
        try:
            root = _expand(denied).resolve()
        except Exception:
            continue
        if target == root or root in target.parents:
            return True
    return False


def envelope_covers(envelope: TaskEnvelope, other: TaskEnvelope) -> bool:
    """True when `envelope` is INDEPENDENTLY sufficient for `other`.

    This is a containment test on ONE authority. It never merges two
    authorities together -- that would be an authority union.
    """
    if other.task_class != envelope.task_class:
        return False
    for verb, actions in other.verbs.items():
        have = set(envelope.verbs.get(verb, ()))
        if not set(actions).issubset(have):
            return False
    for root in other.readable_roots:
        if not _under_any(root, envelope.readable_roots):
            return False
    for root in other.writable_roots:
        if not _under_any(root, envelope.writable_roots):
            return False
    if not set(other.service_units).issubset(set(envelope.service_units)):
        return False
    return True


def _under_any(path: str, roots: tuple[str, ...]) -> bool:
    try:
        target = _expand(path).resolve()
    except Exception:
        return False
    for candidate in roots:
        try:
            root = _expand(candidate).resolve()
        except Exception:
            continue
        if target == root or root in target.parents:
            return True
    return False

# ---------------------------------------------------------------------------
# 7. Material boundaries -- always human-gated
# ---------------------------------------------------------------------------

def material_boundary(
    *,
    paths: tuple[str, ...] = (),
    paid_routing: bool = False,
    budget_change: bool = False,
    network_security: bool = False,
    host_install: bool = False,
    release_deploy: bool = False,
    destructive: bool = False,
    repo_reset: bool = False,
    declared_roots: tuple[str, ...] = (),
) -> str | None:
    """Return the material-boundary name when one is crossed, else None.

    No task authority can ever cover these; they always demand explicit
    human approval.
    """
    for path in paths:
        if is_hard_denied(path):
            return "secrets"
    if paid_routing:
        return "paid_routing"
    if budget_change:
        return "budget"
    if network_security:
        return "network_security"
    if host_install:
        return "host_install"
    if release_deploy:
        return "release_deploy"
    if destructive:
        return "destructive"
    if repo_reset:
        return "repo_reset"
    for path in paths:
        if declared_roots and not _under_any(path, declared_roots):
            return "undeclared_root"
    return None


# ---------------------------------------------------------------------------
# 1. Unified resolver
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Resolution:
    """Read-only explanation of the authority decision (TASK_AUTHORITY)."""

    task_id: str
    authority_source: str          # task_bound|standing|approved_request|none
    effective_authority_ids: tuple[str, ...]
    roots: dict[str, tuple[str, ...]]
    verbs: dict[str, tuple[str, ...]]
    state: str
    hard_expires_at: int | None
    selection_reason: str
    approval_required: bool
    missing_capability: str | None
    request_id: str | None = None
    request_identity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": "TASK_AUTHORITY",
            "logical_task_id": self.task_id,
            "authority_source": self.authority_source,
            "effective_authority_ids": list(self.effective_authority_ids),
            "roots": {k: list(v) for k, v in self.roots.items()},
            "verbs": {k: list(v) for k, v in self.verbs.items()},
            "task_state": self.state,
            "hard_expires_at": self.hard_expires_at,
            "selection_reason": self.selection_reason,
            "approval_required": self.approval_required,
            "missing_capability": self.missing_capability,
            "request_id": self.request_id,
            "request_identity": self.request_identity,
        }


def _load(task_id: str, *, root: Path | None = None) -> TaskAuthority | None:
    with _connect(root) as connection:
        row = connection.execute(
            "SELECT * FROM task_authorities WHERE task_id = ?", (task_id,)
        ).fetchone()
    if row is None:
        return None
    data = json.loads(row["envelope_json"])
    envelope = TaskEnvelope(
        readable_roots=tuple(data["readable_roots"]),
        writable_roots=tuple(data["writable_roots"]),
        verbs={k: tuple(v) for k, v in data["verbs"].items()},
        service_units=tuple(data["service_units"]),
        task_class=data["task_class"],
    )
    return TaskAuthority(
        task_id=row["task_id"], envelope=envelope, source=row["source"],
        source_id=row["source_id"], state=row["state"],
        created_at=int(row["created_at"]),
        hard_expires_at=int(row["hard_expires_at"]),
        policy_class=row["policy_class"],
    )


def resolve(
    *,
    task_id: str,
    envelope: TaskEnvelope,
    policy_class: str,
    standing_candidates: tuple[tuple[str, TaskEnvelope], ...] = (),
    boundary: str | None = None,
    now: int | None = None,
    root: Path | None = None,
) -> Resolution:
    """THE single effective-authority resolver.

    Direct operator tools AND delegated workers call this same function, so
    both share one task-authority lifecycle.

    Order:
      1. active task-bound authority sufficient for this task
      2. independently sufficient standing authority
      3. approved / equivalent pending request
      4. otherwise create exactly ONE new approval request
      5. fail closed
    """
    current = int(time.time() if now is None else now)
    identity = request_identity(task_id, envelope, policy_class)
    roots = {
        "readable": envelope.readable_roots,
        "writable": envelope.writable_roots,
    }

    # Material boundary always wins -- never covered by any task authority.
    if boundary:
        res = Resolution(
            task_id=task_id, authority_source="none", effective_authority_ids=(),
            roots=roots, verbs=envelope.verbs, state="blocked",
            hard_expires_at=None,
            selection_reason=f"material boundary '{boundary}' requires explicit human approval",
            approval_required=True, missing_capability=boundary,
            request_identity=identity,
        )
        audit("material_boundary_blocked",
              {"task_id": task_id, "boundary": boundary, "identity": identity}, root=root)
        return res

    # 1. Active task-bound authority.
    existing = _load(task_id, root=root)
    if existing is not None:
        valid, reason = existing.is_valid(now=current)
        if valid and envelope_covers(existing.envelope, envelope):
            return Resolution(
                task_id=task_id, authority_source="task_bound",
                effective_authority_ids=(existing.source_id or task_id,),
                roots=roots, verbs=envelope.verbs, state=existing.state,
                hard_expires_at=existing.hard_expires_at,
                selection_reason=(
                    "active task-bound authority is sufficient; "
                    "reused without new approval"
                ),
                approval_required=False, missing_capability=None,
                request_identity=identity,
            )
        if valid and not envelope_covers(existing.envelope, envelope):
            missing = _first_missing(existing.envelope, envelope)
            # Material scope change -> supersede is legitimate.
            return _create_request(
                task_id=task_id, envelope=envelope, identity=identity,
                policy_class=policy_class, current=current, root=root,
                reason=f"scope materially changed; missing {missing}",
                missing=missing, supersede=True,
            )
        if not valid:
            audit("task_authority_invalid",
                  {"task_id": task_id, "reason": reason}, root=root)
            # A terminal task must not be resurrected by reusing the approved
            # request that originally granted it. Retire that request first so
            # the caller is forced back through explicit human approval.
            if existing.is_terminal():
                with _connect(root) as connection:
                    connection.execute(
                        "UPDATE task_requests SET status = 'retired', "
                        "decided_at = ?, decided_by = ? "
                        "WHERE task_id = ? AND status = 'approved'",
                        (current, f"system:task-{existing.state}", task_id),
                    )
                    connection.commit()
                audit("approved_request_retired",
                      {"task_id": task_id, "cause": existing.state}, root=root)

    # 2. Independently sufficient standing authority (single, never unioned).
    for authority_id, candidate in standing_candidates:
        if envelope_covers(candidate, envelope):
            return Resolution(
                task_id=task_id, authority_source="standing",
                effective_authority_ids=(authority_id,),
                roots=roots, verbs=envelope.verbs, state="active",
                hard_expires_at=current + HARD_TASK_LIFETIME_SECONDS,
                selection_reason=(
                    f"standing authority {authority_id} is independently "
                    "sufficient for this task envelope"
                ),
                approval_required=False, missing_capability=None,
                request_identity=identity,
            )

    # 3 + 4. Reuse an approved/pending equivalent, else create exactly one.
    return _create_request(
        task_id=task_id, envelope=envelope, identity=identity,
        policy_class=policy_class, current=current, root=root,
        reason="no sufficient existing authority", missing=None,
        supersede=False,
    )


def _first_missing(have: TaskEnvelope, want: TaskEnvelope) -> str:
    for verb, actions in want.verbs.items():
        for action in actions:
            if action not in set(have.verbs.get(verb, ())):
                return f"verb {verb}:{action}"
    for path in want.writable_roots:
        if not _under_any(path, have.writable_roots):
            return f"writable root {path}"
    for path in want.readable_roots:
        if not _under_any(path, have.readable_roots):
            return f"readable root {path}"
    for unit in want.service_units:
        if unit not in have.service_units:
            return f"service unit {unit}"
    return "unknown capability"

# ---------------------------------------------------------------------------
# 3. Approval de-duplication
# ---------------------------------------------------------------------------

def _create_request(
    *,
    task_id: str,
    envelope: TaskEnvelope,
    identity: str,
    policy_class: str,
    current: int,
    root: Path | None,
    reason: str,
    missing: str | None,
    supersede: bool,
) -> Resolution:
    """Reuse an equivalent approved/pending request before creating one.

    Critically: re-sending the SAME request does NOT supersede the earlier
    one. Supersede happens only on a material scope change.
    """
    roots = {"readable": envelope.readable_roots, "writable": envelope.writable_roots}
    envelope_json = json.dumps(envelope.canonical(), sort_keys=True)

    with _connect(root) as connection:
        approved = connection.execute(
            "SELECT request_id FROM task_requests WHERE request_identity = ? "
            "AND status = 'approved' ORDER BY created_at DESC LIMIT 1",
            (identity,),
        ).fetchone()
        if approved is not None:
            rid = str(approved["request_id"])
            audit("approved_request_reused",
                  {"task_id": task_id, "request_id": rid, "identity": identity}, root=root)
            return Resolution(
                task_id=task_id, authority_source="approved_request",
                effective_authority_ids=(rid,), roots=roots, verbs=envelope.verbs,
                state="active", hard_expires_at=current + HARD_TASK_LIFETIME_SECONDS,
                selection_reason="equivalent approved authority reused (identical request identity)",
                approval_required=False, missing_capability=None,
                request_id=rid, request_identity=identity,
            )

        pending = connection.execute(
            "SELECT request_id FROM task_requests WHERE request_identity = ? "
            "AND status = 'pending' ORDER BY created_at LIMIT 1",
            (identity,),
        ).fetchone()
        if pending is not None:
            rid = str(pending["request_id"])
            audit("pending_request_deduplicated",
                  {"task_id": task_id, "request_id": rid, "identity": identity}, root=root)
            return Resolution(
                task_id=task_id, authority_source="none",
                effective_authority_ids=(), roots=roots, verbs=envelope.verbs,
                state="pending_approval",
                hard_expires_at=None,
                selection_reason=(
                    f"equivalent pending request {rid} already awaiting approval; "
                    "not duplicated, not superseded"
                ),
                approval_required=True, missing_capability=missing,
                request_id=rid, request_identity=identity,
            )

        if supersede:
            # Material scope change only.
            old = connection.execute(
                "SELECT request_id FROM task_requests WHERE task_id = ? AND status = 'pending'",
                (task_id,),
            ).fetchall()
            if old:
                connection.execute(
                    "UPDATE task_requests SET status = 'superseded', decided_at = ?, "
                    "decided_by = 'system:material-scope-change' "
                    "WHERE task_id = ? AND status = 'pending'",
                    (current, task_id),
                )
                for row in old:
                    audit("request_superseded",
                          {"task_id": task_id, "request_id": str(row["request_id"]),
                           "cause": "material_scope_change"}, root=root)

        # Include a uniqueness nonce: the same identity may legitimately need a
        # NEW request later (e.g. after the prior grant was retired on task
        # completion), possibly within the same clock second.
        rid = "tr_" + hashlib.sha256(
            f"{identity}|{current}|{secrets.token_hex(8)}".encode("utf-8")
        ).hexdigest()[:8]
        connection.execute(
            "INSERT INTO task_requests(request_id, request_identity, task_id, "
            "envelope_json, status, created_at) VALUES (?,?,?,?, 'pending', ?)",
            (rid, identity, task_id, envelope_json, current),
        )
        connection.commit()

    audit("request_created",
          {"task_id": task_id, "request_id": rid, "identity": identity,
           "reason": reason, "task_class": envelope.task_class}, root=root)
    return Resolution(
        task_id=task_id, authority_source="none", effective_authority_ids=(),
        roots=roots, verbs=envelope.verbs, state="pending_approval",
        hard_expires_at=None,
        selection_reason=f"one new approval request created: {reason}",
        approval_required=True, missing_capability=missing,
        request_id=rid, request_identity=identity,
    )


# ---------------------------------------------------------------------------
# 4. Task lifecycle
# ---------------------------------------------------------------------------

def approve_request(
    request_id: str, *, approved_by: str, now: int | None = None,
    root: Path | None = None,
) -> TaskAuthority:
    """Human approval turns a request into a task-bound authority whose
    lifetime follows the LOGICAL TASK, not a 30-minute session timer."""
    current = int(time.time() if now is None else now)
    with _connect(root) as connection:
        row = connection.execute(
            "SELECT * FROM task_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        if row is None:
            raise TaskAuthorityError(f"unknown request {request_id!r}")
        if row["status"] != "pending":
            raise TaskAuthorityError(
                f"request {request_id!r} is {row['status']}, not pending"
            )
        data = json.loads(row["envelope_json"])
        task_id = str(row["task_id"])
        identity = str(row["request_identity"])
        connection.execute(
            "UPDATE task_requests SET status='approved', decided_at=?, decided_by=? "
            "WHERE request_id = ?",
            (current, approved_by, request_id),
        )
        connection.execute(
            "INSERT OR REPLACE INTO task_authorities(task_id, envelope_json, "
            "capability_hash, source, source_id, state, created_at, "
            "hard_expires_at, policy_class, request_identity) "
            "VALUES (?,?,?,?,?, 'active', ?,?,?,?)",
            (
                task_id, json.dumps(data, sort_keys=True),
                hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:32],
                "task_bound", request_id, current,
                current + HARD_TASK_LIFETIME_SECONDS,
                data.get("task_class", "generic"), identity,
            ),
        )
        connection.commit()
    audit("task_authority_granted",
          {"task_id": task_id, "request_id": request_id, "approved_by": approved_by},
          root=root)
    loaded = _load(task_id, root=root)
    assert loaded is not None
    return loaded


def grant_external_approval(
    *,
    task_id: str,
    envelope: TaskEnvelope,
    policy_class: str,
    source_id: str,
    approved_by: str,
    now: int | None = None,
    root: Path | None = None,
) -> TaskAuthority:
    """Mint or refresh a task-bound authority from an approval performed by
    the existing operator approval system.

    The external approval must already have passed the operator risk gate.
    This function only persists the exact approved envelope and task lifecycle;
    it never broadens capabilities and never approves a pending request itself.
    """
    current = int(time.time() if now is None else now)
    identity = request_identity(task_id, envelope, policy_class)
    envelope_json = json.dumps(envelope.canonical(), sort_keys=True)
    capability_hash = envelope.capability_hash()

    existing = _load(task_id, root=root)
    if existing is not None:
        valid, _ = existing.is_valid(now=current)
        if valid and envelope_covers(existing.envelope, envelope):
            audit(
                "external_approval_reused",
                {
                    "task_id": task_id,
                    "source_id": source_id,
                    "approved_by": approved_by,
                    "request_identity": identity,
                },
                root=root,
            )
            return existing

    with _connect(root) as connection:
        connection.execute(
            "INSERT OR REPLACE INTO task_authorities(task_id, envelope_json, "
            "capability_hash, source, source_id, state, created_at, "
            "hard_expires_at, policy_class, request_identity) "
            "VALUES (?,?,?,?,?, 'active', ?,?,?,?)",
            (
                task_id,
                envelope_json,
                capability_hash,
                "task_bound",
                source_id,
                current,
                current + HARD_TASK_LIFETIME_SECONDS,
                policy_class,
                identity,
            ),
        )
        # If the module-level resolver had already produced an equivalent
        # bookkeeping request, retire it as externally approved so a later
        # resolve cannot surface a duplicate approval ask.
        connection.execute(
            "UPDATE task_requests SET status='approved', decided_at=?, decided_by=? "
            "WHERE request_identity=? AND status='pending'",
            (current, approved_by, identity),
        )
        connection.commit()
    audit(
        "task_authority_granted_external",
        {
            "task_id": task_id,
            "source_id": source_id,
            "approved_by": approved_by,
            "request_identity": identity,
        },
        root=root,
    )
    loaded = _load(task_id, root=root)
    assert loaded is not None
    return loaded


def _set_state(task_id: str, state: str, *, root: Path | None, actor: str) -> None:
    if state not in TERMINAL_STATES:
        raise TaskAuthorityError(f"invalid terminal state {state!r}")
    with _connect(root) as connection:
        connection.execute(
            "UPDATE task_authorities SET state = ? WHERE task_id = ?", (state, task_id)
        )
        connection.commit()
    audit(f"task_{state}", {"task_id": task_id, "actor": actor}, root=root)


def complete_task(task_id: str, *, actor: str = "operator", root: Path | None = None) -> None:
    _set_state(task_id, "completed", root=root, actor=actor)


def cancel_task(task_id: str, *, actor: str = "operator", root: Path | None = None) -> None:
    _set_state(task_id, "cancelled", root=root, actor=actor)


def revoke_task(task_id: str, *, actor: str = "human", root: Path | None = None) -> None:
    _set_state(task_id, "revoked", root=root, actor=actor)


# ---------------------------------------------------------------------------
# 8. Observability -- read-only explanation surface
# ---------------------------------------------------------------------------

def explain(
    *,
    task_id: str,
    envelope: TaskEnvelope,
    policy_class: str = "default",
    standing_candidates: tuple[tuple[str, TaskEnvelope], ...] = (),
    boundary: str | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    """Read-only TASK_AUTHORITY status. Performs no mutation beyond the
    request bookkeeping the resolver itself would do."""
    return resolve(
        task_id=task_id, envelope=envelope, policy_class=policy_class,
        standing_candidates=standing_candidates, boundary=boundary, root=root,
    ).to_dict()


def task_status(task_id: str, *, root: Path | None = None, now: int | None = None) -> dict[str, Any]:
    authority = _load(task_id, root=root)
    if authority is None:
        return {"label": "TASK_AUTHORITY", "logical_task_id": task_id,
                "task_state": "none", "approval_required": True}
    valid, reason = authority.is_valid(now=now)
    return {
        "label": "TASK_AUTHORITY",
        "logical_task_id": task_id,
        "task_state": authority.state,
        "authority_source": authority.source,
        "effective_authority_ids": [authority.source_id or task_id],
        "roots": {
            "readable": list(authority.envelope.readable_roots),
            "writable": list(authority.envelope.writable_roots),
        },
        "verbs": {k: list(v) for k, v in authority.envelope.verbs.items()},
        "hard_expires_at": authority.hard_expires_at,
        "valid": valid,
        "selection_reason": reason or "task-bound authority active",
        "approval_required": not valid,
    }
