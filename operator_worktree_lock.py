"""Persistent single-writer ownership locks for governed Hermes worktrees.

Locks live in the operator-session state root, not inside the target repository,
so they cannot become untracked project files or be accidentally committed.
They contain only an authority id, normalized worktree path, and timestamp.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from operator_sessions import session_root


LOCK_DIR_NAME = "worktree-writer-locks"


class WriterLockError(ValueError):
    pass


class WriterLockConflictError(WriterLockError):
    pass


class WriterLockMissingError(WriterLockError):
    pass


@dataclass(frozen=True)
class WriterLock:
    authority_id: str
    worktree: Path
    claimed_at: int

    def to_dict(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            "worktree": str(self.worktree),
            "claimed_at": self.claimed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "WriterLock":
        return cls(
            authority_id=str(data["authority_id"]),
            worktree=Path(str(data["worktree"])).expanduser().resolve(),
            claimed_at=int(data["claimed_at"]),
        )


def _normalized_worktree(path: str | os.PathLike[str]) -> Path:
    return Path(path).expanduser().resolve()


def _lock_dir(root: Path | None = None) -> Path:
    return (root or session_root()) / LOCK_DIR_NAME


def lock_path(path: str | os.PathLike[str], *, root: Path | None = None) -> Path:
    normalized = _normalized_worktree(path)
    digest = hashlib.sha256(str(normalized).encode("utf-8")).hexdigest()
    return _lock_dir(root) / f"{digest}.json"


def _read_lock(path: Path) -> WriterLock | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("lock payload is not an object")
        return WriterLock.from_dict(data)
    except FileNotFoundError:
        return None
    except Exception as exc:
        raise WriterLockError(
            f"Writer-lock state {path.name!r} is malformed or unreadable: {exc.__class__.__name__}"
        ) from exc


def _write_lock(lock: WriterLock, *, root: Path | None = None) -> None:
    path = lock_path(lock.worktree, root=root)
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(
        json.dumps(lock.to_dict(), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)


def claim_writer_locks(
    authority_id: str,
    writable_roots: Iterable[str | os.PathLike[str]],
    *,
    root: Path | None = None,
    now: int | None = None,
) -> tuple[WriterLock, ...]:
    """Atomically claim all roots or release any partial claims on conflict."""
    if not authority_id.strip():
        raise WriterLockError("authority_id is required")
    current = int(time.time()) if now is None else int(now)
    roots = tuple(dict.fromkeys(_normalized_worktree(path) for path in writable_roots))
    claimed: list[WriterLock] = []
    newly_created: list[WriterLock] = []
    try:
        for worktree in roots:
            path = lock_path(worktree, root=root)
            existing = _read_lock(path)
            if existing is not None and existing.authority_id != authority_id:
                raise WriterLockConflictError(
                    f"Worktree {worktree} is already owned by authority {existing.authority_id}"
                )
            lock = existing or WriterLock(authority_id, worktree, current)
            if existing is None:
                _write_lock(lock, root=root)
                newly_created.append(lock)
            claimed.append(lock)
    except Exception:
        release_writer_locks(
            authority_id,
            (lock.worktree for lock in newly_created),
            root=root,
            missing_ok=True,
        )
        raise
    return tuple(claimed)


def assert_writer_locks(
    authority_id: str,
    writable_roots: Iterable[str | os.PathLike[str]],
    *,
    root: Path | None = None,
) -> None:
    for worktree in tuple(dict.fromkeys(_normalized_worktree(path) for path in writable_roots)):
        existing = _read_lock(lock_path(worktree, root=root))
        if existing is None:
            raise WriterLockMissingError(f"No writer lock exists for worktree {worktree}")
        if existing.authority_id != authority_id:
            raise WriterLockConflictError(
                f"Worktree {worktree} is owned by {existing.authority_id}, not {authority_id}"
            )


def release_writer_locks(
    authority_id: str,
    writable_roots: Iterable[str | os.PathLike[str]],
    *,
    root: Path | None = None,
    missing_ok: bool = True,
) -> int:
    released = 0
    for worktree in tuple(dict.fromkeys(_normalized_worktree(path) for path in writable_roots)):
        path = lock_path(worktree, root=root)
        existing = _read_lock(path)
        if existing is None:
            if missing_ok:
                continue
            raise WriterLockMissingError(f"No writer lock exists for worktree {worktree}")
        if existing.authority_id != authority_id:
            raise WriterLockConflictError(
                f"Refusing to release worktree {worktree}; owned by {existing.authority_id}"
            )
        path.unlink()
        released += 1
    return released
