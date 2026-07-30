from pathlib import Path

import pytest

import operator_policy as op
import operator_sessions as sessions
import operator_policy_templates as templates


ROOT = Path(__file__).resolve().parent
DROP_IN = ROOT / "examples" / "hermes-gpt-chatgpt-operator-write-roots.conf"


def _decode_systemd_path(value: str) -> str:
    return value.replace("\\x20", " ")


def _read_write_paths() -> set[str]:
    paths: set[str] = set()
    for raw_line in DROP_IN.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("ReadWritePaths="):
            continue
        value = line.split("=", 1)[1].strip()
        if value:
            paths.add(_decode_systemd_path(value))
    return paths


def _is_covered(root: str, allowed: set[str]) -> bool:
    candidate = Path(root)
    return any(candidate == Path(parent) or Path(parent) in candidate.parents for parent in allowed)


def test_operator_service_drop_in_covers_all_active_policy_writable_roots():
    allowed = _read_write_paths()
    assert allowed, "operator service drop-in contains no ReadWritePaths entries"

    missing: list[tuple[str, str]] = []
    for name, template in templates.POLICY_TEMPLATES.items():
        if not template.get("active", False):
            continue
        for root in template["policy"].get("writable_roots", []):
            if not _is_covered(root, allowed):
                missing.append((name, root))

    assert not missing, f"active policy writable roots missing from systemd sandbox: {missing}"


def test_operator_service_policy_keeps_hard_denies_inside_systemd_boundary(tmp_path, monkeypatch):
    allowed = _read_write_paths()
    sensitive_path = "/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"
    assert _is_covered(sensitive_path, allowed)

    resolved = templates.resolve_template("hermes-overnight-maintenance")
    policy = {
        **resolved["policy"],
        "policy_template": "hermes-overnight-maintenance",
    }
    assert sensitive_path in policy["hard_denied_paths"]

    session_root = tmp_path / "sessions"
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(session_root))
    monkeypatch.delenv(op.OPERATOR_ENABLED_ENV, raising=False)
    monkeypatch.delenv(op.OPERATOR_LEVEL_ENV, raising=False)
    monkeypatch.delenv(op.OPERATOR_APPLY_MODE_ENV, raising=False)
    monkeypatch.delenv(op.OPERATOR_ALLOWED_PATHS_ENV, raising=False)
    record = sessions.create_session(
        policy,
        duration_seconds=60 * 60,
        root=session_root,
    )
    sessions._write_active_pointer(record.session_id, root=session_root)

    active_policy = op.OperatorPolicy()
    with pytest.raises(PermissionError, match="hard-denied"):
        active_policy.require_write_path(sensitive_path)
