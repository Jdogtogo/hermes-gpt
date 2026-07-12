from __future__ import annotations

import json
from pathlib import Path

import operator_agent as agent
import operator_policy as op


def _enable_read_only_operator(monkeypatch, workdir: Path) -> None:
    monkeypatch.setenv(op.OPERATOR_ENABLED_ENV, "1")
    monkeypatch.setenv(op.OPERATOR_LEVEL_ENV, "read_only")
    monkeypatch.setenv(op.OPERATOR_APPLY_MODE_ENV, "dry_run")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PROFILES_ENV, "default")
    monkeypatch.setenv(op.OPERATOR_ALLOWED_PATHS_ENV, str(workdir))
    monkeypatch.delenv(op.OPERATOR_DENIED_PATHS_ENV, raising=False)
    monkeypatch.delenv(op.OWNER_ACK_ENV, raising=False)


def test_agent_accepts_3600_second_timeout(monkeypatch, tmp_path: Path) -> None:
    _enable_read_only_operator(monkeypatch, tmp_path)
    monkeypatch.setattr(op, "audit_record", lambda **_: None)
    captured: dict[str, object] = {}

    def runner(argv, *, timeout, workdir, env):
        captured.update(
            argv=argv,
            timeout=timeout,
            workdir=workdir,
            safe_root=env[agent.FILE_READ_SAFE_ROOT_ENV],
        )
        return 0, "ok", ""

    result = json.loads(
        agent.hermes_agent_run(
            "Inspect this workspace.",
            mode="read_only",
            workdir=str(tmp_path),
            timeout=3600,
            runner=runner,
        )
    )

    assert result["success"] is True
    assert result["timeout"] == 3600
    assert captured["timeout"] == 3600
    assert captured["workdir"] == str(tmp_path)
    assert captured["safe_root"] == str(tmp_path)


def test_agent_rejects_timeout_above_3600(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(op, "audit_record", lambda **_: None)

    result = json.loads(
        agent.hermes_agent_run(
            "Inspect this workspace.",
            mode="read_only",
            workdir=str(tmp_path),
            timeout=3601,
        )
    )

    assert result["success"] is False
    assert "between 1 and 3600 seconds" in result["error"]
