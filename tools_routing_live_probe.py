#!/usr/bin/env python3
"""One harmless live exact-output probe through a materialised delegated runtime.

Proves the resolved primary route is genuinely reachable and returns an exact
expected token. Makes exactly one bounded model call, writes nothing outside a
temporary runtime home, and never reads or prints credential values.

Usage:  python3 tools_routing_live_probe.py [--route nvidia] [output.json]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

import operator_delegation as delegation
import operator_routing as routing

EXPECTED = "HERMES_ROUTE_OK"
PROMPT = (
    "Reply with exactly this token and nothing else, no punctuation, "
    f"no explanation: {EXPECTED}"
)
TIMEOUT_SECONDS = 180


def probe(lane: str | None) -> dict:
    resolved = routing.resolve_routing(
        hermes_root=delegation.HERMES_ROOT,
        profile="default",
        profile_home=delegation.op.resolve_profile_home("default", delegation.HERMES_ROOT),
        deadline_seconds=TIMEOUT_SECONDS,
    )
    route = resolved.primary
    if lane:
        match = next((item for item in resolved.alternates if item.lane == lane), None)
        if match is None:
            return {"error": f"no eligible alternate on lane {lane!r}"}
        route = match

    with tempfile.TemporaryDirectory(prefix="routing-live-probe-") as tmp:
        original_root = delegation._TASKS_ROOT
        delegation._TASKS_ROOT = Path(tmp) / "tasks"
        try:
            home = delegation._prepare_runtime_home(
                {"task_id": "dt_" + "1" * 32, "profile": "default", "timeout": TIMEOUT_SECONDS},
                route_override=route,
            )
            config = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
            env = os.environ.copy()
            env["HERMES_HOME"] = str(home)
            argv = [
                delegation.HERMES_BIN,
                "chat",
                "-Q",
                "--source",
                "tool",
                "--max-turns",
                "1",
                "-t",
                "file_read_only",
                "-q",
                PROMPT,
            ]
            started = time.time()
            try:
                completed = subprocess.run(
                    argv,
                    env=env,
                    cwd=tmp,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=TIMEOUT_SECONDS,
                )
                rc, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
            except subprocess.TimeoutExpired:
                rc, stdout, stderr = 124, "", "probe timed out"
            elapsed = round(time.time() - started, 2)

            stdout = delegation.op.redact_output(stdout or "")
            stderr = delegation.op.redact_output(stderr or "")
            failure, recovery, reason = routing.classify_outcome(
                status="running",
                rc=rc,
                stdout=stdout,
                stderr=stderr,
                mode="read_only",
                changed_files=[],
                final_answer=delegation._extract_final_answer(stdout, stderr)[0],
                final_answer_reason=delegation._extract_final_answer(stdout, stderr)[1],
            )
            return {
                "route": route.to_audit_dict(),
                "runtime_model": config.get("model"),
                "runtime_fallback_providers": config.get("fallback_providers"),
                "returncode": rc,
                "elapsed_seconds": elapsed,
                "exact_output_verified": EXPECTED in stdout,
                "failure_class": failure.value,
                "recovery_class": recovery.value,
                "reason": reason,
                "stdout_tail": stdout[-600:],
                "stderr_tail": stderr[-600:],
            }
        finally:
            delegation._TASKS_ROOT = original_root


def main() -> int:
    args = [a for a in sys.argv[1:]]
    lane = None
    if "--route" in args:
        index = args.index("--route")
        lane = args[index + 1]
        del args[index : index + 2]
    result = probe(lane)
    payload = json.dumps(result, indent=2, sort_keys=True)
    if args:
        Path(args[0]).write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
