from __future__ import annotations

import json
import subprocess
import sys

SSH_PROGRAM = "/mnt/c/Windows/System32/OpenSSH/ssh.exe"
SSH_TARGET = "jfroh@172.29.176.132"
REMOTE_PYTHON = "/home/jfroh/.hermes/hermes-agent/venv/bin/python3"

REMOTE_PROGRAM = r'''from __future__ import annotations
import hashlib, json, re, sqlite3, stat, time
from pathlib import Path

PROFILE=Path("/home/jfroh/.hermes/profiles/first-safe")
CONFIG=PROFILE/"config.yaml"
STATE_DB=PROFILE/"state.db"
APPROVED_MODEL="cohere/north-mini-code:free"

result={
  "success": True,
  "config_exists": CONFIG.is_file(),
  "state_db_exists": STATE_DB.is_file(),
}

if CONFIG.is_file():
    raw=CONFIG.read_bytes()
    text=raw.decode("utf-8", errors="strict")
    result["config_sha256"]=hashlib.sha256(raw).hexdigest()
    result["config_mode"]=oct(stat.S_IMODE(CONFIG.stat().st_mode))
    result["config_size_bytes"]=len(raw)
    result["config_mtime_ns"]=CONFIG.stat().st_mtime_ns

    top=[]; model=[]; in_model=False; model_indent=None
    allowed_values={}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent=len(re.match(r"^\s*", line).group(0).replace("\t","    "))
        m=re.match(r"^\s*([A-Za-z0-9_.-]+)\s*:\s*(.*)$", line)
        if not m:
            continue
        key=m.group(1); value=m.group(2).split("#",1)[0].strip()
        if indent==0:
            top.append(key)
            in_model=(key=="model")
            model_indent=indent if in_model else None
            if key=="base_url": allowed_values["top_level_base_url"]=value
            continue
        if in_model and model_indent is not None and indent>model_indent:
            model.append(key)
            if key in {"provider","default","base_url","model"}:
                allowed_values["model_"+key]=value
        elif indent<=0:
            in_model=False
    result["top_level_keys"]=sorted(set(top))
    result["model_keys"]=sorted(set(model))
    result.update(allowed_values)
    result["fallback_providers_explicit_empty"]=bool(re.search(r"(?m)^fallback_providers\s*:\s*\[\s*\]\s*$",text))
    result["providers_explicit_empty"]=bool(re.search(r"(?m)^providers\s*:\s*\{\s*\}\s*$",text))
    result["credential_pool_strategies_explicit_empty"]=bool(re.search(r"(?m)^credential_pool_strategies\s*:\s*\{\s*\}\s*$",text))

if STATE_DB.is_file():
    try:
        conn=sqlite3.connect(str(STATE_DB), timeout=2)
        conn.row_factory=sqlite3.Row
        tables={r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        result["state_tables_present"]={name:(name in tables) for name in ("sessions","session_model_usage")}
        cutoff=time.time()-7200
        if "sessions" in tables:
            cols={r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
            result["sessions_has_api_call_count"]="api_call_count" in cols
            if {"started_at","model"}.issubset(cols):
                row=conn.execute("SELECT COUNT(*) c, MAX(started_at) mx FROM sessions WHERE started_at>=? AND model=?",(cutoff,APPROVED_MODEL)).fetchone()
                result["approved_model_sessions_last_2h"]=int(row["c"] or 0)
                result["approved_model_latest_started_at"]=row["mx"]
                if "api_call_count" in cols:
                    row2=conn.execute("SELECT COALESCE(SUM(api_call_count),0) s FROM sessions WHERE started_at>=? AND model=?",(cutoff,APPROVED_MODEL)).fetchone()
                    result["approved_model_session_api_calls_last_2h"]=int(row2["s"] or 0)
        if "session_model_usage" in tables:
            cols={r[1] for r in conn.execute("PRAGMA table_info(session_model_usage)")}
            if {"model","api_call_count"}.issubset(cols):
                row=conn.execute("SELECT COUNT(*) c, COALESCE(SUM(api_call_count),0) s FROM session_model_usage WHERE model=?",(APPROVED_MODEL,)).fetchone()
                result["approved_model_usage_rows_total"]=int(row["c"] or 0)
                result["approved_model_usage_api_calls_total"]=int(row["s"] or 0)
        conn.close()
    except Exception as exc:
        result["state_db_probe_error"]=type(exc).__name__

print("HERMES_FIRST_SAFE_PREFLIGHT_JSON="+json.dumps(result,sort_keys=True))
'''


def main() -> int:
    proc = subprocess.run(
        [
            SSH_PROGRAM, "-T",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ConnectionAttempts=1",
            SSH_TARGET, REMOTE_PYTHON, "-",
        ],
        input=REMOTE_PROGRAM,
        capture_output=True,
        text=True,
        timeout=30,
        shell=False,
    )
    marker="HERMES_FIRST_SAFE_PREFLIGHT_JSON="
    lines=[line[len(marker):] for line in (proc.stdout or "").splitlines() if line.startswith(marker)]
    if proc.returncode != 0 or len(lines) != 1:
        print(json.dumps({"success":False,"error":"PREFLIGHT_TRANSPORT_FAILED","returncode":proc.returncode},sort_keys=True))
        return 1
    data=json.loads(lines[0])
    print(json.dumps(data,indent=2,sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
