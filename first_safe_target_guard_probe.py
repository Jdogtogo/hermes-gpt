from __future__ import annotations

import json
import subprocess

SSH_PROGRAM = "/mnt/c/Windows/System32/OpenSSH/ssh.exe"
SSH_TARGET = "jfroh@172.29.176.132"
REMOTE_PYTHON = "/home/jfroh/.hermes/hermes-agent/venv/bin/python3"

REMOTE_PROGRAM = r'''from __future__ import annotations
import json, os
from pathlib import Path

ROOT=Path("/home/jfroh/.hermes")
PROFILE=ROOT/"profiles"/"first-safe"
CONFIG=PROFILE/"config.yaml"
REPO=ROOT/"hermes-agent"
STATE_DB=PROFILE/"state.db"

result={"success":True,"repo_exists":REPO.is_dir(),"state_db_exists":STATE_DB.is_file()}
if CONFIG.is_file():
    text=CONFIG.read_text(encoding="utf-8")
    default=""
    in_model=False
    for raw in text.splitlines():
        line=raw.strip()
        if not line or line.startswith("#"): continue
        if not raw.startswith((" ","\t")):
            in_model=line.startswith("model:")
            continue
        if in_model and line.startswith("default:"):
            default=line.split(":",1)[1].strip()
            break
    result["model_default"]=default

result["guard_contract"]="first_safe_runtime_free_only_v1"
result["external_guard_file_required"]=False

print("HERMES_FIRST_SAFE_GUARD_PROBE_JSON="+json.dumps(result,sort_keys=True))
'''


def main() -> int:
    proc=subprocess.run([
        SSH_PROGRAM,"-T","-o","BatchMode=yes","-o","ConnectTimeout=10","-o","ConnectionAttempts=1",
        SSH_TARGET,REMOTE_PYTHON,"-"
    ],input=REMOTE_PROGRAM,capture_output=True,text=True,timeout=30,shell=False)
    marker="HERMES_FIRST_SAFE_GUARD_PROBE_JSON="
    rows=[x[len(marker):] for x in (proc.stdout or "").splitlines() if x.startswith(marker)]
    if proc.returncode != 0 or len(rows)!=1:
        print(json.dumps({"success":False,"error":"GUARD_PROBE_FAILED","returncode":proc.returncode},sort_keys=True))
        return 1
    print(json.dumps(json.loads(rows[0]),indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
