from __future__ import annotations

import json
import subprocess

SSH_PROGRAM = "/mnt/c/Windows/System32/OpenSSH/ssh.exe"
SSH_TARGET = "jfroh@172.29.176.132"
REMOTE_PYTHON = "/home/jfroh/.hermes/hermes-agent/venv/bin/python3"

REMOTE_PROGRAM = r'''from __future__ import annotations
import hashlib, json, os, re, stat, tempfile
from pathlib import Path

CONFIG=Path("/home/jfroh/.hermes/profiles/first-safe/config.yaml")
STATE_DB=Path("/home/jfroh/.hermes/profiles/first-safe/state.db")
APPROVED_MODEL="cohere/north-mini-code:free"
PROVIDER="openrouter"
BASE_URL="https://openrouter.ai/api/v1"


def scalar(v):
    v=v.strip()
    return v[1:-1] if len(v)>=2 and v[0]==v[-1] and v[0] in "\"'" else v


def locate_model_fields(text):
    lines=text.splitlines(keepends=True); model_index=None; model_indent=None
    for i,line in enumerate(lines):
        m=re.match(r"^(\s*)model\s*:\s*(?:#.*)?(?:\r?\n)?$",line)
        if m:
            if model_index is not None: raise RuntimeError("multiple model blocks")
            model_index,model_indent=i,len(m.group(1).replace("\t","    "))
    if model_index is None: raise RuntimeError("model block missing")
    fields={}; indexes={}
    for i in range(model_index+1,len(lines)):
        line=lines[i]
        if not line.strip() or line.lstrip().startswith("#"): continue
        indent=len(re.match(r"^\s*",line).group(0).replace("\t","    "))
        if indent<=model_indent: break
        m=re.match(r"^(\s*)(provider|default|base_url|model)\s*:\s*([^#\r\n]*?)(\s*(?:#.*)?)?(\r?\n)?$",line)
        if m:
            key=m.group(2)
            if key in fields: raise RuntimeError(f"duplicate model.{key}")
            fields[key]=scalar(m.group(3)); indexes[key]=i
    return lines,fields,indexes


def atomic_write(path,text):
    st=path.stat(); fd,tmp=tempfile.mkstemp(prefix=".config.yaml.rollback-",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="") as fh:
            fh.write(text); fh.flush(); os.fsync(fh.fileno())
        os.chmod(tmp,st.st_mode & 0o777); os.replace(tmp,path)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

if not CONFIG.is_file(): raise SystemExit("config missing")
raw=CONFIG.read_bytes(); text=raw.decode("utf-8")
if stat.S_IMODE(CONFIG.stat().st_mode) & 0o077: raise SystemExit("config permissions too broad")
if not re.search(r"(?m)^fallback_providers\s*:\s*\[\s*\]\s*$",text): raise SystemExit("fallback_providers drift")
if not re.search(r"(?m)^providers\s*:\s*\{\s*\}\s*$",text): raise SystemExit("providers drift")
if not re.search(r"(?m)^credential_pool_strategies\s*:\s*\{\s*\}\s*$",text): raise SystemExit("credential_pool_strategies drift")
lines,fields,idx=locate_model_fields(text)
if fields.get("provider")!=PROVIDER: raise SystemExit("provider drift")
if fields.get("base_url","").rstrip("/")!=BASE_URL.rstrip("/"): raise SystemExit("base_url drift")
if fields.get("default")!=APPROVED_MODEL: raise SystemExit("default is not the observed partial FIRST_SAFE value")
if "model" in fields: raise SystemExit("legacy model alias present")
i=idx["default"]; original=lines[i]
m=re.match(r"^([ \t]*default[ \t]*:[ \t]*)([^#\r\n]*?)([ \t]*(?:#.*)?)?(\r?\n)?$",original)
if not m: raise SystemExit("default line rewrite unsafe")
lines[i]=f"{m.group(1)}{m.group(3) or ''}{m.group(4) or ''}"
new_text="".join(lines)
_,check,_=locate_model_fields(new_text)
if check.get("default")!="": raise SystemExit("rollback verification failed")
if check.get("provider")!=PROVIDER or check.get("base_url","").rstrip("/")!=BASE_URL.rstrip("/"): raise SystemExit("rollback changed routing fields")
atomic_write(CONFIG,new_text)
final=CONFIG.read_bytes()
print("HERMES_FIRST_SAFE_ROLLBACK_JSON="+json.dumps({
  "success": True,
  "changed_key": "model.default",
  "previous_default": APPROVED_MODEL,
  "resulting_default": "",
  "config_sha256_before": hashlib.sha256(raw).hexdigest(),
  "config_sha256_after": hashlib.sha256(final).hexdigest(),
  "state_db_exists": STATE_DB.exists(),
},sort_keys=True))
'''


def main() -> int:
    proc=subprocess.run([
        SSH_PROGRAM,"-T","-o","BatchMode=yes","-o","ConnectTimeout=10","-o","ConnectionAttempts=1",
        SSH_TARGET,REMOTE_PYTHON,"-"
    ],input=REMOTE_PROGRAM,capture_output=True,text=True,timeout=30,shell=False)
    marker="HERMES_FIRST_SAFE_ROLLBACK_JSON="
    lines=[line[len(marker):] for line in (proc.stdout or "").splitlines() if line.startswith(marker)]
    if proc.returncode!=0 or len(lines)!=1:
        print(json.dumps({"success":False,"error":"ROLLBACK_FAILED","returncode":proc.returncode},sort_keys=True))
        return 1
    print(json.dumps(json.loads(lines[0]),indent=2,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
