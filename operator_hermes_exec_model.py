"""Immutable FIRST_SAFE acceptance specification for ``hermes-exec``.

This module is the single source of truth for *what* the approved FIRST_SAFE
operation is.  The ChatGPT-facing Prepare tool records an immutable intent,
the trusted host-side worker is the only component that can contact
``hermes-exec``, and Verify exposes bounded evidence only.

The repaired design is deliberately narrower than the legacy root-wide design:

* Linux runtime identity is fixed to ``jfroh``.
* FIRST_SAFE runs only in the dedicated static ``first-safe`` named profile.
* Root provider/auth/environment state must be absent.
* The initial acceptance is API-key-provider-only; OAuth and Nous shared auth
  are not permitted.
* The worker supplies a sanitized process environment, so a missing profile
  credential cannot be silently satisfied by an ambient parent-process key.
* There is exactly one approved zero-price model and no model fallback chain.
* The only config mutation permitted is ``model.default`` inside the dedicated
  FIRST_SAFE profile.

Nothing in this module is caller-supplied.
"""
from __future__ import annotations

import json
from typing import Any

TOOL_NAME = "hermes_exec_first_safe_model"
POLICY_TEMPLATE = "hermes-exec-first-safe-model"
EGRESS_HOST = "hermes-exec"
REMOTE_RUNTIME_USER = "jfroh"
REMOTE_LINUX_HOME = "/home/jfroh"
REMOTE_HERMES_ROOT = "/home/jfroh/.hermes"
REMOTE_PROFILE = "first-safe"
REMOTE_PROFILE_HOME = "/home/jfroh/.hermes/profiles/first-safe"
REMOTE_CONFIG = "/home/jfroh/.hermes/profiles/first-safe/config.yaml"
APPROVED_PROVIDER = "openrouter"
APPROVED_MODEL = "cohere/north-mini-code:free"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
GUARD_KIND = "first_safe_runtime_free_only_v1"
REQUIRED_GUARD_CHECKS = (
    "selected_model_exact",
    "selected_model_free_suffix",
    "provider_exact",
    "base_url_exact",
    "catalog_prompt_zero",
    "catalog_completion_zero",
    "fallback_providers_disabled",
    "providers_empty",
    "credential_pool_strategies_empty",
)
MAX_OUTPUT = 12_000

REMOTE_PROGRAM = r'''from __future__ import annotations
import hashlib, json, os, pwd, re, sqlite3, stat, subprocess, sys, tempfile, time
from pathlib import Path

LINUX_HOME=Path("/home/jfroh")
ROOT=LINUX_HOME/".hermes"
PROFILE_NAME="first-safe"
PROFILE_HOME=ROOT/"profiles"/PROFILE_NAME
REPO=ROOT/"hermes-agent"
CONFIG=PROFILE_HOME/"config.yaml"
PROFILE_ENV=PROFILE_HOME/".env"
PROFILE_AUTH=PROFILE_HOME/"auth.json"
ROOT_CONFIG=ROOT/"config.yaml"
ROOT_ENV=ROOT/".env"
ROOT_AUTH=ROOT/"auth.json"
ROOT_SHARED_NOUS=ROOT/"shared"/"nous_auth.json"
PROFILE_SHARED_DIR=PROFILE_HOME/"shared"
PROFILE_SHARED_NOUS=PROFILE_SHARED_DIR/"nous_auth.json"
STATE_DB=PROFILE_HOME/"state.db"
AGENT_LOG=PROFILE_HOME/"logs"/"agent.log"
PYTHON=REPO/"venv"/"bin"/"python3"
HERMES=Path("/home/jfroh/.local/bin/hermes")
APPROVED_MODEL="cohere/north-mini-code:free"
PROVIDER="openrouter"
BASE_URL="https://openrouter.ai/api/v1"
GUARD_KIND="first_safe_runtime_free_only_v1"
SIBLINGS=("backend-eng","coder","maintenance","ops","thinker")
PHASE="startup"

# Strip ambient credential-shaped values before any Hermes module is imported.
# The approved OpenRouter key is loaded later by the Hermes CLI from the
# dedicated first-safe profile .env, never inherited from the ssh parent.
for _key in list(os.environ):
    _upper=_key.upper()
    if _upper.endswith(("_API_KEY","_TOKEN","_SECRET","_PASSWORD")) or _upper in {"API_KEY","TOKEN","BEARER_TOKEN"}:
        os.environ.pop(_key,None)
os.environ["HOME"]=str(LINUX_HOME)
os.environ["HERMES_HOME"]=str(PROFILE_HOME)
os.environ["HERMES_SHARED_AUTH_DIR"]=str(PROFILE_SHARED_DIR)


def fail(message, **extra):
    print("HERMES_EXEC_FIRST_SAFE_MODEL_JSON="+json.dumps({"success":False,"error":str(message),"phase":PHASE,**extra},sort_keys=True))
    raise SystemExit(2)


def run(argv,*,cwd=None,timeout=180,env=None):
    try:
        p=subprocess.run([str(x) for x in argv],cwd=str(cwd) if cwd else None,env=env,capture_output=True,text=True,timeout=timeout,shell=False)
        return p.returncode,p.stdout or "",p.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124,exc.stdout if isinstance(exc.stdout,str) else "",exc.stderr if isinstance(exc.stderr,str) else f"timeout after {timeout}s"


def sha(data): return hashlib.sha256(data).hexdigest()

def scalar(v):
    v=v.strip()
    return v[1:-1] if len(v)>=2 and v[0]==v[-1] and v[0] in "\"'" else v


def assert_absent(path,label):
    if Path(path).exists(): fail(f"{label} must be absent for FIRST_SAFE",path=str(path))


def env_has_key(path,key):
    try:
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line=raw.strip()
            if not line or line.startswith("#"): continue
            if line.startswith("export "): line=line[7:].lstrip()
            if "=" in line and line.split("=",1)[0].strip()==key: return True
    except OSError as exc:
        fail("unable to inspect FIRST_SAFE profile environment metadata",detail=type(exc).__name__)
    return False


def require_private_file(path,label):
    p=Path(path)
    if not p.is_file(): fail(f"{label} missing",path=str(p))
    mode=stat.S_IMODE(p.stat().st_mode)
    if mode & 0o077: fail(f"{label} permissions are too broad",mode=oct(mode))


def validate_profile_auth_metadata(path):
    """Allow only Hermes' reference-only OpenRouter env credential metadata."""
    p=Path(path)
    if not p.exists():
        return {"present":False,"source":"profile_env_only","auth_type":"api_key","entry_count":0,"secret_persisted":False,"oauth_present":False}
    require_private_file(p,"FIRST_SAFE profile auth metadata")
    try:
        data=json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("FIRST_SAFE profile auth metadata is unreadable",detail=type(exc).__name__)
    if not isinstance(data,dict): fail("FIRST_SAFE profile auth metadata must be an object")
    allowed_top={"version","providers","credential_pool","active_provider","updated_at"}
    unexpected=sorted(set(data)-allowed_top)
    if unexpected: fail("FIRST_SAFE profile auth metadata has unexpected top-level keys",keys=unexpected)
    if data.get("version",1)!=1: fail("FIRST_SAFE profile auth metadata version drift",observed=data.get("version"))
    providers=data.get("providers",{})
    if not isinstance(providers,dict) or providers:
        fail("FIRST_SAFE profile auth providers state must be empty",providers=sorted(providers) if isinstance(providers,dict) else "invalid")
    for oauth_marker in ("oauth","oauth_tokens","oauth_state"):
        if oauth_marker in data: fail("FIRST_SAFE profile auth metadata contains OAuth state",key=oauth_marker)
    active=data.get("active_provider")
    if active not in (None,"","openrouter"):
        fail("FIRST_SAFE profile auth active provider drift",observed=active)
    # _save_auth_store() stamps "updated_at" (ISO-8601 UTC) on every write;
    # its presence is genuine Hermes behaviour, not drift. Require it to be a
    # sane timestamp string when present, never a credential-shaped value.
    updated_at=data.get("updated_at")
    if updated_at is not None and (not isinstance(updated_at,str) or not updated_at.strip()):
        fail("FIRST_SAFE profile auth updated_at drift",observed_type=type(updated_at).__name__)
    pool=data.get("credential_pool",{})
    if not isinstance(pool,dict) or set(pool)!={"openrouter"}:
        fail("FIRST_SAFE credential pool must contain only openrouter metadata",providers=sorted(pool) if isinstance(pool,dict) else "invalid")
    entries=pool.get("openrouter")
    if not isinstance(entries,list) or len(entries)!=1 or not isinstance(entries[0],dict):
        fail("FIRST_SAFE OpenRouter credential pool must contain exactly one metadata entry")
    entry=entries[0]
    if entry.get("auth_type")!="api_key": fail("FIRST_SAFE credential metadata auth type drift",observed=entry.get("auth_type"))
    if entry.get("source")!="env:OPENROUTER_API_KEY": fail("FIRST_SAFE credential metadata source drift",observed=entry.get("source"))
    if entry.get("label")!="OPENROUTER_API_KEY": fail("FIRST_SAFE credential metadata label drift",observed=entry.get("label"))
    if entry.get("priority") not in (0,None): fail("FIRST_SAFE credential metadata priority drift",observed=entry.get("priority"))
    # PooledCredential.to_dict() emits base_url only when set; when present it
    # must be the approved OpenRouter endpoint (metadata, not a credential).
    entry_base_url=entry.get("base_url")
    if entry_base_url is not None and str(entry_base_url).rstrip("/")!="https://openrouter.ai/api/v1":
        fail("FIRST_SAFE credential metadata base_url drift",observed=entry_base_url)
    fingerprint=entry.get("secret_fingerprint")
    if not isinstance(fingerprint,str) or not fingerprint.startswith("sha256:"):
        fail("FIRST_SAFE credential metadata lacks a non-reversible fingerprint")
    forbidden={"access_token","refresh_token","api_key","token","password","client_secret","agent_key","session_key","bearer_token","private_key"}
    found=[]
    def scan(node,path=()):
        if isinstance(node,dict):
            for key,value in node.items():
                name=str(key).lower()
                if name in forbidden and value not in (None,""):
                    found.append(".".join(path+(str(key),)))
                scan(value,path+(str(key),))
        elif isinstance(node,list):
            for index,value in enumerate(node): scan(value,path+(str(index),))
        elif isinstance(node,str):
            stripped=node.strip()
            if stripped.startswith(("sk-","Bearer ","eyJ")):
                found.append(".".join(path))
    scan(data)
    if found: fail("FIRST_SAFE profile auth metadata contains persisted secret material",fields=sorted(set(found)))
    return {"present":True,"source":"env:OPENROUTER_API_KEY","auth_type":"api_key","entry_count":1,"secret_persisted":False,"oauth_present":False}


def sanitized_env():
    # Deliberately do not inherit provider/API credential variables from the
    # ssh worker process. Hermes may load the one authorized key from the
    # dedicated profile .env itself.
    env={
        "HOME": str(LINUX_HOME),
        "HERMES_HOME": str(PROFILE_HOME),
        "HERMES_SHARED_AUTH_DIR": str(PROFILE_SHARED_DIR),
        "PATH": "/home/jfroh/.local/bin:/usr/local/bin:/usr/bin:/bin",
        "LANG": os.environ.get("LANG","C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL","C.UTF-8"),
    }
    return env


def tree_digest(path):
    root=Path(path)
    if not root.exists(): return "ABSENT"
    h=hashlib.sha256()
    for p in sorted(root.rglob("*"),key=lambda x:str(x.relative_to(root))):
        rel=str(p.relative_to(root)).encode()
        h.update(rel+b"\0")
        if p.is_symlink():
            h.update(b"L"+os.readlink(p).encode()+b"\0")
        elif p.is_file():
            h.update(b"F"+oct(stat.S_IMODE(p.stat().st_mode)).encode()+b"\0"+p.read_bytes()+b"\0")
        elif p.is_dir():
            h.update(b"D"+oct(stat.S_IMODE(p.stat().st_mode)).encode()+b"\0")
    return h.hexdigest()


def sibling_snapshot():
    return {name:tree_digest(ROOT/"profiles"/name) for name in SIBLINGS}


def locate_model_fields(text):
    lines=text.splitlines(keepends=True); model_index=None; model_indent=None
    for i,line in enumerate(lines):
        m=re.match(r"^(\s*)model\s*:\s*(?:#.*)?(?:\r?\n)?$",line)
        if m:
            if model_index is not None: fail("config has multiple model blocks")
            model_index,model_indent=i,len(m.group(1).replace("\t","    "))
    if model_index is None: fail("config model block not found")
    fields={}; indexes={}
    for i in range(model_index+1,len(lines)):
        line=lines[i]
        if not line.strip() or line.lstrip().startswith("#"): continue
        indent=len(re.match(r"^\s*",line).group(0).replace("\t","    "))
        if indent<=model_indent: break
        m=re.match(r"^(\s*)(provider|default|base_url|model)\s*:\s*([^#\r\n]*?)(\s*(?:#.*)?)?(\r?\n)?$",line)
        if m:
            key=m.group(2)
            if key in fields: fail(f"config model.{key} appears more than once")
            fields[key]=scalar(m.group(3)); indexes[key]=i
    for key in ("provider","default","base_url"):
        if key not in fields: fail(f"config model.{key} not found")
    if "model" in fields: fail("legacy model.model alias is not permitted in FIRST_SAFE profile")
    return lines,fields,indexes


def validate_static_profile_config(text):
    # Keep the static profile intentionally tiny and explicit.  This text-level
    # validation avoids importing Hermes config code, which can create runtime
    # scaffolding as a side effect.
    if not re.search(r"(?m)^fallback_providers\s*:\s*\[\s*\]\s*$",text):
        fail("FIRST_SAFE profile must explicitly disable fallback_providers")
    if not re.search(r"(?m)^providers\s*:\s*\{\s*\}\s*$",text):
        fail("FIRST_SAFE profile providers map must be explicitly empty")
    if not re.search(r"(?m)^credential_pool_strategies\s*:\s*\{\s*\}\s*$",text):
        fail("FIRST_SAFE profile credential_pool_strategies must be explicitly empty")
    _,fields,_=locate_model_fields(text)
    if fields["provider"]!=PROVIDER: fail("model.provider drift",observed=fields["provider"])
    if fields["base_url"].rstrip("/")!=BASE_URL.rstrip("/"): fail("model.base_url drift",observed=fields["base_url"])
    if fields["default"] not in {"",APPROVED_MODEL}: fail("model.default outside approved transition set",observed=fields["default"])


def replace_default(text,selected):
    validate_static_profile_config(text)
    lines,fields,idx=locate_model_fields(text)
    i=idx["default"]; original=lines[i]
    m=re.match(r"^([ \t]*default[ \t]*:[ \t]*)([^#\r\n]*?)([ \t]*(?:#.*)?)?(\r?\n)?$",original)
    if not m: fail("unable to rewrite model.default safely")
    lines[i]=f"{m.group(1)}{selected}{m.group(3) or ''}{m.group(4) or ''}"
    new_text="".join(lines)
    validate_static_profile_config(new_text)
    _,check,_=locate_model_fields(new_text)
    if check["default"]!=selected: fail("post-rewrite config verification failed")
    expected=text.splitlines(keepends=True); expected[i]=lines[i]
    if new_text!="".join(expected): fail("config rewrite changed more than model.default")
    return fields["default"],new_text


def pricing_zero(entry):
    if not isinstance(entry,dict): return False
    try: return float(entry.get("prompt","nan"))==0.0 and float(entry.get("completion","nan"))==0.0
    except (TypeError,ValueError): return False


def select_model():
    sys.path.insert(0,str(REPO))
    try:
        from hermes_cli.models import get_pricing_for_provider
        pricing=get_pricing_for_provider(PROVIDER,force_refresh=True)
    except Exception as exc: fail("OpenRouter zero-price preflight unavailable",detail=type(exc).__name__)
    entry=pricing.get(APPROVED_MODEL)
    if not pricing_zero(entry):
        fail("approved FIRST_SAFE model is not catalog-qualified at zero price",model=APPROVED_MODEL)
    price={"prompt":float(entry["prompt"]),"completion":float(entry["completion"])}
    return APPROVED_MODEL,"single_model_catalog_zero_price",price


def atomic_write(path,text):
    st=path.stat(); fd,tmp=tempfile.mkstemp(prefix=".config.yaml.hermes-safe-",dir=str(path.parent))
    try:
        with os.fdopen(fd,"w",encoding="utf-8",newline="") as fh:
            fh.write(text); fh.flush(); os.fsync(fh.fileno())
        os.chmod(tmp,st.st_mode & 0o777); os.replace(tmp,path)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass


def git_status():
    rc,out,err=run(["git","status","--porcelain=v1"],cwd=REPO,timeout=30,env=sanitized_env())
    if rc!=0: fail("remote Hermes git status failed",detail=(err or out)[-800:])
    return out


def run_guard(selected,catalog_price,config_text):
    checks={
        "selected_model_exact": selected==APPROVED_MODEL,
        "selected_model_free_suffix": isinstance(selected,str) and selected.endswith(":free"),
        "provider_exact": PROVIDER=="openrouter",
        "base_url_exact": BASE_URL.rstrip("/")=="https://openrouter.ai/api/v1".rstrip("/"),
        "catalog_prompt_zero": float(catalog_price.get("prompt",float("nan")))==0.0,
        "catalog_completion_zero": float(catalog_price.get("completion",float("nan")))==0.0,
        "fallback_providers_disabled": bool(re.search(r"(?m)^fallback_providers\s*:\s*\[\s*\]\s*$",config_text)),
        "providers_empty": bool(re.search(r"(?m)^providers\s*:\s*\{\s*\}\s*$",config_text)),
        "credential_pool_strategies_empty": bool(re.search(r"(?m)^credential_pool_strategies\s*:\s*\{\s*\}\s*$",config_text)),
    }
    failed=sorted(name for name,ok in checks.items() if ok is not True)
    if failed:
        fail("FIRST_SAFE runtime free-only guard failed",failed_checks=failed)
    return {"kind":GUARD_KIND,"all_passed":True,"checks":checks}


def log_offset():
    try: return AGENT_LOG.stat().st_size
    except FileNotFoundError: return 0


def read_log_since(offset):
    try:
        with AGENT_LOG.open("rb") as fh:
            fh.seek(offset); return fh.read(2_000_000).decode("utf-8",errors="replace")
    except FileNotFoundError: return ""


def cols(conn,table): return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def call_and_evidence(number,selected,offset):
    prompt=f"Reply with exactly HERMES_FREE_ACCEPTANCE_{number}_OK and nothing else."
    expected=f"HERMES_FREE_ACCEPTANCE_{number}_OK"
    env=sanitized_env(); env["HERMES_MAX_TOKENS"]="512"; started=time.time()
    rc,out,err=run([HERMES,"-z",prompt],cwd=REPO,timeout=240,env=env)
    if rc!=0 or expected not in out:
        fail(f"acceptance call {number} failed",returncode=rc,stdout=out[-800:],stderr=err[-800:])
    deadline=time.time()+8; row=None; usage=None
    while time.time()<deadline:
        try:
            conn=sqlite3.connect(str(STATE_DB),timeout=2); conn.row_factory=sqlite3.Row
            req={"id","started_at","model","billing_provider","billing_base_url","estimated_cost_usd","actual_cost_usd","cost_status","cost_source","api_call_count"}
            if not req.issubset(cols(conn,"sessions")):
                conn.close(); fail("state.db sessions schema lacks required cost fields")
            row=conn.execute("SELECT id,started_at,model,billing_provider,billing_base_url,estimated_cost_usd,actual_cost_usd,cost_status,cost_source,api_call_count FROM sessions WHERE started_at>=? AND model=? ORDER BY started_at DESC LIMIT 1",(started-1.0,selected)).fetchone()
            if row is not None and {"session_id","api_call_count","estimated_cost_usd","actual_cost_usd","cost_status","model","billing_provider"}.issubset(cols(conn,"session_model_usage")):
                usage=conn.execute("SELECT COALESCE(SUM(api_call_count),0) calls,COALESCE(SUM(estimated_cost_usd),0) est,COALESCE(SUM(actual_cost_usd),0) actual,GROUP_CONCAT(DISTINCT cost_status) statuses,GROUP_CONCAT(DISTINCT model) models,GROUP_CONCAT(DISTINCT billing_provider) providers FROM session_model_usage WHERE session_id=?",(row["id"],)).fetchone()
            conn.close()
            if row is not None and usage is not None and int(usage["calls"] or 0)>=1: break
        except sqlite3.Error: pass
        time.sleep(.25)
    if row is None or usage is None: fail(f"acceptance call {number} lacks persisted zero-cost evidence")
    if row["model"]!=selected or not str(row["model"]).endswith(":free"):
        fail(f"acceptance call {number} model drift",observed=row["model"])
    if str(row["billing_provider"] or "").lower()!=PROVIDER:
        fail(f"acceptance call {number} provider drift",observed=row["billing_provider"])
    if str(row["billing_base_url"] or "").rstrip("/")!=BASE_URL.rstrip("/"):
        fail(f"acceptance call {number} base URL drift",observed=row["billing_base_url"])
    if float(row["estimated_cost_usd"] or 0)!=0.0 or float(usage["est"] or 0)!=0.0:
        fail(f"acceptance call {number} nonzero estimated cost")
    if float(row["actual_cost_usd"] or 0)!=0.0 or float(usage["actual"] or 0)!=0.0:
        fail(f"acceptance call {number} nonzero actual cost")
    statuses={s for s in str(usage["statuses"] or "").split(",") if s}
    if not statuses or "unknown" in {s.lower() for s in statuses}:
        fail(f"acceptance call {number} ambiguous cost status",statuses=sorted(statuses))
    if int(usage["calls"] or 0)!=1:
        fail(f"acceptance call {number} unexpected model-call count",api_call_count=int(usage["calls"] or 0))
    if str(usage["models"] or "")!=selected or str(usage["providers"] or "").lower()!=PROVIDER:
        fail(f"acceptance call {number} usage route drift")
    new_log=read_log_since(offset)
    bad=re.findall(r"(?im)^.*(?:cooldown|rotat(?:e|ed|ing|ion)|credential[^\n]*(?:fail|switch|next)|billing error|auth failure).*$",new_log)
    if bad: fail(f"acceptance call {number} observed cooldown/rotation",events=bad[:5])
    return {"call":number,"ok":True,"session_id":row["id"],"model":selected,"provider":PROVIDER,"estimated_cost_usd":0.0,"actual_cost_usd":0.0,"cost_status":sorted(statuses),"api_call_count":1,"cooldown_rotation_events":0,"route_seen_in_appended_log":bool(re.search(re.escape(selected),new_log))}


def main():
    global PHASE
    identity=pwd.getpwuid(os.geteuid())
    if identity.pw_name!="jfroh" or Path(identity.pw_dir)!=LINUX_HOME: fail("effective Linux identity drift",observed_user=identity.pw_name,observed_home=identity.pw_dir)
    for required in (ROOT,PROFILE_HOME,REPO,CONFIG,PYTHON,HERMES):
        if not Path(required).exists(): fail("required Hermes runtime path missing",path=str(required))
    for path,label in ((ROOT_CONFIG,"root config"),(ROOT_ENV,"root environment"),(ROOT_AUTH,"root auth"),(ROOT_SHARED_NOUS,"root Nous shared state")):
        assert_absent(path,label)
    auth_before=validate_profile_auth_metadata(PROFILE_AUTH)
    require_private_file(PROFILE_ENV,"FIRST_SAFE profile environment")
    if not env_has_key(PROFILE_ENV,"OPENROUTER_API_KEY"):
        fail("FIRST_SAFE profile environment lacks OPENROUTER_API_KEY")
    if PROFILE_SHARED_NOUS.exists(): fail("FIRST_SAFE profile must not contain Nous shared auth state")

    before_siblings=sibling_snapshot()
    before_git=git_status()
    before_bytes=CONFIG.read_bytes(); before_sha=sha(before_bytes); before_text=before_bytes.decode("utf-8")
    PHASE="pre_config"
    validate_static_profile_config(before_text)
    PHASE="catalog"
    selected,reason,catalog_price=select_model()
    PHASE="guard"
    guard=run_guard(selected,catalog_price,before_text)

    PHASE="rewrite"
    previous,new_text=replace_default(before_text,selected)
    changed=new_text.encode()!=before_bytes
    if changed: atomic_write(CONFIG,new_text)
    if CONFIG.read_bytes()!=new_text.encode(): fail("config atomic-write verification failed")

    try:
        offset=log_offset(); calls=[]
        for n in (1,2):
            PHASE=f"call_{n}"
            calls.append(call_and_evidence(n,selected,offset)); offset=log_offset()

        PHASE="final_config"
        final_bytes=CONFIG.read_bytes(); validate_static_profile_config(final_bytes.decode())
        _,fields,_=locate_model_fields(final_bytes.decode())
        if fields["default"]!=selected or fields["provider"]!=PROVIDER or fields["base_url"].rstrip("/")!=BASE_URL.rstrip("/"):
            fail("final config verification failed")
        after_git=git_status()
        if after_git!=before_git: fail("Hermes Git worktree changed during acceptance",before=before_git,after=after_git)
        after_siblings=sibling_snapshot()
        if after_siblings!=before_siblings: fail("sibling profile changed during FIRST_SAFE acceptance")
        for path,label in ((ROOT_CONFIG,"root config"),(ROOT_ENV,"root environment"),(ROOT_AUTH,"root auth"),(ROOT_SHARED_NOUS,"root Nous shared state"),(PROFILE_SHARED_NOUS,"FIRST_SAFE Nous shared state")):
            assert_absent(path,label)
        auth_after=validate_profile_auth_metadata(PROFILE_AUTH)
    except BaseException:
        if changed:
            PHASE="rollback"
            atomic_write(CONFIG,before_text)
            if CONFIG.read_bytes()!=before_bytes:
                fail("config rollback verification failed")
        raise

    result={
        "success":True,"changed":changed,"host":"hermes-exec","profile":PROFILE_NAME,
        "config":str(CONFIG),"changed_key":"model.default","previous_default":previous,
        "resulting_default":selected,"selected_model":selected,"selection_reason":reason,
        "provider":PROVIDER,"base_url":BASE_URL,"catalog_price":catalog_price,
        "guard":guard,"calls":calls,"total_acceptance_calls":2,"total_estimated_cost_usd":0.0,
        "total_actual_cost_usd":0.0,"cooldown_rotation_events":0,"config_sha256_before":before_sha,
        "config_sha256_after":sha(final_bytes),"git_status_unchanged":True,"broader_routing_changed":False,
        "sibling_profiles_unchanged":True,"root_provider_state_absent_before_after":True,
        "shared_nous_state_absent_before_after":True,"api_key_auth_only":True,"oauth_used":False,
        "profile_auth_metadata_only":True,"profile_auth_source":"env:OPENROUTER_API_KEY",
        "profile_auth_secret_persisted":False,"profile_auth_oauth_present":False,
        "profile_auth_entry_count_before":auth_before["entry_count"],"profile_auth_entry_count_after":auth_after["entry_count"],
        "ambient_provider_env_inherited":False,
    }
    print("HERMES_EXEC_FIRST_SAFE_MODEL_JSON="+json.dumps(result,sort_keys=True))

if __name__=="__main__": main()
'''


def fixed_plan() -> dict[str, Any]:
    """Return the complete constant description of the approved operation."""
    return {
        "host": EGRESS_HOST,
        "remote_runtime_user": REMOTE_RUNTIME_USER,
        "linux_home": REMOTE_LINUX_HOME,
        "hermes_root": REMOTE_HERMES_ROOT,
        "profile": REMOTE_PROFILE,
        "profile_home": REMOTE_PROFILE_HOME,
        "config": REMOTE_CONFIG,
        "change_only": "model.default",
        "provider": APPROVED_PROVIDER,
        "approved_model": APPROVED_MODEL,
        "model_fallbacks": [],
        "base_url": OPENROUTER_BASE_URL,
        "api_key_auth_only": True,
        "oauth_allowed": False,
        "root_provider_state_required_absent": True,
        "shared_nous_state_required_absent": True,
        "ambient_provider_env_inherited": False,
        "guard_kind": GUARD_KIND,
        "guard_required_checks": list(REQUIRED_GUARD_CHECKS),
        "acceptance_calls": 2,
        "required_cost_usd_each": 0.0,
        "required_cooldown_rotation_events": 0,
        "shell": False,
        "arbitrary_remote_command_surface": False,
    }


def spec_hash() -> str:
    """Digest binding an intent record to this exact specification."""
    import hashlib

    canonical = json.dumps(
        {"plan": fixed_plan(), "remote_program_sha256": hashlib.sha256(REMOTE_PROGRAM.encode()).hexdigest()},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_acceptance_payload(payload: dict[str, Any]) -> None:
    """Enforce every FIRST_SAFE acceptance invariant on a remote result."""
    if payload.get("success") is not True:
        raise RuntimeError(str(payload.get("error") or "remote acceptance did not report success"))
    if payload.get("profile") != REMOTE_PROFILE:
        raise RuntimeError("remote result did not prove the fixed FIRST_SAFE profile")
    if payload.get("provider") != APPROVED_PROVIDER:
        raise RuntimeError("remote result did not prove the approved provider")
    if str(payload.get("base_url") or "").rstrip("/") != OPENROUTER_BASE_URL.rstrip("/"):
        raise RuntimeError("remote result did not prove the approved base URL")
    if payload.get("selected_model") != APPROVED_MODEL or payload.get("resulting_default") != APPROVED_MODEL:
        raise RuntimeError("remote result selected an unapproved model")
    if payload.get("selection_reason") != "single_model_catalog_zero_price":
        raise RuntimeError("remote result did not prove zero-price catalog qualification")
    catalog_price = payload.get("catalog_price") or {}
    try:
        if float(catalog_price.get("prompt", -1)) != 0.0 or float(catalog_price.get("completion", -1)) != 0.0:
            raise RuntimeError("remote result did not prove exact zero-price catalog values")
    except (TypeError, ValueError):
        raise RuntimeError("remote result did not prove exact zero-price catalog values")
    if payload.get("total_acceptance_calls") != 2:
        raise RuntimeError("remote result did not prove exactly two acceptance calls")
    calls = payload.get("calls")
    if not isinstance(calls, list) or len(calls) != 2:
        raise RuntimeError("remote result did not include exactly two call evidence records")
    for number, call in enumerate(calls, 1):
        if not isinstance(call, dict) or call.get("call") != number or call.get("ok") is not True:
            raise RuntimeError("remote call evidence sequence is invalid")
        if call.get("model") != APPROVED_MODEL or call.get("provider") != APPROVED_PROVIDER:
            raise RuntimeError("remote call evidence route drift")
        if float(call.get("estimated_cost_usd", -1)) != 0.0 or float(call.get("actual_cost_usd", -1)) != 0.0:
            raise RuntimeError("remote call evidence did not prove zero cost")
        if int(call.get("api_call_count", -1)) != 1:
            raise RuntimeError("remote call evidence did not prove one API call")
        if int(call.get("cooldown_rotation_events", -1)) != 0:
            raise RuntimeError("remote call evidence reported cooldown/rotation activity")
    if float(payload.get("total_estimated_cost_usd", -1)) != 0.0 or float(payload.get("total_actual_cost_usd", -1)) != 0.0:
        raise RuntimeError("remote result did not prove zero-cost acceptance")
    if payload.get("cooldown_rotation_events") != 0:
        raise RuntimeError("remote result reported cooldown/rotation activity")
    if payload.get("changed_key") != "model.default" or payload.get("broader_routing_changed") is not False:
        raise RuntimeError("remote result did not prove bounded config scope")
    if payload.get("git_status_unchanged") is not True or payload.get("sibling_profiles_unchanged") is not True:
        raise RuntimeError("remote result did not prove repository/profile isolation")
    if payload.get("root_provider_state_absent_before_after") is not True:
        raise RuntimeError("remote result did not prove root provider-state absence")
    if payload.get("shared_nous_state_absent_before_after") is not True:
        raise RuntimeError("remote result did not prove shared Nous-state absence")
    if payload.get("api_key_auth_only") is not True or payload.get("oauth_used") is not False:
        raise RuntimeError("remote result did not prove API-key-only authentication")
    if payload.get("ambient_provider_env_inherited") is not False:
        raise RuntimeError("remote result did not prove ambient-provider environment isolation")
    guard = payload.get("guard")
    if not isinstance(guard, dict) or guard.get("kind") != GUARD_KIND or guard.get("all_passed") is not True:
        raise RuntimeError("remote result did not prove the FIRST_SAFE runtime free-only guard")
    checks = guard.get("checks")
    if not isinstance(checks, dict) or set(checks) != set(REQUIRED_GUARD_CHECKS):
        raise RuntimeError("remote result runtime guard check-set drift")
    if any(checks.get(name) is not True for name in REQUIRED_GUARD_CHECKS):
        raise RuntimeError("remote result runtime free-only guard reported a failed check")


EVIDENCE_KEYS = (
    "changed", "previous_default", "resulting_default", "selected_model",
    "selection_reason", "provider", "base_url", "catalog_price", "guard",
    "calls", "total_acceptance_calls", "total_estimated_cost_usd",
    "total_actual_cost_usd", "cooldown_rotation_events", "git_status_unchanged",
    "broader_routing_changed", "changed_key", "profile", "sibling_profiles_unchanged",
    "root_provider_state_absent_before_after", "shared_nous_state_absent_before_after",
    "api_key_auth_only", "oauth_used", "ambient_provider_env_inherited",
)


def bounded_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Project a validated remote result onto the allow-listed evidence keys."""
    evidence = {key: payload.get(key) for key in EVIDENCE_KEYS if key in payload}
    evidence["host"] = EGRESS_HOST
    evidence["profile"] = REMOTE_PROFILE
    evidence["config"] = REMOTE_CONFIG
    evidence["changed_key"] = "model.default"
    evidence["total_acceptance_calls"] = 2
    evidence["total_estimated_cost_usd"] = 0.0
    evidence["total_actual_cost_usd"] = 0.0
    evidence["cooldown_rotation_events"] = 0
    evidence["git_status_unchanged"] = True
    evidence["broader_routing_changed"] = False
    evidence["sibling_profiles_unchanged"] = True
    evidence["root_provider_state_absent_before_after"] = True
    evidence["shared_nous_state_absent_before_after"] = True
    evidence["api_key_auth_only"] = True
    evidence["oauth_used"] = False
    evidence["ambient_provider_env_inherited"] = False
    return evidence


def extract_result(stdout: str) -> dict[str, Any]:
    prefix = "HERMES_EXEC_FIRST_SAFE_MODEL_JSON="
    candidates = [line[len(prefix):] for line in stdout.splitlines() if line.startswith(prefix)]
    if len(candidates) != 1:
        raise RuntimeError("remote acceptance did not return exactly one structured result")
    try:
        payload = json.loads(candidates[0])
    except json.JSONDecodeError as exc:
        raise RuntimeError("remote acceptance returned invalid structured JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("remote acceptance result is not an object")
    return payload
