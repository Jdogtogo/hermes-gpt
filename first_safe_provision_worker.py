"""Trusted host-side worker for PRE-LIVE FIRST_SAFE static profile provisioning.

Not an MCP tool. No caller-supplied host/user/path/command/model/credential inputs.
The worker consumes one immutable local provisioning intent, validates the exact
plan hash and approval binding, then contacts only jfroh@hermes-exec. It makes
no model/API calls and never reads or returns credential values.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import operator_first_safe_provision as intents
import operator_hermes_exec_model as spec
import operator_lease as lease
import operator_sessions as sessions

VM_NAME = "hermes-exec"
SSH_USER = "jfroh"
SSH_PROGRAM = "/usr/bin/ssh"
REMOTE_PYTHON = "/home/jfroh/.hermes/hermes-agent/venv/bin/python3"
EXPECTED_AGENT_COMMIT = "f80f453ae0679347e38abc917c7f94f717bf96c5"


def _resolve_target_ipv4() -> str:
    """Return the fixed private IPv4 for the legacy remote transport."""
    return "172.29.176.132"


def _transport_argv() -> list[str]:
    """Use a local Python subprocess only when already on the approved VM.

    The Controller now runs on hermes-exec; Windows OpenSSH under /mnt/c is
    unavailable there. A distinct Linux host must still use bounded SSH to
    the pinned target. The payload independently verifies its target identity.
    """
    if socket.gethostname().split(".", 1)[0] == VM_NAME:
        return [sys.executable, "-"]
    return [
        SSH_PROGRAM, "-T",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "ConnectionAttempts=1",
        f"{SSH_USER}@{_resolve_target_ipv4()}", REMOTE_PYTHON, "-",
    ]

REMOTE_PROGRAM = r'''from __future__ import annotations
import hashlib, json, os, pwd, stat, subprocess
from pathlib import Path

HOME=Path("/home/jfroh")
ROOT=HOME/".hermes"
PROFILE=ROOT/"profiles"/"first-safe"
CONFIG=PROFILE/"config.yaml"
PROFILE_ENV=PROFILE/".env"
PROFILE_AUTH=PROFILE/"auth.json"
PROFILE_AUTH_QUARANTINE=PROFILE/"auth.json.pre-first-safe.quarantine"
PROFILE_SHARED=PROFILE/"shared"
PROFILE_NOUS=PROFILE_SHARED/"nous_auth.json"
ROOT_CONFIG=ROOT/"config.yaml"
ROOT_ENV=ROOT/".env"
ROOT_AUTH=ROOT/"auth.json"
ROOT_NOUS=ROOT/"shared"/"nous_auth.json"
REPO=ROOT/"hermes-agent"
EXPECTED_COMMIT="f80f453ae0679347e38abc917c7f94f717bf96c5"
SIBLINGS=("backend-eng","coder","maintenance","ops","thinker")
CONFIG_TEXT="""model:\n  provider: openrouter\n  default: \n  base_url: https://openrouter.ai/api/v1\nfallback_providers: []\nproviders: {}\ncredential_pool_strategies: {}\n"""

def fail(msg, **extra):
    print("HERMES_FIRST_SAFE_PROVISION_JSON="+json.dumps({"success":False,"error":str(msg),**extra},sort_keys=True))
    raise SystemExit(2)

def digest_tree(path):
    p=Path(path)
    if not p.exists(): return "ABSENT"
    h=hashlib.sha256()
    for item in sorted(p.rglob("*"), key=lambda x:str(x.relative_to(p))):
        rel=str(item.relative_to(p)).encode(); h.update(rel+b"\0")
        if item.is_file():
            h.update(b"F"+oct(stat.S_IMODE(item.stat().st_mode)).encode()+b"\0"+item.read_bytes()+b"\0")
        elif item.is_dir(): h.update(b"D"+oct(stat.S_IMODE(item.stat().st_mode)).encode()+b"\0")
        elif item.is_symlink(): h.update(b"L"+os.readlink(item).encode()+b"\0")
    return h.hexdigest()

def env_has_key(path,key):
    try:
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line=raw.strip()
            if not line or line.startswith("#"): continue
            if line.startswith("export "): line=line[7:].lstrip()
            if "=" in line and line.split("=",1)[0].strip()==key: return True
    except OSError as exc:
        fail("unable to inspect profile environment metadata",detail=type(exc).__name__)
    return False

who=pwd.getpwuid(os.geteuid())
if who.pw_name!="jfroh" or who.pw_dir!="/home/jfroh": fail("wrong target runtime identity")
profile_auth_quarantined=False
if PROFILE_AUTH.exists():
    if PROFILE_AUTH.is_symlink() or not PROFILE_AUTH.is_file(): fail("profile auth.json must be a regular file before quarantine",path=str(PROFILE_AUTH))
    if PROFILE_AUTH_QUARANTINE.exists(): fail("profile auth quarantine already exists",path=str(PROFILE_AUTH_QUARANTINE))
    try:
        os.rename(PROFILE_AUTH,PROFILE_AUTH_QUARANTINE)
        os.chmod(PROFILE_AUTH_QUARANTINE,0o600)
    except OSError as exc:
        fail("unable to quarantine profile auth.json",detail=type(exc).__name__)
    profile_auth_quarantined=True
for p,label in ((ROOT_CONFIG,"root config.yaml"),(ROOT_ENV,"root .env"),(ROOT_AUTH,"root auth.json"),(ROOT_NOUS,"root Nous auth"),(PROFILE_AUTH,"profile auth.json"),(PROFILE_NOUS,"profile Nous auth")):
    if p.exists(): fail(label+" must be absent",path=str(p))

rc=subprocess.run(["git","rev-parse","HEAD"],cwd=str(REPO),capture_output=True,text=True,shell=False)
if rc.returncode!=0 or rc.stdout.strip()!=EXPECTED_COMMIT: fail("target Hermes commit mismatch",observed=rc.stdout.strip()[:64])
git_before=subprocess.run(["git","status","--porcelain=v1"],cwd=str(REPO),capture_output=True,text=True,shell=False).stdout
siblings_before={name:digest_tree(ROOT/"profiles"/name) for name in SIBLINGS}

# Credential placement is intentionally NOT performed here. The target-local
# profile .env must already exist under a separately governed secret-placement
# step. Only metadata/key-name presence is inspected; the value is never read,
# printed, returned or copied.
if not PROFILE_ENV.is_file(): fail("first-safe profile .env missing; secret placement gate has not completed")
mode=stat.S_IMODE(PROFILE_ENV.stat().st_mode)
if mode & 0o077: fail("first-safe profile .env permissions too broad",mode=oct(mode))
if not env_has_key(PROFILE_ENV,"OPENROUTER_API_KEY"): fail("first-safe profile .env lacks OPENROUTER_API_KEY")

PROFILE.mkdir(mode=0o700,parents=True,exist_ok=True)
PROFILE_SHARED.mkdir(mode=0o700,parents=True,exist_ok=True)
if CONFIG.exists() and CONFIG.read_text(encoding="utf-8")!=CONFIG_TEXT: fail("existing first-safe config differs from approved sparse config")
CONFIG.write_text(CONFIG_TEXT,encoding="utf-8")
os.chmod(CONFIG,0o600)

siblings_after={name:digest_tree(ROOT/"profiles"/name) for name in SIBLINGS}
if siblings_after!=siblings_before: fail("sibling profile changed during provisioning")
git_after=subprocess.run(["git","status","--porcelain=v1"],cwd=str(REPO),capture_output=True,text=True,shell=False).stdout
if git_after!=git_before: fail("Hermes repository status changed during provisioning")

print("HERMES_FIRST_SAFE_PROVISION_JSON="+json.dumps({
  "success":True,
  "target_user":"jfroh","target_host":"hermes-exec","profile":"first-safe",
  "config_path":str(CONFIG),"config_mode":oct(stat.S_IMODE(CONFIG.stat().st_mode)),
  "credential_file_present":True,"credential_key_name_present":True,"credential_value_exposed":False,
  "profile_auth_quarantined":profile_auth_quarantined,"profile_auth_quarantine_path":str(PROFILE_AUTH_QUARANTINE) if profile_auth_quarantined else None,
  "root_provider_state_absent":True,"sibling_profiles_unchanged":True,"git_status_unchanged":True,
  "model_api_calls":0,"services_changed":False,"cloudflare_changed":False,"cron_changed":False,"cutover":False,
},sort_keys=True))
'''


def _extract(stdout: str) -> dict[str, Any]:
    marker = "HERMES_FIRST_SAFE_PROVISION_JSON="
    matches = [line[len(marker):] for line in stdout.splitlines() if line.startswith(marker)]
    if len(matches) != 1:
        raise RuntimeError("trusted provisioning worker returned invalid bounded evidence")
    data = json.loads(matches[0])
    if not isinstance(data, dict):
        raise RuntimeError("invalid provisioning evidence type")
    return data


def execute(intent_id: str) -> dict[str, Any]:
    if not intents._INTENT_ID_RE.match(str(intent_id)):
        raise ValueError("invalid provisioning intent id")
    if intents.plan_hash() != intents.plan_hash():
        raise RuntimeError("unreachable plan hash drift")
    authority = sessions.resolve_effective_authority()
    if not authority.is_active or authority.policy_template != intents.POLICY_TEMPLATE:
        raise PermissionError("live hermes-exec-first-safe-provision authority required")
    status = lease.verify_lease(owner=intents.REQUIRED_LEASE_OWNER, require_owner_match=True)
    if status.get("success") is not True or status.get("has_lease") is not True or status.get("owner_match") is not True:
        raise PermissionError("Mission Control lease required")

    with intents._connect() as c:
        row = c.execute("SELECT * FROM provision_intents WHERE intent_id=?", (intent_id,)).fetchone()
        if row is None: raise RuntimeError("provisioning intent not found")
        if row["state"] != intents.STATE_PREPARED: raise RuntimeError("provisioning intent is not prepared")
        if int(row["expires_at"]) < int(time.time()): raise RuntimeError("provisioning intent expired")
        if row["plan_hash"] != intents.plan_hash(): raise RuntimeError("provisioning plan hash mismatch")
        if json.loads(row["plan_json"]) != intents.fixed_plan(): raise RuntimeError("provisioning plan payload mismatch")
        if row["policy_template"] != intents.POLICY_TEMPLATE: raise RuntimeError("provisioning policy binding mismatch")
        if row["session_id"] != str(authority.session_id) or row["snapshot_hash"] != str(authority.snapshot_hash):
            raise PermissionError("provisioning authority binding changed")
        if row["logical_task_id"] != str(authority.logical_task_id): raise PermissionError("provisioning logical-task binding changed")
        if row["lease_owner"] != intents.REQUIRED_LEASE_OWNER: raise PermissionError("provisioning lease-owner binding mismatch")
        if row["lease_id"] != str(status.get("lease_id") or ""): raise PermissionError("provisioning lease binding changed")
        c.execute("UPDATE provision_intents SET state=?, claimed_at=? WHERE intent_id=?", (intents.STATE_CLAIMED,int(time.time()),intent_id)); c.commit()

    try:
        proc = subprocess.run(
            _transport_argv(), input=REMOTE_PROGRAM,
            capture_output=True, text=True, timeout=30, shell=False,
        )
        if not any(line.startswith("HERMES_FIRST_SAFE_PROVISION_JSON=") for line in (proc.stdout or "").splitlines()):
            stderr_text = (proc.stderr or "").lower()
            if "no such file or directory" in stderr_text:
                failure_class = "remote_program_missing"
            elif "permission denied" in stderr_text:
                failure_class = "ssh_permission_denied"
            elif "could not resolve hostname" in stderr_text or "name or service not known" in stderr_text:
                failure_class = "ssh_name_resolution"
            elif "connection refused" in stderr_text:
                failure_class = "ssh_connection_refused"
            elif "connection timed out" in stderr_text or "operation timed out" in stderr_text:
                failure_class = "ssh_timeout"
            elif proc.returncode == 255:
                failure_class = "ssh_transport_failed"
            else:
                failure_class = "missing_bounded_evidence"
            raise RuntimeError(f"trusted provisioning worker returned invalid bounded evidence [{failure_class}; rc={proc.returncode}]")
        evidence = _extract(proc.stdout or "")
        if proc.returncode != 0 or evidence.get("success") is not True:
            raise RuntimeError(str(evidence.get("error") or "target provisioning failed"))
        allowed = {
            "success","target_user","target_host","profile","config_path","config_mode",
            "credential_file_present","credential_key_name_present","credential_value_exposed",
            "profile_auth_quarantined","profile_auth_quarantine_path",
            "root_provider_state_absent","sibling_profiles_unchanged","git_status_unchanged",
            "model_api_calls","services_changed","cloudflare_changed","cron_changed","cutover"
        }
        if set(evidence) - allowed: raise RuntimeError("provisioning evidence contains non-allowlisted fields")
        with intents._connect() as c:
            c.execute("UPDATE provision_intents SET state=?, completed_at=?, evidence_json=? WHERE intent_id=?",
                      (intents.STATE_COMPLETED,int(time.time()),json.dumps(evidence,sort_keys=True),intent_id)); c.commit()
        return evidence
    except Exception as exc:
        with intents._connect() as c:
            c.execute("UPDATE provision_intents SET state=?, completed_at=?, failure_reason=? WHERE intent_id=?",
                      (intents.STATE_FAILED,int(time.time()),type(exc).__name__,intent_id)); c.commit()
        raise


def main(argv: list[str] | None = None) -> int:
    args=list(sys.argv[1:] if argv is None else argv)
    if len(args)!=1 or not intents._INTENT_ID_RE.match(args[0]):
        print("usage: first_safe_provision_worker.py <provision-intent-id>",file=sys.stderr); return 2
    try:
        evidence=execute(args[0]); print(json.dumps({"success":True,"evidence":evidence},sort_keys=True)); return 0
    except Exception as exc:
        print(json.dumps({"success":False,"error":type(exc).__name__},sort_keys=True)); return 2

if __name__ == "__main__":
    raise SystemExit(main())
