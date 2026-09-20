from __future__ import annotations

import inspect
import json

import operator_first_safe_provision as provision
import first_safe_provision_worker as worker
import operator_policy_templates as templates


def test_fixed_plan_is_single_target_and_non_live():
    plan = provision.fixed_plan()
    assert plan["egress_host"] == "hermes-exec"
    assert plan["remote_runtime_user"] == "jfroh"
    assert plan["profile"] == "first-safe"
    assert plan["profile_home"] == "/home/jfroh/.hermes/profiles/first-safe"
    assert plan["live_model_calls"] == 0
    assert plan["service_changes"] is False
    assert plan["cloudflare_changes"] is False
    assert plan["cron_changes"] is False
    assert plan["cutover"] is False


def test_prepare_has_no_caller_operational_parameters():
    assert list(inspect.signature(provision.hermes_first_safe_provision_prepare).parameters) == []
    params = list(inspect.signature(provision.prepare_intent).parameters)
    assert params == ["now"]


def test_verify_only_accepts_opaque_intent_id():
    assert list(inspect.signature(provision.hermes_first_safe_provision_verify).parameters) == ["intent_id"]


def test_execute_only_accepts_opaque_intent_id():
    assert list(inspect.signature(provision.hermes_first_safe_provision_execute).parameters) == ["intent_id"]


def test_execute_rejects_injection_before_worker_or_authority(monkeypatch):
    called = {"worker": False, "authority": False}

    def fail_worker(_intent_id):
        called["worker"] = True
        raise AssertionError("worker must not run")

    def fail_authority(*, mutation):
        called["authority"] = True
        raise AssertionError("authority must not be reached")

    monkeypatch.setattr(worker, "execute", fail_worker)
    monkeypatch.setattr(provision, "_require_authority", fail_authority)
    result = json.loads(provision.hermes_first_safe_provision_execute("fsp_bad;rm -rf /"))
    assert result["success"] is False
    assert result["code"] == "FIRST_SAFE_PROVISION_EXECUTE_ERROR"
    assert called == {"worker": False, "authority": False}


def test_worker_revalidates_full_prepared_binding_before_claim():
    src = inspect.getsource(worker.execute)
    for required in (
        'row["state"] != intents.STATE_PREPARED',
        'row["expires_at"]',
        'row["plan_hash"] != intents.plan_hash()',
        'json.loads(row["plan_json"]) != intents.fixed_plan()',
        'row["policy_template"] != intents.POLICY_TEMPLATE',
        'row["session_id"] != str(authority.session_id)',
        'row["snapshot_hash"] != str(authority.snapshot_hash)',
        'row["logical_task_id"] != str(authority.logical_task_id)',
        'row["lease_owner"] != intents.REQUIRED_LEASE_OWNER',
        'row["lease_id"] != str(status.get("lease_id") or "")',
    ):
        assert required in src
    claim = 'UPDATE provision_intents SET state=?, claimed_at=?'
    assert src.index('row["lease_id"] != str(status.get("lease_id") or "")') < src.index(claim)


def test_worker_uses_stdin_for_remote_python_transport():
    src = inspect.getsource(worker.execute)
    transport = inspect.getsource(worker._transport_argv)
    assert '"BatchMode=yes"' in transport
    assert '"ConnectTimeout=10"' in transport
    assert '"ConnectionAttempts=1"' in transport
    assert 'REMOTE_PYTHON, "-"' in transport
    assert "_transport_argv()" in src
    assert "input=REMOTE_PROGRAM" in src
    assert 'REMOTE_PYTHON, "-c", REMOTE_PROGRAM' not in src
    assert src.index("try:") < src.index("proc = subprocess.run")
    assert 'UPDATE provision_intents SET state=?, completed_at=?, failure_reason=?' in src


def test_worker_local_transport_only_on_approved_host(monkeypatch):
    monkeypatch.setattr(worker.socket, "gethostname", lambda: "hermes-exec")
    assert worker._transport_argv() == [worker.sys.executable, "-"]
    monkeypatch.setattr(worker.socket, "gethostname", lambda: "hermes-exec.example")
    assert worker._transport_argv() == [worker.sys.executable, "-"]
    monkeypatch.setattr(worker.socket, "gethostname", lambda: "unrelated-host")
    argv = worker._transport_argv()
    assert argv[0] == worker.SSH_PROGRAM
    assert argv[-3:] == ["jfroh@172.29.176.132", worker.REMOTE_PYTHON, "-"]
    assert "BatchMode=yes" in argv


def test_worker_target_and_paths_are_fixed():
    assert worker.VM_NAME == "hermes-exec"
    assert worker.SSH_USER == "jfroh"
    assert worker.SSH_PROGRAM == "/usr/bin/ssh"
    assert worker._resolve_target_ipv4() == "172.29.176.132"
    resolver = inspect.getsource(worker._resolve_target_ipv4)
    assert "Get-VMNetworkAdapter" not in resolver
    assert worker.REMOTE_PYTHON == "/home/jfroh/.hermes/hermes-agent/venv/bin/python3"
    assert worker.EXPECTED_AGENT_COMMIT == "f80f453ae0679347e38abc917c7f94f717bf96c5"
    src = worker.REMOTE_PROGRAM
    assert '/home/jfroh' in src
    assert 'profiles"/"first-safe' in src
    assert "cohere/north-mini-code:free" not in src
    assert "hermes -z" not in src
    assert "curl " not in src
    assert "requests." not in src


def test_worker_never_accepts_host_user_path_command_or_secret_arguments():
    assert list(inspect.signature(worker.execute).parameters) == ["intent_id"]
    src = inspect.getsource(worker)
    for forbidden in ("host: str", "user: str", "command: str", "model: str", "api_key: str", "secret: str"):
        assert forbidden not in src


def test_remote_program_requires_existing_private_profile_credential_and_never_returns_value():
    src = worker.REMOTE_PROGRAM
    assert 'PROFILE_ENV.is_file()' in src
    assert 'mode & 0o077' in src
    assert 'env_has_key(PROFILE_ENV,"OPENROUTER_API_KEY")' in src
    assert 'credential_value_exposed":False' in src
    assert 'PROFILE_ENV.read_text' not in src
    assert 'OPENROUTER_API_KEY=' not in src


def test_remote_program_quarantines_only_profile_auth_without_reading_contents():
    src = worker.REMOTE_PROGRAM
    fixed_path = 'PROFILE_AUTH_QUARANTINE=PROFILE/"auth.json.pre-first-safe.quarantine"'
    collision = 'if PROFILE_AUTH_QUARANTINE.exists(): fail("profile auth quarantine already exists"'
    rename = 'os.rename(PROFILE_AUTH,PROFILE_AUTH_QUARANTINE)'
    chmod = 'os.chmod(PROFILE_AUTH_QUARANTINE,0o600)'
    config_write = 'CONFIG.write_text(CONFIG_TEXT,encoding="utf-8")'
    assert fixed_path in src
    assert 'if PROFILE_AUTH.exists():' in src
    assert 'PROFILE_AUTH.is_symlink() or not PROFILE_AUTH.is_file()' in src
    assert collision in src
    assert rename in src
    assert chmod in src
    assert src.index(collision) < src.index(rename) < src.index(chmod) < src.index(config_write)
    assert 'profile_auth_quarantined=False' in src
    assert 'profile_auth_quarantined=True' in src
    assert '"profile_auth_quarantined":profile_auth_quarantined' in src
    assert '"profile_auth_quarantine_path":str(PROFILE_AUTH_QUARANTINE)' in src
    assert 'PROFILE_AUTH.read_text' not in src
    assert 'PROFILE_AUTH.read_bytes' not in src
    assert 'PROFILE_AUTH.unlink' not in src


def test_remote_program_fails_closed_on_root_state_and_sibling_or_git_change():
    src = worker.REMOTE_PROGRAM
    assert 'ROOT_CONFIG' in src and 'ROOT_ENV' in src and 'ROOT_AUTH' in src and 'ROOT_NOUS' in src
    assert 'must be absent' in src
    assert 'sibling profile changed during provisioning' in src
    assert 'Hermes repository status changed during provisioning' in src
    assert 'target Hermes commit mismatch' in src
    assert 'wrong target runtime identity' in src


def test_bounded_evidence_allowlist_excludes_secret_and_transport_fields():
    good = {"success": True, "credential_value_exposed": False}
    parsed = worker._extract("HERMES_FIRST_SAFE_PROVISION_JSON=" + json.dumps(good))
    assert parsed == good
    src = inspect.getsource(worker.execute)
    for forbidden in ("api_key", "secret", "stdout", "stderr", "ssh_command", "credential_value"):
        assert f'"{forbidden}"' not in src


def test_provision_policy_is_distinct_from_live_acceptance_policy():
    assert provision.POLICY_TEMPLATE == "hermes-exec-first-safe-provision"
    assert provision.POLICY_TEMPLATE != "hermes-exec-first-safe-model"


def test_default_intent_state_root_uses_operator_scratch(monkeypatch):
    monkeypatch.delenv("HERMES_GPT_FIRST_SAFE_PROVISION_ROOT", raising=False)
    expected = provision.Path.home() / ".hermes" / "worktrees" / "chatgpt-operator-scratch" / "operator-first-safe-provision"
    assert provision.state_root() == expected


def test_intent_identifier_is_strict_and_separate_from_acceptance_intents():
    assert provision._INTENT_ID_RE.match("fsp_abcdefghijklmnop")
    assert not provision._INTENT_ID_RE.match("fsi_abcdefghijklmnop")
    assert not provision._INTENT_ID_RE.match("fsp_bad/path")


def test_policy_is_tier3_nonstanding_zero_local_write_and_fixed_egress():
    resolved = templates.resolve_template("hermes-exec-first-safe-provision")
    policy = resolved["policy"]
    assert resolved["risk_tier"] == 3
    assert resolved["standing_authority_eligible"] is False
    assert policy["writable_roots"] == []
    assert policy["egress_hosts"] == ["hermes-exec"]
    assert policy["service_units"] == []
    assert policy["verbs"] == {
        "filesystem": ["read", "edit"],
        "tests": ["run"],
        "mission_control": ["lease_status"],
    }
    assert policy["has_secret_access"] is False
    assert policy["has_credential_access"] is True
    assert policy["has_external_communication"] is False


def test_provision_and_acceptance_authorities_are_not_interchangeable():
    provision_policy = templates.resolve_template("hermes-exec-first-safe-provision")
    acceptance_policy = templates.resolve_template("hermes-exec-first-safe-model")
    assert provision_policy != acceptance_policy
    assert provision.POLICY_TEMPLATE == "hermes-exec-first-safe-provision"


# ANTIGRAVITY HARDENING TESTS
# These three tests are required by the Antigravity review for Controller activation

def test_missing_first_safe_env_fails_closed_even_with_ambient_openrouter_key(monkeypatch):
    """Ambient OPENROUTER_API_KEY must never substitute for profile-local .env."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "ambient-should-not-matter")
    src = worker.REMOTE_PROGRAM

    missing_env_check = 'if not PROFILE_ENV.is_file(): fail("first-safe profile .env missing; secret placement gate has not completed")'
    assert missing_env_check in src
    assert 'env_has_key(PROFILE_ENV,"OPENROUTER_API_KEY")' in src
    assert 'os.environ.get("OPENROUTER_API_KEY")' not in src
    assert "os.getenv(\"OPENROUTER_API_KEY\")" not in src
    assert src.index(missing_env_check) < src.index("CONFIG.write_text")


def test_provisioning_authority_cannot_invoke_live_first_safe_acceptance(monkeypatch):
    """A live provisioning policy must be rejected by the live acceptance gate."""
    import operator_first_safe as acceptance
    import pytest

    class ProvisioningPolicy:
        session_status = "active"
        session_id = "ops_test"
        policy_template = provision.POLICY_TEMPLATE
        authority_kind = "task_bound"

        def require_level(self, _level):
            return None

    monkeypatch.setattr(acceptance.op, "OperatorPolicy", lambda: ProvisioningPolicy())

    assert provision.POLICY_TEMPLATE == "hermes-exec-first-safe-provision"
    assert acceptance.POLICY_TEMPLATE == "hermes-exec-first-safe-model"
    with pytest.raises(PermissionError, match="FIRST_SAFE requires policy template"):
        acceptance._require_first_safe_authority(for_mutation=True)


def test_unexpected_sibling_profile_git_tampering_fails_provisioning_verification_gate():
    """Sibling-profile or Git drift must trip fail-closed worker checks."""
    src = worker.REMOTE_PROGRAM

    sibling_before = 'siblings_before={name:digest_tree(ROOT/"profiles"/name) for name in SIBLINGS}'
    sibling_after = 'siblings_after={name:digest_tree(ROOT/"profiles"/name) for name in SIBLINGS}'
    sibling_fail = 'if siblings_after!=siblings_before: fail("sibling profile changed during provisioning")'
    git_before = 'git_before=subprocess.run(["git","status","--porcelain=v1"]'
    git_after = 'git_after=subprocess.run(["git","status","--porcelain=v1"]'
    git_fail = 'if git_after!=git_before: fail("Hermes repository status changed during provisioning")'

    for required in (sibling_before, sibling_after, sibling_fail, git_before, git_after, git_fail):
        assert required in src
    assert src.index(sibling_before) < src.index("CONFIG.write_text") < src.index(sibling_after) < src.index(sibling_fail)
    assert src.index(git_before) < src.index("CONFIG.write_text") < src.index(git_after) < src.index(git_fail)
    assert 'target Hermes commit mismatch' in src
    assert 'f80f453ae0679347e38abc917c7f94f717bf96c5' in src
