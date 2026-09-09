from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import operator_github_release_auth as auth
import operator_policy_templates as templates


class FakePolicy:
    session_id = "ops_test"
    level = "workspace"
    apply_mode = "direct"
    policy_template = auth.POLICY_TEMPLATE

    def __init__(self):
        self.required = []

    def require_verb(self, group, verb):
        assert group == "github_release_auth"
        assert verb in auth.VALID_ACTIONS
        self.required.append((group, verb))

    def require_egress_host(self, host):
        assert host in {auth.GITHUB_HOST, auth.GITHUB_API_HOST}
        self.required.append(("egress", host))

    def require_mutation(self, dry_run):
        assert dry_run is False


def _install_runtime(tmp_path, monkeypatch):
    worktree = tmp_path / "repo"
    tools = worktree / "logs/.release-tools"
    gh_dir = tools / "gh"
    auth_dir = tools / "gh-auth"
    gh_dir.mkdir(parents=True)
    gh = gh_dir / "gh"
    gh.write_text("fake", encoding="utf-8")
    gh.chmod(0o700)

    monkeypatch.setattr(auth, "WORKTREE", worktree)
    monkeypatch.setattr(auth, "RELEASE_TOOLS_ROOT", tools)
    monkeypatch.setattr(auth, "GH_BINARY", gh)
    monkeypatch.setattr(auth, "AUTH_DIR", auth_dir)
    monkeypatch.setattr(auth, "STATE_FILE", auth_dir / "device-flow.json")
    monkeypatch.setattr(auth, "AUTH_CONFIG", auth_dir / "hosts.yml")
    monkeypatch.setattr(auth.op, "OperatorPolicy", FakePolicy)
    audits = []
    monkeypatch.setattr(auth.op, "audit_record", lambda **kwargs: audits.append(kwargs))
    return worktree, tools, gh, auth_dir, audits


def _device_response(device_code="a" * 40):
    return {
        "device_code": device_code,
        "user_code": "ABCD-EFGH",
        "verification_uri": "https://github.com/login/device",
        "expires_in": 900,
        "interval": 5,
    }


def test_start_persists_opaque_device_code_but_returns_only_user_code(tmp_path, monkeypatch):
    _, _, _, auth_dir, audits = _install_runtime(tmp_path, monkeypatch)
    device_code = "a" * 40

    def post(url, form):
        assert url == auth.DEVICE_CODE_URL
        assert form == {"client_id": auth.OAUTH_CLIENT_ID, "scope": auth.OAUTH_SCOPES}
        return _device_response(device_code)

    payload = auth.hermes_github_release_auth("start", http_post=post, now=1000)
    result = json.loads(payload)

    assert result["success"] is True
    assert result["pending"] is True
    assert result["user_code"] == "ABCD-EFGH"
    assert result["verification_uri"] == "https://github.com/login/device"
    assert device_code not in payload
    state = json.loads((auth_dir / "device-flow.json").read_text())
    assert state["device_code"] == device_code
    assert stat.S_IMODE(auth_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((auth_dir / "device-flow.json").stat().st_mode) == 0o600
    assert device_code not in json.dumps(audits)


def test_start_reuses_live_device_flow_idempotently(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    calls = []

    def post(url, form):
        calls.append((url, form))
        return _device_response()

    first = json.loads(auth.hermes_github_release_auth("start", http_post=post, now=1000))
    second = json.loads(auth.hermes_github_release_auth("start", http_post=post, now=1001))
    assert first["user_code"] == second["user_code"]
    assert len(calls) == 1


def test_complete_pending_never_exposes_device_code(tmp_path, monkeypatch):
    _, _, _, _, audits = _install_runtime(tmp_path, monkeypatch)
    device_code = "b" * 40
    auth.hermes_github_release_auth(
        "start",
        http_post=lambda *_: _device_response(device_code),
        now=1000,
    )

    def pending(url, form):
        assert url == auth.TOKEN_URL
        assert form["device_code"] == device_code
        return {"error": "authorization_pending"}

    payload = auth.hermes_github_release_auth("complete", http_post=pending, now=1001)
    result = json.loads(payload)
    assert result["success"] is True
    assert result["pending"] is True
    assert result["authorized"] is False
    assert device_code not in payload
    assert device_code not in json.dumps(audits)


def test_complete_success_passes_token_only_on_stdin_and_redacts_every_surface(tmp_path, monkeypatch):
    worktree, _, gh, auth_dir, audits = _install_runtime(tmp_path, monkeypatch)
    device_code = "c" * 40
    token = "gho_SECRET_SENTINEL_12345678901234567890"
    auth.hermes_github_release_auth(
        "start",
        http_post=lambda *_: _device_response(device_code),
        now=1000,
    )
    captured = {}

    def post(url, form):
        assert url == auth.TOKEN_URL
        assert form["device_code"] == device_code
        return {"access_token": token, "token_type": "bearer", "scope": "repo,read:org,gist"}

    def runner(argv, *, input_text, env, timeout, workdir):
        captured["argv"] = argv
        captured["input_text"] = input_text
        captured["env"] = env
        captured["workdir"] = workdir
        assert argv[0] == str(gh)
        assert "--with-token" in argv
        assert token not in " ".join(argv)
        assert token not in json.dumps(env)
        assert env["GH_CONFIG_DIR"] == str(auth_dir)
        assert workdir == str(worktree)
        auth_dir.mkdir(parents=True, exist_ok=True)
        (auth_dir / "hosts.yml").write_text("github.com:\n  user: test-user\n  oauth_token: secret\n", encoding="utf-8")
        return 0, "logged in", ""

    payload = auth.hermes_github_release_auth(
        "complete",
        http_post=post,
        gh_runner=runner,
        now=1001,
    )
    result = json.loads(payload)
    assert result == {
        "success": True,
        "action": "complete",
        "authorized": True,
        "pending": False,
        "auth_config_present": True,
    }
    assert captured["input_text"] == token + "\n"
    assert not auth.STATE_FILE.exists()
    assert stat.S_IMODE(auth.AUTH_CONFIG.stat().st_mode) == 0o600
    assert token not in payload
    assert token not in json.dumps(audits)
    assert device_code not in payload
    assert device_code not in json.dumps(audits)


def test_complete_runner_error_redacts_token_sentinel(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    token = "gho_SECRET_SENTINEL_12345678901234567890"
    auth.hermes_github_release_auth("start", http_post=lambda *_: _device_response(), now=1000)

    def runner(argv, *, input_text, env, timeout, workdir):
        return 1, "", f"bad credential {token}"

    payload = auth.hermes_github_release_auth(
        "complete",
        http_post=lambda *_: {"access_token": token},
        gh_runner=runner,
        now=1001,
    )
    assert json.loads(payload)["success"] is False
    assert token not in payload
    assert "SECRET_SENTINEL" not in payload


def test_top_level_oauth_exception_sanitizes_token_and_device_material(tmp_path, monkeypatch):
    _, _, _, _, audits = _install_runtime(tmp_path, monkeypatch)
    token = "gho_TOP_LEVEL_SECRET_12345678901234567890"
    device_code = "d" * 40

    def failing_post(url, form):
        raise RuntimeError(f"oauth transport failed token={token} device={device_code}")

    payload = auth.hermes_github_release_auth("start", http_post=failing_post, now=1000)
    result = json.loads(payload)
    assert result["success"] is False
    assert result["code"] == "GITHUB_RELEASE_AUTH_ERROR"
    assert token not in payload
    assert device_code not in payload
    assert "TOP_LEVEL_SECRET" not in payload
    audit_payload = json.dumps(audits)
    assert token not in audit_payload
    assert device_code not in audit_payload
    assert "TOP_LEVEL_SECRET" not in audit_payload


def test_status_reads_presence_only_and_clear_is_fixed_scope(tmp_path, monkeypatch):
    _, tools, gh, auth_dir, _ = _install_runtime(tmp_path, monkeypatch)
    auth_dir.mkdir(parents=True)
    (auth_dir / "hosts.yml").write_text("top secret", encoding="utf-8")
    (auth_dir / "other").write_text("runtime", encoding="utf-8")
    sibling = tools / "gh/keep-me"
    sibling.write_text("keep", encoding="utf-8")

    status_payload = auth.hermes_github_release_auth("status")
    status = json.loads(status_payload)
    assert status["gh_binary_present"] is True
    assert status["auth_config_present"] is True
    assert "top secret" not in status_payload

    cleared = json.loads(auth.hermes_github_release_auth("clear"))
    assert cleared == {"success": True, "action": "clear", "changed": True}
    assert auth_dir.exists()
    assert list(auth_dir.iterdir()) == []
    assert gh.exists()
    assert sibling.exists()


def test_invalid_action_refuses_before_policy_side_effect(tmp_path, monkeypatch):
    _install_runtime(tmp_path, monkeypatch)
    payload = auth.hermes_github_release_auth("token")
    result = json.loads(payload)
    assert result["success"] is False
    assert result["code"] == "GITHUB_RELEASE_AUTH_ERROR"


def test_install_template_stays_credential_free_and_release_asset_scoped():
    resolved = templates.resolve_template("hermes-github-cli-install")
    policy = resolved["policy"]
    assert resolved["standing_authority_eligible"] is False
    assert policy["egress_hosts"] == ["github.com", "release-assets.githubusercontent.com"]
    assert policy["has_secret_access"] is False
    assert policy["has_credential_access"] is False
    assert policy["verbs"] == {
        "filesystem": ["read", "edit"],
        "tests": ["run"],
    }


def test_release_auth_template_exposes_only_fixed_broker_verbs_and_hard_denies_runtime():
    resolved = templates.resolve_template(auth.POLICY_TEMPLATE)
    policy = resolved["policy"]
    fixed_auth_dir = str(auth.AUTH_DIR)
    assert resolved["standing_authority_eligible"] is False
    assert policy["readable_roots"] == [fixed_auth_dir]
    assert policy["writable_roots"] == [fixed_auth_dir]
    assert policy["egress_hosts"] == [auth.GITHUB_HOST, auth.GITHUB_API_HOST]
    assert policy["hard_denied_paths"] == [fixed_auth_dir]
    assert policy["verbs"] == {
        "github_release_auth": ["start", "complete", "status", "clear"]
    }
    assert policy["has_secret_access"] is False
    assert policy["has_credential_access"] is False
    assert policy["has_deployment"] is False
