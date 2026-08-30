import json

import operator_windows_app_control as mod


class FakePolicy:
    def __init__(self, *, template="hermes-claude-desktop-restart", direct=True):
        self.level = "workspace"
        self.apply_mode = "direct" if direct else "dry_run"
        self.session_status = "active"
        self.session_id = "ops_test"
        self.policy_template = template

    def require_level(self, level):
        assert level == "workspace"

    def require_verb(self, family, verb):
        assert (family, verb) == ("applications", "restart")

    def effective_dry_run(self, dry_run):
        return bool(dry_run) or self.apply_mode != "direct"

    def require_mutation(self, dry_run):
        assert self.apply_mode == "direct"
        assert dry_run is False


def _quiet_audit(**kwargs):
    return None


def test_dry_run_is_fixed_and_contains_no_caller_command(monkeypatch):
    monkeypatch.setattr(mod.op, "OperatorPolicy", lambda: FakePolicy())
    monkeypatch.setattr(mod.op, "audit_record", _quiet_audit)
    result = json.loads(mod.hermes_claude_desktop_restart(dry_run=True, powershell_binary="powershell.exe"))
    assert result["success"] is True
    assert result["dry_run"] is True
    plan = result["plan"]
    assert plan["application"] == "Claude Desktop"
    assert plan["process_name"] == "Claude"
    assert plan["requires_already_running_process"] is True
    assert plan["reuses_resolved_executable_path"] is True
    assert plan["verifies_new_pid"] is True
    assert plan["caller_supplied_command_or_path"] is False


def test_wrong_policy_template_fails_closed(monkeypatch):
    monkeypatch.setattr(mod.op, "OperatorPolicy", lambda: FakePolicy(template="hermes-gpt-operator-maintenance"))
    monkeypatch.setattr(mod.op, "audit_record", _quiet_audit)
    result = json.loads(mod.hermes_claude_desktop_restart(dry_run=True, powershell_binary="powershell.exe"))
    assert result["success"] is False
    assert result["code"] == "CLAUDE_DESKTOP_RESTART_ERROR"


def test_success_requires_verified_new_pid_and_uses_fixed_script(monkeypatch):
    monkeypatch.setattr(mod.op, "OperatorPolicy", lambda: FakePolicy())
    monkeypatch.setattr(mod.op, "audit_record", _quiet_audit)
    captured = {}

    def runner(argv, timeout, workdir):
        captured["argv"] = argv
        captured["timeout"] = timeout
        captured["workdir"] = workdir
        evidence = {
            "success": True,
            "application": "Claude Desktop",
            "previous_pids": [101, 102],
            "new_pid": 201,
            "executable": r"C:\Users\user\AppData\Local\AnthropicClaude\Claude.exe",
            "verified_running": True,
        }
        return 0, json.dumps(evidence), ""

    result = json.loads(mod.hermes_claude_desktop_restart(dry_run=False, runner=runner, powershell_binary="powershell.exe"))
    assert result["success"] is True
    assert result["verified_running"] is True
    assert result["previous_pids"] == [101, 102]
    assert result["new_pid"] == 201
    argv = captured["argv"]
    assert argv[0] == "powershell.exe"
    assert argv[-2] == "-Command"
    script = argv[-1]
    assert "Get-Process -Name 'Claude'" in script
    assert "Start-Process -FilePath $exe" in script
    assert "verified_running = $true" in script
    assert captured["timeout"] == 30
    assert captured["workdir"] is None


def test_unverified_output_is_failure(monkeypatch):
    monkeypatch.setattr(mod.op, "OperatorPolicy", lambda: FakePolicy())
    monkeypatch.setattr(mod.op, "audit_record", _quiet_audit)

    def runner(argv, timeout, workdir):
        return 0, json.dumps({"verified_running": False, "new_pid": None}), ""

    result = json.loads(mod.hermes_claude_desktop_restart(dry_run=False, runner=runner, powershell_binary="powershell.exe"))
    assert result["success"] is False
    assert result["verified_running"] is False
