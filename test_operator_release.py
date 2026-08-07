from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import operator_policy as op
import operator_policy_templates as templates
import operator_release as release
import operator_sessions as sessions


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


@pytest.fixture
def release_repo(tmp_path: Path, monkeypatch):
    source = tmp_path / "routing-policy-resolver"
    source.mkdir()
    git(source, "init", "-q", "-b", "main")
    git(source, "config", "user.email", "test@example.test")
    git(source, "config", "user.name", "Test")
    (source / "README.md").write_text("baseline\n", encoding="utf-8")
    git(source, "add", "README.md")
    git(source, "commit", "-q", "-m", "baseline")
    merge_base = git(source, "rev-parse", "HEAD")

    (source / "MAIN_ONLY.md").write_text("main-only\n", encoding="utf-8")
    git(source, "add", "MAIN_ONLY.md")
    git(source, "commit", "-q", "-m", "main-only")
    main_head = git(source, "rev-parse", "HEAD")

    git(source, "switch", "-q", "-c", "v018-candidate", merge_base)
    (source / "CANDIDATE_ONLY.md").write_text("must-not-ship\n", encoding="utf-8")
    git(source, "add", "CANDIDATE_ONLY.md")
    git(source, "commit", "-q", "-m", "candidate-only")

    git(source, "switch", "-q", "-c", "routing-policy-resolver")
    tests_dir = source / "tests" / "agent"
    tests_dir.mkdir(parents=True)
    (tests_dir / "test_routing_policy_resolver.py").write_text(
        "def test_free_only_excludes_paid():\n"
        "    rule = 'cost'\n"
        "    assert rule == 'cost'\n\n"
        "def test_targeted_rejection():\n"
        "    assert 'paid' not in {'free', 'cost'}\n",
        encoding="utf-8",
    )
    git(source, "add", "tests/agent/test_routing_policy_resolver.py")
    git(source, "commit", "-q", "-m", "routing")
    source_head = git(source, "rev-parse", "HEAD")

    releases = tmp_path / "releases"
    releases.mkdir()
    v018 = releases / "v018-live"
    git(source, "worktree", "add", "-q", "--detach", str(v018), main_head)
    temp = tmp_path / "routing-v019-main"
    v019 = releases / "v019"

    monkeypatch.setattr(release, "SOURCE_WORKTREE", source)
    monkeypatch.setattr(release, "TEMP_WORKTREE", temp)
    monkeypatch.setattr(release, "RELEASE_WORKTREE", v019)
    monkeypatch.setattr(release, "V018_LIVE", v018)
    monkeypatch.setattr(release, "EXPECTED_SOURCE_HEAD", source_head)
    monkeypatch.setattr(release, "EXPECTED_MAIN_HEAD", main_head)
    monkeypatch.setattr(release, "EXPECTED_SOURCE_MERGE_BASE", merge_base)
    monkeypatch.setattr(release, "ROUTING_COMMITS", [source_head])
    monkeypatch.setattr(release, "PYTHON", sys.executable)

    session_root = tmp_path / "sessions"
    record = sessions.create_session(
        {
            "policy_template": "hermes-routing-v019-release",
            "level": "workspace",
            "apply_mode": "direct",
            "readable_roots": [str(source), str(temp), str(v018), str(v019)],
            "writable_roots": [str(temp), str(v019)],
            "verbs": {
                "filesystem": ["read", "edit"],
                "git": ["release"],
                "tests": ["run"],
            },
        },
        duration_seconds=600,
        root=session_root,
        session_id="ops-release-test",
    )
    monkeypatch.setenv(sessions.SESSION_ROOT_ENV, str(session_root))
    monkeypatch.setenv(sessions.ACTIVE_SESSION_ID_ENV, record.session_id)
    op.set_audit_log_override(tmp_path / "audit.jsonl")
    yield source, temp, v018, v019, main_head, source_head
    op.set_audit_log_override(None)


def test_release_template_is_narrow():
    template = templates.resolve_template("hermes-routing-v019-release")
    policy = template["policy"]
    assert policy["verbs"] == {
        "filesystem": ["read", "edit"],
        "git": ["release"],
        "tests": ["run"],
    }
    assert "services" not in policy["verbs"]
    assert "network" not in policy["verbs"]
    assert "/home/jfroh/.hermes/releases/v018-live" not in policy["writable_roots"]


def test_v019_dry_run_is_non_mutating(release_repo):
    source, temp, v018, v019, main_head, _ = release_repo
    before_v018 = git(v018, "rev-parse", "HEAD")
    out = json.loads(release.hermes_routing_release_v019(dry_run=True))
    assert out["success"] is True
    assert out["dry_run"] is True
    assert out["plan"]["starting_main"] == main_head
    assert out["plan"]["merge_base"] != main_head
    assert out["plan"]["integration_strategy"] == "replay_exact_routing_commits"
    assert out["plan"]["routing_commits"] == [release.EXPECTED_SOURCE_HEAD]
    assert not temp.exists()
    assert not v019.exists()
    assert git(source, "rev-parse", "main") == main_head
    assert git(v018, "rev-parse", "HEAD") == before_v018


def test_v019_release_happy_path(release_repo):
    source, temp, v018, v019, main_head, source_head = release_repo
    before_v018 = git(v018, "rev-parse", "HEAD")
    out = json.loads(release.hermes_routing_release_v019(dry_run=False))
    assert out["success"] is True
    assert out["starting_main"] == main_head
    assert out["source_head"] == source_head
    assert out["ending_main"] == out["merge_commit"]
    assert out["release_head"] == out["merge_commit"]
    assert out["release_detached"] is True
    assert out["release_status"] == ""
    assert out["replayed_source_commits"] == [source_head]
    assert len(out["replayed_commits"]) == 1
    assert not (v019 / "CANDIDATE_ONLY.md").exists()
    assert (v019 / "MAIN_ONLY.md").read_text(encoding="utf-8") == "main-only\n"
    assert git(source, "rev-parse", "main") == out["merge_commit"]
    assert git(source, "rev-parse", "v019") == out["merge_commit"]
    assert git(v019, "branch", "--show-current") == ""
    assert git(v018, "rev-parse", "HEAD") == before_v018
    assert not temp.exists()
    assert all(item["returncode"] == 0 for item in out["tests"])


def test_v019_refuses_checked_out_main(release_repo, tmp_path: Path):
    source, _, _, _, main_head, _ = release_repo
    main_checkout = tmp_path / "main-checkout"
    git(source, "worktree", "add", "-q", str(main_checkout), "main")
    out = json.loads(release.hermes_routing_release_v019(dry_run=True))
    assert out["success"] is False
    assert "already checked out" in out["error"]
    assert git(source, "rev-parse", "main") == main_head
