"""Tests for the Telegram notification module: message content, callback_data
shape, and that it never raises even when misconfigured or the send fails.
"""

from __future__ import annotations

import pytest

import operator_approval_notify as notify


@pytest.fixture
def telegram_env(monkeypatch):
    monkeypatch.setenv(notify.TELEGRAM_BOT_TOKEN_ENV, "test-token-value")
    monkeypatch.setenv(notify.TELEGRAM_ALLOWED_USERS_ENV, "12345,67890")


def test_no_config_returns_false_without_raising(monkeypatch):
    monkeypatch.delenv(notify.TELEGRAM_BOT_TOKEN_ENV, raising=False)
    monkeypatch.delenv(notify.TELEGRAM_ALLOWED_USERS_ENV, raising=False)
    result = notify.notify_pending_request("oauth", "abc123", {"client_id": "c1"})
    assert result is False


def test_target_chat_id_uses_first_allowed_user(telegram_env):
    assert notify._target_chat_id() == "12345"


def test_session_request_sends_correct_payload(telegram_env, monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return FakeResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    result = notify.notify_pending_request(
        "session_creation",
        "sr_abc123",
        {
            "policy_template": "sandbox",
            "resolved_policy": {
                "writable_roots": ["/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch"],
                "verbs": {"git": ["commit"]},
            },
            "requested_duration_seconds": 3600,
            "reason": "test run",
        },
    )
    assert result is True
    assert "test-token-value" in captured["url"]
    body = captured["json"]
    assert body["chat_id"] == "12345"
    assert "sandbox" in body["text"]
    assert "test run" in body["text"]
    buttons = body["reply_markup"]["inline_keyboard"][0]
    assert buttons[0]["callback_data"] == "hop:approve:sr_abc123"
    assert buttons[1]["callback_data"] == "hop:deny:sr_abc123"
    # No secret ever appears in the message text.
    assert "test-token-value" not in body["text"]


def test_oauth_request_message_shows_domain_not_full_url(telegram_env, monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200

    def fake_post(url, json=None, timeout=None):
        captured["json"] = json
        return FakeResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    notify.notify_pending_request(
        "oauth", "abc12345",
        {"client_id": "client-1", "redirect_domain": "chatgpt.com", "scope": "hermes:operator", "expires_at": 123},
    )
    assert "chatgpt.com" in captured["json"]["text"]


def test_extension_request_message(telegram_env, monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200

    def fake_post(url, json=None, timeout=None):
        captured["json"] = json
        return FakeResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    notify.notify_pending_request(
        "extension", "ext_xyz",
        {
            "session_id": "ops_abcdefghijklmnopqrstuvwxyz",
            "current_expiry": 123,
            "requested_seconds": 30 * 60,
        },
    )
    assert "30 minutes" in captured["json"]["text"]
    buttons = captured["json"]["reply_markup"]["inline_keyboard"][0]
    assert buttons[0]["callback_data"] == "hop:approve:ext_xyz"
    assert buttons[0]["text"] == "Approve 30 minutes"


def test_extension_message_reports_the_actual_requested_duration(telegram_env, monkeypatch):
    """The approver must be shown the duration actually requested, not a
    hardcoded default -- approving "30 minutes" for a 4-hour request would
    mean the human authorised something they were never shown."""
    captured = {}

    class FakeResponse:
        status_code = 200

    def fake_post(url, json=None, timeout=None):
        captured["json"] = json
        return FakeResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    notify.notify_pending_request(
        "extension", "ext_long",
        {
            "session_id": "ops_abcdefghijklmnopqrstuvwxyz",
            "current_expiry": 123,
            "requested_seconds": 4 * 60 * 60,
        },
    )
    assert "240 minutes" in captured["json"]["text"]
    assert "30 minutes" not in captured["json"]["text"]
    buttons = captured["json"]["reply_markup"]["inline_keyboard"][0]
    assert buttons[0]["text"] == "Approve 240 minutes"


def test_extension_message_fails_closed_on_missing_duration(telegram_env, monkeypatch):
    """A missing duration must not render as a plausible default. Previously an
    absent requested_seconds displayed "30 minutes", which would show the
    approver a concrete number nobody had actually requested."""
    captured = {}

    class FakeResponse:
        status_code = 200

    def fake_post(url, json=None, timeout=None):
        captured["json"] = json
        return FakeResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    notify.notify_pending_request(
        "extension", "ext_missing",
        {"session_id": "ops_abcdefghijklmnopqrstuvwxyz", "current_expiry": 123},
    )
    assert notify.UNKNOWN_DURATION in captured["json"]["text"]
    assert "30 minutes" not in captured["json"]["text"]


@pytest.mark.parametrize(
    "seconds,expected",
    [
        (30 * 60, "30 minutes"),
        (4 * 60 * 60, "240 minutes"),
        (60, "1 minute"),
        (90, "90 seconds"),
        (1, "1 second"),
        ("1800", "30 minutes"),
    ],
)
def test_format_requested_duration_valid_values(seconds, expected):
    assert notify.format_requested_duration(seconds) == expected


@pytest.mark.parametrize(
    "seconds",
    [None, 0, -1, -3600, "", "abc", "30 minutes", True, False, [], {}, object()],
)
def test_format_requested_duration_fails_closed(seconds):
    """Missing, malformed, non-numeric, boolean, and non-positive values all
    render as the explicit unknown sentinel rather than a plausible number.
    details arrives over the loopback /notify JSON boundary, so any type is
    reachable here."""
    assert notify.format_requested_duration(seconds) == notify.UNKNOWN_DURATION


def test_send_failure_returns_false_without_raising(telegram_env, monkeypatch):
    def fake_post(url, json=None, timeout=None):
        raise ConnectionError("network unreachable")

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    result = notify.notify_pending_request("oauth", "abc123", {"client_id": "c1"})
    assert result is False


def test_unknown_request_type_returns_false(telegram_env):
    result = notify.notify_pending_request("not-a-real-type", "id1", {})
    assert result is False


def test_falls_back_to_shared_env_file_when_process_env_unset(tmp_path, monkeypatch):
    """No systemd unit ever duplicates the real token into its own config --
    this module reads it at call-time from the same .env file Hermes
    Agent's gateway already loads it from."""
    monkeypatch.delenv(notify.TELEGRAM_BOT_TOKEN_ENV, raising=False)
    monkeypatch.delenv(notify.TELEGRAM_ALLOWED_USERS_ENV, raising=False)
    env_file = tmp_path / "shared.env"
    env_file.write_text(
        "SOME_OTHER_VAR=irrelevant\n"
        "TELEGRAM_BOT_TOKEN=fallback-token-value\n"
        "TELEGRAM_ALLOWED_USERS=555,666\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_GPT_SHARED_ENV_FILE", str(env_file))

    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        class FakeResponse:
            status_code = 200
        return FakeResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    result = notify.notify_pending_request("oauth", "abc123", {"client_id": "c1"})
    assert result is True
    assert "fallback-token-value" in captured["url"]
    assert captured["json"]["chat_id"] == "555"


def test_process_env_takes_priority_over_shared_env_file(tmp_path, monkeypatch):
    env_file = tmp_path / "shared.env"
    env_file.write_text("TELEGRAM_BOT_TOKEN=should-not-be-used\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_GPT_SHARED_ENV_FILE", str(env_file))
    monkeypatch.setenv(notify.TELEGRAM_BOT_TOKEN_ENV, "process-env-token")
    monkeypatch.setenv(notify.TELEGRAM_ALLOWED_USERS_ENV, "12345")

    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        class FakeResponse:
            status_code = 200
        return FakeResponse()

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)

    notify.notify_pending_request("oauth", "abc123", {"client_id": "c1"})
    assert "process-env-token" in captured["url"]
    assert "should-not-be-used" not in captured["url"]


def test_missing_shared_env_file_returns_false_without_raising(monkeypatch):
    monkeypatch.delenv(notify.TELEGRAM_BOT_TOKEN_ENV, raising=False)
    monkeypatch.delenv(notify.TELEGRAM_ALLOWED_USERS_ENV, raising=False)
    monkeypatch.setenv("HERMES_GPT_SHARED_ENV_FILE", "/nonexistent/path/does/not/exist.env")
    result = notify.notify_pending_request("oauth", "abc123", {"client_id": "c1"})
    assert result is False
