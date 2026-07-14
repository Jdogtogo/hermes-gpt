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
        {"session_id": "ops_abcdefghijklmnopqrstuvwxyz", "current_expiry": 123},
    )
    assert "30 minutes" in captured["json"]["text"]
    buttons = captured["json"]["reply_markup"]["inline_keyboard"][0]
    assert buttons[0]["callback_data"] == "hop:approve:ext_xyz"


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
