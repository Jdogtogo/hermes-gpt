"""Send Hermes Operator approval notifications through the existing Hermes
Agent Telegram bot -- never a second bot, never a duplicated token.

Reuses the same bot identity (TELEGRAM_BOT_TOKEN, read at call-time from the
same .env file Hermes Agent's gateway loads it from -- never copied into
systemd unit config, so it can never leak via `systemctl show`/`systemctl
cat`) and the same authorized-user configuration (TELEGRAM_ALLOWED_USERS)
the Telegram adapter already enforces for inbound callbacks. This module
only ever sends -- it never polls getUpdates itself (that would race with
Hermes Agent's own long-running poller for the same bot). The corresponding
button press is received by a small, additive branch in Hermes Agent's own
callback dispatcher, which calls back into hermes-gpt's local approval
endpoint (POST http://127.0.0.1:7690/telegram-resolve) after authorizing the
caller against the exact same TELEGRAM_ALLOWED_USERS allowlist.

This module must only ever be imported/called from the localhost-only
approval centre (127.0.0.1:7690), never from the internet-facing chatgpt-
operator connector -- that process forwards to POST /notify on the approval
centre instead, so the Telegram bot token never transits the internet-facing
process at all.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

TELEGRAM_BOT_TOKEN_ENV = "TELEGRAM_BOT_TOKEN"
TELEGRAM_ALLOWED_USERS_ENV = "TELEGRAM_ALLOWED_USERS"
_API_BASE = "https://api.telegram.org"
_ENV_FILE_PATH_ENV = "HERMES_GPT_SHARED_ENV_FILE"
_DEFAULT_ENV_FILE = Path.home() / ".hermes" / ".env"


def _read_env_value(key: str) -> str:
    """Look up an env var from the process environment first (lets tests
    and future deployments override cheaply), falling back to reading it
    directly from the shared Hermes Agent .env file at call-time. Never
    caches the value and never writes it anywhere -- this is what lets the
    localhost approval centre reuse the real bot token without it ever
    being duplicated into systemd unit config."""
    value = os.environ.get(key, "").strip()
    if value:
        return value
    env_path = Path(os.environ.get(_ENV_FILE_PATH_ENV, "") or _DEFAULT_ENV_FILE)
    try:
        with env_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                found_key, _, found_value = line.partition("=")
                if found_key.strip() == key:
                    return found_value.strip().strip('"').strip("'")
    except OSError:
        return ""
    return ""


def _target_chat_id() -> str | None:
    """For a single-user private bot, the DM chat_id equals the user_id, so
    the first configured authorized user is also the notification target."""
    raw = _read_env_value(TELEGRAM_ALLOWED_USERS_ENV)
    if not raw:
        return None
    first = raw.split(",")[0].strip()
    return first or None


def _send_message(text: str, callback_rows: list[list[tuple[str, str]]]) -> bool:
    token = _read_env_value(TELEGRAM_BOT_TOKEN_ENV)
    chat_id = _target_chat_id()
    if not token or not chat_id:
        return False
    import httpx

    keyboard = {
        "inline_keyboard": [
            [{"text": label, "callback_data": data} for label, data in row]
            for row in callback_rows
        ]
    }
    response = httpx.post(
        f"{_API_BASE}/bot{token}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": text,
            "reply_markup": keyboard,
        },
        timeout=10.0,
    )
    return response.status_code == 200


def _format_session_summary(details: dict[str, Any]) -> str:
    policy = details.get("resolved_policy") or {}
    roots = ", ".join(policy.get("writable_roots") or policy.get("readable_roots") or [])
    verbs = json.dumps(policy.get("verbs") or {})
    minutes = int(details.get("requested_duration_seconds", 0)) // 60
    return (
        "Hermes Operator session request\n\n"
        f"Policy: {details.get('policy_template')}\n"
        f"Repository/worktree: {roots}\n"
        f"Access: {verbs}\n"
        f"Duration: {minutes} minutes\n"
        f"Reason: {details.get('reason')}"
    )


def _format_oauth_summary(details: dict[str, Any]) -> str:
    return (
        "Hermes Operator connection request\n\n"
        f"Client: {details.get('client_id')}\n"
        f"Redirect domain: {details.get('redirect_domain')}\n"
        f"Scope: {details.get('scope')}\n"
        f"Expires: {details.get('expires_at')}"
    )


def _format_extension_summary(details: dict[str, Any]) -> str:
    return (
        "Hermes Operator extension request\n\n"
        f"Session: {str(details.get('session_id'))[:16]}\n"
        f"Current expiry: {details.get('current_expiry')}\n"
        f"Requested extension: 30 minutes"
    )


def notify_pending_request(request_type: str, request_id: str, details: dict[str, Any]) -> bool:
    """Best-effort: never raises. Returns False (silently) if Telegram isn't
    configured or the send fails -- the localhost approval page remains the
    always-available fallback regardless."""
    try:
        if request_type == "session_creation":
            text = _format_session_summary(details)
            rows = [[("Approve", f"hop:approve:{request_id}"), ("Deny", f"hop:deny:{request_id}")]]
        elif request_type == "oauth":
            text = _format_oauth_summary(details)
            rows = [[("Approve once", f"hop:approve:{request_id}"), ("Deny", f"hop:deny:{request_id}")]]
        elif request_type == "extension":
            text = _format_extension_summary(details)
            rows = [[("Approve 30 minutes", f"hop:approve:{request_id}"), ("Deny", f"hop:deny:{request_id}")]]
        else:
            return False
        return _send_message(text, rows)
    except Exception:
        return False
