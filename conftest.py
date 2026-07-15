"""Shared test safety net.

Tests must never make real outbound network calls (Telegram's API, or the
locally-running approval-web service on this machine) and must never read
the real production .env file, regardless of what any individual test does
or forgets to mock -- both would otherwise be able to send a real Telegram
message to the real user during a test run. Individual tests may still
override either behavior within their own scope by monkeypatching further
after this fixture has run.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_real_network_or_secrets(monkeypatch, tmp_path):
    import httpx

    def _blocked_post(*args, **kwargs):
        raise RuntimeError(
            "Real network calls are blocked during tests; a test that needs "
            "to exercise httpx.post must mock it explicitly."
        )

    monkeypatch.setattr(httpx, "post", _blocked_post)

    # Point the operator_approval_notify .env fallback at a path that does
    # not exist by default, so tests never silently read real secrets.
    monkeypatch.setenv("HERMES_GPT_SHARED_ENV_FILE", str(tmp_path / "nonexistent.env"))
