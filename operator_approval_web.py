"""Localhost-only approval centre for Hermes Operator.

Serves http://127.0.0.1:7690/approvals -- the fallback approval surface when
Telegram is unavailable. Also exposes /telegram-resolve, an internal endpoint
the Hermes Agent Telegram adapter calls after it has already authorized the
caller against its own allowlist; this endpoint re-verifies the request
still exists and is still pending before acting, and never trusts the
caller_id alone as authorization (Telegram-side auth already happened).

This module must never be reachable through Cloudflare or either public MCP
hostname -- it binds to 127.0.0.1 only and is deployed as its own separate
systemd service, never through the tunnel.
"""

from __future__ import annotations

import html
import json
import secrets
import time
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route

import operator_auth as op_auth
import operator_policy as op_policy
import operator_sessions as op_sessions

# CSRF tokens are one-time-use and short-lived: a page load mints one, the
# form embeds it, and the POST handler consumes it. This defends against a
# malicious page in another browser tab auto-submitting to this port.
_CSRF_TTL_SECONDS = 10 * 60
_csrf_tokens: dict[str, float] = {}


def _mint_csrf_token() -> str:
    token = secrets.token_urlsafe(24)
    now = time.time()
    # Opportunistic cleanup of expired tokens.
    for key, issued_at in list(_csrf_tokens.items()):
        if now - issued_at > _CSRF_TTL_SECONDS:
            _csrf_tokens.pop(key, None)
    _csrf_tokens[token] = now
    return token


def _consume_csrf_token(token: str) -> bool:
    issued_at = _csrf_tokens.pop(token, None)
    if issued_at is None:
        return False
    return (time.time() - issued_at) <= _CSRF_TTL_SECONDS


def _oauth_provider() -> op_auth.PersistentOAuthProvider:
    config = op_auth.AuthRuntimeConfig.from_env()
    return op_auth.PersistentOAuthProvider(config)


def _fmt_time(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(ts)))
    except Exception:
        return str(ts)


def _render_page() -> str:
    csrf = _mint_csrf_token()
    try:
        oauth_pending = _oauth_provider().list_pending_requests()
    except Exception:
        oauth_pending = []
    session_pending = op_sessions.list_pending_session_requests()
    extension_pending = op_sessions.list_pending_extensions()
    audit_records = list(reversed(op_policy.audit_tail(limit=20)))

    def esc(value: Any) -> str:
        return html.escape(str(value), quote=True)

    sections = []

    sections.append("<h2>Pending OAuth connection requests</h2>")
    if not oauth_pending:
        sections.append("<p><em>None.</em></p>")
    for item in oauth_pending:
        sections.append(f"""
<div class="card">
  <p><b>Client:</b> {esc(item.get('client_id'))}<br>
     <b>Redirect:</b> {esc(item.get('redirect_uri'))}<br>
     <b>Scope:</b> {esc(', '.join(item.get('scopes') or []))}<br>
     <b>Expires:</b> {esc(_fmt_time(item.get('expires_at', 0)))}</p>
  <form method="post" action="/approvals/oauth/approve" style="display:inline">
    <input type="hidden" name="csrf_token" value="{esc(csrf)}">
    <input type="hidden" name="request_id" value="{esc(item.get('request_id'))}">
    <button type="submit">Approve once</button>
  </form>
  <form method="post" action="/approvals/oauth/deny" style="display:inline">
    <input type="hidden" name="csrf_token" value="{esc(csrf)}">
    <input type="hidden" name="request_id" value="{esc(item.get('request_id'))}">
    <button type="submit">Deny</button>
  </form>
</div>
""")

    sections.append("<h2>Pending operator-session requests</h2>")
    if not session_pending:
        sections.append("<p><em>None.</em></p>")
    for item in session_pending:
        policy = item.get("resolved_policy") or {}
        sections.append(f"""
<div class="card">
  <p><b>Policy template:</b> {esc(item.get('policy_template'))}<br>
     <b>Readable roots:</b> {esc(', '.join(policy.get('readable_roots') or []))}<br>
     <b>Writable roots:</b> {esc(', '.join(policy.get('writable_roots') or []))}<br>
     <b>Verbs:</b> {esc(json.dumps(policy.get('verbs') or {}))}<br>
     <b>Requested duration:</b> {esc(item.get('requested_duration_seconds'))}s<br>
     <b>Reason:</b> {esc(item.get('reason'))}<br>
     <b>Expires:</b> {esc(_fmt_time(item.get('expires_at', 0)))}</p>
  <form method="post" action="/approvals/session/approve" style="display:inline">
    <input type="hidden" name="csrf_token" value="{esc(csrf)}">
    <input type="hidden" name="request_id" value="{esc(item.get('request_id'))}">
    <button type="submit">Approve</button>
  </form>
  <form method="post" action="/approvals/session/deny" style="display:inline">
    <input type="hidden" name="csrf_token" value="{esc(csrf)}">
    <input type="hidden" name="request_id" value="{esc(item.get('request_id'))}">
    <button type="submit">Deny</button>
  </form>
</div>
""")

    sections.append("<h2>Pending session-extension requests</h2>")
    if not extension_pending:
        sections.append("<p><em>None.</em></p>")
    for item in extension_pending:
        sections.append(f"""
<div class="card">
  <p><b>Session:</b> {esc(item.get('session_id'))}<br>
     <b>Requested extension:</b> {esc(item.get('requested_seconds'))}s</p>
  <form method="post" action="/approvals/extension/approve" style="display:inline">
    <input type="hidden" name="csrf_token" value="{esc(csrf)}">
    <input type="hidden" name="request_id" value="{esc(item.get('request_id'))}">
    <button type="submit">Approve 30 minutes</button>
  </form>
  <form method="post" action="/approvals/extension/deny" style="display:inline">
    <input type="hidden" name="csrf_token" value="{esc(csrf)}">
    <input type="hidden" name="request_id" value="{esc(item.get('request_id'))}">
    <button type="submit">Deny</button>
  </form>
</div>
""")

    sections.append("<h2>Recent audit records</h2><table><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Source</th></tr>")
    for record in audit_records[:20]:
        sections.append(
            f"<tr><td>{esc(record.get('timestamp'))}</td><td>{esc(record.get('tool'))}</td>"
            f"<td>{esc(record.get('decision') or record.get('success'))}</td>"
            f"<td>{esc(record.get('approval_source') or '')}</td></tr>"
        )
    sections.append("</table>")

    body = "\n".join(sections)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Hermes Approvals</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 900px; }}
.card {{ border: 1px solid #ccc; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.75rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 4px 8px; font-size: 0.85em; text-align: left; }}
button {{ margin-right: 0.5rem; }}
</style>
</head>
<body>
<h1>Hermes Approvals</h1>
<p>Local-only approval centre for Hermes Operator. Never shows secret values.</p>
<input type="hidden" id="page-csrf-token" value="{esc(csrf)}">
{body}
</body></html>"""


async def approvals_page(request: Request):
    return HTMLResponse(_render_page(), headers={"Cache-Control": "no-store"})


async def _handle_decision(request: Request, *, resource: str, decision: str):
    form = await request.form()
    csrf_token = str(form.get("csrf_token", ""))
    request_id = str(form.get("request_id", ""))
    if not _consume_csrf_token(csrf_token):
        return PlainTextResponse("Invalid or expired form submission. Reload the page and try again.", status_code=400)
    if not request_id:
        return PlainTextResponse("request_id is required.", status_code=400)

    try:
        if resource == "oauth":
            provider = _oauth_provider()
            if decision == "approve":
                provider.approve_request(request_id, decided_by="localhost")
            else:
                provider.deny_request(request_id, decided_by="localhost")
        elif resource == "session":
            if decision == "approve":
                op_sessions.approve_session_request(request_id, decided_by="localhost")
            else:
                op_sessions.deny_session_request(request_id, decided_by="localhost")
        elif resource == "extension":
            if decision == "approve":
                op_sessions.approve_extension(request_id, decided_by="localhost")
            else:
                op_sessions.deny_extension(request_id, decided_by="localhost")
    except Exception as exc:
        return PlainTextResponse(f"Could not process decision: {exc}", status_code=400)

    return RedirectResponse("/approvals", status_code=303)


async def oauth_approve(request: Request):
    return await _handle_decision(request, resource="oauth", decision="approve")


async def oauth_deny(request: Request):
    return await _handle_decision(request, resource="oauth", decision="deny")


async def session_approve(request: Request):
    return await _handle_decision(request, resource="session", decision="approve")


async def session_deny(request: Request):
    return await _handle_decision(request, resource="session", decision="deny")


async def extension_approve(request: Request):
    return await _handle_decision(request, resource="extension", decision="approve")


async def extension_deny(request: Request):
    return await _handle_decision(request, resource="extension", decision="deny")


def _infer_request_type(request_id: str) -> str:
    if request_id.startswith("sr_"):
        return "session"
    if request_id.startswith("ext_"):
        return "extension"
    return "oauth"


async def telegram_resolve(request: Request):
    """Called only by the Hermes Agent Telegram adapter after it has already
    authorized the caller against its own TELEGRAM_ALLOWED_USERS allowlist.
    This endpoint independently re-verifies the request still exists and is
    still pending -- it never trusts the caller_id alone as authorization,
    since that check already happened on the Telegram side."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"success": False, "message": "Invalid request body."}, status_code=400)
    request_id = str(body.get("request_id", "")).strip()
    decision = str(body.get("decision", "")).strip()
    caller_id = str(body.get("caller_id", "")).strip()
    if not request_id or decision not in {"approve", "deny"}:
        return JSONResponse({"success": False, "message": "request_id and decision are required."}, status_code=400)

    request_type = _infer_request_type(request_id)
    source = f"telegram:{caller_id}" if caller_id else "telegram"
    try:
        if request_type == "oauth":
            provider = _oauth_provider()
            if decision == "approve":
                provider.approve_request(request_id, decided_by=source)
                message = "Hermes Operator connection approved."
            else:
                provider.deny_request(request_id, decided_by=source)
                message = "Hermes Operator connection denied."
        elif request_type == "session":
            if decision == "approve":
                record = op_sessions.approve_session_request(request_id, decided_by=source)
                message = f"Operator session approved (expires {_fmt_time(record.expires_at)})."
            else:
                op_sessions.deny_session_request(request_id, decided_by=source)
                message = "Operator session request denied."
        else:
            if decision == "approve":
                record = op_sessions.approve_extension(request_id, decided_by=source)
                message = f"Session extension approved (new expiry {_fmt_time(record.expires_at)})."
            else:
                op_sessions.deny_extension(request_id, decided_by=source)
                message = "Session extension denied."
    except Exception as exc:
        return JSONResponse({"success": False, "message": f"Could not process: {exc}"}, status_code=400)

    return JSONResponse({"success": True, "message": message})


async def healthz(request: Request):
    return PlainTextResponse("ok")


async def notify(request: Request):
    """Internal-only: the internet-facing chatgpt-operator connector calls
    this instead of sending Telegram messages itself, so the bot token never
    transits that internet-facing process. Loopback-bound like every other
    route here; no additional secret is required since only this machine's
    own operator service ever has a reason to call it."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"success": False}, status_code=400)
    request_type = str(body.get("request_type", ""))
    request_id = str(body.get("request_id", ""))
    details = body.get("details") or {}
    if not request_type or not request_id or not isinstance(details, dict):
        return JSONResponse({"success": False}, status_code=400)
    import operator_approval_notify as approval_notify

    sent = approval_notify.notify_pending_request(request_type, request_id, details)
    return JSONResponse({"success": bool(sent)})


app = Starlette(
    routes=[
        Route("/approvals", approvals_page, methods=["GET"]),
        Route("/approvals/oauth/approve", oauth_approve, methods=["POST"]),
        Route("/approvals/oauth/deny", oauth_deny, methods=["POST"]),
        Route("/approvals/session/approve", session_approve, methods=["POST"]),
        Route("/approvals/session/deny", session_deny, methods=["POST"]),
        Route("/approvals/extension/approve", extension_approve, methods=["POST"]),
        Route("/approvals/extension/deny", extension_deny, methods=["POST"]),
        Route("/telegram-resolve", telegram_resolve, methods=["POST"]),
        Route("/notify", notify, methods=["POST"]),
        Route("/healthz", healthz, methods=["GET"]),
    ]
)


def main() -> None:
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Hermes Operator localhost approval centre.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7690)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("The approval centre must bind to loopback only.")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
