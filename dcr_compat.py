"""Dynamic Client Registration compatibility for public PKCE clients.

Some MCP clients (notably ChatGPT) send ``token_endpoint_auth_method`` =
``"client_secret_post"`` in their RFC 7591 registration request even though they
authenticate as *public* clients using PKCE and never present a client secret.
The upstream MCP SDK registration handler reacts to any non-``none`` method by
minting a ``client_secret`` and marking the client confidential
(``mcp/server/auth/handlers/register.py``). This single-user server only issues
public PKCE clients, so :meth:`operator_auth.PersistentOAuthProvider.register_client`
then rejects it with "Only public OAuth clients using PKCE are accepted."

RFC 7591 section 2 makes ``token_endpoint_auth_method`` a *requested* value and
section 3.2.1 explicitly allows the authorization server to replace requested
client metadata with values it deems appropriate. This ASGI shim normalizes the
requested method to ``"none"`` for ``POST /register`` **only when the request
carries no client secret material** — i.e. when the client is unambiguously
public. The SDK then registers a public client and issues no secret. PKCE is
still enforced later at ``/authorize`` (S256 ``code_challenge``) and ``/token``
(matching ``code_verifier``); redirect-URI validation, scope enforcement and
bearer-token protection of ``/mcp`` are untouched — this shim only ever rewrites
one field of the registration request body and passes every other request
through verbatim.
"""

from __future__ import annotations

import json
import logging

_REGISTER_PATH = "/register"
_CONFIDENTIAL_METHODS = frozenset(
    {"client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt"}
)

logger = logging.getLogger("hermes.dcr")


def _should_normalize(body: object) -> bool:
    """True when the registration body describes an unambiguously public client.

    A registration request that supplies a ``client_secret`` is treated as a
    genuine confidential-client attempt and left untouched (the provider will
    reject it). Otherwise an omitted method — which the SDK would upgrade to
    ``client_secret_post`` — or an explicitly confidential method is normalized
    to ``none``.
    """
    if not isinstance(body, dict):
        return False
    if "client_secret" in body:
        return False
    method = body.get("token_endpoint_auth_method")
    return method is None or method in _CONFIDENTIAL_METHODS


def normalize_public_client_registration(app):
    """Wrap an ASGI ``app`` to register public PKCE clients on ``POST /register``."""

    async def wrapped(scope, receive, send):
        if not (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and scope.get("path", "").rstrip("/") == _REGISTER_PATH
        ):
            await app(scope, receive, send)
            return

        # Buffer the request body so we can inspect and optionally rewrite it.
        body = b""
        while True:
            message = await receive()
            if message["type"] != "http.request":
                # Unexpected (e.g. disconnect): forward original and stop.
                await app(scope, _single_message_receiver(message, receive), send)
                return
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break

        new_body = body
        try:
            parsed = json.loads(body or b"{}")
            if _should_normalize(parsed) and parsed.get("token_endpoint_auth_method") != "none":
                parsed["token_endpoint_auth_method"] = "none"
                new_body = json.dumps(parsed).encode("utf-8")
                logger.info(
                    "Normalized DCR registration to a public PKCE client "
                    "(token_endpoint_auth_method=none)."
                )
        except (ValueError, TypeError):
            # Not JSON we understand; forward the original body unchanged so the
            # SDK returns its own standards-compliant error.
            new_body = body

        send_scope = scope
        if new_body is not body:
            headers = [
                (k, v) for (k, v) in scope.get("headers", []) if k.lower() != b"content-length"
            ]
            headers.append((b"content-length", str(len(new_body)).encode("ascii")))
            send_scope = dict(scope)
            send_scope["headers"] = headers

        await app(send_scope, _body_receiver(new_body), send)

    return wrapped


def _body_receiver(body: bytes):
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


def _single_message_receiver(first, downstream):
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return first
        return await downstream()

    return receive
