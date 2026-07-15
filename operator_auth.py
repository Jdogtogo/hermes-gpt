"""Persistent OAuth 2.1 authorization for the remote Hermes-GPT MCP server.

The module uses the authentication interfaces shipped with MCP Python SDK v1.
It is intentionally single-user, but implements the protocol pieces expected by
remote MCP clients: dynamic public-client registration, authorization code with
PKCE, refresh-token rotation, bearer-token verification, revocation, and RFC
9728 protected-resource discovery through FastMCP.

Secrets are never accepted through MCP tools or service command lines. A local
bootstrap creates a mode-0600 credential record containing a scrypt password
hash and an independent HMAC pepper used to hash OAuth state and tokens before
SQLite persistence.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

from pydantic import AnyHttpUrl, AnyUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken


AUTH_ENABLED_ENV = "HERMES_GPT_AUTH_ENABLED"
AUTH_ISSUER_URL_ENV = "HERMES_GPT_AUTH_ISSUER_URL"
AUTH_RESOURCE_URL_ENV = "HERMES_GPT_AUTH_RESOURCE_URL"
AUTH_ROOT_ENV = "HERMES_GPT_AUTH_ROOT"
AUTH_SCOPE_ENV = "HERMES_GPT_AUTH_SCOPE"
AUTH_USERNAME_ENV = "HERMES_GPT_AUTH_USERNAME"

# When set, the login page shows no password form at all. Instead, ChatGPT's
# authorization request is recorded as a pending approval that only a local
# CLI (or, if wired up separately, a private Telegram approval channel) can
# approve or deny. The browser polls for the decision. This is additive and
# gated: local-owner never sets this env var, so its password-based login is
# completely unaffected.
AUTH_APPROVAL_MODE_ENV = "HERMES_GPT_AUTH_APPROVAL_MODE"

DEFAULT_AUTH_ROOT = Path.home() / ".hermes" / "auth" / "hermes-gpt"
DEFAULT_SCOPE = "hermes:operator"
DEFAULT_USERNAME = "justin"

_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_MAX_FORM_BYTES = 16_384
_LOGIN_WINDOW_SECONDS = 15 * 60
_MAX_LOGIN_FAILURES = 10
_MAX_PENDING_PER_CLIENT = 5


@dataclass(frozen=True)
class AuthRuntimeConfig:
    issuer_url: str
    resource_server_url: str
    scope: str
    root: Path
    username: str = DEFAULT_USERNAME
    authorization_ttl: int = 10 * 60
    code_ttl: int = 5 * 60
    access_ttl: int = 60 * 60
    refresh_ttl: int = 30 * 24 * 60 * 60
    approval_mode: bool = False

    @property
    def db_path(self) -> Path:
        return self.root / "oauth.sqlite3"

    @property
    def credential_path(self) -> Path:
        return self.root / "credentials.json"

    @property
    def initial_login_path(self) -> Path:
        return self.root / "initial-login.txt"

    @classmethod
    def from_env(cls) -> "AuthRuntimeConfig":
        issuer = _validate_https_origin(os.environ.get(AUTH_ISSUER_URL_ENV, ""), AUTH_ISSUER_URL_ENV)
        resource = _validate_https_origin(
            os.environ.get(AUTH_RESOURCE_URL_ENV, issuer), AUTH_RESOURCE_URL_ENV
        )
        scope = os.environ.get(AUTH_SCOPE_ENV, DEFAULT_SCOPE).strip()
        if not scope or any(ch.isspace() for ch in scope):
            raise ValueError(f"{AUTH_SCOPE_ENV} must contain one non-empty scope token.")
        username = os.environ.get(AUTH_USERNAME_ENV, DEFAULT_USERNAME).strip()
        if not username or len(username) > 128:
            raise ValueError(f"{AUTH_USERNAME_ENV} must be a non-empty username.")
        root = Path(os.environ.get(AUTH_ROOT_ENV, str(DEFAULT_AUTH_ROOT))).expanduser().resolve()
        approval_mode = os.environ.get(AUTH_APPROVAL_MODE_ENV, "").strip().lower() in {
            "1", "true", "yes", "on", "enabled",
        }
        return cls(
            issuer_url=issuer,
            resource_server_url=resource,
            scope=scope,
            root=root,
            username=username,
            approval_mode=approval_mode,
        )


def auth_enabled() -> bool:
    return os.environ.get(AUTH_ENABLED_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
        "enabled",
    }


def _validate_https_origin(value: str, variable: str) -> str:
    raw = (value or "").strip().rstrip("/")
    if not raw:
        raise ValueError(f"{variable} is required when OAuth is enabled.")
    parsed = urlparse(raw)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(f"{variable} must be an absolute HTTPS origin.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{variable} must not contain credentials, query, or fragment.")
    return raw


def _origin_of_url(value: str) -> str:
    """Return ``scheme://host[:port]`` for a URL, or "" if it cannot be parsed."""
    parsed = urlparse((value or "").strip())
    if not parsed.scheme or not parsed.hostname:
        return ""
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        origin = f"{origin}:{parsed.port}"
    return origin


def _secure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _atomic_secret_write(path: Path, text: str) -> None:
    _secure_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _derive_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=128 * 1024 * 1024,
    )


def bootstrap_credentials(config: AuthRuntimeConfig, *, force: bool = False) -> dict[str, Any]:
    """Create a local one-time login credential without returning the password."""
    _secure_directory(config.root)
    if config.credential_path.exists() and not force:
        return {
            "created": False,
            "credential_path": str(config.credential_path),
            "initial_login_path": str(config.initial_login_path),
        }

    password = secrets.token_urlsafe(32)
    salt = os.urandom(16)
    verifier = _derive_password(password, salt)
    payload = {
        "version": 1,
        "username": config.username,
        "salt_hex": salt.hex(),
        "password_hash_hex": verifier.hex(),
        "token_pepper_hex": os.urandom(32).hex(),
        "created_at": int(time.time()),
    }
    _atomic_secret_write(
        config.credential_path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )
    _atomic_secret_write(
        config.initial_login_path,
        (
            "Hermes-GPT OAuth initial login\n"
            f"username: {config.username}\n"
            f"password: {password}\n"
            "Store this password in your password manager, then delete this file.\n"
        ),
    )
    return {
        "created": True,
        "credential_path": str(config.credential_path),
        "initial_login_path": str(config.initial_login_path),
    }


class CredentialStore:
    def __init__(self, path: Path):
        self.path = path
        self._validate_permissions()
        self._payload = self._load()

    def _validate_permissions(self) -> None:
        if not self.path.is_file():
            raise FileNotFoundError(
                f"OAuth credentials are missing at {self.path}. Run the local auth bootstrap first."
            )
        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode & 0o077:
            raise PermissionError("OAuth credential file must not be accessible by group or others.")

    def _load(self) -> dict[str, Any]:
        value = json.loads(self.path.read_text(encoding="utf-8"))
        required = {"username", "salt_hex", "password_hash_hex", "token_pepper_hex"}
        if not isinstance(value, dict) or not required.issubset(value):
            raise ValueError("OAuth credential file is malformed.")
        return value

    @property
    def username(self) -> str:
        return str(self._payload["username"])

    @property
    def pepper(self) -> bytes:
        return bytes.fromhex(str(self._payload["token_pepper_hex"]))

    def verify(self, username: str, password: str) -> bool:
        username_ok = hmac.compare_digest(username.encode("utf-8"), self.username.encode("utf-8"))
        try:
            candidate = _derive_password(password, bytes.fromhex(str(self._payload["salt_hex"])))
            expected = bytes.fromhex(str(self._payload["password_hash_hex"]))
        except (ValueError, TypeError):
            return False
        return username_ok and hmac.compare_digest(candidate, expected)


class PersistentOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """Single-user OAuth provider with persistent, hashed token storage."""

    def __init__(self, config: AuthRuntimeConfig):
        self.config = config
        self.credentials = CredentialStore(config.credential_path)
        self._lock = threading.RLock()
        _secure_directory(config.root)
        self._initialize_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.config.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_db(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending_auth (
                    state_hash TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_codes (
                    code_hash TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS access_tokens (
                    token_hash TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    family_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token_hash TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    family_id TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    rate_key TEXT NOT NULL,
                    attempted_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approved_authorizations (
                    state_hash TEXT PRIMARY KEY,
                    redirect_url TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_login_attempts_key_time
                    ON login_attempts(rate_key, attempted_at);
                CREATE INDEX IF NOT EXISTS idx_access_family
                    ON access_tokens(family_id);
                CREATE INDEX IF NOT EXISTS idx_refresh_family
                    ON refresh_tokens(family_id);
                """
            )
            # Additive migration for approval-mode support. request_id is a
            # short, human-typeable identifier separate from the (long,
            # security-sensitive) login state, so a local operator can
            # reference a pending request without ever seeing the state
            # value. status distinguishes pending/approved/denied.
            existing_cols = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(pending_auth)").fetchall()
            }
            if "request_id" not in existing_cols:
                connection.execute("ALTER TABLE pending_auth ADD COLUMN request_id TEXT")
            if "status" not in existing_cols:
                connection.execute(
                    "ALTER TABLE pending_auth ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_pending_auth_request_id ON pending_auth(request_id)"
            )
        os.chmod(self.config.db_path, 0o600)

    def _digest(self, value: str) -> str:
        return hmac.new(self.credentials.pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _cleanup(self, connection: sqlite3.Connection) -> None:
        now = int(time.time())
        connection.execute("DELETE FROM pending_auth WHERE expires_at < ?", (now,))
        connection.execute("DELETE FROM auth_codes WHERE expires_at < ? OR used = 1", (now,))
        connection.execute("DELETE FROM access_tokens WHERE expires_at < ?", (now,))
        connection.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now,))
        connection.execute("DELETE FROM approved_authorizations WHERE expires_at < ?", (now,))
        connection.execute(
            "DELETE FROM login_attempts WHERE attempted_at < ?",
            (now - _LOGIN_WINDOW_SECONDS, ),
        )

    def _validate_redirect_uri(self, value: AnyUrl) -> None:
        parsed = urlparse(str(value))
        loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="Redirect URIs must use HTTPS, except for loopback HTTP callbacks.",
            )
        if parsed.username or parsed.password or parsed.fragment:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="Redirect URIs must not contain credentials or fragments.",
            )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT data FROM clients WHERE client_id = ?", (client_id,)
            ).fetchone()
        if row is None:
            return None
        return OAuthClientInformationFull.model_validate_json(row["data"])

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            raise RegistrationError(
                error="invalid_client_metadata", error_description="client_id is required."
            )
        if client_info.token_endpoint_auth_method != "none" or client_info.client_secret:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Only public OAuth clients using PKCE are accepted.",
            )
        if not client_info.redirect_uris:
            raise RegistrationError(
                error="invalid_redirect_uri", error_description="At least one redirect URI is required."
            )
        for redirect_uri in client_info.redirect_uris:
            self._validate_redirect_uri(redirect_uri)
        requested_scopes = set((client_info.scope or "").split())
        if requested_scopes and requested_scopes != {self.config.scope}:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="The client requested an unsupported scope.",
            )
        data = client_info.model_dump_json(exclude_none=True)
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO clients(client_id, data, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(client_id) DO UPDATE SET data=excluded.data",
                (client_info.client_id, data, int(time.time())),
            )

    def _normalize_resource(self, resource: str | None) -> str:
        value = (resource or self.config.resource_server_url).rstrip("/")
        if value != self.config.resource_server_url.rstrip("/"):
            raise AuthorizeError(
                error="invalid_request",
                error_description="The requested OAuth resource does not match this MCP server.",
            )
        return self.config.resource_server_url

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not client.client_id:
            raise AuthorizeError(error="invalid_request", error_description="client_id is missing.")
        requested_scopes = params.scopes or [self.config.scope]
        if set(requested_scopes) != {self.config.scope}:
            raise AuthorizeError(error="invalid_scope", error_description="Unsupported OAuth scope.")
        resource = self._normalize_resource(params.resource)
        login_state = secrets.token_urlsafe(32)
        request_id = secrets.token_hex(4)
        payload = {
            "client_id": client.client_id,
            "client_state": params.state,
            "scopes": requested_scopes,
            "code_challenge": params.code_challenge,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "resource": resource,
        }
        expires_at = int(time.time()) + self.config.authorization_ttl
        with self._lock, self._connect() as connection:
            self._cleanup(connection)
            if self.config.approval_mode:
                pending_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM pending_auth WHERE status = 'pending'"
                ).fetchone()["count"]
                if pending_count >= _MAX_PENDING_PER_CLIENT:
                    raise AuthorizeError(
                        error="temporarily_unavailable",
                        error_description="Too many pending authorization requests. Try again shortly.",
                    )
            connection.execute(
                "INSERT INTO pending_auth(state_hash, data, expires_at, request_id, status) "
                "VALUES (?, ?, ?, ?, 'pending')",
                (self._digest(login_state), json.dumps(payload, sort_keys=True), expires_at, request_id),
            )
        if self.config.approval_mode:
            self._notify_pending_oauth_request(request_id, payload, expires_at)
        return f"{self.config.issuer_url}/login?state={quote(login_state, safe='')}"

    def _notify_pending_oauth_request(self, request_id: str, payload: dict[str, Any], expires_at: int) -> None:
        """Best-effort: tell a human a new connection request is waiting.
        Never raises, never blocks authorize().

        Forwards to the localhost-only approval centre (127.0.0.1:7690)
        rather than sending Telegram messages directly from this process --
        this is the internet-facing OAuth connector, so it must never hold
        the Telegram bot token. Only the loopback-bound approval centre does."""
        try:
            import httpx

            redirect_domain = urlparse(str(payload.get("redirect_uri", ""))).hostname or ""
            httpx.post(
                "http://127.0.0.1:7690/notify",
                json={
                    "request_type": "oauth",
                    "request_id": request_id,
                    "details": {
                        "client_id": payload.get("client_id"),
                        "redirect_domain": redirect_domain,
                        "scope": " ".join(payload.get("scopes") or []),
                        "expires_at": expires_at,
                    },
                },
                timeout=3.0,
            )
        except Exception:
            pass

    def _load_pending(self, state: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as connection:
            self._cleanup(connection)
            row = connection.execute(
                "SELECT data, expires_at FROM pending_auth WHERE state_hash = ?",
                (self._digest(state),),
            ).fetchone()
        if row is None or int(row["expires_at"]) < int(time.time()):
            return None
        return json.loads(row["data"])

    def _consume_pending(self, state: str) -> dict[str, Any] | None:
        digest = self._digest(state)
        now = int(time.time())
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT data, expires_at FROM pending_auth WHERE state_hash = ?",
                (digest,),
            ).fetchone()
            if row is None or int(row["expires_at"]) < now:
                connection.execute("DELETE FROM pending_auth WHERE state_hash = ?", (digest,))
                connection.commit()
                return None
            connection.execute("DELETE FROM pending_auth WHERE state_hash = ?", (digest,))
            connection.commit()
        return json.loads(row["data"])

    def _rate_key(self, request: Request, username: str) -> str:
        source = request.headers.get("cf-connecting-ip")
        if not source and request.client:
            source = request.client.host
        return self._digest(f"{source or 'unknown'}|{username.lower()}")

    def _login_is_rate_limited(self, rate_key: str) -> bool:
        threshold = int(time.time()) - _LOGIN_WINDOW_SECONDS
        with self._lock, self._connect() as connection:
            self._cleanup(connection)
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM login_attempts "
                "WHERE rate_key = ? AND attempted_at >= ?",
                (rate_key, threshold),
            ).fetchone()
        return bool(row and int(row["count"]) >= _MAX_LOGIN_FAILURES)

    def _record_login_failure(self, rate_key: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO login_attempts(rate_key, attempted_at) VALUES (?, ?)",
                (rate_key, int(time.time())),
            )

    def _clear_login_failures(self, rate_key: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("DELETE FROM login_attempts WHERE rate_key = ?", (rate_key,))

    def login_page(self, state: str) -> HTMLResponse:
        pending = self._load_pending(state) if state else None
        if pending is None:
            return HTMLResponse("Invalid or expired authorization request.", status_code=400)
        escaped_state = html.escape(state, quote=True)
        # A successful login redirects (302) to the OAuth client's registered
        # redirect_uri, which is cross-origin (e.g. ChatGPT). Browsers enforce
        # form-action across that redirect, so the client's callback origin must
        # be allowlisted or the redirect is blocked and the code never reaches
        # the client. The redirect_uri was validated at registration/authorize.
        redirect_origin = _origin_of_url(str(pending.get("redirect_uri", "")))
        form_action = f"'self' {redirect_origin}" if redirect_origin else "'self'"

        if self.config.approval_mode:
            # No password form. The request is already pending (created in
            # authorize()); this page just polls until a local operator (or
            # a private approval channel wired to approve_request/
            # deny_request) decides it.
            # default-src 'none' blocks the inline polling <script> outright
            # unless script-src explicitly allows it. There is no untrusted
            # or user-reflected content on this page (state is rendered via
            # json.dumps, and is itself just an opaque token), so allowing
            # inline script here does not reopen an XSS hole — it's what
            # actually lets the "waiting" page complete the flow.
            csp = (
                f"default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; "
                f"form-action {form_action}; base-uri 'none'; frame-ancestors 'none'"
            )
            content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize Hermes-GPT</title></head>
<body><main>
<h1>Waiting for approval on your Hermes device</h1>
<p id="status">No password is required here. Approve or deny this request locally, then this page will continue automatically.</p>
<form id="redirect-form" method="get" action="" style="display:none"></form>
<script>
(function() {{
  var state = {json.dumps(state)};
  function poll() {{
    fetch('/login/poll?state=' + encodeURIComponent(state), {{cache: 'no-store'}})
      .then(function(r) {{ return r.json(); }})
      .then(function(data) {{
        if (data.status === 'approved' && data.redirect) {{
          window.location.replace(data.redirect);
        }} else if (data.status === 'denied') {{
          document.getElementById('status').textContent = 'This authorization request was denied.';
        }} else if (data.status === 'expired') {{
          document.getElementById('status').textContent = 'This authorization request has expired. Please reconnect from ChatGPT.';
        }} else {{
          setTimeout(poll, 2000);
        }}
      }})
      .catch(function() {{ setTimeout(poll, 3000); }});
  }}
  poll();
}})();
</script>
</main></body></html>"""
            return HTMLResponse(
                content,
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                    "Content-Security-Policy": csp,
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                },
            )

        action = html.escape(f"{self.config.issuer_url}/login/callback", quote=True)
        csp = (
            f"default-src 'none'; form-action {form_action}; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
        content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize Hermes-GPT</title></head>
<body><main><h1>Authorize Hermes-GPT</h1>
<p>Sign in to allow your MCP client to access the Hermes operator tools.</p>
<form action="{action}" method="post">
<input type="hidden" name="state" value="{escaped_state}">
<label>Username <input name="username" autocomplete="username" required></label><br>
<label>Password <input type="password" name="password" autocomplete="current-password" required></label><br>
<button type="submit">Authorize</button></form></main></body></html>"""
        return HTMLResponse(
            content,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Content-Security-Policy": csp,
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )

    def _issue_code(self, pending: dict[str, Any]) -> str:
        """Generate and persist an authorization code for an already-consumed
        pending request, returning the client redirect URL. Shared by both
        the password flow and the approval-mode flow — the only difference
        between them is what gates reaching this point."""
        code = secrets.token_urlsafe(32)
        auth_code = AuthorizationCode(
            code=code,
            scopes=list(pending["scopes"]),
            expires_at=time.time() + self.config.code_ttl,
            client_id=str(pending["client_id"]),
            code_challenge=str(pending["code_challenge"]),
            redirect_uri=AnyUrl(str(pending["redirect_uri"])),
            redirect_uri_provided_explicitly=bool(
                pending["redirect_uri_provided_explicitly"]
            ),
            resource=str(pending["resource"]),
            subject=self.credentials.username,
        )
        stored = auth_code.model_dump(mode="json", exclude={"code"})
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO auth_codes(code_hash, data, expires_at, used) VALUES (?, ?, ?, 0)",
                (
                    self._digest(code),
                    json.dumps(stored, sort_keys=True),
                    int(auth_code.expires_at),
                ),
            )
        return construct_redirect_uri(
            str(auth_code.redirect_uri),
            code=code,
            state=pending.get("client_state"),
        )

    def complete_login(self, *, username: str, password: str, state: str, request: Request) -> str:
        pending = self._load_pending(state)
        if pending is None:
            raise ValueError("Invalid or expired authorization request.")
        rate_key = self._rate_key(request, username)
        if self._login_is_rate_limited(rate_key):
            raise PermissionError("Too many failed login attempts. Try again later.")
        if not self.credentials.verify(username, password):
            self._record_login_failure(rate_key)
            raise PermissionError("Invalid username or password.")
        self._clear_login_failures(rate_key)
        pending = self._consume_pending(state)
        if pending is None:
            raise ValueError("Authorization request was already used or has expired.")
        return self._issue_code(pending)

    # --- Approval-mode (passwordless) flow ----------------------------------

    def list_pending_requests(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as connection:
            self._cleanup(connection)
            rows = connection.execute(
                "SELECT request_id, data, expires_at FROM pending_auth "
                "WHERE status = 'pending' ORDER BY expires_at"
            ).fetchall()
        out = []
        for row in rows:
            data = json.loads(row["data"])
            out.append({
                "request_id": row["request_id"],
                "client_id": data.get("client_id"),
                "redirect_uri": data.get("redirect_uri"),
                "scopes": data.get("scopes"),
                "expires_at": row["expires_at"],
            })
        return out

    def _find_pending_by_request_id(self, connection: sqlite3.Connection, request_id: str) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT state_hash, data, expires_at, status FROM pending_auth WHERE request_id = ?",
            (request_id,),
        ).fetchone()

    def approve_request(self, request_id: str, *, decided_by: str = "local-cli") -> None:
        """Local-only: approve a pending authorization request. Never callable
        by the MCP client itself — there is no HTTP route that reaches this."""
        now = int(time.time())
        state_hash: str
        pending: dict[str, Any]
        with self._lock, self._connect() as connection:
            self._cleanup(connection)
            row = self._find_pending_by_request_id(connection, request_id)
            if row is None:
                raise ValueError("Authorization request does not exist or has expired.")
            if row["status"] != "pending":
                raise ValueError(f"Authorization request already {row['status']}.")
            if int(row["expires_at"]) < now:
                raise ValueError("Authorization request has expired.")
            state_hash = row["state_hash"]
            pending = json.loads(row["data"])
            connection.execute(
                "UPDATE pending_auth SET status = 'approved' WHERE state_hash = ?", (state_hash,)
            )
        # _issue_code opens its own connection; it must run after the block
        # above has released its connection/transaction, or SQLite reports
        # "database is locked" for a same-thread nested write.
        redirect = self._issue_code(pending)
        with self._lock, self._connect() as connection:
            connection.execute(
                "INSERT INTO approved_authorizations(state_hash, redirect_url, expires_at) VALUES (?, ?, ?)",
                (state_hash, redirect, now + 120),
            )
        self._audit_approval_decision(
            request_id=request_id, decision="approved", decided_by=decided_by, pending=pending,
        )

    def deny_request(self, request_id: str, *, decided_by: str = "local-cli") -> None:
        with self._lock, self._connect() as connection:
            row = self._find_pending_by_request_id(connection, request_id)
            if row is None:
                raise ValueError("Authorization request does not exist or has expired.")
            if row["status"] != "pending":
                raise ValueError(f"Authorization request already {row['status']}.")
            pending = json.loads(row["data"])
            connection.execute(
                "UPDATE pending_auth SET status = 'denied' WHERE state_hash = ?", (row["state_hash"],)
            )
        self._audit_approval_decision(
            request_id=request_id, decision="denied", decided_by=decided_by, pending=pending,
        )

    def _audit_approval_decision(
        self, *, request_id: str, decision: str, decided_by: str, pending: dict[str, Any]
    ) -> None:
        try:
            import operator_policy as op_policy
            op_policy.audit_record(
                tool="oauth_approval",
                level="oauth",
                apply_mode="approval",
                dry_run=False,
                success=True,
                summary=f"authorization request {decision}",
                extra={
                    "request_id": request_id,
                    "decision": decision,
                    "approval_source": decided_by,
                    "oauth_client_id": pending.get("client_id"),
                },
            )
        except Exception:
            # Auditing must never block an approval/denial decision.
            pass

    def poll_status(self, state: str) -> dict[str, Any]:
        """Called by the waiting browser page. Never exposes secrets — only
        a status string and, once approved, the one-time redirect URL."""
        digest = self._digest(state)
        now = int(time.time())
        with self._lock, self._connect() as connection:
            approved = connection.execute(
                "SELECT redirect_url, expires_at FROM approved_authorizations WHERE state_hash = ?",
                (digest,),
            ).fetchone()
            if approved is not None:
                connection.execute(
                    "DELETE FROM approved_authorizations WHERE state_hash = ?", (digest,)
                )
                if int(approved["expires_at"]) < now:
                    return {"status": "expired"}
                return {"status": "approved", "redirect": approved["redirect_url"]}
            pending = connection.execute(
                "SELECT expires_at, status FROM pending_auth WHERE state_hash = ?",
                (digest,),
            ).fetchone()
        if pending is None:
            return {"status": "expired"}
        if int(pending["expires_at"]) < now:
            return {"status": "expired"}
        if pending["status"] == "denied":
            return {"status": "denied"}
        if pending["status"] == "approved":
            # The one-time redirect was already delivered and consumed above
            # (or by a previous poll) — never redeliver it.
            return {"status": "expired"}
        return {"status": "pending"}

    async def handle_login_callback(self, request: Request) -> Response:
        body = await request.body()
        if len(body) > _MAX_FORM_BYTES:
            return PlainTextResponse("Request is too large.", status_code=413)
        values = parse_qs(body.decode("utf-8", errors="strict"), keep_blank_values=True)
        username = values.get("username", [""])[0]
        password = values.get("password", [""])[0]
        state = values.get("state", [""])[0]
        if not username or not password or not state:
            return PlainTextResponse("Missing login fields.", status_code=400)
        try:
            redirect = self.complete_login(
                username=username,
                password=password,
                state=state,
                request=request,
            )
        except PermissionError as exc:
            return PlainTextResponse(str(exc), status_code=429 if "Too many" in str(exc) else 401)
        except (ValueError, UnicodeError) as exc:
            return PlainTextResponse(str(exc), status_code=400)
        return RedirectResponse(
            redirect,
            status_code=302,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        if not client.client_id:
            return None
        with self._lock, self._connect() as connection:
            self._cleanup(connection)
            row = connection.execute(
                "SELECT data, expires_at, used FROM auth_codes WHERE code_hash = ?",
                (self._digest(authorization_code),),
            ).fetchone()
        if row is None or int(row["used"]) or int(row["expires_at"]) < int(time.time()):
            return None
        data = json.loads(row["data"])
        if data.get("client_id") != client.client_id:
            return None
        return AuthorizationCode(code=authorization_code, **data)

    def _issue_token_pair(
        self,
        *,
        client_id: str,
        scopes: list[str],
        resource: str,
        subject: str | None,
        family_id: str | None = None,
        connection: sqlite3.Connection | None = None,
    ) -> OAuthToken:
        now = int(time.time())
        access_raw = secrets.token_urlsafe(48)
        refresh_raw = secrets.token_urlsafe(48)
        family = family_id or secrets.token_hex(16)
        access = AccessToken(
            token=access_raw,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + self.config.access_ttl,
            resource=resource,
            subject=subject,
        )
        refresh = RefreshToken(
            token=refresh_raw,
            client_id=client_id,
            scopes=scopes,
            expires_at=now + self.config.refresh_ttl,
            subject=subject,
        )
        access_data = access.model_dump(mode="json", exclude={"token"})
        refresh_data = {
            "refresh": refresh.model_dump(mode="json", exclude={"token"}),
            "resource": resource,
        }
        def persist(target: sqlite3.Connection) -> None:
            target.execute(
                "INSERT INTO access_tokens(token_hash, data, family_id, expires_at, revoked) "
                "VALUES (?, ?, ?, ?, 0)",
                (
                    self._digest(access_raw),
                    json.dumps(access_data, sort_keys=True),
                    family,
                    access.expires_at,
                ),
            )
            target.execute(
                "INSERT INTO refresh_tokens(token_hash, data, family_id, expires_at, revoked) "
                "VALUES (?, ?, ?, ?, 0)",
                (
                    self._digest(refresh_raw),
                    json.dumps(refresh_data, sort_keys=True),
                    family,
                    refresh.expires_at,
                ),
            )

        if connection is None:
            with self._lock, self._connect() as owned_connection:
                persist(owned_connection)
        else:
            persist(connection)
        return OAuthToken(
            access_token=access_raw,
            token_type="Bearer",
            expires_in=self.config.access_ttl,
            scope=" ".join(scopes),
            refresh_token=refresh_raw,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if not client.client_id or authorization_code.client_id != client.client_id:
            raise TokenError(error="invalid_grant", error_description="Authorization code client mismatch.")
        code_hash = self._digest(authorization_code.code)
        now = int(time.time())
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE auth_codes SET used = 1 "
                "WHERE code_hash = ? AND used = 0 AND expires_at >= ?",
                (code_hash, now),
            ).rowcount
            if changed != 1:
                connection.rollback()
                raise TokenError(
                    error="invalid_grant",
                    error_description="Authorization code is invalid, expired, or already used.",
                )
            tokens = self._issue_token_pair(
                client_id=client.client_id,
                scopes=authorization_code.scopes,
                resource=authorization_code.resource or self.config.resource_server_url,
                subject=authorization_code.subject,
                connection=connection,
            )
            connection.commit()
        return tokens

    async def load_access_token(self, token: str) -> AccessToken | None:
        with self._lock, self._connect() as connection:
            self._cleanup(connection)
            row = connection.execute(
                "SELECT data, expires_at, revoked FROM access_tokens WHERE token_hash = ?",
                (self._digest(token),),
            ).fetchone()
        if row is None or int(row["revoked"]) or int(row["expires_at"]) < int(time.time()):
            return None
        data = json.loads(row["data"])
        if str(data.get("resource", "")).rstrip("/") != self.config.resource_server_url.rstrip("/"):
            return None
        return AccessToken(token=token, **data)

    def _refresh_record(self, token: str) -> sqlite3.Row | None:
        with self._lock, self._connect() as connection:
            self._cleanup(connection)
            return connection.execute(
                "SELECT data, family_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?",
                (self._digest(token),),
            ).fetchone()

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        if not client.client_id:
            return None
        row = self._refresh_record(refresh_token)
        if row is None or int(row["revoked"]) or int(row["expires_at"]) < int(time.time()):
            return None
        data = json.loads(row["data"])["refresh"]
        if data.get("client_id") != client.client_id:
            return None
        return RefreshToken(token=refresh_token, **data)

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        if not client.client_id or refresh_token.client_id != client.client_id:
            raise TokenError(error="invalid_grant", error_description="Refresh token client mismatch.")
        digest = self._digest(refresh_token.token)
        now = int(time.time())
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT data, family_id, expires_at, revoked FROM refresh_tokens "
                "WHERE token_hash = ?",
                (digest,),
            ).fetchone()
            if row is None or int(row["revoked"]) or int(row["expires_at"]) < now:
                connection.rollback()
                raise TokenError(
                    error="invalid_grant",
                    error_description="Refresh token is invalid, expired, or already used.",
                )
            wrapper = json.loads(row["data"])
            original_scopes = list(wrapper["refresh"]["scopes"])
            requested_scopes = scopes or original_scopes
            if not set(requested_scopes).issubset(set(original_scopes)):
                connection.rollback()
                raise TokenError(
                    error="invalid_scope",
                    error_description="Requested scope exceeds the original grant.",
                )
            family_id = str(row["family_id"])
            changed = connection.execute(
                "UPDATE refresh_tokens SET revoked = 1 "
                "WHERE token_hash = ? AND revoked = 0 AND expires_at >= ?",
                (digest, now),
            ).rowcount
            if changed != 1:
                connection.rollback()
                raise TokenError(
                    error="invalid_grant",
                    error_description="Refresh token was already rotated.",
                )
            connection.execute(
                "UPDATE access_tokens SET revoked = 1 WHERE family_id = ?", (family_id,)
            )
            connection.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?", (family_id,)
            )
            tokens = self._issue_token_pair(
                client_id=client.client_id,
                scopes=requested_scopes,
                resource=str(wrapper["resource"]),
                subject=refresh_token.subject,
                family_id=family_id,
                connection=connection,
            )
            connection.commit()
        return tokens

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        raw = token.token
        digest = self._digest(raw)
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT family_id FROM access_tokens WHERE token_hash = ? "
                "UNION SELECT family_id FROM refresh_tokens WHERE token_hash = ?",
                (digest, digest),
            ).fetchone()
            if row is None:
                return
            family_id = str(row["family_id"])
            connection.execute(
                "UPDATE access_tokens SET revoked = 1 WHERE family_id = ?", (family_id,)
            )
            connection.execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?", (family_id,)
            )

    def auth_settings(self) -> AuthSettings:
        return AuthSettings(
            issuer_url=AnyHttpUrl(self.config.issuer_url),
            resource_server_url=AnyHttpUrl(self.config.resource_server_url),
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=[self.config.scope],
                default_scopes=[self.config.scope],
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=[self.config.scope],
        )


def register_login_routes(server: Any, provider: PersistentOAuthProvider) -> None:
    @server.custom_route("/login", methods=["GET"], include_in_schema=False)
    async def login_page(request: Request) -> Response:
        return provider.login_page(request.query_params.get("state", ""))

    @server.custom_route("/login/callback", methods=["POST"], include_in_schema=False)
    async def login_callback(request: Request) -> Response:
        return await provider.handle_login_callback(request)

    @server.custom_route("/login/poll", methods=["GET"], include_in_schema=False)
    async def login_poll(request: Request) -> Response:
        state = request.query_params.get("state", "")
        if not state:
            return JSONResponse({"status": "expired"}, status_code=400)
        result = provider.poll_status(state)
        return JSONResponse(result, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    @server.custom_route("/health/auth", methods=["GET"], include_in_schema=False)
    async def auth_health(_: Request) -> Response:
        return PlainTextResponse("oauth-enabled", headers={"Cache-Control": "no-store"})


def _cli() -> None:
    """Local-only OAuth approval administration. Never expose this as a
    remote MCP tool or HTTP route: approval must stay a human, local (or
    private-channel) action, never something the remote client can invoke
    on itself."""
    import argparse

    parser = argparse.ArgumentParser(description="Hermes-GPT OAuth approval admin (local only).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list-pending", help="List pending authorization requests.")
    approve = sub.add_parser("approve", help="Approve a pending authorization request.")
    approve.add_argument("request_id")
    approve.add_argument("--source", default="local-cli", help="Approval source for the audit log.")
    deny = sub.add_parser("deny", help="Deny a pending authorization request.")
    deny.add_argument("request_id")
    deny.add_argument("--source", default="local-cli", help="Denial source for the audit log.")
    args = parser.parse_args()

    config = AuthRuntimeConfig.from_env()
    provider = PersistentOAuthProvider(config)

    if args.cmd == "list-pending":
        print(json.dumps(provider.list_pending_requests(), indent=2))
    elif args.cmd == "approve":
        provider.approve_request(args.request_id, decided_by=args.source)
        print(json.dumps({"approved": args.request_id}, indent=2))
    elif args.cmd == "deny":
        provider.deny_request(args.request_id, decided_by=args.source)
        print(json.dumps({"denied": args.request_id}, indent=2))


if __name__ == "__main__":
    _cli()
