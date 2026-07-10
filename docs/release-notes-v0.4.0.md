# hermes-gpt v0.4.0

Release date: 2026-07-11

## Asynchronous Hermes file bridge

This release adds an authenticated command-and-report bridge between a remote MCP supervisor and the local Hermes Agent.

### New MCP tools

- `bridge_status`
- `bridge_read`
- `bridge_submit_command`
- `bridge_read_result`
- `bridge_write_adjudication`

### Local worker

The new worker consumes one queued command at a time and invokes Hermes through the existing `operator_agent` local stdio execution path. It records success or escalation in `bridge.md`, persists state in `state.json`, and archives every attempt.

Safety controls include:

- explicit bridge enablement;
- absolute allowlisted command working directories;
- atomic mailbox and state writes;
- immutable command identifiers;
- duplicate and concurrent execution prevention;
- bounded Hermes turns and timeout;
- stale-running recovery without automatic replay;
- adjudicated retries that include the binding verdict;
- audit records with prompt hashing rather than raw prompt logging.

## OAuth 2.1 protection

Remote HTTP/SSE bridge activation now fails closed unless OAuth is enabled.

The implementation uses the MCP Python SDK v1 authorization interfaces and provides:

- OAuth protected-resource metadata;
- authorization-server discovery;
- dynamic public-client registration;
- authorization-code flow with PKCE S256;
- a local single-user authorization page;
- one-time authorization codes;
- short-lived bearer access tokens;
- rotating refresh tokens;
- token-family revocation;
- RFC 8707 resource validation;
- persistent SQLite state.

Authorization states, codes, access tokens, and refresh tokens are stored only as keyed digests. The local login password is stored only as a scrypt hash. Credential and database files are restricted to the local user.

## Deployment

The release includes:

- `examples/hermes-file-bridge.service`
- `examples/hermes-gpt-sidecar-file-bridge.conf`
- `docs/file-bridge.md`
- `auth_bootstrap.py`

The existing unauthenticated connector must be reconnected after deployment so it can complete OAuth authorization. The worker must not be enabled before the authenticated connector has been verified.

## Compatibility

The MCP dependency is constrained to the production v1 line:

```text
mcp[cli]>=1.28,<2
```

## Verification

The release adds tests for:

- bridge state and mailbox handling;
- per-command workdir enforcement;
- worker locking and duplicate prevention;
- worker exception and stale-run recovery;
- adjudicated retries;
- credential file permissions;
- public-client registration;
- PKCE authorization and rejection;
- access and refresh token rotation;
- token revocation;
- raw-secret absence from persistent OAuth storage;
- HTTP 401 enforcement and OAuth metadata;
- a complete SDK-routed OAuth HTTP flow.
