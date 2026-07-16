# Hermes Operator Approval System

Canonical reference for the passwordless, Hermes-owned approval system that
gates ChatGPT's remote access to Hermes-GPT. Supersedes the tool-surface and
session-lifecycle sections of `chatgpt-operator-deployment.md` (kept for its
original Stage-C historical context); this document is authoritative for
everything approval-related.

## 1. Overview

Three concerns are deliberately kept separate:

1. **OAuth** proves *identity* (this is really ChatGPT, holding a valid
   token) — it never by itself grants file/git/mutation authority.
2. **Operator Sessions** grant *temporary, scoped repository authority* —
   created only after a human approves a named policy template, never
   self-approved, always time-boxed.
3. **Approval delivery** (Telegram primary, localhost fallback, CLI
   break-glass) is how a human actually presses Approve/Deny — it is not
   itself an authority boundary, just a delivery mechanism.

Every pending item (OAuth connection, session-creation, session-extension)
is resolved by exactly one human decision, is one-time-use, and produces an
audit record with a caller identity attached (`telegram:<user_id>` or
`localhost`).

## 2. Architecture diagram (textual)

```
ChatGPT ──HTTPS──> Cloudflare Tunnel ──> hermes-gpt-chatgpt-operator.service
                                          (127.0.0.1:7680, OAuth-gated,
                                           internet-facing, holds NO
                                           Telegram credential)
                                              │
                                              │ POST /notify, POST /telegram-resolve
                                              ▼
                                    hermes-gpt-approval-web.service
                                    (127.0.0.1:7690, loopback-only,
                                     holds the Telegram bot token,
                                     serves the localhost fallback page)
                                              │
                                              ▼
                                    Telegram Bot API (existing bot,
                                    reused — never a second bot)
                                              │
                                              ▼
                                    Your phone: Approve / Deny
```

The internet-facing process (port 7680) never imports the Telegram-sending
module and never holds the bot token — see §11.

## 3. Telegram approval workflow

1. A remote request (OAuth authorize, session-request, extension-request)
   creates a pending row and calls `_notify_pending_request()` in-process.
2. That call POSTs `{request_type, request_id, details}` to
   `http://127.0.0.1:7690/notify`.
3. The approval-web service calls `operator_approval_notify.notify_pending_request()`,
   which reads `TELEGRAM_BOT_TOKEN`/`TELEGRAM_ALLOWED_USERS` (process env,
   falling back to `/home/jfroh/.hermes/.env` at call-time — never
   duplicated into systemd config) and sends a message with inline
   `Approve`/`Deny` buttons (`callback_data` = `hop:approve:<id>` /
   `hop:deny:<id>`).
4. Hermes Agent's own Telegram adapter (`plugins/platforms/telegram/adapter.py`,
   the `hop:` branch) receives the button press, authorizes the caller
   against the existing `TELEGRAM_ALLOWED_USERS` allowlist (same check as
   every other approval button in that bot), and POSTs
   `{request_id, decision, caller_id}` to `http://127.0.0.1:7690/telegram-resolve`.
5. The approval-web service independently re-verifies the request still
   exists and is pending (never trusts the Telegram-side auth check alone),
   then applies the decision and writes the audit record.

The Telegram message itself never contains a token, password, code, or
policy JSON — only a human-readable summary (client id / redirect domain /
scope, or policy template / roots / verbs / duration / reason).

## 4. Localhost fallback workflow

`http://127.0.0.1:7690/approvals` — always available, independent of
Telegram. Lists every pending OAuth / session / extension request with
Approve/Deny forms, each protected by a one-time CSRF token (10-minute TTL,
minted per page load, consumed on submit). Use this when Telegram is down,
when your phone isn't handy, or to clear stale/duplicate messages without
further Telegram round-trips. The Windows desktop shortcut **Hermes
Approvals** opens this page directly (see §14).

## 5. CLI break-glass workflow

Last resort only, direct on the host:

```bash
cd /home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt
HERMES_GPT_AUTH_ROOT=/home/jfroh/.hermes/auth/hermes-gpt-chatgpt-operator \
  /home/jfroh/hermes-gpt/.venv/bin/python operator_auth.py list-pending
  /home/jfroh/hermes-gpt/.venv/bin/python operator_auth.py approve <request_id>
  /home/jfroh/hermes-gpt/.venv/bin/python operator_auth.py deny <request_id>

HERMES_GPT_OPERATOR_SESSION_ROOT=/home/jfroh/.hermes/operator-sessions/chatgpt-operator \
  /home/jfroh/hermes-gpt/.venv/bin/python operator_sessions.py list-pending-sessions
  /home/jfroh/hermes-gpt/.venv/bin/python operator_sessions.py approve-session <request_id>
  /home/jfroh/hermes-gpt/.venv/bin/python operator_sessions.py deny-session <request_id>
  /home/jfroh/hermes-gpt/.venv/bin/python operator_sessions.py approve-extension <request_id>
  /home/jfroh/hermes-gpt/.venv/bin/python operator_sessions.py revoke-session <session_id>
```

Session *creation* and extension *approval* are never exposed as remote MCP
tools at all — only the CLI, Telegram, and the localhost page can grant
them.

## 6. OAuth approval vs. operator-session authority

| | OAuth approval | Operator session approval |
|---|---|---|
| Proves | This really is a legitimate ChatGPT connection | A human has reviewed and granted a specific, named scope of repository authority |
| Created by | ChatGPT's `/authorize` call | The `hermes_operator_session_request` MCP tool (itself requires a valid OAuth token to call) |
| Grants | A Bearer access/refresh token, scope `hermes:operator` | Read/write roots, allowed verbs, a hard expiry |
| Approving one | Never creates a session | — |
| Approving the other | — | Never re-runs the OAuth handshake |

A valid access token lets a client *ask* for a session (and call read-only
tools); it never grants mutation by itself. Mutation requires a separately
approved, active, non-expired, non-revoked session.

## 7. Named policy templates

Defined in `operator_policy_templates.py`. A remote caller can only name a
template — never submit raw paths, verbs, or policy JSON.

- **`sandbox`** (active) — read/write root `/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch`
  only. Verbs: `filesystem: [read, edit]`, `git: [commit]`, `tests: [run]`.
  Max duration capped by `MAX_SESSION_DURATION_SECONDS` (4h).
- **`hermes-gpt-operator-maintenance`** (active) — read/write root is the
  operator worktree itself, restricted to branch
  `codex/operator-session-chatgpt-20260713`.
- **`tax-calculator-controller`** (active) — read/write root is exactly
  `/mnt/c/Dev/Tax Calculator`, restricted to branch
  `feat/projection-architecture-discovery`, with a two-hour maximum and a
  required pinned baseline for controlled commits.

Every resolved policy also carries a fixed set of `hard_denied_paths`
(`.ssh`, `.aws`, `.azure`, `.gnupg`, `.docker`, `.kube`,
`.hermes/auth`, `.hermes/mcp-tokens`, `.cloudflared`) regardless of
template — confirmed live during Step 4 testing.

## 8. Session duration and extension rules

- Requested duration is capped at the template's own max (`sandbox`: 4h).
- Each extension request is fixed at 30 minutes
  (`EXTENSION_SECONDS`/`op_sessions.request_extension`).
- Absolute cap: `created_at + MAX_SESSION_DURATION_SECONDS` (4h from
  original creation) — approval **clamps** to this cap
  (`min(expires_at + requested, max_expiry)`), it does not just reject over
  the cap.
- `approve_extension`/`approve_session_request` are local-only functions,
  never exposed as remote MCP tools — a session can never approve its own
  extension or a new session's creation.
- Extension/session requests, once approved or denied, cannot be replayed
  (verified live: re-submitting the same `request_id` returns
  `"already approved"`/`"already denied"`).

## 9. No-session service behaviour

The service must run continuously whether or not a session is active or
has expired/been revoked:

- `operator_sessions.active_session()` returns `None` (never raises) when
  there is no pointer file, an unreadable pointer file, or the pointed-to
  session has expired/been revoked — treated identically, by design.
- Every mutating tool call without an active session returns a structured
  `{"success": false, "error": "... requires an active Operator Session."}`
  — never a crash, never a 500.
- Read-only tools (`hermes_operator_status`, `hermes_operator_policy`,
  `hermes_operator_audit_tail`, `hermes_operator_session_request`,
  `hermes_operator_session_request_extension`) remain fully available with
  no active session.

## 10. Services and ports

| Service | Port | Bind | Purpose |
|---|---|---|---|
| `hermes-gpt-chatgpt-operator.service` | 7680 | 127.0.0.1 only (public via Cloudflare Tunnel → `operator.frohnert-hermes.org`) | OAuth-gated ChatGPT connector, 21 tools |
| `hermes-gpt-approval-web.service` | 7690 | 127.0.0.1 only, **never tunneled** | Localhost approval page + internal `/notify` + `/telegram-resolve` |
| `hermes-gpt-sidecar-bridge.service` | 7677 | 127.0.0.1 only (public via Cloudflare Tunnel → `mcp.frohnert-hermes.org`) | `chatgpt-restricted` profile, read-only, unrelated to this system, unchanged |
| `hermes-gpt-owner-local.service` | 7679 | 127.0.0.1 only, **local only, never tunneled** | `local-owner` profile, full owner surface, unrelated to this system, unchanged |
| `hermes-gateway.service` | — | — | Hermes Agent's real Telegram bot (existing, reused — receives the `hop:` callback branch) |

## 11. Telegram credential isolation (why it matters)

The internet-facing `hermes-gpt-chatgpt-operator.service` **never** imports
`operator_approval_notify` and **never** holds `TELEGRAM_BOT_TOKEN`. This
was a deliberate fix (see §16) after live testing showed the original
design would have required duplicating the bot token into that unit's
config — an independent review flagged that (a) `systemctl show`/`cat`
print inline `Environment=` values in cleartext, and (b) a Telegram token
is unscoped (full bot authority, not just "send one message"), so it
should never sit in the one process reachable from the public internet.
Only `hermes-gpt-approval-web.service` (loopback-only) ever touches the
token, reading it at call-time from `/home/jfroh/.hermes/.env`.

## 12. Audit locations

- Primary (this deployment): `/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt/logs/hermes_gpt_operator_audit.jsonl`
  — resolved via `operator_policy.audit_log_path()`: prefers
  `~/AppData/Local/hermes/logs/` if that directory exists (Windows-native
  Hermes installs), else falls back to `<repo>/logs/...` (this WSL
  deployment; the `AppData` path does not exist here, hence the fallback).
- Every record includes `request_id`, `decision`, `approval_source`
  (`telegram:<user_id>` or `localhost`), `timestamp`, `trace_id`, and for
  sessions `resulting_session_id`/`snapshot_hash`. Never contains tokens,
  codes, or passwords (verified by grep during Step 4).
- **Known gap (hardening follow-up, not yet built):** `_audit_approval_decision`
  and `operator_sessions._audit_decision` wrap the write in
  `except Exception: pass` — auditing must never block a decision, but this
  means a write failure is currently silent. This is exactly what happened
  in §17. A visible health-check surface for audit-write failures is
  tracked as a separate follow-up (see §18).

## 13. Backups

All systemd unit backups: `/home/jfroh/.hermes/backups/systemd-unit-backups/`
- `telegram-hop-deploy-20260715_090900/` — pre-deploy snapshot of
  `hermes-gateway.service` + drop-in, `hermes-gpt-chatgpt-operator.service`
  + both drop-ins, and `releases/v018-live` HEAD marker (`d60226c8e`).
- `approval-web-readwritepaths-fix-20260716_053753/` — pre-fix snapshot of
  `hermes-gpt-approval-web.service` (before the `ReadWritePaths` correction).

## 14. Windows shortcut

`C:\Users\jfroh\Desktop\Hermes Approvals.lnk` → `http://127.0.0.1:7690/approvals`.
Verified: opens the default browser and returns a real `200 OK` from the
approval-web service. Port 7690 is not, and must never be, exposed via
Cloudflare or any public route.

## 15. Rollback procedures

**Telegram receiving-side (hermes-agent):** the isolated worktree commit
(`92a31ac9a`) is deployed into `releases/v018-live` as a detached checkout.
Rollback:
```bash
cd /home/jfroh/.hermes/releases/v018-live
git checkout --detach d60226c8e
systemctl --user restart hermes-gateway.service   # from a separate shell
```

**Approval-web service (config):**
```bash
cp /home/jfroh/.hermes/backups/systemd-unit-backups/approval-web-readwritepaths-fix-20260716_053753/hermes-gpt-approval-web.service \
   /home/jfroh/.config/systemd/user/hermes-gpt-approval-web.service
systemctl --user daemon-reload
systemctl --user restart hermes-gpt-approval-web.service
```
To fully remove the port-7690 service (returns host to pre-approval-centre state):
```bash
systemctl --user disable --now hermes-gpt-approval-web.service
rm /home/jfroh/.config/systemd/user/hermes-gpt-approval-web.service
systemctl --user daemon-reload
```

**Operator worktree source (code):** do **not** use
`git checkout <commit> -- .` for rollback — it overwrites files in place and
leaves the worktree dirty against its own HEAD. Instead, from a stopped
service, use an explicit detached checkout in a **separate** rollback
worktree after recording the current clean HEAD, and only fast-forward the
original worktree back once the issue is resolved:
```bash
systemctl --user stop hermes-gpt-chatgpt-operator.service
git -C /home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt rev-parse HEAD   # record current
git worktree add /home/jfroh/.hermes/worktrees/hermes-gpt-operator-ROLLBACK <known-good-commit>
# point the service at the rollback path temporarily, or cherry-pick the fix forward instead
```

## 16. Codex OAuth token (separate follow-up, not part of this system)

The gateway's own autonomous background task (unrelated self-improvement /
context-compaction loop) has an invalidated Codex OAuth token, producing
repeated `HTTP 401` errors, most visibly during gateway shutdown/restart
(observed 2026-07-13, 07-14, 07-15). Fix (deferred, tracked separately,
deliberately not touched during this task): run `codex` in a terminal to
generate fresh tokens, then `hermes auth` to re-authenticate. This is
unrelated to Telegram/OAuth/session approval and does not affect any of the
services in this document.

## 17. cloudflared: tunnel architecture and prior instability

`cloudflared` runs as a **system-level** service (not `systemctl --user`),
token-based (`cloudflared --no-autoupdate tunnel run --token ...`), with
ingress routes managed via the Cloudflare dashboard ("Published application
routes") rather than a local `config.yml` — confirmed earlier in this
project; there is no local file to check for route definitions.

A prior incident (documented in this session's own history) saw both the
restricted (`mcp.frohnert-hermes.org`) and operator connectors return
upstream `502` errors from ChatGPT's perspective; this was resolved with a
plain `cloudflared` service restart, not a configuration change. Cloudflare
Tunnels proxy HTTP/2 to the origin by default unless the dashboard's
per-route HTTP settings specify otherwise; local Python ASGI origins
(uvicorn, as used by both the port-7680 and port-7690 services here) are
generally fine over HTTP/1.1 but can be a source of intermittent 502s under
HTTP/2 to origin depending on server configuration. If 502s recur: first
try `sudo systemctl restart cloudflared`; if they persist, check the
dashboard's per-route "HTTP Settings" for the HTTP/2-origin toggle. This
document does not claim a confirmed HTTP/2-specific root cause beyond what
was actually observed (a restart resolved it) — treat the HTTP/2 note as
troubleshooting guidance, not a diagnosed fix.

## 18. The `ReadWritePaths` audit-write defect (found and fixed during Step 4)

`hermes-gpt-approval-web.service`, as originally created, had
`ProtectHome=read-only` with a `ReadWritePaths` list that omitted the
`logs/` directory used by `operator_policy.audit_record()`. Every audit
write from that service (both localhost-page decisions and Telegram-
forwarded decisions) silently failed — caught by the deliberate
`except Exception: pass` in `_audit_approval_decision` (auditing must never
block a decision) — with no visible symptom beyond an audit log that simply
never grew for that service's decisions. Found by noticing a real, just-
completed Telegram denial never appeared in the audit file. Fixed by adding
`/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt/logs` to
`ReadWritePaths` (matching the sibling `hermes-gpt-chatgpt-operator.service`,
which already had this correct). Verified post-fix: both a localhost deny
and a Telegram approve each produced exactly one new, correct audit record.
See §12 for the follow-up (visible audit-write health signal) this
motivated.

## 19. Common troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| No Telegram message arrives | Approval-web service down, or bot token unreadable | `curl http://127.0.0.1:7690/healthz`; `journalctl --user -u hermes-gpt-approval-web.service` |
| Telegram button says "already approved/denied" | You tapped an old duplicate/stale message | Check `http://127.0.0.1:7690/approvals` for what's *actually* still pending before tapping anything |
| Request "does not exist or has expired" | The 10-minute (OAuth) / other TTL elapsed before the tap | Reconnect from ChatGPT / re-request; TTLs are intentionally short |
| Mutation tool always refuses | No active session, or it expired/was revoked | `hermes_operator_session_status`; request a fresh session |
| Audit log not growing | Check `ReadWritePaths` on whichever service made the decision (see §18) | `systemctl --user cat <service> \| grep ReadWritePaths` |
| ChatGPT still shows only 20 tools | Cached connector schema from before `hermes_operator_session_request` was added | See §21 remediation |
| Public endpoint 502 | Tunnel-side issue, not this system | See §17 |

## 20. Routine workflows

**1. Connect ChatGPT via OAuth:** add/select the Hermes Operator connector
in ChatGPT → ChatGPT performs DCR + `/authorize` →  you get a Telegram
message (or check `/approvals`) → tap Approve → ChatGPT's connector
completes automatically.

**2. Approve an OAuth request in Telegram:** tap **Approve once** on the
"Hermes Operator connection request" message. No password is ever involved.

**3. Request a new operator session:** from ChatGPT, ask it to request
operator access (calls `hermes_operator_session_request` with a named
template, e.g. `sandbox`); you'll get a Telegram message showing the exact
resolved roots/verbs/duration/reason.

**4. Approve or deny a session:** tap **Approve** or **Deny** on that
message, or use `http://127.0.0.1:7690/approvals`.

**5. Approve or deny a 30-minute extension:** ChatGPT/the session calls
`hermes_operator_session_request_extension`; tap **Approve 30 minutes** or
**Deny** on the resulting Telegram message.

**6. Revoke a session:** ask ChatGPT to call
`hermes_operator_session_revoke`, or run the CLI `revoke-session` command
directly (§5) if you want to revoke without going through the connector at
all.

**7. Use the localhost page when Telegram is unavailable:** open
`http://127.0.0.1:7690/approvals` (Windows shortcut: **Hermes Approvals**
on the desktop) — every pending item and the recent audit tail are listed
there with the same Approve/Deny actions.

## 21. Tool-surface cache note

Existing ChatGPT conversations that connected before
`hermes_operator_session_request` was added may retain a cached 20-tool
schema. Remediation: refresh/reconnect the Hermes Operator connector, or
start a new ChatGPT conversation with it selected. Do not remove and
recreate the connector unless the refresh/reconnect doesn't resolve it.
