# chatgpt-operator local deployment (Stage C)

> **Superseded:** this connector is now publicly deployed (via Cloudflare
> Tunnel, `operator.frohnert-hermes.org`) with a full Telegram + localhost
> approval system and a 21-tool surface (this file's tool list and "no
> public exposure" framing below are historical, from before that work).
> See `hermes-operator-approval-system.md` for the current, authoritative
> reference.

Local-only, OAuth + session gated MCP endpoint intended for a future ChatGPT
remote connector. As deployed here it has **no public exposure** — it is
reachable only from this machine.

## Service

- Unit: `hermes-gpt-chatgpt-operator.service`
- Source: `/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt`
  (branch `codex/operator-session-chatgpt-20260713`)
- Local endpoint: `http://127.0.0.1:7680/mcp` (loopback only)
- Profile: `chatgpt-operator` — refuses to start without OAuth enabled and an
  active, non-owner Operator Session snapshot (`validate_chatgpt_operator_runtime`
  in `server.py`).

This is intentionally separate from:
- `hermes-gpt-sidecar-bridge.service` (port 7677, `chatgpt-restricted` profile,
  no auth, read-only, dry-run) — unchanged.
- `hermes-gpt-owner-local.service` (port 7679, `local-owner` profile, OAuth
  enabled in Stage A, full owner tool surface, static env-driven authority,
  no session model) — unchanged apart from the Stage A OAuth drop-in. This
  remains a local maintenance endpoint only and must never be tunneled.

## Tool surface (20 tools)

`hermes_ops_brain_query`, `hermes_operator_policy`, `hermes_operator_status`,
`hermes_operator_session_status`, `hermes_operator_session_request_extension`,
`hermes_operator_session_revoke`, `hermes_operator_audit_tail`,
`hermes_operator_doctor`, `hermes_operator_snapshot`, `hermes_config_get`,
`hermes_env_status`, `hermes_gateway_status`, `hermes_search_files`,
`hermes_workspace_read`, `hermes_workspace_patch`, `hermes_workspace_write_file`,
`hermes_workspace_run_test`, `hermes_workspace_git_commit`, `hermes_git_status`,
`hermes_git_diff`.

Deliberately excluded: `hermes_owner_run_command`, `hermes_owner_patch`,
`hermes_owner_write_file`, `bridge_submit_command`, `hermes_config_set`,
`hermes_config_patch`, `hermes_env_set_nonsecret`, `hermes_gateway_restart`,
`hermes_cron_*` mutation, `hermes_skill_delete`/`write_file`/etc mutation, and
`hermes_agent_run` (unrestricted agent delegation).

## Session lifecycle (local-only administration)

Session creation and extension approval are **never** exposed as remote MCP
tools — only status, extension *request*, and revoke are. Use
`operator_sessions.py` directly on the host:

```bash
cd /home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt
HERMES_GPT_OPERATOR_SESSION_ROOT=/home/jfroh/.hermes/operator-sessions/chatgpt-operator \
  ../../hermes-gpt/.venv/bin/python operator_sessions.py create-session --policy-file policy.json
# ... set HERMES_GPT_OPERATOR_SESSION_ID in the systemd drop-in, then:
systemctl --user daemon-reload && systemctl --user restart hermes-gpt-chatgpt-operator.service

# Remote agent calls hermes_operator_session_request_extension; approve it locally:
HERMES_GPT_OPERATOR_SESSION_ROOT=/home/jfroh/.hermes/operator-sessions/chatgpt-operator \
  ../../hermes-gpt/.venv/bin/python operator_sessions.py approve-extension <request_id>

# Revoke immediately if needed:
HERMES_GPT_OPERATOR_SESSION_ROOT=/home/jfroh/.hermes/operator-sessions/chatgpt-operator \
  ../../hermes-gpt/.venv/bin/python operator_sessions.py revoke-session <session_id>
```

Session timing: default 2h, hard cap 4h from creation regardless of
extensions, each extension grants at most 30 minutes and always requires the
local `approve-extension` step above — a session can never approve its own
extension.

## Path scope

The current validation session's `readable_roots`/`writable_roots` are
restricted to a single **standalone** (non-linked) disposable git repository:
`/home/jfroh/.hermes/worktrees/chatgpt-operator-scratch`. It is intentionally
not a `git worktree add` linked worktree, because linked worktrees share the
main repository's `.git/objects` database — committing through one would
require write access into `/home/jfroh/hermes-gpt/.git`, which is explicitly
off-limits. Read-only access to `/mnt/c/Dev/Tax Calculator` is a future step,
not enabled yet.

## Rollback

```bash
systemctl --user stop hermes-gpt-chatgpt-operator.service
systemctl --user disable hermes-gpt-chatgpt-operator.service
rm /home/jfroh/.config/systemd/user/hermes-gpt-chatgpt-operator.service
systemctl --user daemon-reload
```

No existing unit was overwritten (none existed under this name before this
change), so there is no unit backup to restore — removal returns the host to
its pre-Stage-C state. The restricted and local-owner services are untouched
by this rollback.
