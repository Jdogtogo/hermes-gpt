# Hermes Asynchronous File Bridge

## Purpose

The file bridge lets a remote authenticated MCP supervisor submit a bounded command to a local Hermes worker. The worker executes through Hermes' existing local `operator_agent` path and returns either success evidence or an adjudication request through a shared Markdown mailbox.

## Security boundary

The bridge worker converts a queued command into a local Hermes apply run. For that reason:

- bridge tools are disabled unless `HERMES_GPT_ENABLE_BRIDGE=1`;
- bridge tools are refused over HTTP or SSE unless OAuth is enabled;
- remote MCP requests require the `hermes:operator` OAuth scope;
- only public OAuth clients using authorization-code flow with PKCE S256 are accepted;
- Justin must authorize the connector using the local single-user login credential;
- command working directories must be absolute, exist, and be under the operator allowlist;
- only one command can be active at a time;
- worker locking prevents concurrent execution;
- a stale `running` command is escalated rather than automatically re-run;
- authorization states, codes, access tokens, and refresh tokens are stored only as HMAC digests;
- refresh tokens rotate and revoke their previous token family members;
- credential and OAuth database files are private to the local user.

The bridge must never be activated on an unauthenticated public MCP endpoint.

## Files

Runtime mailbox:

```text
/home/jfroh/.hermes/bridge/
├── bridge.md
├── state.json
├── worker.lock
├── archive/
└── logs/
```

OAuth state:

```text
/home/jfroh/.hermes/auth/hermes-gpt/
├── credentials.json
├── initial-login.txt
└── oauth.sqlite3
```

`initial-login.txt` is created only for first login. Save the generated password in a password manager and delete the file after the connector is authorized.

## MCP tools

- `bridge_status`
- `bridge_read`
- `bridge_submit_command`
- `bridge_read_result`
- `bridge_write_adjudication`

`bridge_submit_command` requires:

- `command`: the complete bounded instruction;
- `workdir`: an absolute allowed working directory;
- optional `command_id`: a unique stable identifier.

## Mailbox sections

```markdown
### COMMAND_FROM_CHATGPT

command_id: <id>
timestamp: <UTC timestamp>
workdir: <absolute allowed path>

<command>
```

The worker appends one of:

```markdown
### EXECUTION_SUCCESS
```

or:

```markdown
### REQUEST_FOR_ADJUDICATION
```

ChatGPT can append:

```markdown
### ADJUDICATION_FROM_CHATGPT
```

An adjudicated retry includes the original command, prior escalation, and binding verdict.

## OAuth bootstrap

Run locally from the isolated release worktree:

```bash
/home/jfroh/hermes-gpt/.venv/bin/python \
  /home/jfroh/.hermes/worktrees/hermes-file-bridge/auth_bootstrap.py \
  --issuer-url https://mcp.frohnert-hermes.org \
  --resource-url https://mcp.frohnert-hermes.org/mcp \
  --root /home/jfroh/.hermes/auth/hermes-gpt \
  --username justin
```

The command prints paths only. It does not print the password.

Read the initial password locally:

```bash
cat /home/jfroh/.hermes/auth/hermes-gpt/initial-login.txt
```

Do not paste that password into chat, logs, screenshots, or source control.

## Sidecar environment

Required remote deployment values:

```text
HERMES_GPT_ENABLE_BRIDGE=1
HERMES_GPT_AUTH_ENABLED=1
HERMES_GPT_AUTH_ISSUER_URL=https://mcp.frohnert-hermes.org
HERMES_GPT_AUTH_RESOURCE_URL=https://mcp.frohnert-hermes.org/mcp
HERMES_GPT_AUTH_ROOT=/home/jfroh/.hermes/auth/hermes-gpt
HERMES_GPT_AUTH_SCOPE=hermes:operator
HERMES_GPT_AUTH_USERNAME=justin
```

The remote sidecar must run the worktree's `server.py`. The local worker must run the worktree's `bridge_worker.py`.

## Connector reconnection

After the authenticated sidecar starts, the old unauthenticated ChatGPT connector will stop working. Reconnect the MCP connector to:

```text
https://mcp.frohnert-hermes.org/mcp
```

The client should discover OAuth metadata, dynamically register as a public client, open the Hermes-GPT login page, and complete PKCE authorization.

After successful authorization:

```bash
rm /home/jfroh/.hermes/auth/hermes-gpt/initial-login.txt
```

## Harmless acceptance test

Use a dedicated test workspace under the allowed paths. Submit a command that creates one fixed marker file and reads it back. Do not use the live sidecar repository or Hermes configuration for the first test.

Acceptance criteria:

1. unauthenticated `/mcp` returns HTTP 401;
2. OAuth protected-resource and authorization-server metadata are reachable;
3. the authenticated connector lists all five bridge tools;
4. `bridge_status` reports `idle` before submission;
5. the worker claims the command once;
6. the marker file is created only inside the test workspace;
7. `bridge.md` contains `EXECUTION_SUCCESS`;
8. `state.json` reports `success`;
9. one archive file exists for the attempt;
10. a second worker pass does not re-execute the command.

## Rollback

1. Stop and disable `hermes-file-bridge.service`.
2. Restore the previous `hermes-gpt-sidecar.service` `ExecStart` and working directory.
3. Remove the deployment-specific OAuth/bridge drop-in.
4. Reload the user systemd manager and restart the sidecar.
5. Leave the feature worktree and OAuth state intact for investigation unless compromise is suspected.
6. If compromise is suspected, stop the sidecar, revoke/delete the OAuth database and credentials, rotate the Cloudflare tunnel token, and reconnect only after rebuilding credentials.
