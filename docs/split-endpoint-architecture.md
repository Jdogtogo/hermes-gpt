# Split Endpoint Architecture

Hermes-GPT now supports two separate MCP profiles for Justin's deployment.

## Public ChatGPT endpoint

- URL: `https://mcp.frohnert-hermes.org/mcp`
- Local origin: `http://127.0.0.1:7677/mcp`
- Service: `hermes-gpt-sidecar-bridge.service`
- Server profile: `chatgpt-restricted`
- Authentication: none
- Registered tools:
  - `hermes_restricted_status`
  - `hermes_restricted_agent_run`
  - `hermes_ops_brain_query`

The restricted profile fails closed at startup unless it is bound to loopback,
OAuth is disabled, bridge/write/terminal/session/memory-write gates are unset,
and the operator policy is exactly `read_only` plus `dry_run`.

The restricted agent wrapper permits only `plan` and `read_only` modes, disables
web access, refuses denied paths, requires an allowlisted workdir, and caps the
remote request timeout at 300 seconds. Use the local file bridge for longer jobs.

## Local owner endpoint

- Local URL: `http://127.0.0.1:7679/mcp`
- Service: `hermes-gpt-owner-local.service`
- Server profile: `local-owner`
- Authentication: none, because it is loopback-only
- Owner/direct and bridge tools are available according to the operator policy.

Cloudflare must not route to port `7679`.

## File bridge

The file bridge worker remains local and runs owner apply through stdio. Its
supported execution timeout is now 3600 seconds.

## Rollback

1. Restore the previous `hermes-gpt-sidecar-bridge.service` from the recovery snapshot.
2. Stop and disable `hermes-gpt-owner-local.service`.
3. Restore the previous `hermes-file-bridge.service` if needed.
4. Run `systemctl --user daemon-reload`.
5. Restart `hermes-gpt-sidecar-bridge.service` and `hermes-file-bridge.service`.
6. Confirm Cloudflare origin logs route only to the intended port.
