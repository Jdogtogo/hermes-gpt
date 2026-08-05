# ChatGPT Connector Tool Snapshot Reconciliation — 2026-08-06

## Verdict

The 40-versus-38 discrepancy is not a Hermes Controller registration or implementation defect. The live `chatgpt-operator` MCP server registers and validates all 40 canonical tools, including `hermes_computer_use_status` and `hermes_computer_use_doctor`. The current ChatGPT app/connector retains an older frozen action snapshot containing 38 tools.

## Live and test evidence

- Live operator status: manifest version 1.0.1, 40 expected, 40 registered, no missing or unexpected tools, no schema drift, PASS.
- The current ChatGPT consumer exposes 38 functions; the two absent functions are `hermes_computer_use_status` and `hermes_computer_use_doctor`.
- `test_operator_manifest.py` passed.
- `test_server.py::test_computer_use_readonly_tools_route_to_bounded_host_diagnostics` passed.
- `test_server.py::test_computer_use_tools_in_operator_surface` passed.
- Eight relevant tests passed in total.
- The computer-use wrappers route only to the bounded read-only host-diagnostics adapter.

## Root cause

OpenAI documents that an approved custom MCP app uses a frozen snapshot of its available tools and inputs. Later MCP server additions are not automatically applied. For Enterprise/Edu, an admin/owner must use the app's Action control and select Refresh to pull new or changed actions. New actions are disabled by default until reviewed and enabled. Business custom apps may require recreation and republishing when the published app cannot be updated.

The installed MCP SDK supports `notifications/tools/list_changed`, but adding a server notification would not override ChatGPT's approved frozen app-action snapshot. Implementing a notification-only controller change would therefore add complexity without resolving this consumer-side governance gate.

## Required consumer action

1. Use ChatGPT web.
2. Open Workspace Settings or Settings > Apps, depending on the app's deployment mode.
3. Open Hermes Controller 6R.
4. Open Action control or the app's Manage/Configure actions screen.
5. Select Refresh or Scan Tools.
6. Review and enable `hermes_computer_use_status` and `hermes_computer_use_doctor`.
7. Save/publish the updated action set.
8. Start a new chat and verify that 40 functions are exposed and both tools are callable.

If the deployment does not provide Refresh, recreate and republish the custom app from the same MCP endpoint, then reconnect it.

## Decision

No Hermes Controller source change is required. The server is correct and fail-closed. The remaining work is the ChatGPT app action-snapshot refresh and a new-chat callability check.
