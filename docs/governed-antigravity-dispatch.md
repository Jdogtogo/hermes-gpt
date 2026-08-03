# Governed Antigravity Dispatch

## Purpose

The ChatGPT operator exposes the official host Antigravity CLI through four narrow tools:

- `hermes_antigravity_smoke_test`
- `hermes_antigravity_dispatch`
- `hermes_antigravity_dispatch_status`
- `hermes_antigravity_dispatch_cancel`

These tools do not expose a host shell. They use the fixed binary `/home/jfroh/.local/bin/agy`, the pinned free model `gemini-3.6-flash-low`, and `plan` mode.

## Security boundary

Mission Control cannot supply command arguments, shell text, a model, mode, environment, working directory, output path, or raw prompt. Dispatch accepts only an absolute canonical JSON or YAML packet path that:

1. is beneath an active Operator Session readable root;
2. contains no symlink or parent traversal;
3. is no larger than 256 KiB; and
4. conforms to the fixed packet schema below.

Runtime state and evidence are written only under:

`logs/antigravity-dispatch`

The worker revalidates the originating Operator Session identity, snapshot hash, and expiry before and after model execution. Child `agy` processes receive a sanitised environment without API keys, tokens, passwords, secrets, or the Operator Session pointer. Subprocesses use structured argv and `shell=False`. Cancellation verifies that the recorded PID still belongs to the exact governed worker command before signalling its process group, preventing stale or reused PIDs from targeting an unrelated process. A successful cancellation is recorded durably as the terminal `cancelled` state.

The packet is treated as untrusted quoted data. The fixed system prompt prohibits tool calls, file reads, command execution, credential access, and modifications. No Antigravity settings permissions are widened.

## Required authority

The active Operator Session must provide:

- operator level `workspace`;
- `filesystem:read`;
- `filesystem:edit` for dispatch state/evidence;
- `tests:run` as the explicit execution grant;
- packet-path read authority; and
- write authority for `logs/antigravity-dispatch`.

The implementation does not hard-code a policy-template name. Authority is derived entirely from the immutable approved Operator Session snapshot.

## Packet schema

```yaml
schema_version: 1
objective: "Required bounded objective"
context:
  - "Optional fact or evidence text"
questions:
  - "At least one required question"
constraints:
  - "Optional analysis constraint"
expected_output:
  - "Optional requested section"
```

Only these six fields are accepted. Fields such as `prompt`, `argv`, `command`, `model`, `mode`, `environment`, `workdir`, and `output_path` are rejected as unsupported.

## Validation sequence

1. Run focused tests:

   ```bash
   pytest -q test_operator_antigravity_dispatch.py \
     test_server.py::test_chatgpt_operator_tool_surface_is_authenticated_and_non_owner \
     test_server.py::test_operator_status_reports_actual_registered_tools \
     test_server.py::test_governed_antigravity_dispatch_tools_route_to_dispatch_module \
     test_server.py::test_antigravity_public_tools_route_to_tax_calculator_launcher
   ```

2. Run the complete changed-area suite:

   ```bash
   python3 -m pytest -q \
     test_server.py \
     test_operator_antigravity_dispatch.py \
     test_operator_antigravity.py \
     test_operator_antigravity_tax.py
   ```

3. Run the full repository suite without inheriting the live Operator Session pointer:

   ```bash
   python3 tools/run_pytest_without_operator_session.py -q
   ```

4. Restart the ChatGPT operator using the approval-gated exact service tool.

5. Confirm the live tool count is 38 and the four new names are reported.

6. Run `hermes_antigravity_smoke_test(dry_run=true)` to verify authority and host preflight.

7. Run `hermes_antigravity_smoke_test(dry_run=false)` and require:

   - `success: true`;
   - `exact_match: true`;
   - response `ANTIGRAVITY_MISSION_CONTROL_SMOKE_OK`; and
   - a returned conversation identifier when supplied by `agy`.

8. Create a harmless packet beneath an approved readable root, dry-run dispatch it, then perform a live dispatch and review the result through the status tool.

## Operational notes

Only one governed packet dispatch may run at a time. Cancellation targets only the process group whose live command line matches the exact internal worker script and task ID recorded in state; stale or reused PIDs fail closed. Raw stdout and stderr are redacted, bounded, and retained in the fixed job directory for review. The Docker workspace executor remains unchanged and does not receive the host CLI or host authentication state.
