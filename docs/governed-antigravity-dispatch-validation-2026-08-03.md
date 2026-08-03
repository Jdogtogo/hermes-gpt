# Governed Antigravity Dispatch Validation — 2026-08-03

## Verdict

**PASS**

The governed host-side Antigravity smoke and packet-dispatch capabilities are implemented, loaded by the live ChatGPT operator service, audited, hardened against stale PID cancellation, and validated against the official `/home/jfroh/.local/bin/agy` CLI.

Hermes Controller 6R exposes the complete current **38-tool** operator surface, including:

- `hermes_antigravity_smoke_test`
- `hermes_antigravity_dispatch`
- `hermes_antigravity_dispatch_status`
- `hermes_antigravity_dispatch_cancel`

## Implementation scope

The bounded implementation consists of:

- `operator_antigravity_dispatch.py`
- `server.py`
- `test_operator_antigravity_dispatch.py`
- `test_server.py`
- `docs/governed-antigravity-dispatch.md`
- `docs/governed-antigravity-dispatch-validation-2026-08-03.md`
- `tools/run_pytest_without_operator_session.py`

Unrelated prototypes, skill-estate material, operator-regression documents, proof files, backlog files and dependency-lock changes remain outside this work.

## Security controls verified

- Absolute host binary pinned to `/home/jfroh/.local/bin/agy`.
- Free model pinned to `gemini-3.6-flash-low`; no fallback or provider substitution.
- Mode pinned to `plan`.
- No arbitrary prompt, command, argv, model, mode, environment, working directory or output-path inputs.
- Dispatch accepts only an absolute, canonical, policy-readable JSON/YAML packet path.
- Symlinks, parent traversal, non-canonical paths, unsupported fields and oversized packets are rejected.
- Packet contents are normalised into a fixed schema and treated as untrusted quoted data.
- Child `agy` execution uses structured argv with `shell=False`.
- Child environment strips API-key, token, secret, password and Operator Session pointer variables.
- The worker revalidates the originating Operator Session identity, snapshot hash and expiry before and after model execution.
- Runtime state and evidence are confined to `logs/antigravity-dispatch`.
- Raw stdout and stderr are redacted and bounded before durable retention.
- Only one governed dispatch may run at a time.
- Cancellation validates that the recorded PID still belongs to the exact internal worker script and task ID before signalling the process group.
- Stale or reused PIDs fail closed and cannot be signalled.
- A successful worker cancellation reaches the durable terminal state `cancelled`.
- Docker workspace execution, authentication state, global package configuration and model routing were not widened or changed.

## Test evidence

### Focused dispatcher suite

```text
python3 -m pytest -q test_operator_antigravity_dispatch.py
15 passed
```

Coverage includes:

- public input-surface confinement;
- packet schema and path validation;
- authority-before-path inspection;
- fixed smoke exact-output behaviour;
- internal worker-only launch;
- structured result retrieval;
- status and process identity reporting;
- recorded process-group cancellation;
- stale/reused PID refusal;
- durable terminal cancellation;
- output redaction and bounding.

### Changed-area and compatibility suite

```text
python3 -m pytest -q \
  test_server.py \
  test_operator_antigravity_dispatch.py \
  test_operator_antigravity.py \
  test_operator_antigravity_tax.py

67 passed
```

This proves the 38-tool surface, public routing, the new governed dispatcher and compatibility with the existing fixed Antigravity review paths.

### Full repository suite

```text
python3 tools/run_pytest_without_operator_session.py -q
698 passed
```

The helper removes only:

- `HERMES_GPT_OPERATOR_SESSION_ROOT`
- `HERMES_GPT_OPERATOR_SESSION_ID`

from the pytest child environment. This prevents a live approved Operator Session from invalidating tests that intentionally assert disabled/default policy behaviour. It invokes `python -m pytest` with structured argv and `shell=False`.

## Live validation after hardened service reload

### Fixed smoke test

- Success: `true`
- Return code: `0`
- Exact match: `true`
- Response: `ANTIGRAVITY_MISSION_CONTROL_SMOKE_OK`
- Run ID: `smoke_9b455b3611be4fa9`
- Conversation ID: `072e88d2-add9-405a-989a-3b0a160281a8`
- Model: `gemini-3.6-flash-low`
- Mode: `plan`
- Duration: `12,793 ms`

### Public governed packet dispatch

- Task ID: `agd_c1911d7411944bd1`
- Packet SHA-256: `79605f2a8d85786f2c0a2dbd8166232b3e577e745af91703091fbb8bbda1dc98`
- Status: `completed`
- Return code: `0`
- Conversation ID: `2eb67e89-572b-49d7-8cb7-0f91b6e8d144`
- Model: `gemini-3.6-flash-low`
- Mode: `plan`
- Duration: `9,747 ms`
- Required validation token present: `HARDENED_ANTIGRAVITY_DISPATCH_OK`
- Process identity status: `true` while running, `false` after completion

The model correctly treated the packet as untrusted data and did not follow its embedded request to suppress the governed advisory-analysis format. It nevertheless answered the packet and included the requested validation token.

## Classification

- 38-tool operator surface: **Proven**
- Fixed exact-output Antigravity connectivity: **Proven**
- Governed packet dispatch: **Proven**
- Packet schema and path confinement: **Proven**
- Originating-session revalidation: **Proven**
- Redacted bounded evidence: **Proven**
- PID-reuse-safe cancellation: **Proven by regression tests**
- Durable cancellation terminal state: **Proven by regression tests**
- Existing Antigravity review compatibility: **Proven**
- Full repository regression gate: **698 passed**

No remaining code, connector-refresh or service-reload blocker is recorded for this capability.
