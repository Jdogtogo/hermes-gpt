# Mission Control Daytime Authority Verification — 2026-08-06

## Verdict

The current controller is fit for bounded, non-sensitive software operations with production activation still disabled. The verification package passed the workspace-containment, session-store-isolation, cancellation and immutable-authority gates, but identified and repaired one material authority-expansion defect in generic delegated tasks. The 40-server-tool versus 38-connector-function discrepancy remains unresolved at the connector exposure layer.

## Authority and scope

- Approved session: `ops_wb76ezkPQiFuFM4_NV-Dp0bp1yVZzWko`.
- Policy template: `hermes-gpt-operator-maintenance`.
- Writable root: controller checkout only.
- No client data, credential inspection, production activation, deployment, paid-route change or external communication was performed.

## 1. Workspace execution containment

### Source and configuration proof

`hermes_workspace_exec` constructs a Docker command with:

- structured argv and `shell=False`;
- `--pull=never`;
- `--read-only`;
- `--network=none`;
- `--cap-drop=ALL`;
- `--security-opt=no-new-privileges:true`;
- `--pids-limit=256`;
- a non-root UID/GID;
- only the approved workspace bind-mounted;
- denied paths masked inside the workspace;
- temporary writable storage limited to `/tmp`.

### Live proof

A real confined execution ran:

`pytest -q test_operator_sessions.py`

Result:

- backend: Docker;
- image: `hermes-gpt-workspace-exec:python3.11-nodejs20`;
- network: none;
- return code: 0;
- seven tests passed;
- dry-run preflight reported 366 masked paths.

The broader workspace and service-sandbox regression group also passed.

## 2. Session and policy-store isolation

- `HERMES_GPT_OPERATOR_SESSION_ROOT` is unset in the live profile.
- The source default is `~/.hermes/operator-sessions`.
- The active maintenance session's only readable and writable root is the controller checkout.
- A direct read probe against `~/.hermes/operator-sessions/active_session` was denied because the path is outside every readable root.
- Immutable snapshot, hard-deny, expiry and revocation regression tests passed.

## 3. Server registration, connector exposure and callability

### Server registration gate

- Manifest version: 1.0.1.
- Expected tools: 40.
- Registered tools: 40.
- Schema fingerprint matched.
- Missing, unexpected and duplicate tools: none.
- Schema drift: false.
- Status: PASS.

### Connector exposure gate

The current ChatGPT connector exposes 38 functions. The server-registered functions not exposed to this consumer are:

- `hermes_computer_use_status`;
- `hermes_computer_use_doctor`.

The operator doctor reports connector re-registration as unsupported from the controller. Therefore the cause and intendedness of this filtering remain unverified and must not be inferred.

### Callability evidence

The following control surfaces were called successfully during this package:

- operator and session status;
- audit tail;
- environment status;
- delegated-task forecast;
- delegated-task queue admission;
- delegated-task cancellation and terminal status;
- workspace execution;
- operator service restart.

## 4. Emergency cancellation proof

A synthetic read-only task was queued under the free test profile:

- task: `dt_5da3bbcaf0514824929e91e583945445`;
- logical work: `lw_d868abe7dd04ca45b64ac7aeeae6ba45`.

Cancellation was requested immediately. The task reached terminal `cancelled` with return code 130, changed no files and retained the exact originating session ID and snapshot hash in its authority envelope.

A destructive live revocation of the active maintenance session was not performed because that would terminate the authority required to finish and persist this verification. Expiry and revocation fail-closed behavior is covered by the passing session regression suite.

## 5. Lease and authority non-expansion

### Passed boundary probe

A forecast attempting to move the delegated workdir from the approved controller checkout to OpsBrain was denied before queue admission because the path was outside the readable roots.

### Material defect discovered

A generic read-only delegated-task forecast with `allow_web: true` was initially granted even though the active maintenance session did not carry network authority. Source inspection confirmed that the flag adds the Hermes `web` tool to the worker. This was a genuine authority-expansion defect, not inert metadata.

### Repair

Commit `a84c4742bd1f3477c48eb031258bcdf3a26ee133` now requires the explicit authority verb `network:web` at:

1. delegated-task forecast;
2. queue admission; and
3. worker authority revalidation.

Three regression tests prove denial without the verb and allowance only with an explicitly authorised policy.

After service restart, the original live forecast was repeated and correctly denied with:

`Verb network:web is not granted by this Operator Session.`

## 6. Regression evidence

Before the defect repair, 281 targeted tests passed across workspace containment, service sandboxing, sessions, effective authority, Antigravity dispatch, delegation and manifest integrity.

After the repair:

- the focused delegation suite passed;
- the full session-neutral repository suite passed at 100%;
- the live server manifest remained PASS with 40 registered tools and no schema drift.

## Guarded runtime integration plan

Production behavior remains off. The minimum next steps are:

1. Add a connector exposure report that separately records registered, exposed and callable tools.
2. Resolve why the two computer-use diagnostic tools are absent from the ChatGPT connector and decide whether this is intentional policy filtering or stale connector registration.
3. Add synthetic end-to-end probes for mandatory status, cancellation and revocation controls without exposing arbitrary host operations.
4. Keep generic delegated web access denied unless a separately reviewed policy template grants `network:web`.
5. Preserve exact task identity, snapshot hash, roots, verbs, profile, mode, timeout and data classification in every delegated authority envelope.
6. Keep client-identifiable financial data excluded until the Privacy and Security project passes synthetic-data redaction, pseudonymisation, local-routing and audit-minimisation gates.
7. Do not enable the production feature flag until Mission Control accepts the connector/callability evidence and a controlled non-destructive pilot passes.

## Final status

- Workspace containment: PASS.
- Session-store isolation: PASS.
- Cancellation: PASS.
- Root expansion: PASS — denied.
- Network authority expansion: defect found, repaired and live-verified.
- Server manifest: PASS.
- Connector exposure parity: OPEN — 40 registered versus 38 exposed.
- Client-data readiness: NOT APPROVED.
- Production activation: OFF.
