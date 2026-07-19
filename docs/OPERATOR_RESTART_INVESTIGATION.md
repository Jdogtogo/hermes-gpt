# Hermes Operator Restart — Policy Resolution Investigation

**Date:** 2026-07-19
**Investigator:** Claude Code (read-only diagnostic pass)
**Subsystem:** hermes-gpt ChatGPT operator (session handling, policy resolution, `hermes_operator_service_restart`)
**Status:** Root cause **CONFIRMED**. Operational fix **APPLIED and verified 2026-07-19 ~18:24 AEST** (owner-approved). See "Resolution applied" at the end.

---

## Verdict (one line)

`hermes_operator_service_restart` fails because the **active session's stored policy
snapshot has no `policy_template` field**, so `resolve_effective_authority().policy_template`
resolves to `None` and the restart gate `None != "hermes-gpt-operator-maintenance"` rejects it.
The field is absent because the process that *writes* session snapshots (the **approval-web
service, running since 2026-07-16 05:38**) predates the commit that persists `policy_template`
(**377dce1, 2026-07-18 19:28**), while the process that *enforces* the check (the operator
server, started 2026-07-18 19:28) has the new code. The approval is **not** missing — only this
one field is dropped at write time by a stale writer.

---

## Step 0 — Source map (file paths reported before analysis)

The operator tools are **not** in the Tax Calculator repo (grep for the tool names and the
template string returned no matches there). They live in the `hermes-gpt` worktree the operator
service runs from:

Worktree: `/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt`
(branch `codex/operator-session-chatgpt-20260713`, repo github.com/asimons81/hermes-gpt)

| Tool / concern | File | Symbol |
|---|---|---|
| `hermes_operator_service_restart` | `operator_workspace.py` | `hermes_operator_service_restart()` (L390), gate at **L404** |
| `hermes_operator_session_request` | `server.py` (tool) → `operator_sessions.py` | `request_session()` (L576) |
| `hermes_operator_status` / `hermes_operator_session_status` | `server.py` + `operator_policy.py` | via `OperatorPolicy` / `resolve_effective_authority` |
| Effective-authority resolver (read path) | `operator_sessions.py` | `resolve_effective_authority()` (L123), field read at **L236** |
| Policy object used by workspace tools | `operator_policy.py` | `OperatorPolicy.__init__` (L625), authority at **L630** |
| Session store / snapshot writer | `operator_sessions.py` | `create_session()` (L369), `approve_session_request()` (L634), inject at **L658** |
| Template registry | `operator_policy_templates.py` | `POLICY_TEMPLATES["hermes-gpt-operator-maintenance"]` (L35) |
| Approval writer (runs `approve_session_request`) | `operator_approval_web.py` | L205, L280 |
| Session DB (service) | `/home/jfroh/.hermes/operator-sessions/chatgpt-operator/operator_sessions.sqlite3` | tables: `operator_sessions`, `policy_snapshots`, `session_creation_requests`, `session_extension_requests` |
| Active-session pointer | `/home/jfroh/.hermes/operator-sessions/chatgpt-operator/active_session_id` | plain text session id |

Service runtime config (from `hermes-gpt-chatgpt-operator.service`):
`HERMES_GPT_OPERATOR_SESSION_ROOT=/home/jfroh/.hermes/operator-sessions/chatgpt-operator`,
`HERMES_GPT_OPERATOR_SESSION_ID=ops_rds4NPYRVCf-_T3oQlQVOT8JqN5PUN5-`.

---

## The two policy-resolution paths (Step 3 diff)

**Restart tool** — `operator_workspace.py:398-408`:
```python
policy = op.OperatorPolicy()
policy.require_level("workspace")
if policy.session_id is None:
    raise PermissionError("An active approved Operator Session is required.")
authority = op_sessions.resolve_effective_authority()
if authority.policy_template != _OPERATOR_SERVICE_RESTART_TEMPLATE:   # "hermes-gpt-operator-maintenance"
    raise PermissionError(
        "Operator service restart requires the "
        f"{_OPERATOR_SERVICE_RESTART_TEMPLATE!r} policy template.")
```

**Workspace edit tools** — `operator_workspace.py:567-569` (e.g. `hermes_workspace_patch`):
```python
policy = op.OperatorPolicy()
policy.require_level("workspace")
policy.require_workspace_path(path)
```

Same store, same lookup key, same resolver: `OperatorPolicy.__init__` (`operator_policy.py:630`)
also derives its authority from `resolve_effective_authority()`. The **only** extra condition the
restart tool imposes is the equality check on `authority.policy_template`. Everything the workspace
tools check (`level == workspace`, writable roots, path policy) is satisfied by the active session;
only the `policy_template` equality is not. `policy_template` is read from the stored snapshot at
`operator_sessions.py:236`:
```python
policy_template=(str(snapshot["policy_template"]) if snapshot.get("policy_template") else None),
```
When the snapshot has no `policy_template` key, this is `None`.

---

## Evidence log (raw tool output)

### Step 1 — the approved maintenance session exists; its stored snapshot has NO `policy_template`

Active pointer (governs resolution; read before the env id):
```
$ cat .../chatgpt-operator/active_session_id
ops_3OD6apYZ26y1V_2FJlX-EkQ-oHyPI1Zq       (len 36)
```
The pointer (file mtime 2026-07-19 17:55) differs from the unit's
`HERMES_GPT_OPERATOR_SESSION_ID=ops_rds4NPYRVCf-...`; `resolve_effective_authority` reads the
pointer first (`operator_sessions.py:154-160`), so `ops_3OD6…` is the effective session.

Session row (approved, unrevoked, unexpired):
```
session_id                            hash12        created_at  expires_at  revoked_at  approval_state
ops_3OD6apYZ26y1V_2FJlX-EkQ-oHyPI1Zq  b25a3c352804  1784447708  1784458508  (null)      approved
```

Stored policy snapshot for that session (integrity-verified — the stored hash equals the SHA-256 of
the stored JSON, so the record is intact, not corrupted):
```
STORED snapshot_hash : b25a3c35280476a078b53af771507f08241724a873f33cd39abdf8ccce4d665f
sha256(stored cj)    : b25a3c35280476a078b53af771507f08241724a873f33cd39abdf8ccce4d665f
stored cj has "policy_template" key : False
canonical_json:
{"apply_mode":"direct","egress_hosts":[],"git_remotes":[],
 "hard_denied_paths":[...],"level":"workspace",
 "readable_roots":["/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"],
 "service_units":["hermes-gpt-chatgpt-operator.service"],
 "verbs":{"filesystem":["edit","read"],"git":["commit"],"services":["restart"],"tests":["run"]},
 "version":1,
 "writable_roots":["/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt"]}
```
The snapshot grants exactly what the restart needs — `level=workspace`, the operator worktree as
writable root, `service_units=["hermes-gpt-chatgpt-operator.service"]`, `verbs.services=["restart"]`
— but the `policy_template` key is **entirely absent** (not null; missing).

The creation request for this session recorded the template correctly:
```
request_id           = sr_2e5e81e0
policy_template      = hermes-gpt-operator-maintenance
status               = approved
resulting_session_id = ops_3OD6apYZ26y1V_2FJlX-EkQ-oHyPI1Zq
```
So the template identity was known at request time; it just never reached the snapshot.

Across the whole store, **only 1 of 8 distinct snapshots contains a `policy_template`** — the
exception (hash `8e2fc5e92e8b…`, session `ops_qQfT2…`) matches byte-for-byte the hash the current
on-disk code produces for the maintenance template *with* the injection applied (see Step 4). Every
snapshot written by the live approver lacks it.

### Step 2 — which record the restart tool resolves at call time

Reproduced with the on-disk code against the live DB/pointer (read-only; no writes):
```
resolve_effective_authority():
  status          : active
  session_id      : ops_3OD6apYZ26y1V_2FJlX-EkQ-oHyPI1Zq
  is_active       : True
  level           : workspace
  policy_template : None        <-- gate compares this to "hermes-gpt-operator-maintenance" => fails
```
This reproduces the reported error exactly. The tool resolves the correct, active, approved session
(same one the workspace tools use) — the resolution target is not stale or wrong; the field on it is.

### Step 4 — name-vs-id / propagation check (the mechanism)

There is no name-vs-id mismatch. `policy_template` is compared as a literal string on both sides
(`operator_workspace.py:367` constant vs the snapshot string). The defect is **propagation**: the
maintenance template's inner `policy` dict (`operator_policy_templates.py:38-50`) contains no
`policy_template` key, and the field is injected only at approval time:
```python
# operator_sessions.py:654-662  (approve_session_request)
policy = json.loads(row["resolved_policy_json"])
policy["policy_template"] = str(row["policy_template"])   # <-- introduced in commit 377dce1
record = create_session(policy, duration_seconds=duration, root=root, now=current)
```
Hash proof that the stored snapshot was NOT produced by this current code path:
```
hash of maintenance template WITH injection (current code) : 8e2fc5e92e8b...   (has "policy_template")
hash of maintenance template WITHOUT injection             : f75178004e8c...
stored hash for the active session                         : b25a3c352804...   (no key at all)
```
The active session's snapshot (`b25a3c…`) matches neither current-code output; it was written by an
older normaliser that emitted no `policy_template` key. Because snapshots are content-addressed with
`INSERT OR IGNORE` (`operator_sessions.py:388`), the stale writer's output persists and is reused.

### Steps 5 & 6 — stale state / conversation binding (the "why", with git + process evidence)

The writer and the enforcer are **different long-running processes** that snapshotted the module into
memory at different times, straddling the fix commit:

```
# Enforcer — operator server (serves the restart tool), NEW code:
hermes-gpt-chatgpt-operator.service  ExecMainStartTimestamp = Sat 2026-07-18 19:28:41 AEST  PID 1135949

# Writer — approval web (runs approve_session_request -> create_session -> snapshot), STALE code:
hermes-gpt-approval-web.service      ExecMainStartTimestamp = Thu 2026-07-16 05:38:06 AEST  PID 4012543
```
```
# approve_session_request call sites (the writer):
operator_approval_web.py:205  op_sessions.approve_session_request(request_id, decided_by="localhost")
operator_approval_web.py:280  record = op_sessions.approve_session_request(request_id, decided_by=source)

# git: the commit that persists policy_template into the snapshot (injection + the restart gate):
377dce1  2026-07-18 19:28:01 +1000  Fix workspace secret discovery and add gated self-restart
```
The approval-web process (PID 4012543) has run continuously since **2026-07-16 05:38**, i.e. **before
377dce1 (2026-07-18 19:28)**. It has never been restarted onto the fixed code, so every session it
approves is snapshotted by pre-fix logic and lands without `policy_template`. `ops_3OD6…` was minted
≈2026-07-19 17:55 (created_at 1784447708) — a day *after* the operator server got the new enforcing
code, but by the still-stale approver. The lone correct snapshot (`8e2fc5e92e8b`, `ops_qQfT2…`,
created ≈2026-07-19 10:23) was produced by the fixed code running out-of-band (manual/CLI or test),
proving the on-disk code is correct — it simply isn't the code the live approver is running.

Conversation/session binding is **not** the problem: the pointer correctly binds to the freshly
approved session, and both tool families resolve that same session. Working tree is clean
(`git status --porcelain` empty), so on-disk == committed HEAD; the divergence is purely in-memory
(process age), not on disk.

---

## Ranked hypotheses

| # | Hypothesis | Confidence | Supporting evidence | Contradicting |
|---|---|---|---|---|
| **1** | **Stale writer / fresh enforcer split-brain**: the approval-web process (started 2026-07-16, pre-377dce1) writes snapshots without `policy_template`; the operator server (post-377dce1) enforces the field. | **Confirmed** | Snapshot has no key (integrity-verified); `resolve_effective_authority().policy_template == None` reproduced; approver process start 07-16 predates injection commit 377dce1 (07-18 19:28); 7/8 snapshots lack the key; the 1 correct snapshot matches the fixed-code hash exactly. | None found. |
| 2 | Template propagation gap in the code itself (template `policy` dict lacks `policy_template`; only injected at approve time). | High (contributing factor) | `operator_policy_templates.py:38-50` has no `policy_template`; injection sits solely at `operator_sessions.py:658`. | On-disk code *does* inject correctly (hash `8e2fc5…` proves it), so on current code alone the bug would not reproduce — it requires the stale process (H1) to manifest. |
| 3 | Name-vs-ID mismatch in the comparison. | Refuted | Both sides use the literal string `"hermes-gpt-operator-maintenance"`; the request row stores that exact name. | Failure is `None != name`, not `idA != nameB`. |
| 4 | Approval missing / session not approved / wrong session resolved. | Refuted | `approval_state=approved`, unrevoked, unexpired; pointer binds correctly; workspace tools work on it. | Explicitly disproven by the raw session row and live resolver output. |
| 5 | Stale env `HERMES_GPT_OPERATOR_SESSION_ID` outranking the approval. | Refuted | Env id `ops_rds4…` differs from pointer, but resolver reads the pointer first (`ops_3OD6…`). | Even the env session shares the pre-fix snapshot family; swapping it would not add the field. |

---

## Root cause (confirmed)

A **deploy-ordering / process-lifetime split-brain across two services that share one session
database**. The snapshot **writer** (`approve_session_request`, executed by
`hermes-gpt-approval-web.service`, PID 4012543, running since 2026-07-16 05:38) is older than commit
**377dce1 (2026-07-18 19:28)** that persists `policy_template` into the immutable snapshot. The
snapshot **reader/enforcer** (`hermes_operator_service_restart` in `hermes-gpt-chatgpt-operator.service`,
started 2026-07-18 19:28) has that commit and now *requires* `policy_template ==
"hermes-gpt-operator-maintenance"`. Every session the stale approver mints is therefore snapshotted
without the field, and `resolve_effective_authority().policy_template` returns `None`, which the
restart gate rejects — even though the session genuinely grants `services:restart` for the exact unit.

---

## Smallest safe fix (PENDING APPROVAL — NOT APPLIED)

**Primary (operational, no code change):**
1. Restart the snapshot writer so it loads post-377dce1 code:
   `systemctl --user restart hermes-gpt-approval-web.service`
2. Request a **new** `hermes-gpt-operator-maintenance` session and approve it. The new snapshot will
   carry `policy_template` (verified: current code hashes it to `8e2fc5e92e8b…` with the key present),
   and the restart gate will pass. The current `ops_3OD6…` snapshot is immutable and cannot be
   back-filled, so a fresh approval is required.

Caveats to weigh before doing this:
- Per operator memory, approving a session **repoints** the active pointer and displaces the current
  active session — do it deliberately, not mid-task.
- General deploy discipline: after editing shared modules, **every** service that imports them
  (operator server *and* approval-web, plus any owner/sidecar unit) must be restarted together, or
  writer/reader will diverge again.

**Optional defensive code hardening (larger; separate change, also pending approval):** have the
restart gate resolve template identity from the authoritative
`session_creation_requests.policy_template` column (which is `NOT NULL` and always correct) rather
than the snapshot field, or make snapshot persistence of `policy_template` a validated invariant at
`create_session` time so a writer can never omit it. This removes the dependency on every writer
being freshly deployed. Not required to clear the immediate failure.

---

## What was NOT done (scope compliance)

Read-only pass only. No code edited, no config/units changed, no sessions created/approved/denied,
no services restarted, no DB writes. The Tax Calculator repo was not modified. All probes were reads
(`sqlite3 SELECT`, `systemctl show`, `git log`, and an import-only Python probe calling
`resolve_effective_authority()` / `normalize_policy()` / `snapshot_hash()` with no persistence).

---

## Resolution applied (2026-07-19 ~18:24 AEST, owner-approved)

The **primary operational fix** was executed after explicit owner approval. No source code was
changed; the fix was purely operational (restart the stale writer + mint a fresh session through the
fixed code).

**1. Restarted the stale writer** so it loads post-377dce1 code:
```
systemctl --user restart hermes-gpt-approval-web.service
# before: PID 4012543, started Thu 2026-07-16 05:38:06
# after : PID 1826252, started Sun 2026-07-19 18:23:30, active/running, listening 127.0.0.1:7690
```

**2. Minted + approved a fresh maintenance session** (break-glass local CLI approval, mirroring
`server.hermes_operator_session_request` then `approve_session_request`, against the live service
session root `.../operator-sessions/chatgpt-operator`):
```
request_id           : sr_1065a0a4  (template hermes-gpt-operator-maintenance, capped 3600s)
new session_id       : ops_hzV7P1797weg0G4ddY6HcDUqRNTZBLXT
active pointer        : ops_3OD6…  ->  ops_hzV7P1797weg0G4ddY6HcDUqRNTZBLXT   (repointed, expected)
```

**3. Verified end-to-end** (independent sqlite read, separate process, WAL committed):
```
session_id      : ops_hzV7P1797weg0G4ddY6HcDUqRNTZBLXT
approval_state  : approved
expires_at      : 1784453058   (~1 hour from creation)
policy_template : hermes-gpt-operator-maintenance    <-- now present in the snapshot

resolve_effective_authority().policy_template : 'hermes-gpt-operator-maintenance'
restart-gate simulation:
  policy_template == maintenance : True
  operator unit granted          : True
  verbs.services has 'restart'    : True
  => restart gate WOULD PASS
```

**Outcome:** `hermes_operator_service_restart` will now pass its policy gate for the active session.
Because the writer (approval-web) was restarted onto the fixed code, **future** sessions approved
through the normal Telegram / localhost path will also carry `policy_template` — the split-brain is
closed.

**Notes / follow-ups:**
- The prior active session `ops_3OD6…` was displaced (pointer repointed) — this is the intended
  effect of approving a new session. The old pointer value is recorded above if a restore is ever
  wanted (it would reintroduce the bug, so not recommended).
- The new session expires ~1 hour after creation (epoch 1784453058). If the operator restart is not
  exercised before then, request+approve another maintenance session (now that the writer is fixed).
- **Deploy discipline (root prevention):** after editing shared modules, restart *every* service
  that imports them together (operator server + approval-web + any owner/sidecar unit), or writer and
  reader will diverge again.
- The optional code-hardening (resolve template identity from the `NOT NULL`
  `session_creation_requests.policy_template` column, or enforce the snapshot invariant in
  `create_session`) remains **not applied** and available as a separate, more durable change.

---

## Durable code-hardening (implemented on branch; NOT yet deployed)

Implemented as a reviewed diff, pending explicit approval before commit/deploy. Summary:

1. **Snapshot invariant.** `operator_sessions.create_session()` now refuses to persist an
   *approved* session whose normalized snapshot has no non-empty `policy_template`, raising the new
   `SessionPolicyInvariantError`. This is the single chokepoint through which every snapshot is
   written, so no path (normal approval, break-glass CLI, or a future caller) can mint an unbound
   approved session.
2. **Explicit approval-boundary check.** `operator_sessions.approve_session_request()` validates the
   request's `policy_template` is non-empty *before* creating the session and fails the approval
   explicitly if not, rather than producing a partially valid session.
3. **Single authoritative resolution for the gate.** `OperatorPolicy` now exposes `policy_template`,
   sourced from the *same* immutable snapshot as `level`/`verbs`/`service_units`.
   `hermes_operator_service_restart` reads every gate condition from that one `OperatorPolicy()`
   object and no longer performs a second, independently-resolved `resolve_effective_authority()`
   lookup that could disagree. It also requires `session_status == "active"` explicitly rather than
   inferring it.
4. **Regression tests** (`test_operator_restart_policy_hardening.py`): normal Telegram approval;
   localhost/break-glass approval; missing `policy_template` (at both approval and creation);
   stale-writer/new-reader version mismatch (a legacy snapshot with no template is written directly,
   then shown to fail-close at the restart gate while workspace authority still resolves);
   maintenance-policy restart allowed (schedules the exact unit); non-maintenance-policy restart
   denied (rejects on template value, not just presence).

Full suite after the change: **532 passed, 0 failed, 0 errors, 0 skipped**.

---

## Coordinated restart order for services importing the shared session code

The shared modules are `operator_sessions.py` and `operator_policy.py` (which imports the former);
`operator_workspace.py` hosts the restart gate. Every long-running process that imports them holds
the code **in memory from its start time** — editing the files on disk changes nothing until the
process is restarted. That process-age skew across a shared session DB is exactly what caused this
incident.

**Services that load THIS worktree's copy** (`~/.hermes/worktrees/hermes-gpt-operator-session-chatgpt`)
— verified from each unit's `ExecStart`:

| Service | Port | Role | Imports |
|---|---|---|---|
| `hermes-gpt-approval-web.service` | 7690 | **Writer** — `approve_session_request` → `create_session` mints snapshots + repoints the pointer | `operator_sessions`, `operator_policy` |
| `hermes-gpt-chatgpt-operator.service` | 7680 | **Reader / enforcer** — serves the restart gate | `operator_policy`, `operator_workspace`, `operator_sessions`, `operator_policy_templates` |

The other two hermes-gpt user services run **different worktrees** and are *not* affected by edits
confined to this one — restart them only if/when the same change is deployed into their worktrees:
`hermes-gpt-sidecar-bridge.service` (7677, worktree `fix-restricted-notebooklm-runtime`) and
`hermes-gpt-owner-local.service` (7679, worktree `hermes-file-bridge`).

**Required order (writer before reader):** the only unsafe pairing is **new reader + old writer**
(the incident: the enforcer requires a field the stale writer never persisted). New writer + old
reader is benign (the old reader simply ignores the extra field). Therefore, after checking out the
change into a worktree, restart in this order:

```
# 1. Writer first — starts persisting policy_template into every new snapshot:
systemctl --user restart hermes-gpt-approval-web.service

# 2. Reader/enforcer second — begins requiring it, with the writer already compliant:
systemctl --user restart hermes-gpt-chatgpt-operator.service

# 3. Mint + approve a FRESH session. Sessions approved before step 1 remain template-less and are
#    (correctly) rejected by the restart gate until replaced.
```

Never restart the enforcer ahead of the writer. Treat all processes sharing a worktree's
`operator_sessions.py` as a single deploy unit; if in doubt, restart the writer(s) first, then the
reader(s), then re-approve a session. (Verification only needs the writer and reader on matching
code — a mismatch is what the new `SessionPolicyInvariantError` and the single-resolution gate now
make loud instead of silent.)
