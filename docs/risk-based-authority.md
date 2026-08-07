# Hermes Risk-Based Authority

## Purpose

Hermes authority is granted according to verified risk, not merely by tool name or elapsed time. Technical containment carries the routine safety burden; human approval is reserved for material increases in scope, impact, data sensitivity, network reach, or reversibility risk.

Standing authority is never an unrestricted permanent operator session. It is a revocable policy-bound authorization that remains valid only while the exact approved risk facts, template identity, containment controls, branch guard, baseline guard, and single-writer ownership remain unchanged.

## Risk tiers

### Tier 0 — Read-only visibility

Read-only status, diagnostics, audit inspection, and bounded non-secret project visibility. No write, service, deployment, network, credential, client-data, or financial-data capability. No recurring human approval is required when the policy remains read-only and bounded.

### Tier 1 — Contained reversible maintenance

Standing authority may be used only for a named policy template whose deterministic classifier resolves to LOW risk and Tier 1. Required controls include:

- bounded readable and writable roots;
- container-or-stronger verified containment;
- no network egress;
- hard secret-path denies;
- exact branch guard and baseline guard;
- persistent single-writer ownership lock;
- protection against untracked-file deletion;
- version-controlled rollback;
- required deliverable verification before completion;
- no service restart, deployment, destructive delete, force push, external communication, client-identifiable data, financial data, credential access, or paid-route change.

A Tier 1 standing authorization has no authorization expiry. Operational watchdog deadlines are separate and do not silently revoke or renew authorization. Any material policy/risk change invalidates the standing authority and the runtime fails closed.

## Tier 2 — Material bounded task

Material but bounded work uses a task-bound Authority Bundle. The approval binds the exact risk-factor snapshot, roots, verbs, template, policy version/hash, and required deliverables. Completion is refused until required deliverables are verified. Risk escalation invalidates the bundle and requires renewed approval.

## Tier 3 — High-impact boundary

High-impact actions require explicit human approval at the material boundary and are never eligible for standing authority. Examples include service restarts, deployment/configuration changes, destructive deletion, force push, external communications, private/allowlisted network egress, client-identifiable or regulated data, and financial data.

## Prohibited standing/bundle boundaries

The standing/bundle pathway fails closed for direct secret or credential access, unrestricted network egress, paid-route changes, root expansion beyond the approved policy, or weakened containment. These conditions cannot be converted into standing authority by duration changes or caller assertions.

## Runtime controls

### Policy and risk binding

Every standing authority stores the complete approved `RiskFactors` snapshot and its deterministic hash. Runtime policy resolution re-resolves the local named template, recomputes its normalized snapshot and risk, and accepts the standing authority only when the approved and current facts match exactly.

### Single-writer ownership

Writable worktrees use persistent ownership locks stored in the operator-session state root, outside the repository. A second authority cannot claim an owned worktree. Multi-root claims roll back only locks newly created by the failed claim; a re-entrant lock already owned by the same authority is preserved.

### Branch, baseline, and untracked files

Tier 1 requires verified branch and baseline guards. Governed commit operations are expected to refuse baseline/branch mismatch, refuse out-of-scope tracked changes, and leave unrelated untracked files untouched. Broad clean/reset/stash or untracked deletion is not part of standing maintenance authority.

### Network and secrets

Workspace execution is expected to run with network disabled for Tier 1. Hard-denied secret paths are containment evidence, not evidence that secret access was requested. A request for direct secret/credential access is prohibited.

### Delegation

Delegated tasks capture an immutable authority envelope. Normal Operator Sessions retain expiry checks. Standing-authority envelopes carry `authority_kind=standing` and no authorization expiry; they remain usable only while the current `OperatorPolicy` still resolves the same active standing authority and snapshot.

### Deliverable evidence

Authority Bundles can declare required deliverables. A bundle cannot complete until all required deliverables are explicitly verified. Tier 1 policy requires deliverable verification as an invariant even though verification naturally occurs after execution.

## Approval forecasting and audit

Session requests compute deterministic risk before the pending request is created. The approval forecast reports risk class, tier, reasons, standing eligibility, bundle eligibility, human-approval requirement, and risk-factor hash. A requested standing authority is rejected before approval unless it resolves to Tier 1 LOW risk.

At approval, Hermes recomputes the risk from the immutable normalized snapshot. Safe audit evidence includes the policy template, risk class/tier, factor hash, writable roots, verbs, allowed branches, baseline-guard state, approver, standing-authority id when applicable, and the distinction between an operational deadline and authorization expiry. Secret values are never audit fields.

## Revocation and escalation

The existing operator revoke surface accepts a standing authority id (`sa_...`) for emergency revocation. Revocation releases writer locks. Template drift, risk escalation, containment loss, branch/baseline mismatch, or ownership-lock failure invalidates standing authority and causes policy resolution to fail closed rather than silently falling back to broader environment authority.

## Known limitations and non-goals

- Standing authority is intentionally narrow and template-specific; it is not a general owner-mode replacement.
- Deployment and service restart remain Tier 3 and require explicit approval.
- Host/root repairs such as `/etc/fstab` are outside this contained workspace authority unless a separately reviewed host-maintenance pathway is provided.
- Canonical repository promotion is a separate bounded integration workstream and must not overwrite or clean a dirty development worktree.
- The live connector must be restarted/reloaded only after committed code, manifest/schema verification, and an explicit deployment gate.
