# OpsBrain Governed Publisher V1 — Integration Notes

## Status

**Phase 1 core hardening is implementation-ready and test-clean. Controller integration and real GitHub publication remain separate governed steps.**

Antigravity adjudication `agd_c8487e0e056b4747` returned **HYBRID_PATCH_BASELINE**. The tracked publisher baseline is retained because it already has the stronger security architecture: disposable scratch clone isolation, trusted governance-source comparison, the correct pre-push guard contract, and exact-SHA atomic compare-and-swap protection. The worktree-based replacement was not adopted.

Focused core tests currently pass **21/21**.

## Fixed public contract

The eventual public Controller tool is:

`hermes_ops_brain_publish(expected_commit, expected_remote_sha, dry_run=True)`

Caller-supplied fields are limited to:

- `expected_commit`: exact lowercase 40-character Git SHA
- `expected_remote_sha`: exact lowercase 40-character Git SHA
- `dry_run`: exact boolean

No repository path, branch, remote, URL, command, refspec, scratch path, validator path, guard path, timeout, environment or runner argument is caller-controlled.

## Fixed constants

- Canonical repository: `/home/jfroh/.hermes/ops-brain`
- Canonical branch: `master`
- Remote: `origin`
- Allowed host: `github.com`
- Expected repository identity: `Jdogtogo/hermes-ops-brain`
- Scratch root: `/home/jfroh/.hermes/ops-brain-publish-scratch`
- Validator: `tools/validate_ops_brain.py`
- Pre-push guard: `scripts/opsbrain-pre-push-guard.sh`

## Security architecture retained from the tracked baseline

1. The canonical OpsBrain working copy may be dirty and is never cleaned, reset, stashed, switched, checked out, rebased, merged, added or committed by the publisher.
2. Publication validation occurs in a disposable local clone created with `git clone --local --no-hardlinks --no-checkout` under the fixed scratch root.
3. The configured `origin` must resolve to the exact approved GitHub repository and must not contain credentials or malformed URL data.
4. Remote `master` must equal the caller's exact `expected_remote_sha` before publication proceeds.
5. `expected_remote_sha` must be an ancestor of `expected_commit`.
6. The candidate is rejected if it changes trusted executable governance sources under `tools/` or `scripts/`; a candidate may not self-modify its validator or pre-push guard and then self-validate.
7. The scratch clone is pinned to the exact target commit and exact expected remote baseline.
8. Hooks are disabled in the scratch clone.
9. The validator and pre-push guard are executed only after trusted-source comparison.
10. The pre-push guard receives the standard Git pre-push contract: `refs/heads/master <target> refs/heads/master <expected_remote_sha>` on stdin and `origin <canonical_remote_url>` as argv.
11. Validation/guard execution may not leave the scratch clone dirty or change its HEAD.
12. Git remote preflight uses an exact-SHA atomic CAS lease: `--force-with-lease=refs/heads/master:<expected_remote_sha>` after ancestry proof.
13. Unconstrained force operations remain prohibited: no `--force`, `-f`, `+refspec`, `--delete`, `--mirror`, `--all` or tags publication.
14. Apply performs the same exact CAS release and then verifies `origin/master` equals `expected_commit`.
15. Scratch cleanup is deterministic and never broadens into cleanup/reset of the canonical working copy.

## Hybrid hardening added after Antigravity review

The retained baseline is hardened with these narrow changes:

- **Gate-path/symlink defence:** validator and guard paths must remain inside the disposable scratch repository and may not escape through symlinks.
- **Authority separation:** dry-run/preflight requires `opsbrain:preflight`; real release requires `opsbrain:release`.
- **Exact boolean validation:** `dry_run` must be an actual boolean, not truthy integers or strings.
- **Truthful CAS telemetry:** output records the atomic-CAS/lease strategy explicitly rather than describing it as a generic non-force operation.
- **Regression coverage:** tests cover authority separation, gate-path escape rejection and unconstrained-force prohibition in addition to the tracked baseline controls.

## Why exact `--force-with-lease` is retained

The publisher does **not** permit a destructive force push. The exact form:

`--force-with-lease=refs/heads/master:<expected_remote_sha>`

is used as an atomic compare-and-swap precondition. The publisher first proves `expected_remote_sha` is an ancestor of `expected_commit`; therefore history can only advance. If the remote moves between the initial read and the push, the exact lease fails closed rather than publishing against an unexpected remote state.

## Required authority separation

### Implementation authority

May permit only the Controller implementation worktree to be read/edited/tested/committed. It must not grant GitHub publication.

### OpsBrain preflight/release authority

A dedicated non-standing template should be added during Controller integration, recommended name:

`hermes-opsbrain-release`

Recommended policy:

- level: `workspace`
- apply mode: `direct`
- standing authority: false
- readable root: `/home/jfroh/.hermes/ops-brain`
- writable root: `/home/jfroh/.hermes/ops-brain-publish-scratch`
- egress host: `github.com`
- verbs: `opsbrain: [preflight, release]`
- allowed branch: `master`
- no services, arbitrary workspace exec, credentials, provider-routing, Capacity Broker, Cloudflare, Telegram or unrelated deployment authority

The final real publication remains a distinct human-approved release gate.

## Phase 2 Controller integration

The current Controller worktree contains unrelated dirty changes in `server.py`, `operator_manifest.py`, `operator_policy_templates.py`, manifest/server tests and shadow-resolver files. Those changes must not be reset, stashed, overwritten or silently absorbed by this workstream.

Phase 2 should therefore occur only after either:

1. the owning workstream safely reconciles those changes, or
2. a clean, separately governed integration worktree is available.

Required integration changes are narrow:

1. **`operator_policy_templates.py`** — add `hermes-opsbrain-release` with only the fixed roots, GitHub egress, `opsbrain:preflight/release`, and `master` restriction.
2. **`server.py`** — import the publisher and expose only `expected_commit`, `expected_remote_sha`, and `dry_run`.
3. **`operator_manifest.py`** — register `hermes_ops_brain_publish`, increment the expected tool count and regenerate/reconcile the schema fingerprint through the established manifest path.
4. **Tests** — prove one tool registration, bounded schema, exact policy-template resolution, manifest count/fingerprint consistency and no changes to unrelated public surfaces.

## Core test evidence

`python3 -m pytest -q test_operator_ops_brain_publish.py`

Current result: **21 passed**.

Coverage includes:

- dry-run happy path
- exact apply and remote verification
- strict SHA and exact boolean validation
- bad/malformed/credential-bearing remote URLs
- remote divergence
- non-ancestor rejection
- trusted `tools/` / `scripts/` immutability
- validator failure
- guard failure
- post-validation dirty state
- Git preflight rejection
- post-push verification mismatch
- scratch cleanup failure
- gate-path/symlink escape defence
- separate preflight/release authority
- exact CAS lease presence
- prohibition of unconstrained force forms
- no mutation of the canonical working copy

## Current OpsBrain publication target

The local canonical OpsBrain work currently culminates at:

`4365f295bc2a4fa072c27bdd24216889f1fc4429`

which includes the preceding Antigravity baseline record:

`ebc01c4c1b747386b07a44a12953aa6039abc1c0`

Do not reuse an old remote SHA at release time. The caller must obtain a fresh `origin/master` SHA immediately before the governed preflight, and the publisher independently verifies exact equality before any publication attempt.
