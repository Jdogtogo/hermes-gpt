# Operator Regression Maintenance Evidence - 2026-07-31

## Baseline

- Workspace: `/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt`
- Branch: `codex/operator-session-chatgpt-20260713`
- Baseline commit: `f7b907a70445f9ec6a422439081af84123c9c106`
- Clean comparison worktree: `/tmp/hermes-operator-clean.Dejfp7`

## Reproduction

The two originally named focused failures did not reproduce at the baseline commit, either in the dirty target worktree or in a clean detached worktree at `f7b907a`.

- `uv run pytest -q test_operator_session_requests.py::test_long_extension_request_is_retained_and_policy_bounded`: passed.
- `uv run pytest -q test_operator_service_sandbox.py::test_operator_service_drop_in_covers_all_active_policy_writable_roots`: passed.
- Clean detached full suite at `f7b907a`: 585 passed.

Further inspection found remaining coverage/security gaps against the handoff requirements:

- Extension approval did not explicitly reject `decided_by == session_id`.
- Extension request audit evidence did not record requested duration/current expiry; approval audit did not record requested duration.
- Service sandbox coverage proved writable-root coverage but did not prove that the OperatorPolicy hard-denied boundary remains active inside the broader systemd writable envelope.

## Root Cause

- Extension handling: production code relied on approve-extension being local-only, but did not encode the no-self-approval invariant at the function boundary. Audit evidence also omitted requested extension seconds from approval records and had no request record.
- Service sandboxing: test coverage modeled the systemd drop-in outer boundary but did not assert the policy-layer hard-deny boundary that keeps sensitive paths inaccessible when they sit under a writable root needed by another maintenance template.

## Files Changed

- `operator_sessions.py`
- `test_operator_session_requests.py`
- `test_operator_service_sandbox.py`
- `evidence/operator-regression-maintenance-2026-07-31.md`

Pre-existing dirty files intentionally not included in this fix:

- `operator_approval_notify.py`
- `operator_approval_web.py`
- `operator_workspace.py`
- `test_operator_restart_policy_hardening.py`

## Behaviour Before

- A direct call to `approve_extension(request_id, decided_by=session_id)` could approve the session's own pending extension.
- Extension approval audit recorded resulting expiry but not the requested extension duration.
- Extension request creation was not independently audited.
- Service sandbox tests did not prove that hard-denied paths remain denied by OperatorPolicy inside the systemd writable-root boundary.

## Behaviour After

- `approve_extension()` raises `PermissionError` when `decided_by` equals the target session id.
- Extension request audit records request id, session id, requested seconds, and current expiry.
- Extension approval audit records requested seconds and resulting expiry.
- Service sandbox tests create a real approved overnight-maintenance session and verify a hard-denied path under the systemd writable envelope remains denied by OperatorPolicy.

## Validation

- `uv run pytest -q test_operator_session_requests.py`: 12 passed.
- `uv run pytest -q test_operator_service_sandbox.py`: 2 passed.
- `uv run pytest -q test_operator_session_requests.py test_operator_sessions.py test_operator_approval_web.py test_operator_approval_notify.py`: 41 passed.
- `uv run pytest -q test_operator_service_sandbox.py test_operator_restart_policy_hardening.py test_operator_workspace.py`: 177 passed.
- `uv run pytest -q test_operator_*.py`: 536 passed.
- `uv run pytest -q`: 588 passed.
- `git diff --check -- operator_sessions.py test_operator_session_requests.py test_operator_service_sandbox.py`: passed.

The repository metadata and README identify pytest as the required release check. No configured ruff, mypy, pyright, black, tox, or Makefile lint target was present.

## Security Boundary Confirmation

- No readable or writable roots were broadened.
- No service unit allowlist was relaxed.
- No operator approval requirement was weakened.
- No self-approval path remains for extension approvals at the function boundary.
- No credentials, tokens, private session databases, or raw policy/session state were written to this report.
- Existing hard-denied paths remain enforced by OperatorPolicy even where the systemd drop-in must expose a parent writable root.

## Remaining Risks

- The originally reported failures could not be reproduced at `f7b907a`, so this fix addresses verified residual gaps rather than a captured failing baseline for those exact historical failures.
- Pre-existing dirty changes in approval UI and approval-web restart code remain outside this commit and require separate review.

## Rollback

Revert the bounded commit that includes this evidence report and the three source/test files:

`git revert <commit>`

## Recommendation

ACCEPT
