# Hermes Controller Manifest Integrity Hardening — Evidence Report

**Date:** 2026-08-04  
**Repository:** `/home/jfroh/.hermes/worktrees/hermes-gpt-operator-session-chatgpt`  
**Branch at start:** `codex/operator-session-chatgpt-20260713`  
**Starting HEAD:** `083ab7727052412f0d09faab738fd090f49a1e57`

## Scope

Implement bounded integrity enforcement for the authenticated ChatGPT operator connector's public MCP tool contract. Provider routing, delegation result extraction, Antigravity execution, authority semantics, service configuration, and unrelated workspace files are out of scope.

## Implementation

- Added `operator_manifest.py` with:
  - explicit manifest version `1.0.0`;
  - canonical 38-tool name set;
  - recursive mapping-key canonicalization;
  - deterministic compact UTF-8 JSON serialization;
  - SHA-256 schema fingerprinting independent of registration order;
  - separate missing, unexpected, duplicate, and schema-drift classifications.
- Updated `server.register_tools()` to extract names and input schemas from FastMCP's native registered tool manager after registration.
- Preserved registration duplicates in the validation input instead of allowing the registry map to hide them.
- Made `chatgpt-operator` construction fail loudly when the canonical set or schema fingerprint does not match.
- Extended `hermes_operator_status()` with a backward-compatible `public_manifest` object.
- Replaced the count-only health assertion with exact set/schema validation while retaining expected count `38` as informational evidence.
- Added focused manifest unit tests and operational change-control documentation.

## Canonical Baseline

- Expected public tool count: `38`
- Expected schema fingerprint: `5e3d36f8ffcd1aafcfc39157f0411907710f585dae93136edefa07c496e3d9c8`
- Historical baseline: 34 tools
- Accepted additions:
  - `hermes_antigravity_dispatch`
  - `hermes_antigravity_dispatch_cancel`
  - `hermes_antigravity_dispatch_status`
  - `hermes_antigravity_smoke_test`

## Files in the Bounded Package

- `operator_manifest.py`
- `server.py`
- `test_operator_manifest.py`
- `test_server.py`
- `pyproject.toml`
- `docs/hermes-operator-manifest-integrity.md`
- `docs/manifest-integrity-hardening-evidence-2026-08-04.md`

## Verification Record

Completed controller verification:

1. Focused manifest and live-surface regression:
   - `pytest -q test_operator_manifest.py test_server.py::test_operator_status_reports_actual_registered_tools`
   - Result: PASS, 7 tests.
2. Broad relevant regression:
   - `python logs/run_pytest_without_operator_session.py test_server.py test_operator_diagnostics.py`
   - Result: PASS, 55 tests.
   - The wrapper removes only `HERMES_GPT_OPERATOR_SESSION_ROOT` and `HERMES_GPT_OPERATOR_SESSION_ID` so tests exercise their intended no-session baseline. Running the suite without that isolation produced one false failure because the test process inherited the currently approved Operator Session; no authority code or test was changed.
3. Full repository suite:
   - `python logs/run_pytest_without_operator_session.py`
   - Result: PASS, no failures.
4. Native baseline generation:
   - FastMCP's registered input schemas produced fingerprint `5e3d36f8ffcd1aafcfc39157f0411907710f585dae93136edefa07c496e3d9c8` for the exact 38-tool surface.

Remaining acceptance gates:

1. Runtime read-only check after deployment/restart:
   - call `hermes_operator_status`;
   - verify `public_manifest.status == "PASS"`;
   - verify registered count `38` and exact pinned fingerprint.
2. Genuine-new-ChatGPT-conversation gate:
   - compare discovery with the canonical manifest;
   - execute one read call;
   - execute one authorised actual write;
   - verify exact read-back.

## Risks

- The integration uses FastMCP's native tool manager to capture generated input schemas. A future MCP SDK internal registry API change should fail loudly rather than silently bypass validation.
- Schema descriptions and defaults are part of the fingerprint. Intentional documentation-level schema changes therefore require a manifest version/fingerprint update.
- Existing ChatGPT conversations may retain stale connector discovery; only a genuinely new conversation satisfies the freshness gate.

## Next Action

Commit only the listed owned files, deploy/restart the operator connector when safe, verify the runtime `public_manifest` PASS result, then complete the genuine-new-conversation evidence gate.
