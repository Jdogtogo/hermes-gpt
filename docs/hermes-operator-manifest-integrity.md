# Hermes Operator Public Manifest Integrity

## Purpose

The authenticated `chatgpt-operator` connector has a versioned, machine-readable public tool contract. Health is determined from the exact tool-name set and the canonical input-schema fingerprint, not from tool count alone.

Canonical baseline:

- Manifest version: `1.0.0`
- Expected public tools: `38`
- Expected schema fingerprint: `5e3d36f8ffcd1aafcfc39157f0411907710f585dae93136edefa07c496e3d9c8`

The baseline is defined in `operator_manifest.py`. `server.register_tools()` extracts the native FastMCP input schemas after registration, validates the complete surface, and refuses to construct the `chatgpt-operator` server when it detects:

- missing canonical tools;
- unexpected tools;
- duplicate tool names; or
- input-schema drift.

`hermes_operator_status` exposes the resulting `public_manifest` record, including version, expected and registered counts, expected and actual fingerprints, mismatch categories, and PASS/FAIL verdict.

## Intentional Public Contract Changes

Every intentional addition, removal, rename, or input-schema change must be handled as one controlled change:

1. Update the canonical tool-name set when applicable.
2. Increment `MANIFEST_VERSION`.
3. Regenerate and pin `EXPECTED_SCHEMA_FINGERPRINT` from the native registered FastMCP schemas.
4. Update focused tests and any affected operator documentation.
5. Run the focused manifest tests and the relevant broad regression suite.
6. Refresh or recreate the ChatGPT connector when its discovered contract may be cached.
7. Prove the new contract in a genuinely new ChatGPT conversation.

## Genuine-New-Conversation Evidence Gate

Discovery alone is insufficient. Acceptance evidence must include all of the following from a newly created ChatGPT conversation:

1. Compare the discovered public tool names and schemas with the canonical manifest.
2. Invoke at least one read-only operator tool successfully.
3. Obtain a bounded Operator Session and perform one authorised actual write.
4. Read the written content back and verify it exactly.

Record the conversation/session evidence, manifest version, schema fingerprint, write path, and exact read-back result. Do not claim connector freshness from an existing conversation or from tool discovery alone.
