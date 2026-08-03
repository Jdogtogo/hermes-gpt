# Delegated Final-Answer Extraction Repair

Date: 2026-08-03
Status: PASS

## Objective

Separate the delegated worker's caller-facing final answer from diagnostic warnings, reasoning/transcript output, raw stdout and stderr.

## Root cause

`hermes_delegated_task_result()` returned the redacted raw worker `stdout` and `stderr` but did not expose a dedicated final-answer field. Hermes CLI output may contain a Tirith warning, a reasoning transcript and the final response in one stream.

## Implementation

- Added deterministic final-answer delimiters for newly delegated workers.
- Added `final_answer` and `final_answer_extraction_status` to terminal task results.
- Preserved existing raw `stdout`, `stderr`, messages, changed-files and authority fields.
- Added fail-closed extraction statuses for empty, incomplete, missing and ambiguous output.
- Added a narrow legacy fallback for a simple machine-token terminal line or a single non-diagnostic line.
- Applied existing output redaction to extracted final answers.

## Files changed

- `operator_delegation.py`
- `test_operator_delegation.py`
- `docs/delegated-final-answer-extraction-2026-08-03.md`

All pre-existing unrelated worktree changes were preserved.

## Tests

- Focused extraction tests: `8 passed`
- Complete delegation test module: `53 passed`
- Repository-wide pytest: non-zero because the pre-existing dirty worktree contains unrelated bridge and Antigravity failures; no failure occurred in `test_operator_delegation.py`.

## Live validation

### Legacy contaminated task

Task: `dt_da2f596b0c67467e8f3bc818e65d2890`

- Status: completed
- Return code: 0
- `final_answer`: `HERMES_CONNECTOR_DELEGATION_OK`
- `final_answer_extraction_status`: `legacy_terminal_token`
- Raw stdout retained for audit
- Files changed: none

### New structured task

Task: `dt_d0599e3e8dd9497c8573c6b89c9da13e`

- Status: completed
- Return code: 0
- `final_answer`: `STRUCTURED_FINAL_ANSWER_OK`
- `final_answer_extraction_status`: `structured_delimiters`
- Raw stdout retained for audit
- Files changed: none

## Delegated implementation attempt

The initial bounded implementation delegation (`dt_bbbe5a7392e943bda7cd6d54d79c48e3`) correctly located the defect but exhausted two continuations without changing files. Mission Control completed the bounded implementation directly under the same approved authority.

## Remaining risk

Legacy natural-language transcripts without deterministic delimiters may remain ambiguous and intentionally return `final_answer: null`. New delegated tasks use the structured delimiter protocol.
