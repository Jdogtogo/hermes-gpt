from __future__ import annotations

from collections import Counter
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any


# 1.10.0 -- governed canonical OpsBrain publisher added to the public Controller surface.
# The public surface gains hermes_ops_brain_publish while preserving the Phase 3 R1 pilot tool.
# 54 tools.
MANIFEST_VERSION = "1.10.0"
EXPECTED_TOOL_COUNT = 54

# Canonical public surface for the authenticated ChatGPT operator connector.
# This is intentionally independent of registration order.
CANONICAL_TOOL_NAMES = tuple(
    sorted(
        {
            "hermes_approval_web_service_restart",
            "hermes_computer_use_status",
            "hermes_computer_use_doctor",
            "hermes_claude_desktop_restart",
            "hermes_controller_publish",
            "hermes_antigravity_dispatch",
            "hermes_antigravity_dispatch_cancel",
            "hermes_antigravity_dispatch_status",
            "hermes_antigravity_review_cancel",
            "hermes_antigravity_review_start",
            "hermes_antigravity_review_status",
            "hermes_antigravity_smoke_test",
            "hermes_config_get",
            "hermes_delegate_task",
            "hermes_delegate_task_forecast",
            "hermes_delegated_task_cancel",
            "hermes_delegated_task_continue",
            "hermes_delegated_task_message",
            "hermes_delegated_task_result",
            "hermes_delegated_task_status",
            "hermes_env_status",
            "hermes_first_safe_model_prepare",
            "hermes_first_safe_model_execute",
            "hermes_first_safe_model_verify",
            "hermes_first_safe_provision_prepare",
            "hermes_first_safe_provision_execute",
            "hermes_first_safe_provision_verify",
            "hermes_gateway_status",
            "hermes_git_diff",
            "hermes_git_status",
            "hermes_operator_audit_tail",
            "hermes_operator_doctor",
            "hermes_operator_policy",
            "hermes_operator_service_restart",
            "hermes_operator_session_request",
            "hermes_operator_session_request_extension",
            "hermes_operator_session_revoke",
            "hermes_operator_session_status",
            "hermes_operator_snapshot",
            "hermes_operator_status",
            "hermes_ops_brain_query",
            "hermes_ops_brain_publish",
            "hermes_operator_phase3_r1_pilot_request",
            "hermes_search_files",
            "hermes_workspace_exec",
            "hermes_workspace_git_commit",
            "hermes_routing_release_v019",
            "hermes_workspace_patch",
            "hermes_workspace_read",
            "hermes_workspace_run_test",
            "hermes_workspace_write_file",
            "hermes_mission_control_lease_acquire",
            "hermes_mission_control_lease_release",
            "hermes_mission_control_lease_status",
        }
    )
)

if len(CANONICAL_TOOL_NAMES) != EXPECTED_TOOL_COUNT:
    raise RuntimeError(
        f"Canonical ChatGPT operator tool manifest must contain exactly {EXPECTED_TOOL_COUNT} unique names."
    )

# Pinned after computing the canonical MCP input-schema payload. Intentional
# public tool or schema changes must update both this digest and MANIFEST_VERSION.
# 1.2.0 was c068da8c29c0be1fca941a4e2060f2bfff694266d9a23b5b70e08ec7abf3f99f
# (45 tools, hermes_exec_first_safe_model present). Re-pinned for 1.3.0 after the
# deliberate FIRST_SAFE prepare/verify split described above.
# 1.10.0 re-pinned after adding the governed OpsBrain publisher (54 tools).
EXPECTED_SCHEMA_FINGERPRINT = "39ba4bdb90d64159641ff67b2c1ba32f64162e3779d28f9f453f43c1dd14bbc2"


def _canonicalize(value: Any) -> Any:
    """Recursively normalize mappings while preserving array semantics."""
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, tuple):
        return [_canonicalize(item) for item in value]
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    return value


def canonical_payload(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return deterministic tool-name/input-schema records.

    Tool registration order and recursive mapping key order do not affect the
    resulting payload. Duplicate entries remain present so validation can fail
    explicitly rather than silently collapsing them.
    """
    normalized: list[dict[str, Any]] = []
    for record in records:
        name = str(record["name"])
        schema = record.get("inputSchema")
        if not isinstance(schema, Mapping):
            raise TypeError(f"Tool {name!r} has no mapping input schema.")
        normalized.append({"name": name, "inputSchema": _canonicalize(schema)})

    return sorted(
        normalized,
        key=lambda item: (
            item["name"],
            json.dumps(
                item["inputSchema"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ),
        ),
    )


def schema_fingerprint(records: Sequence[Mapping[str, Any]]) -> str:
    payload = canonical_payload(records)
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def native_tool_record(tool: Any) -> dict[str, Any]:
    """Extract name and input schema from FastMCP's native registered tool info."""
    name = getattr(tool, "name", None)
    schema = getattr(tool, "parameters", None)
    if schema is None:
        schema = getattr(tool, "inputSchema", None)
    if schema is None:
        schema = getattr(tool, "input_schema", None)
    if schema is None and hasattr(tool, "model_dump"):
        dumped = tool.model_dump(by_alias=True)
        schema = (
            dumped.get("inputSchema")
            or dumped.get("input_schema")
            or dumped.get("parameters")
        )
        name = name or dumped.get("name")
    if not name:
        raise TypeError("Registered FastMCP tool has no name.")
    if not isinstance(schema, Mapping):
        raise TypeError(f"Registered FastMCP tool {name!r} has no mapping input schema.")
    return {"name": str(name), "inputSchema": dict(schema)}


def validate_manifest(
    records: Sequence[Mapping[str, Any]],
    *,
    expected_names: Sequence[str] = CANONICAL_TOOL_NAMES,
    expected_fingerprint: str = EXPECTED_SCHEMA_FINGERPRINT,
) -> dict[str, Any]:
    names = [str(record["name"]) for record in records]
    counts = Counter(names)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    actual_names = set(names)
    expected_name_set = set(expected_names)
    missing = sorted(expected_name_set - actual_names)
    unexpected = sorted(actual_names - expected_name_set)
    actual_fingerprint = schema_fingerprint(records)
    structural_match = not missing and not unexpected and not duplicates
    schema_drift = structural_match and actual_fingerprint != expected_fingerprint
    valid = structural_match and not schema_drift

    issues: list[str] = []
    if missing:
        issues.append("missing_tools")
    if unexpected:
        issues.append("unexpected_tools")
    if duplicates:
        issues.append("duplicate_tool_names")
    if schema_drift:
        issues.append("schema_drift")

    return {
        "manifest_version": MANIFEST_VERSION,
        "expected_tool_count": len(expected_names),
        "registered_tool_count": len(records),
        "expected_schema_fingerprint": expected_fingerprint,
        "schema_fingerprint": actual_fingerprint,
        "missing_tools": missing,
        "unexpected_tools": unexpected,
        "duplicate_tool_names": duplicates,
        "schema_drift": schema_drift,
        "issues": issues,
        "valid": valid,
        "status": "PASS" if valid else "FAIL",
    }
