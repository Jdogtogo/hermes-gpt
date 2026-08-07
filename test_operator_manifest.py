from __future__ import annotations

from copy import deepcopy

import operator_manifest as manifest


def _baseline_records():
    return [
        {
            "name": "alpha",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "value": {"type": "string", "description": "Example value"},
                    "count": {"default": 1, "type": "integer"},
                },
                "required": ["value"],
            },
        },
        {
            "name": "beta",
            "inputSchema": {
                "type": "object",
                "properties": {"enabled": {"type": "boolean"}},
            },
        },
    ]


def test_schema_fingerprint_is_stable_across_tool_and_mapping_order():
    records = _baseline_records()
    reordered = [
        {
            "inputSchema": {
                "properties": {"enabled": {"type": "boolean"}},
                "type": "object",
            },
            "name": "beta",
        },
        {
            "inputSchema": {
                "required": ["value"],
                "properties": {
                    "count": {"type": "integer", "default": 1},
                    "value": {"description": "Example value", "type": "string"},
                },
                "type": "object",
            },
            "name": "alpha",
        },
    ]

    assert manifest.schema_fingerprint(records) == manifest.schema_fingerprint(reordered)


def test_validate_manifest_reports_missing_tool_separately():
    records = _baseline_records()
    expected_fingerprint = manifest.schema_fingerprint(records)

    result = manifest.validate_manifest(
        records[:1],
        expected_names=["alpha", "beta"],
        expected_fingerprint=expected_fingerprint,
    )

    assert result["valid"] is False
    assert result["missing_tools"] == ["beta"]
    assert result["unexpected_tools"] == []
    assert result["duplicate_tool_names"] == []
    assert result["schema_drift"] is False


def test_validate_manifest_reports_unexpected_tool_separately():
    records = _baseline_records()
    expected_fingerprint = manifest.schema_fingerprint(records)
    actual = records + [{"name": "gamma", "inputSchema": {"type": "object"}}]

    result = manifest.validate_manifest(
        actual,
        expected_names=["alpha", "beta"],
        expected_fingerprint=expected_fingerprint,
    )

    assert result["valid"] is False
    assert result["missing_tools"] == []
    assert result["unexpected_tools"] == ["gamma"]
    assert result["duplicate_tool_names"] == []
    assert result["schema_drift"] is False


def test_validate_manifest_reports_duplicate_name_separately():
    records = _baseline_records()
    expected_fingerprint = manifest.schema_fingerprint(records)
    actual = records + [deepcopy(records[0])]

    result = manifest.validate_manifest(
        actual,
        expected_names=["alpha", "beta"],
        expected_fingerprint=expected_fingerprint,
    )

    assert result["valid"] is False
    assert result["missing_tools"] == []
    assert result["unexpected_tools"] == []
    assert result["duplicate_tool_names"] == ["alpha"]
    assert result["schema_drift"] is False


def test_validate_manifest_reports_schema_drift_when_names_match():
    records = _baseline_records()
    expected_fingerprint = manifest.schema_fingerprint(records)
    actual = deepcopy(records)
    actual[0]["inputSchema"]["properties"]["value"]["type"] = "integer"

    result = manifest.validate_manifest(
        actual,
        expected_names=["alpha", "beta"],
        expected_fingerprint=expected_fingerprint,
    )

    assert result["valid"] is False
    assert result["missing_tools"] == []
    assert result["unexpected_tools"] == []
    assert result["duplicate_tool_names"] == []
    assert result["schema_drift"] is True
    assert result["issues"] == ["schema_drift"]


def test_canonical_chatgpt_operator_name_manifest_is_41_tools():
    assert manifest.EXPECTED_TOOL_COUNT == 41
    assert len(manifest.CANONICAL_TOOL_NAMES) == 41
    assert len(set(manifest.CANONICAL_TOOL_NAMES)) == 41
    assert "hermes_routing_release_v019" in manifest.CANONICAL_TOOL_NAMES
    for required in {
        "hermes_antigravity_dispatch",
        "hermes_antigravity_dispatch_cancel",
        "hermes_antigravity_dispatch_status",
        "hermes_antigravity_smoke_test",
        "hermes_computer_use_status",
        "hermes_computer_use_doctor",
    }:
        assert required in manifest.CANONICAL_TOOL_NAMES
