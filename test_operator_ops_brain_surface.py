from __future__ import annotations

import inspect

from mcp.server.fastmcp import FastMCP

import operator_manifest as manifest
import operator_policy_templates as templates
import server


def _public_records():
    mcp = FastMCP("opsbrain-publisher-surface-test")
    for tool in server.chatgpt_operator_tool_list():
        mcp.add_tool(tool)
    return [manifest.native_tool_record(tool) for tool in mcp._tool_manager.list_tools()]


def test_public_wrapper_signature_is_narrow():
    signature = inspect.signature(server.hermes_ops_brain_publish)
    assert list(signature.parameters) == ["expected_commit", "expected_remote_sha", "dry_run"]
    assert signature.parameters["dry_run"].default is True
    forbidden = {"repo", "repository", "remote", "branch", "url", "refspec", "host", "command", "argv"}
    assert forbidden.isdisjoint(signature.parameters)


def test_public_tool_list_contains_opsbrain_publisher_exactly_once():
    names = [tool.__name__ for tool in server.chatgpt_operator_tool_list()]
    assert names.count("hermes_ops_brain_publish") == 1
    assert len(names) == manifest.EXPECTED_TOOL_COUNT
    assert set(names) == set(manifest.CANONICAL_TOOL_NAMES)


def test_opsbrain_release_template_is_fixed_and_has_no_general_git_push():
    resolved = templates.resolve_template("hermes-opsbrain-release")
    policy = resolved["policy"]
    assert resolved["standing_authority_eligible"] is False
    assert resolved["allowed_branches"] == ["master"]
    assert policy["readable_roots"] == ["/home/jfroh/.hermes/ops-brain"]
    assert policy["writable_roots"] == ["/home/jfroh/.hermes/ops-brain-publish-scratch"]
    assert policy["egress_hosts"] == ["github.com"]
    assert policy["service_units"] == []
    assert policy["verbs"] == {"opsbrain": ["preflight", "release"]}
    assert "git" not in policy["verbs"]
    assert policy["paid_route_change"] == "none"
    assert policy["has_credential_access"] is False


def test_manifest_fingerprint_matches_registered_public_surface():
    records = _public_records()
    actual = manifest.schema_fingerprint(records)
    assert actual == manifest.EXPECTED_SCHEMA_FINGERPRINT, actual
    validation = manifest.validate_manifest(records)
    assert validation["valid"] is True
    assert validation["registered_tool_count"] == manifest.EXPECTED_TOOL_COUNT
