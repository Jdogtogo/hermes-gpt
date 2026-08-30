from __future__ import annotations

import ast

import operator_hermes_exec_model as spec

CONFIG_TEXT = """model:\n  provider: openrouter\n  default: \n  base_url: https://openrouter.ai/api/v1\nfallback_providers: []\nproviders: {}\ncredential_pool_strategies: {}\n"""


def test_embedded_remote_parser_accepts_exact_provisioned_config():
    tree = ast.parse(spec.REMOTE_PROGRAM)
    wanted = {"fail", "scalar", "locate_model_fields", "validate_static_profile_config", "replace_default"}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    assert {node.name for node in nodes} == wanted
    module = ast.Module(
        body=[ast.Import(names=[ast.alias(name="re")]), ast.Import(names=[ast.alias(name="json")])] + nodes,
        type_ignores=[],
    )
    ns = {"PROVIDER": "openrouter", "BASE_URL": "https://openrouter.ai/api/v1", "APPROVED_MODEL": "cohere/north-mini-code:free"}
    exec(compile(ast.fix_missing_locations(module), "<embedded-first-safe-parser>", "exec"), ns, ns)
    ns["validate_static_profile_config"](CONFIG_TEXT)
    _, fields, _ = ns["locate_model_fields"](CONFIG_TEXT)
    assert fields == {
        "provider": "openrouter",
        "default": "",
        "base_url": "https://openrouter.ai/api/v1",
    }
    previous, rewritten = ns["replace_default"](CONFIG_TEXT, "cohere/north-mini-code:free")
    assert previous == ""
    assert rewritten == CONFIG_TEXT.replace("  default: \n", "  default: cohere/north-mini-code:free\n")
    ns["validate_static_profile_config"](rewritten)
    _, rewritten_fields, _ = ns["locate_model_fields"](rewritten)
    assert rewritten_fields["default"] == "cohere/north-mini-code:free"
    assert rewritten_fields["base_url"] == "https://openrouter.ai/api/v1"


def test_guard_precedes_config_write_and_post_write_failures_restore_original():
    source = spec.REMOTE_PROGRAM
    main_source = source[source.index("def main():"):]
    assert main_source.index('PHASE="guard"') < main_source.index('PHASE="rewrite"')
    assert main_source.index("guard=run_guard(selected,catalog_price,before_text)") < main_source.index("atomic_write(CONFIG,new_text)")
    assert "except BaseException:" in main_source
    assert 'PHASE="rollback"' in main_source
    assert "atomic_write(CONFIG,before_text)" in main_source
    assert "CONFIG.read_bytes()!=before_bytes" in main_source
