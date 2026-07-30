from pathlib import Path

import operator_policy_templates as templates


ROOT = Path(__file__).resolve().parent
DROP_IN = ROOT / "examples" / "hermes-gpt-chatgpt-operator-write-roots.conf"


def _decode_systemd_path(value: str) -> str:
    return value.replace("\\x20", " ")


def _read_write_paths() -> set[str]:
    paths: set[str] = set()
    for raw_line in DROP_IN.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("ReadWritePaths="):
            continue
        value = line.split("=", 1)[1].strip()
        if value:
            paths.add(_decode_systemd_path(value))
    return paths


def _is_covered(root: str, allowed: set[str]) -> bool:
    candidate = Path(root)
    return any(candidate == Path(parent) or Path(parent) in candidate.parents for parent in allowed)


def test_operator_service_drop_in_covers_all_active_policy_writable_roots():
    allowed = _read_write_paths()
    assert allowed, "operator service drop-in contains no ReadWritePaths entries"

    missing: list[tuple[str, str]] = []
    for name, template in templates.POLICY_TEMPLATES.items():
        if not template.get("active", False):
            continue
        for root in template["policy"].get("writable_roots", []):
            if not _is_covered(root, allowed):
                missing.append((name, root))

    assert not missing, f"active policy writable roots missing from systemd sandbox: {missing}"
