"""Install the reviewed operator write-root drop-in and restart only its service."""

from __future__ import annotations

import os
import pwd
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "examples" / "hermes-gpt-chatgpt-operator-write-roots.conf"
USER_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
TARGET_DIR = USER_HOME / ".config" / "systemd" / "user" / "hermes-gpt-chatgpt-operator.service.d"
TARGET = TARGET_DIR / "50-write-roots.conf"
UNIT = "hermes-gpt-chatgpt-operator.service"


def _read_write_paths(text: str) -> tuple[str, ...]:
    paths: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("ReadWritePaths="):
            continue
        value = line.split("=", 1)[1].strip()
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        if value:
            paths.append(value)
    return tuple(paths)


def validate_drop_in(content: bytes) -> None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("Operator write-root drop-in must be UTF-8 text.") from exc
    if "\\x20" in text or "Taxx20Calculator" in text:
        raise RuntimeError("Refusing malformed/escaped systemd path rendering.")
    if "/mnt/c/Dev/Tax Calculator" in text and 'ReadWritePaths="/mnt/c/Dev/Tax Calculator"' not in text:
        raise RuntimeError("Tax Calculator write root must use a quoted literal-space path.")
    for path in _read_write_paths(text):
        if path == "/home/jfroh/.hermes/releases" or path.startswith("/home/jfroh/.hermes/releases/"):
            raise RuntimeError("Immutable release paths must never be writable in the operator service sandbox.")


def _ensure_target_dir() -> None:
    parent = TARGET_DIR.parent
    if not parent.is_dir():
        raise RuntimeError(
            f"Expected user-systemd parent {parent} is missing; refusing broad parent-directory creation."
        )
    if TARGET_DIR.exists() and TARGET_DIR.is_symlink():
        raise RuntimeError(f"Refusing symlinked systemd drop-in directory: {TARGET_DIR}")
    TARGET_DIR.mkdir(mode=0o755, exist_ok=True)


def main() -> None:
    systemctl = sys.argv[1] if len(sys.argv) > 1 else "systemctl"
    content = SOURCE.read_bytes()
    validate_drop_in(content)
    _ensure_target_dir()
    temporary = TARGET.with_name(f".{TARGET.name}.tmp-{os.getpid()}")
    temporary.write_bytes(content)
    temporary.chmod(0o644)
    os.replace(temporary, TARGET)
    subprocess.run([systemctl, "--user", "daemon-reload"], check=True)
    subprocess.run([systemctl, "--user", "restart", UNIT], check=True)


if __name__ == "__main__":
    main()
