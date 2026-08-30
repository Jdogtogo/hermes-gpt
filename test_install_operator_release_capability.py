from __future__ import annotations

import os
import pwd
import runpy
import sys
from pathlib import Path

import pytest

import install_operator_release_capability as installer


def test_installer_resolves_user_home_from_uid_not_environment(tmp_path: Path, monkeypatch):
    wrong_home = tmp_path / "wrong-home"
    monkeypatch.setenv("HOME", str(wrong_home))
    namespace = runpy.run_path(
        str(Path(__file__).resolve().parent / "install_operator_release_capability.py"),
        run_name="operator_release_installer_test",
    )
    expected_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    assert namespace["USER_HOME"] == expected_home
    assert namespace["TARGET_DIR"] == (
        expected_home
        / ".config"
        / "systemd"
        / "user"
        / "hermes-gpt-chatgpt-operator.service.d"
    )
    assert not str(namespace["TARGET_DIR"]).startswith(str(wrong_home))


def test_installer_copies_exact_drop_in_and_restarts_exact_unit(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.conf"
    source.write_text(
        '[Service]\nReadWritePaths="/mnt/c/Dev/Tax Calculator"\n', encoding="utf-8"
    )
    target_dir = tmp_path / "user" / "hermes-gpt-chatgpt-operator.service.d"
    target_dir.parent.mkdir(parents=True)
    target = target_dir / "50-write-roots.conf"
    calls: list[list[str]] = []

    monkeypatch.setattr(installer, "SOURCE", source)
    monkeypatch.setattr(installer, "TARGET_DIR", target_dir)
    monkeypatch.setattr(installer, "TARGET", target)
    monkeypatch.setattr(sys, "argv", ["installer", "/usr/bin/systemctl"])

    def fake_run(argv, check):
        assert check is True
        calls.append(list(argv))

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    installer.main()

    assert target.read_bytes() == source.read_bytes()
    assert calls == [
        ["/usr/bin/systemctl", "--user", "daemon-reload"],
        ["/usr/bin/systemctl", "--user", "restart", "hermes-gpt-chatgpt-operator.service"],
    ]


def test_validator_rejects_escaped_tax_path():
    with pytest.raises(RuntimeError, match="malformed/escaped"):
        installer.validate_drop_in(b"[Service]\nReadWritePaths=/mnt/c/Dev/Tax\\x20Calculator\n")


def test_validator_rejects_unquoted_literal_space_tax_path():
    with pytest.raises(RuntimeError, match="quoted literal-space"):
        installer.validate_drop_in(b"[Service]\nReadWritePaths=/mnt/c/Dev/Tax Calculator\n")


def test_validator_rejects_release_write_roots():
    for path in (
        "/home/jfroh/.hermes/releases",
        "/home/jfroh/.hermes/releases/v018-live",
        "/home/jfroh/.hermes/releases/v019",
    ):
        with pytest.raises(RuntimeError, match="Immutable release paths"):
            installer.validate_drop_in(f"[Service]\nReadWritePaths={path}\n".encode())


def test_target_directory_creation_is_bounded(tmp_path: Path, monkeypatch):
    target_dir = tmp_path / "missing-parent" / "drop-in"
    monkeypatch.setattr(installer, "TARGET_DIR", target_dir)
    with pytest.raises(RuntimeError, match="refusing broad parent-directory creation"):
        installer._ensure_target_dir()
    assert not target_dir.exists()


def test_target_directory_refuses_symlink(tmp_path: Path, monkeypatch):
    parent = tmp_path / "user"
    parent.mkdir()
    real = tmp_path / "real"
    real.mkdir()
    target_dir = parent / "drop-in"
    target_dir.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(installer, "TARGET_DIR", target_dir)
    with pytest.raises(RuntimeError, match="symlinked"):
        installer._ensure_target_dir()
