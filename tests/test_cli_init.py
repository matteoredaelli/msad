"""Tests for the `msad init` CLI command."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from msad.config import load_config
from msad.main import app

runner = CliRunner()


def test_init_creates_file_when_missing(tmp_path: Path) -> None:
    target = tmp_path / ".msad.toml"
    result = runner.invoke(app, ["init", "--config-file", str(target)])

    assert result.exit_code == 0
    assert target.is_file()
    assert "Created" in result.stdout
    # The written file must be valid and parseable by the real loader.
    cfg = load_config(target)
    assert cfg.defaults.domain == "mydomain"


def test_init_warns_and_keeps_existing_file(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    target = tmp_path / ".msad.toml"
    target.write_text("# my custom config\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        result = runner.invoke(app, ["init", "--config-file", str(target)])

    # Exits cleanly (not an error) but does not overwrite.
    assert result.exit_code == 0
    assert target.read_text(encoding="utf-8") == "# my custom config\n"
    # Warning is emitted via logging.
    assert "already exists" in caplog.text


def test_init_force_overwrites_existing_file(tmp_path: Path) -> None:
    target = tmp_path / ".msad.toml"
    target.write_text("# my custom config\n", encoding="utf-8")

    result = runner.invoke(app, ["init", "--config-file", str(target), "--force"])

    assert result.exit_code == 0
    assert "Overwrote" in result.stdout
    # File now holds the sample and parses correctly.
    cfg = load_config(target)
    assert cfg.defaults.domain == "mydomain"


def test_init_creates_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "dir" / ".msad.toml"
    result = runner.invoke(app, ["init", "--config-file", str(target)])

    assert result.exit_code == 0
    assert target.is_file()
