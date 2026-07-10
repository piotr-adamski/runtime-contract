"""Tests for the installable CLI skeleton."""

import importlib.metadata

import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app

runner = CliRunner()


def test_root_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("scan", "check", "explain", "diff"):
        assert command in result.stdout


@pytest.mark.parametrize("command", ["scan", "check", "explain", "diff"])
def test_command_help_succeeds(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])

    assert result.exit_code == 0
    assert result.stderr == ""


def test_version_uses_distribution_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.1.0.dev0")

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == "runtime-contract 0.1.0.dev0\n"
    assert result.stderr == ""


def test_version_fails_closed_without_distribution_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_metadata(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing_metadata)

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "distribution metadata" in result.stderr


@pytest.mark.parametrize(
    ("arguments", "command"),
    [
        (["scan"], "scan"),
        (["scan", "project"], "scan"),
        (["check"], "check"),
        (["check", "project"], "check"),
        (["explain", "RTC001"], "explain"),
        (["explain", "finding-id", "project"], "explain"),
        (["diff", "left", "right"], "diff"),
    ],
)
def test_commands_fail_closed(arguments: list[str], command: str) -> None:
    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr == f"Error: {command} command is not implemented yet.\n"
