"""Tests for the installable CLI skeleton."""

import importlib
import importlib.metadata
import runpy
import sys

import pytest
from typer.testing import CliRunner

from runtime_contract import cli
from runtime_contract.cli import app

runner = CliRunner()


def test_main_invokes_typer_application(monkeypatch: pytest.MonkeyPatch) -> None:
    invoked = False

    def fake_app() -> None:
        nonlocal invoked
        invoked = True

    monkeypatch.setattr(cli, "app", fake_app)

    cli.main()

    assert invoked


def test_module_entrypoint_invokes_main_only_when_executed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invocations = 0

    def fake_main() -> None:
        nonlocal invocations
        invocations += 1

    monkeypatch.setattr(cli, "main", fake_main)
    module = importlib.import_module("runtime_contract.__main__")
    importlib.reload(module)
    assert invocations == 0
    monkeypatch.delitem(sys.modules, "runtime_contract.__main__")

    runpy.run_module("runtime_contract.__main__", run_name="__main__")

    assert invocations == 1


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
