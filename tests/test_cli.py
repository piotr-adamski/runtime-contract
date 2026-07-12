"""Tests for the installable CLI skeleton."""

import importlib
import importlib.metadata
import re
import runpy
import sys

import pytest
from typer.testing import CliRunner

from runtime_contract import cli
from runtime_contract.cli import app

runner = CliRunner()
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


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
    assert "runtime-contract scan ." in result.stdout
    assert "built-in defaults < YAML" in result.stdout


@pytest.mark.parametrize("command", ["scan", "check", "explain", "diff"])
def test_command_help_succeeds(command: str) -> None:
    result = runner.invoke(app, [command, "--help"])

    assert result.exit_code == 0
    assert result.stderr == ""
    assert "Examples:" in result.stdout
    assert f"runtime-contract {command}" in result.stdout


@pytest.mark.parametrize(
    ("arguments", "suggestion"),
    [
        (["sacn"], "Did you mean 'scan'?"),
        (["scan", "--formt", "json"], "Possible options: --format"),
        (["check", "--failon", "error"], "Possible options: --fail-on"),
        (["explain", "RTC001", "--formt", "json"], "Possible options: --format"),
        (["diff", ".", ".", "--formt", "json"], "Possible options: --format"),
    ],
)
def test_cli_typo_errors_suggest_the_intended_command_or_option(
    arguments: list[str], suggestion: str
) -> None:
    result = runner.invoke(app, arguments, env={"FORCE_COLOR": "1"})
    stderr = ANSI_ESCAPE.sub("", result.stderr)

    assert result.exit_code == 2
    assert result.stdout == ""
    assert suggestion in stderr
    assert "--help" in stderr


def test_version_uses_distribution_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.1.0")

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == "runtime-contract 0.1.0\n"
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
