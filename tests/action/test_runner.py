"""Security and argument-contract tests for the thin Action runner."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from scripts.action import runner

_PAYLOAD = "value with spaces żółć; $(touch ACTION_PWNED) `touch ACTION_PWNED`"


def set_inputs(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    defaults = {
        "COMMAND": "check",
        "PATH": ".",
        "FORMAT": "text",
        "FAIL_ON": "error",
        "CONFIG": "",
        "VERSION": "0.1.0",
        "OUTPUT": "",
        "RULE": "",
        "LEFT": "",
        "RIGHT": "",
        "ENVIRONMENT": "",
    }
    defaults.update(values)
    for name, value in defaults.items():
        monkeypatch.setenv(f"RUNTIME_CONTRACT_ACTION_{name}", value)


@pytest.mark.parametrize("name", ["PATH", "CONFIG", "OUTPUT", "ENVIRONMENT"])
def test_scan_and_check_text_inputs_are_single_argv_elements(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    set_inputs(monkeypatch, **{name: _PAYLOAD})

    arguments = runner.build_cli_arguments(Path("/trusted/runtime-contract"))

    assert arguments.count(_PAYLOAD) == 1
    assert not Path("ACTION_PWNED").exists()


@pytest.mark.parametrize("name", ["RULE", "PATH", "OUTPUT"])
def test_explain_text_inputs_are_single_argv_elements(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    values = {"COMMAND": "explain", "RULE": "RTC001"}
    values[name] = _PAYLOAD
    set_inputs(monkeypatch, **values)

    arguments = runner.build_cli_arguments(Path("/trusted/runtime-contract"))

    assert arguments.count(_PAYLOAD) == 1
    assert not Path("ACTION_PWNED").exists()


@pytest.mark.parametrize("name", ["LEFT", "RIGHT", "OUTPUT", "ENVIRONMENT"])
def test_diff_text_inputs_are_single_argv_elements(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    values = {"COMMAND": "diff", "LEFT": "before", "RIGHT": "after"}
    values[name] = _PAYLOAD
    set_inputs(monkeypatch, **values)

    arguments = runner.build_cli_arguments(Path("/trusted/runtime-contract"))

    assert arguments.count(_PAYLOAD) == 1
    assert not Path("ACTION_PWNED").exists()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("COMMAND", "check; touch ACTION_PWNED"),
        ("FORMAT", "sarif; touch ACTION_PWNED"),
        ("FAIL_ON", "error; touch ACTION_PWNED"),
    ],
)
def test_enum_injection_is_rejected(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    set_inputs(monkeypatch, **{name: value})

    with pytest.raises(runner.ActionError):
        runner.build_cli_arguments(Path("/trusted/runtime-contract"))
    assert not Path("ACTION_PWNED").exists()


@pytest.mark.parametrize("value", [_PAYLOAD, "latest", "main", "0.1.0\nexit-code=0"])
def test_version_requires_an_exact_release(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    set_inputs(monkeypatch, VERSION=value)

    with pytest.raises(runner.ActionError):
        runner._version()


def test_control_characters_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    set_inputs(monkeypatch, PATH="safe\nexit-code=0")

    with pytest.raises(runner.ActionError, match="control character"):
        runner.build_cli_arguments(Path("/trusted/runtime-contract"))


def test_command_specific_inputs_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    set_inputs(monkeypatch, COMMAND="diff", LEFT="before", RIGHT="after", PATH="ambiguous")

    with pytest.raises(runner.ActionError, match="invalid for diff"):
        runner.build_cli_arguments(Path("/trusted/runtime-contract"))


def test_runner_never_uses_a_shell_or_eval() -> None:
    tree = ast.parse(Path(runner.__file__).read_text(encoding="utf-8"))

    assert "eval(" not in Path(runner.__file__).read_text(encoding="utf-8")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "run"
        ):
            assert all(keyword.arg != "shell" for keyword in node.keywords)
