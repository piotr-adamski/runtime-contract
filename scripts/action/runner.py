"""Thin, injection-safe GitHub Action adapter for the released CLI."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Never

_COMMANDS = {"scan", "check", "explain", "diff"}
_FORMATS = {
    "scan": {"text", "json", "sarif"},
    "check": {"text", "json", "sarif"},
    "explain": {"text", "json"},
    "diff": {"text", "json"},
}
_FAIL_ON = {"error", "warning", "info", "never"}
_EXACT_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){2}(?:(?:a|b|rc)[0-9]+|\.post[0-9]+)?$")
_PYTHON_VERSION = "3.11.15"


class ActionError(RuntimeError):
    """A setup or input error owned by the Action rather than the product."""


def _error(message: str) -> None:
    print(f"[runtime-contract-action] Error: {message}", file=sys.stderr)


def _info(message: str) -> None:
    print(f"[runtime-contract-action] {message}", file=sys.stderr)


def _input(name: str, default: str = "") -> str:
    value = os.environ.get(f"RUNTIME_CONTRACT_ACTION_{name}", default)
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ActionError(f"input {name.lower().replace('_', '-')} contains a control character")
    return value


def _require(value: str, name: str, command: str) -> str:
    if not value:
        raise ActionError(f"input {name} is required for command {command}")
    return value


def build_cli_arguments(executable: Path) -> list[str]:
    """Build one argv element per user input; never build or evaluate shell text."""
    command = _input("COMMAND", "check")
    if command not in _COMMANDS:
        raise ActionError("input command must be scan, check, explain, or diff")

    output_format = _input("FORMAT", "text")
    if output_format not in _FORMATS[command]:
        allowed = ", ".join(sorted(_FORMATS[command]))
        raise ActionError(f"input format for {command} must be one of: {allowed}")

    fail_on = _input("FAIL_ON", "error")
    if fail_on not in _FAIL_ON:
        raise ActionError("input fail-on must be error, warning, info, or never")

    path = _input("PATH", ".")
    config = _input("CONFIG")
    output = _input("OUTPUT")
    rule = _input("RULE")
    left = _input("LEFT")
    right = _input("RIGHT")
    environment = _input("ENVIRONMENT")
    arguments = [str(executable), command]

    if command in {"scan", "check"}:
        arguments.append(path)
        if config:
            arguments.extend(("--config", config))
        if environment:
            arguments.extend(("--environment", environment))
        arguments.extend(("--format", output_format, "--fail-on", fail_on))
        if rule or left or right:
            raise ActionError("rule, left, and right are not valid for scan/check")
    elif command == "explain":
        arguments.append(_require(rule, "rule", command))
        if path != ".":
            arguments.append(path)
        arguments.extend(("--format", output_format))
        if config or environment or left or right or fail_on != "error":
            raise ActionError(
                "config, environment, left, right, and non-default fail-on are invalid for explain"
            )
    else:
        arguments.extend(
            (
                _require(left, "left", command),
                _require(right, "right", command),
                "--format",
                output_format,
            )
        )
        if environment:
            arguments.extend(("--environment", environment))
        if path != "." or config or rule or fail_on != "error":
            raise ActionError("path, config, rule, and non-default fail-on are invalid for diff")

    if output:
        arguments.extend(("--output", output))
    return arguments


def _version() -> str:
    version = _input("VERSION", "0.1.0")
    if not _EXACT_VERSION.fullmatch(version):
        raise ActionError("input version must be one exact public release version")
    return version


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _venv_cli(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "runtime-contract.exe"
    return venv / "bin" / "runtime-contract"


def _verified_cli(version: str) -> Path:
    uv = shutil.which("uv")
    if uv is None:
        raise ActionError("the pinned uv installer is unavailable")
    runner_temp = Path(os.environ.get("RUNNER_TEMP", Path.cwd() / ".runtime-contract-action"))
    venv = runner_temp / "runtime-contract-action" / version / f"python-{_PYTHON_VERSION}"
    python = _venv_python(venv)
    executable = _venv_cli(venv)

    def reports_expected_version() -> bool:
        if not executable.is_file():
            return False
        result = subprocess.run(
            [str(executable), "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0 and result.stdout.strip() == f"runtime-contract {version}"

    _info("Preparing an isolated, pinned Python environment")
    commands = [
        [uv, "python", "install", _PYTHON_VERSION],
        [uv, "venv", "--clear", "--python", _PYTHON_VERSION, str(venv)],
        [
            uv,
            "pip",
            "install",
            "--python",
            str(python),
            "--index-url",
            "https://pypi.org/simple",
            "--only-binary",
            ":all:",
            "--no-cache",
            f"runtime-contract=={version}",
        ],
        [uv, "pip", "check", "--python", str(python)],
    ]
    for command in commands:
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            raise ActionError("isolated installation failed")
    if not reports_expected_version():
        raise ActionError("installed CLI version does not match input version")
    return executable


def _write_output(name: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path is None:
        return
    with Path(output_path).open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(f"{name}={value}\n")


def _result_file(arguments: list[str]) -> str:
    if "--output" not in arguments:
        return ""
    output = Path(arguments[arguments.index("--output") + 1])
    if output.is_absolute():
        return str(output)
    command = arguments[1]
    if command in {"scan", "check"}:
        return str((Path(arguments[2]).resolve() / output).resolve())
    return str((Path.cwd() / output).resolve())


def _fail_action(message: str) -> Never:
    _write_output("exit-code", "2")
    _write_output("result-file", "")
    _write_output("runtime-contract-version", "")
    _error(message)
    raise SystemExit(2)


def main() -> None:
    """Install the exact release, verify it, invoke it, and preserve its exit code."""
    try:
        arguments = build_cli_arguments(Path("runtime-contract"))
        version = _version()
        executable = _verified_cli(version)
        arguments[0] = str(executable)
    except ActionError as error:
        _fail_action(str(error))

    _info("Running the released runtime-contract CLI")
    result = subprocess.run(arguments, check=False)
    _write_output("exit-code", str(result.returncode))
    _write_output("result-file", _result_file(arguments))
    _write_output("runtime-contract-version", version)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
