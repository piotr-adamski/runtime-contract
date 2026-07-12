"""D2.13 centralized redaction and traceback safety contract."""

from __future__ import annotations

import ast
import traceback
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from runtime_contract.cli import app
from runtime_contract.commands import scan as scan_command
from runtime_contract.discovery import DiscoveryError, DiscoveryErrorCode
from runtime_contract.errors import PublicError
from runtime_contract.normalization import NormalizationError, NormalizationErrorCode
from runtime_contract.security import redact_exception

CANARY = "security-exception-value-canary-Q7Z9"
REPO = Path(__file__).parents[1]


def test_production_runtime_imports_no_network_subprocess_or_logging_capability() -> None:
    forbidden_modules = {"http", "httpx", "logging", "requests", "socket", "subprocess", "urllib"}
    forbidden_calls = {"compile", "eval", "exec", "__import__"}
    violations: list[str] = []
    for path in sorted((REPO / "src/runtime_contract").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in forbidden_modules:
                        violations.append(f"{path.name}:{node.lineno}:import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                if node.module.split(".", 1)[0] in forbidden_modules:
                    violations.append(f"{path.name}:{node.lineno}:from {node.module}")
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in forbidden_calls
            ):
                violations.append(f"{path.name}:{node.lineno}:call {node.func.id}")
    assert violations == []


@pytest.mark.parametrize("output_format", ["text", "json", "sarif"])
def test_canary_is_absent_from_terminal_stderr_and_atomic_output(
    tmp_path: Path, output_format: str
) -> None:
    (tmp_path / "app.py").write_text(
        f'import os\nvalue = "{CANARY}"\nos.getenv("SERVICE_TOKEN")\n', encoding="utf-8"
    )
    (tmp_path / ".env.example").write_text(f"SERVICE_TOKEN={CANARY}\n", encoding="utf-8")
    (tmp_path / ".env").write_text(f"REAL_SECRET={CANARY}\n", encoding="utf-8")
    report = tmp_path / f"report.{output_format}"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--format",
            output_format,
            "--output",
            report.name,
        ],
    )
    assert result.exit_code == 0
    assert result.stdout == result.stderr == ""
    assert CANARY not in report.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "error",
    [
        ValueError(CANARY),
        RuntimeError(CANARY),
        DiscoveryError(DiscoveryErrorCode.INVALID_ROOT, CANARY),
        NormalizationError(NormalizationErrorCode.CONFLICTING_FACT, CANARY),
    ],
)
def test_central_redaction_never_retains_exception_text(error: BaseException) -> None:
    safe = redact_exception(error)
    public = repr(safe) + safe.model_dump_json()
    assert CANARY not in public
    assert not hasattr(safe, "exception")


def test_public_error_boundary_rejects_unregistered_dynamic_text() -> None:
    with pytest.raises(ValueError, match="unregistered public error message"):
        PublicError(CANARY)


def test_cli_and_suppressed_traceback_never_render_exception_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_scan(*args: object, **kwargs: object) -> None:
        raise ValueError(CANARY)

    monkeypatch.setattr(scan_command, "run_scan", failed_scan)
    result = CliRunner().invoke(app, ["scan", "."])
    assert result.exit_code == 2
    assert result.stderr == "Error: invalid scan request.\n"
    assert CANARY not in result.stdout + result.stderr

    try:
        try:
            raise RuntimeError(CANARY)
        except RuntimeError:
            scan_command._fail("scan failed")
    except typer.Exit as error:
        rendered = "".join(traceback.format_exception(error))
    assert CANARY not in rendered
