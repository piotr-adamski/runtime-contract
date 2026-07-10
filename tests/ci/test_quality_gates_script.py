"""Smoke tests for the thin Bash quality-gate orchestrator."""

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[2] / "scripts" / "quality-gates.sh"


def run_script(*arguments: str, test_mode: bool = False) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if test_mode:
        environment["QUALITY_GATES_TEST_MODE"] = "1"
    return subprocess.run(
        ["bash", str(SCRIPT), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_bash_syntax_is_valid() -> None:
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)], check=False, capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr


def test_help_succeeds() -> None:
    result = run_script("--help")

    assert result.returncode == 0
    assert "--base-ref" in result.stdout
    assert "--full" in result.stdout


def test_bad_argument_fails() -> None:
    result = run_script("--unknown")

    assert result.returncode == 2
    assert "unknown argument" in result.stderr


def test_missing_base_ref_value_fails() -> None:
    result = run_script("--base-ref")

    assert result.returncode == 2
    assert "requires a value" in result.stderr


def test_controlled_execution_path_succeeds() -> None:
    result = run_script("--full", "--base-ref", "fixture", test_mode=True)

    assert result.returncode == 0
    assert "controlled test mode PASS" in result.stdout
