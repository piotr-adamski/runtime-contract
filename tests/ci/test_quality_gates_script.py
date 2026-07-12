"""Smoke tests for the thin Bash quality-gate orchestrator."""

import os
import shutil
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[2] / "scripts" / "quality-gates.sh"


def bash() -> str:
    if os.name != "nt":
        return "bash"
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git for Windows is required")
    roots = tuple(Path(git).parents)
    candidates = tuple(
        root / relative
        for root in roots
        for relative in (Path("bin/bash.exe"), Path("usr/bin/bash.exe"))
    )
    if executable := next((candidate for candidate in candidates if candidate.is_file()), None):
        return str(executable)
    raise RuntimeError("Git Bash is required")


def run_script(*arguments: str, test_mode: bool = False) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    if test_mode:
        environment["QUALITY_GATES_TEST_MODE"] = "1"
    return subprocess.run(
        [bash(), str(SCRIPT), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_bash_syntax_is_valid() -> None:
    result = subprocess.run(
        [bash(), "-n", str(SCRIPT)], check=False, capture_output=True, text=True
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
