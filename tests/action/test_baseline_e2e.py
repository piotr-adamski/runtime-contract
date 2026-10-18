"""The thin adapter invokes the current installed CLI with unchanged report/exit semantics."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.action.runner import build_cli_arguments


def test_action_baseline_to_cli_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "app.py"
    source.write_text('import os\nos.environ["EXISTING"]\n')
    base = subprocess.run(
        [sys.executable, "-m", "runtime_contract", "scan", str(tmp_path), "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    (tmp_path / "accepted.json").write_text(base.stdout, encoding="utf-8")
    for name, value in {
        "COMMAND": "check",
        "PATH": str(tmp_path),
        "FORMAT": "json",
        "BASELINE": "accepted.json",
    }.items():
        monkeypatch.setenv("RUNTIME_CONTRACT_ACTION_" + name, value)
    arguments = build_cli_arguments(Path("runtime-contract"))
    command = [sys.executable, "-m", "runtime_contract", *arguments[1:]]
    existing = subprocess.run(command, capture_output=True, text=True)
    assert existing.returncode == 0
    assert len(json.loads(existing.stdout)["metadata"]["baseline"]["existing"]) == 1
    source.write_text('import os\nos.environ["EXISTING"]\nos.environ["REGRESSION"]\n')
    regression = subprocess.run(command, capture_output=True, text=True)
    assert regression.returncode == 1
    assert len(json.loads(regression.stdout)["findings"]) == 2
    source.write_text("import os\nos.getenv(dynamic_name)\n")
    incomplete = subprocess.run(command, capture_output=True, text=True)
    assert incomplete.returncode == 2
    assert "complete analyses" in incomplete.stderr
