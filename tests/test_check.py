"""D3.07 executable contract for check output and process statuses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app

runner = CliRunner()


def write(root: Path, path: str, content: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def check(root: Path, *arguments: str):  # type: ignore[no-untyped-def]
    return runner.invoke(app, ["check", str(root), "--format", "json", *arguments])


def test_check_exit_zero_for_clean_warning_and_info_findings(tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    write(clean, "settings.py", 'import os\nos.getenv("OPTIONAL", "fallback")\n')
    assert check(clean).exit_code == 0

    warning = tmp_path / "warning"
    write(warning, ".env.example", "UNUSED=\n")
    warning_result = check(warning)
    assert warning_result.exit_code == 0
    assert {item["severity"] for item in json.loads(warning_result.stdout)["findings"]} == {
        "warning"
    }

    info = tmp_path / "info"
    write(info, "service.yaml", "apiVersion: v1\nkind: Service\nmetadata: {name: api}\n")
    info_result = check(info)
    assert info_result.exit_code == 0
    assert {item["severity"] for item in json.loads(info_result.stdout)["diagnostics"]} == {"info"}


def test_check_exit_one_only_for_active_error_and_renders_finding(tmp_path: Path) -> None:
    write(tmp_path, "settings.py", 'import os\nos.environ["REQUIRED"]\n')
    result = check(tmp_path)
    assert result.exit_code == 1
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "check"
    assert payload["status"] == "complete"
    assert [(item["rule_id"], item["severity"]) for item in payload["findings"]] == [
        ("RTC001", "error")
    ]


def test_check_exit_two_distinguishes_unreliable_config_and_usage(tmp_path: Path) -> None:
    partial = tmp_path / "partial"
    write(partial, "settings.py", "import os\nname = 'KEY'\nos.getenv(name)\n")
    partial_result = check(partial)
    assert partial_result.exit_code == 2
    assert json.loads(partial_result.stdout)["status"] == "partial"

    invalid = tmp_path / "invalid"
    write(invalid, "runtime-contract.yaml", "version: 99\n")
    invalid_result = check(invalid)
    assert invalid_result.exit_code == 2
    assert invalid_result.stdout == ""
    assert "configuration file is invalid" in invalid_result.stderr

    usage = runner.invoke(app, ["check", str(tmp_path), "--unknown-option"])
    assert usage.exit_code == 2
    assert usage.stdout == ""
    assert "No such option" in usage.stderr


@pytest.mark.parametrize("output_format", ["text", "json", "sarif"])
def test_check_renders_supported_formats_before_exit_one(
    tmp_path: Path, output_format: str
) -> None:
    write(tmp_path, "settings.py", 'import os\nos.environ["REQUIRED"]\n')
    result = runner.invoke(app, ["check", str(tmp_path), "--format", output_format])
    assert result.exit_code == 1
    assert result.stdout
    if output_format == "json":
        assert json.loads(result.stdout)["findings"][0]["rule_id"] == "RTC001"
    elif output_format == "sarif":
        assert json.loads(result.stdout)["runs"][0]["results"][0]["ruleId"] == "RTC001"
    else:
        assert "RTC001 Required variable not provided" in result.stdout
