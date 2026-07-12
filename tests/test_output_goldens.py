"""D3.13 exact public output and process-contract goldens."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app
from scripts.generate_output_goldens import OUTPUTS, generated

runner = CliRunner()


def write(root: Path, path: str, content: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def test_all_rules_terminal_json_and_sarif_match_exact_goldens() -> None:
    actual = generated()
    for name, path in OUTPUTS.items():
        expected = path.read_bytes()
        assert actual[name] == expected
        assert expected.endswith(b"\n") and b"SUPER_SECRET_CANARY" not in expected

    json_report = json.loads(actual["json"])
    assert [item["rule_id"] for item in json_report["findings"]] == [
        f"RTC{number:03d}" for number in range(1, 13)
    ]
    sarif = json.loads(actual["sarif"])
    sarif_schema = json.loads(
        Path("tests/fixtures/sarif/sarif-schema-2.1.0.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft4Validator(sarif_schema).validate(sarif)
    results = sarif["runs"][0]["results"]
    assert [item["ruleId"] for item in results] == [f"RTC{number:03d}" for number in range(1, 13)]
    assert len({item["partialFingerprints"]["runtimeContract/v1"] for item in results}) == 12


@pytest.mark.parametrize("output_format", ["text", "json", "sarif"])
def test_findings_outputs_use_stdout_and_preserve_scan_check_exit_codes(
    tmp_path: Path, output_format: str
) -> None:
    write(tmp_path, "app.py", 'import os\nos.environ["REQUIRED"]\n')
    scan = runner.invoke(app, ["scan", str(tmp_path), "--format", output_format])
    check = runner.invoke(app, ["check", str(tmp_path), "--format", output_format])
    assert scan.exit_code == 0 and check.exit_code == 1
    assert scan.stdout and check.stdout
    assert scan.stderr == check.stderr == ""
    assert "SUPER_SECRET_CANARY" not in scan.output + check.output


def test_technical_and_usage_errors_use_only_redacted_stderr(tmp_path: Path) -> None:
    write(tmp_path, "runtime-contract.yaml", "version: 99\nvalue: SUPER_SECRET_CANARY\n")
    invalid = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    usage = runner.invoke(app, ["check", str(tmp_path), "--unknown-option"])
    assert invalid.exit_code == usage.exit_code == 2
    assert invalid.stdout == usage.stdout == ""
    assert invalid.stderr and usage.stderr
    assert "SUPER_SECRET_CANARY" not in invalid.stderr + usage.stderr


def test_output_file_is_the_only_report_sink(tmp_path: Path) -> None:
    write(tmp_path, "app.py", 'import os\nos.getenv("OPTIONAL")\n')
    report = tmp_path / "report.json"
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "json", "--output", report.name]
    )
    assert result.exit_code == 0
    assert result.stdout == result.stderr == ""
    assert json.loads(report.read_text(encoding="utf-8"))["metadata"]["command"] == "scan"
