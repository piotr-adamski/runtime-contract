"""D3.08 offline rule and finding explanations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app
from runtime_contract.rules import RuleId

runner = CliRunner()


@pytest.mark.parametrize("rule_id", list(RuleId))
def test_every_v01_rule_has_complete_offline_text_and_json(rule_id: RuleId) -> None:
    text = runner.invoke(app, ["explain", rule_id.value])
    assert text.exit_code == 0
    for label in ("Severity:", "Why:", "Example:", "Remediation:", "Documentation:"):
        assert label in text.stdout

    structured = runner.invoke(app, ["explain", rule_id.value, "--format", "json"])
    assert structured.exit_code == 0
    payload = json.loads(structured.stdout)
    assert payload["schema_id"] == "runtime-contract/explanation/v1"
    assert payload["rule_id"] == rule_id.value
    assert payload["kind"] == "rule"
    assert payload["effective_severity"] == payload["default_severity"]
    assert payload["example"] and payload["remediation"] and payload["documentation"]


def test_finding_is_resolved_from_json_with_effective_policy_and_locations(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text('import os\nos.getenv("TOKEN")\n')
    (tmp_path / "runtime-contract.yaml").write_text(
        "version: 1\nseverity_overrides:\n  - {rule: RTC001, severity: warning, reason: migration}\n"
    )
    scanned = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    report = tmp_path / "report.json"
    report.write_text(scanned.stdout)
    finding_id = json.loads(scanned.stdout)["findings"][0]["id"]

    explained = runner.invoke(app, ["explain", finding_id, str(report), "--format", "json"])
    assert explained.exit_code == 0
    payload = json.loads(explained.stdout)
    assert payload["kind"] == "finding"
    assert payload["finding_id"] == finding_id
    assert payload["rule_id"] == "RTC001"
    assert payload["default_severity"] == "error"
    assert payload["effective_severity"] == "warning"
    assert payload["primary_location"]["path"] == "settings.py"
    assert payload["evidence_locations"]


def test_finding_can_be_resolved_by_offline_project_scan(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text('import os\nos.getenv("MISSING")\n')
    scanned = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    finding_id = json.loads(scanned.stdout)["findings"][0]["id"]
    explained = runner.invoke(app, ["explain", finding_id, str(tmp_path)])
    assert explained.exit_code == 0
    assert finding_id in explained.stdout
    assert "settings.py:2:" in explained.stdout


@pytest.mark.parametrize("arguments", [["RTC999"], ["not-a-finding"], ["not-a-finding", "missing"]])
def test_unknown_and_missing_identifiers_fail_readably(arguments: list[str]) -> None:
    result = runner.invoke(app, ["explain", *arguments])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.startswith("Error:")


def test_incomplete_report_and_unsupported_format_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text("import os\nname = 'X'\nos.getenv(name)\n")
    scanned = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    report = tmp_path / "partial.json"
    report.write_text(scanned.stdout)
    finding_id = json.loads(scanned.stdout)["findings"][0]["id"]
    incomplete = runner.invoke(app, ["explain", finding_id, str(report)])
    assert incomplete.exit_code == 2
    assert "incomplete" in incomplete.stderr

    unsupported = runner.invoke(app, ["explain", "RTC001", "--format", "sarif"])
    assert unsupported.exit_code == 2
    assert "text or json" in unsupported.stderr


def test_invalid_report_missing_finding_and_rule_file_path_fail_closed(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not json")
    malformed = runner.invoke(app, ["explain", "finding-id", str(invalid)])
    assert malformed.exit_code == 2

    project = tmp_path / "project"
    project.mkdir()
    (project / "settings.py").write_text('import os\nos.getenv("MISSING")\n')
    scanned = runner.invoke(app, ["scan", str(project), "--format", "json"])
    report = tmp_path / "report.json"
    report.write_text(scanned.stdout)
    absent = runner.invoke(app, ["explain", "RTC001-" + "0" * 64, str(report)])
    assert absent.exit_code == 2
    assert "not found" in absent.stderr

    wrong_path_kind = runner.invoke(app, ["explain", "RTC001", str(report)])
    assert wrong_path_kind.exit_code == 2
    assert "project directory" in wrong_path_kind.stderr


def test_explanation_output_is_atomic_and_contained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    written = runner.invoke(app, ["explain", "RTC001", "--output", "explanation.json"])
    assert written.exit_code == 0
    assert written.stdout == ""
    assert "RTC001" in (tmp_path / "explanation.json").read_text()

    unavailable = runner.invoke(app, ["explain", "RTC001", "--output", "missing/explanation.txt"])
    assert unavailable.exit_code == 2
    assert "could not write" in unavailable.stderr
