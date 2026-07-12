"""D3.06 runtime severity overrides and suppression audit metadata."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from runtime_contract.cli import app
from runtime_contract.config.models import Severity as ConfigSeverity
from runtime_contract.config.models import SeverityOverride
from runtime_contract.domain import Severity
from runtime_contract.rules import RuleId
from runtime_contract.scan import PolicyRecord

runner = CliRunner()


def write(root: Path, path: str, content: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def run(root: Path, command: str = "scan", output_format: str = "json"):  # type: ignore[no-untyped-def]
    return runner.invoke(app, [command, str(root), "--format", output_format])


def missing_required(root: Path) -> None:
    write(root, "settings.py", 'import os\nos.getenv("TOKEN")\n')


def test_severity_override_requires_reason_and_changes_check_outcome(tmp_path: Path) -> None:
    missing_required(tmp_path)
    write(
        tmp_path,
        "runtime-contract.yaml",
        """version: 1
severity_overrides:
  - {rule: RTC001, severity: warning, reason: migration window}
""",
    )
    result = run(tmp_path, "check")
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    finding = next(item for item in payload["findings"] if item["rule_id"] == "RTC001")
    assert finding["severity"] == "warning"
    assert payload["metadata"]["policy"] == [
        {
            "effective_severity": "warning",
            "id": "/severity_overrides/0",
            "original_severity": "error",
            "pointer": "/severity_overrides/0",
            "reason": "migration window",
            "rule_id": "RTC001",
            "status": "severity_overridden",
        }
    ]

    write(
        tmp_path,
        "runtime-contract.yaml",
        "version: 1\nseverity_overrides:\n  - {rule: RTC001, severity: warning}\n",
    )
    invalid = run(tmp_path)
    assert invalid.exit_code == 2
    assert "reason" in invalid.stderr


def test_precise_suppression_is_applied_and_visible(tmp_path: Path) -> None:
    missing_required(tmp_path)
    write(
        tmp_path,
        "runtime-contract.yaml",
        """version: 1
suppressions:
  - id: exact-migration
    rule: RTC001
    reason: tracked migration
    variable: TOKEN
    path: settings.py
    roots: [default]
""",
    )
    result = run(tmp_path, "check")
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert all(item["rule_id"] != "RTC001" for item in payload["findings"])
    record = payload["metadata"]["policy"][0]
    assert record == {
        "effective_severity": None,
        "id": "exact-migration",
        "original_severity": None,
        "pointer": "/suppressions/0",
        "reason": "tracked migration",
        "rule_id": "RTC001",
        "status": "suppressed",
    }


def test_unused_and_expired_suppressions_are_auditable_and_do_not_hide(
    tmp_path: Path,
) -> None:
    missing_required(tmp_path)
    write(
        tmp_path,
        "runtime-contract.yaml",
        """version: 1
suppressions:
  - {id: expired, rule: RTC001, reason: past exception, variable: TOKEN, expires: 2020-01-01}
  - {id: wrong-key, rule: RTC001, reason: unrelated, variable: OTHER}
""",
    )
    result = run(tmp_path, "check")
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert any(item["rule_id"] == "RTC001" for item in payload["findings"])
    assert [(item["id"], item["status"]) for item in payload["metadata"]["policy"]] == [
        ("expired", "expired"),
        ("wrong-key", "unused"),
    ]


def test_expired_match_does_not_block_later_valid_suppression(tmp_path: Path) -> None:
    missing_required(tmp_path)
    write(
        tmp_path,
        "runtime-contract.yaml",
        """version: 1
suppressions:
  - {id: expired, rule: RTC001, reason: past, variable: TOKEN, expires: 2020-01-01}
  - {id: current, rule: RTC001, reason: current exception, variable: TOKEN}
""",
    )
    payload = json.loads(run(tmp_path, "check").stdout)
    assert all(item["rule_id"] != "RTC001" for item in payload["findings"])
    assert {(item["id"], item["status"]) for item in payload["metadata"]["policy"]} == {
        ("expired", "expired"),
        ("current", "suppressed"),
    }


def test_text_and_sarif_show_policy_audit_without_hiding_reason(tmp_path: Path) -> None:
    missing_required(tmp_path)
    write(
        tmp_path,
        "runtime-contract.yaml",
        """version: 1
suppressions:
  - {id: audit, rule: RTC001, reason: ticket-123, variable: OTHER}
""",
    )
    text = run(tmp_path, output_format="text")
    assert "Policy" in text.stdout
    assert "unused RTC001 audit" in text.stdout
    assert "reason=ticket-123" in text.stdout
    sarif = json.loads(run(tmp_path, output_format="sarif").stdout)
    assert sarif["runs"][0]["properties"]["policy"][0]["status"] == "unused"


def test_policy_models_reject_blank_or_inconsistent_audit_metadata() -> None:
    with pytest.raises(ValidationError, match="reason must not be blank"):
        SeverityOverride(rule=RuleId.RTC001, severity=ConfigSeverity.WARNING, reason=" ")
    with pytest.raises(ValidationError, match="requires id, reason, and JSON pointer"):
        PolicyRecord(
            id="",
            rule_id="RTC001",
            status="unused",
            reason="why",
            pointer="/suppressions/0",
        )
    with pytest.raises(ValidationError, match="only severity override"):
        PolicyRecord(
            id="suppression",
            rule_id="RTC001",
            status="suppressed",
            reason="why",
            pointer="/suppressions/0",
            original_severity=Severity.ERROR,
            effective_severity=Severity.WARNING,
        )
