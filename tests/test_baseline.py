"""Regression gates must fail closed without hiding the existing configuration debt."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app
from runtime_contract.domain import Severity
from runtime_contract.scan import ScanRequest, parse_json_report, run_scan
from runtime_contract.scan.baseline import blocks, compare_baseline

runner = CliRunner()


def project(root: Path, text: str = 'import os\nos.environ["REQUIRED"]\n') -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(text, encoding="utf-8")
    return root


def save(root: Path, **changes: Any) -> Path:
    result = runner.invoke(app, ["scan", str(root), "--format", "json"])
    value = json.loads(result.stdout)
    for key, replacement in changes.items():
        value[key] = replacement
    target = root / "baseline.json"
    target.write_text(json.dumps(value), encoding="utf-8")
    return target


def invoke(root: Path, *args: str) -> Any:
    return runner.invoke(app, ["check", str(root), "--baseline", "baseline.json", *args])


def test_line_shifts_preserve_existing_findings_but_new_keys_block(tmp_path: Path) -> None:
    project(tmp_path)
    save(tmp_path)
    project(tmp_path, '\n\nimport os\nos.environ["REQUIRED"]\n')
    same = invoke(tmp_path, "--format", "json")
    assert same.exit_code == 0
    report = json.loads(same.stdout)
    assert len(report["findings"]) == len(report["metadata"]["baseline"]["existing"]) == 1
    assert report["metadata"]["baseline"]["new"] == []
    project(tmp_path, 'import os\nos.environ["REQUIRED"]\nos.environ["ADDED"]\n')
    added = invoke(tmp_path, "--format", "json")
    assert added.exit_code == 1
    assert len(json.loads(added.stdout)["metadata"]["baseline"]["new"]) == 1
    assert len(json.loads(added.stdout)["findings"]) == 2
    assert "Baseline" in invoke(tmp_path).stdout
    project(tmp_path, "pass\n")
    resolved = json.loads(invoke(tmp_path, "--format", "json").stdout)["metadata"]["baseline"]
    assert len(resolved["resolved"]) == 1


@pytest.mark.parametrize(
    "threshold,expected", [("error", 0), ("warning", 1), ("info", 1), ("never", 0)]
)
def test_threshold_applies_to_new_findings(tmp_path: Path, threshold: str, expected: int) -> None:
    project(tmp_path, "pass\n")
    # Threshold is part of the compatibility contract: generate under the identical threshold.
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json", "--fail-on", threshold])
    (tmp_path / "baseline.json").write_text(result.stdout)
    (tmp_path / ".env.example").write_text("UNUSED=\n")
    assert invoke(tmp_path, "--fail-on", threshold).exit_code == expected


@pytest.mark.parametrize(
    "change", ["version", "fingerprint", "scope", "environment", "policy", "legacy"]
)
def test_incompatible_baselines_are_rejected(tmp_path: Path, change: str) -> None:
    project(tmp_path)
    path = save(tmp_path)
    payload = json.loads(path.read_text())
    if change == "version":
        payload["metadata"]["tool_version"] = "0.0.0"
    elif change == "fingerprint":
        payload["metadata"]["analysis_fingerprint"] = "0" * 64
    elif change == "scope":
        payload["inputs"]["include"] = ["*.py"]
    elif change == "environment":
        payload["inputs"]["environment"] = "other"
    elif change == "legacy":
        del payload["metadata"]["analysis_fingerprint"]
    else:
        (tmp_path / "runtime-contract.yaml").write_text(
            "version: 1\nseverity_overrides:\n  - rule: RTC001\n    severity: warning\n    reason: reviewed policy\n"
        )
    path.write_text(json.dumps(payload))
    result = invoke(tmp_path, "--format", "json")
    assert result.exit_code == 2
    assert result.stdout == "" and "incompatible" in result.stderr


@pytest.mark.parametrize("side", ["baseline", "current"])
def test_incomplete_analysis_always_exits_two(tmp_path: Path, side: str) -> None:
    project(tmp_path, "import os\nos.getenv(dynamic_name)\n" if side == "baseline" else "pass\n")
    save(tmp_path)
    project(tmp_path, "import os\nos.getenv(dynamic_name)\n" if side == "current" else "pass\n")
    result = invoke(tmp_path, "--fail-on", "never")
    assert result.exit_code == 2
    assert "complete analyses" in result.stderr


@pytest.mark.parametrize(
    "content", [b"not JSON SECRET_CANARY", b"\xff", b'{"schema_id":1,"schema_id":1}']
)
def test_malformed_baselines_are_redacted(tmp_path: Path, content: bytes) -> None:
    project(tmp_path)
    (tmp_path / "baseline.json").write_bytes(content)
    result = invoke(tmp_path)
    assert result.exit_code == 2
    assert "SECRET_CANARY" not in result.output
    assert str(tmp_path) not in result.output


def test_missing_oversized_and_recursive_reports_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project(tmp_path)
    assert invoke(tmp_path).exit_code == 2
    monkeypatch.setattr("runtime_contract.scan.baseline.MAX_BASELINE_BYTES", 4)
    (tmp_path / "baseline.json").write_text("12345")
    assert invoke(tmp_path).exit_code == 2
    monkeypatch.setattr("runtime_contract.scan.baseline.MAX_BASELINE_BYTES", 32000000)
    (tmp_path / "baseline.json").write_text("[" * 2000)
    assert invoke(tmp_path).exit_code == 2


def test_occurrence_counts_and_severity_increases_cannot_hide(tmp_path: Path) -> None:
    project(tmp_path)
    path = save(tmp_path)
    baseline = parse_json_report(path.read_bytes())
    old = baseline.findings[0]
    weak = old.model_copy(update={"severity": Severity.WARNING})
    path.write_text(baseline.model_copy(update={"findings": (weak,)}).model_dump_json())
    assessment = compare_baseline(path, baseline)
    assert assessment.worsened == (old.id,)
    extra = old.model_copy(update={"id": "additional-occurrence"})
    current = baseline.model_copy(update={"findings": (old, extra)})
    assessment = compare_baseline(path, current)
    assert len(assessment.new) == len(assessment.worsened) == 1
    assert not blocks((old,), "never") and blocks((old,), "error")


def test_baseline_cannot_be_overwritten_and_scan_api_rejects_baseline(tmp_path: Path) -> None:
    project(tmp_path)
    path = save(tmp_path)
    before = path.read_bytes()
    assert invoke(tmp_path, "--output", "baseline.json").exit_code == 2
    assert path.read_bytes() == before
    with pytest.raises(ValueError, match="only by check"):
        run_scan(ScanRequest(path=tmp_path, baseline=path))


def test_output_and_serialization_keep_all_findings(tmp_path: Path) -> None:
    project(tmp_path)
    save(tmp_path)
    result = invoke(tmp_path, "--format", "sarif", "--output", "report.sarif")
    assert result.exit_code == 0 and result.stdout == ""
    report = json.loads((tmp_path / "report.sarif").read_text())
    assert len(report["runs"][0]["results"]) == 1
    assert report["runs"][0]["results"][0]["baselineState"] == "unchanged"
    project(tmp_path, 'import os\nos.environ["REQUIRED"]\nos.environ["NEW"]\n')
    new = json.loads(invoke(tmp_path, "--format", "sarif").stdout)
    assert {item["baselineState"] for item in new["runs"][0]["results"]} == {"new", "unchanged"}
    baseline = parse_json_report((tmp_path / "baseline.json").read_bytes())
    baseline = baseline.model_copy(
        update={
            "findings": tuple(
                item.model_copy(update={"severity": Severity.WARNING}) for item in baseline.findings
            )
        }
    )
    (tmp_path / "baseline.json").write_text(baseline.model_dump_json())
    worsened = json.loads(invoke(tmp_path, "--format", "sarif").stdout)
    assert "updated" in {item["baselineState"] for item in worsened["runs"][0]["results"]}
    # Output formatting/report destinations do not alter the analysis fingerprint.
    (tmp_path / "runtime-contract.yaml").write_text("version: 1\nexecution: {format: json}\n")
    save(tmp_path)
    (tmp_path / "runtime-contract.yaml").write_text("version: 1\nexecution: {format: sarif}\n")
    assert invoke(tmp_path).exit_code == 0
