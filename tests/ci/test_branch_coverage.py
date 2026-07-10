"""Tests for the exact global branch coverage gate."""

from decimal import Decimal
from pathlib import Path

import pytest

from scripts.ci import check_branch_coverage


def write_report(path: Path, branch_rate: str | None) -> None:
    attribute = "" if branch_rate is None else f' branch-rate="{branch_rate}"'
    path.write_text(f"<?xml version='1.0'?><coverage{attribute}/>", encoding="utf-8")


@pytest.mark.parametrize("rate", ["0.90", "0.900000", "1", "0.91"])
def test_accepts_threshold_and_higher(tmp_path: Path, rate: str) -> None:
    report = tmp_path / "coverage.xml"
    write_report(report, rate)

    assert check_branch_coverage.read_branch_rate(report) == Decimal(rate)
    assert check_branch_coverage.main([str(report)]) == 0


def test_rejects_rate_below_threshold(tmp_path: Path) -> None:
    report = tmp_path / "coverage.xml"
    write_report(report, "0.8999999999999999")

    assert check_branch_coverage.main([str(report)]) == 1


@pytest.mark.parametrize("content", ["<coverage>", "<coverage branch-rate='NaN'/>", "<coverage/>"])
def test_fails_closed_for_invalid_reports(tmp_path: Path, content: str) -> None:
    report = tmp_path / "coverage.xml"
    report.write_text(content, encoding="utf-8")

    assert check_branch_coverage.main([str(report)]) == 1


def test_fails_closed_for_missing_report(tmp_path: Path) -> None:
    assert check_branch_coverage.main([str(tmp_path / "missing.xml")]) == 1
