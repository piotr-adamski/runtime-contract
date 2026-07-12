"""D3.01 stable public rule and technical diagnostic catalogs."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from runtime_contract.analysis import DIAGNOSTIC_CATALOG, DiagnosticCode, diagnostic_severity
from runtime_contract.rules import RULE_CATALOG, RuleId, get_rule


def test_rule_catalog_matches_the_public_golden_fixture() -> None:
    expected = json.loads(Path("tests/fixtures/rules/catalog-v1.json").read_text())
    actual = [
        {
            "id": item.id.value,
            "name": item.name,
            "title": item.title,
            "default_severity": item.default_severity,
        }
        for item in RULE_CATALOG.values()
    ]
    assert actual == expected
    assert tuple(RULE_CATALOG) == tuple(RuleId)
    assert len({item.name for item in RULE_CATALOG.values()}) == len(RuleId) == 12
    assert all(
        item.title.strip() and item.rationale.strip() and item.remediation.strip()
        for item in RULE_CATALOG.values()
    )


def test_rule_definitions_and_mapping_are_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        get_rule("RTC001").name = "CHANGED"  # type: ignore[misc]
    with pytest.raises(TypeError):
        RULE_CATALOG[RuleId.RTC001] = get_rule(RuleId.RTC002)  # type: ignore[index]
    with pytest.raises(ValueError, match="unknown runtime-contract rule identifier"):
        get_rule("RTC999")


def test_parser_diagnostics_are_complete_separate_and_value_safe() -> None:
    assert tuple(DIAGNOSTIC_CATALOG) == tuple(DiagnosticCode)
    assert all(
        item.title and item.rationale and item.remediation for item in DIAGNOSTIC_CATALOG.values()
    )
    assert {diagnostic_severity(code) for code in DiagnosticCode} == {"error", "warning", "info"}
    serialized = repr(tuple(DIAGNOSTIC_CATALOG.values()))
    assert "secret value" not in serialized.casefold()
    assert "RTC001" not in serialized
