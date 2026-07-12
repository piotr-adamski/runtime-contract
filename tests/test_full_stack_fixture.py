"""D2.14 public, domain-neutral full-stack fixture contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict, cast

from runtime_contract.config.loader import load_config
from runtime_contract.domain import ConsumerAccessKind
from runtime_contract.scan import ScanRequest, run_scan

FIXTURE = Path(__file__).parent / "fixtures" / "full-stack"


class FixtureExpectation(TypedDict):
    inputs: list[str]
    required_config_keys: list[str]
    forbidden_terms: list[str]
    scenario_expectations: list[dict[str, str]]
    expected_diagnostics: list[str]


def expectation() -> FixtureExpectation:
    return cast(
        FixtureExpectation,
        json.loads((FIXTURE / "expected.json.golden").read_text(encoding="utf-8")),
    )


def test_full_stack_fixture_is_complete_domain_neutral_and_value_safe() -> None:
    expected = expectation()
    actual = sorted(
        path.relative_to(FIXTURE).as_posix()
        for path in FIXTURE.rglob("*")
        if path.is_file() and path.name != "expected.json.golden"
    )
    assert actual == expected["inputs"]
    public = "\n".join((FIXTURE / path).read_text(encoding="utf-8") for path in actual)
    assert all(term not in public.casefold() for term in expected["forbidden_terms"])
    assert (
        "hidden-placeholder"
        not in run_scan(ScanRequest(path=FIXTURE, output_format="json")).rendered
    )


def test_full_stack_fixture_scans_deterministically_with_expected_graph_scenarios() -> None:
    document = load_config(FIXTURE, require=True)
    assert document is not None
    first = run_scan(ScanRequest(path=FIXTURE, output_format="json"))
    second = run_scan(ScanRequest(path=FIXTURE, output_format="json"))
    assert first.exit_code == second.exit_code == 0
    assert first.rendered == second.rendered
    expected = expectation()
    assert [item.code.value for item in first.result.diagnostics] == expected[
        "expected_diagnostics"
    ]
    assert first.result.status.value == "complete"
    assert {item.name for item in first.result.contract.config_keys} == set(
        expected["required_config_keys"]
    )
    access_kinds = {item.access_kind for item in first.result.contract.consumers}
    assert ConsumerAccessKind.PYDANTIC_SETTINGS in access_kinds
    assert ConsumerAccessKind.VITE_IMPORT_META_ENV in access_kinds
    assert {item["id"] for item in expected["scenario_expectations"]} == {
        "valid-secret-flow",
        "valid-public-flow",
        "missing-provider",
        "unused-provider",
        "conflicting-provider",
        "secret-in-configmap",
    }
