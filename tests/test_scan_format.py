"""D1.13 public JSON v1 format and compatibility tests."""

import json
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from typing import cast

import jsonschema
import pytest
from pydantic import ValidationError

from runtime_contract.domain import Finding, Phase, Severity, SourceLocation
from runtime_contract.rules import RuleId
from runtime_contract.scan import (
    ReportInputs,
    ReportMetadata,
    ScanRequest,
    ScanResult,
    parse_json_report,
    schema_bytes,
)
from runtime_contract.scan import engine as scan_engine
from runtime_contract.scan.engine import run_scan
from runtime_contract.scan.models import ScanFile, ScanStatus, ScanSummary
from runtime_contract.scan.renderers import render_json
from runtime_contract.scan.schema import generate_schema_bytes

TOP_LEVEL_FIELDS = {
    "schema_id",
    "schema_version",
    "metadata",
    "inputs",
    "status",
    "summary",
    "contract",
    "flow_graph",
    "diagnostics",
    "findings",
    "files",
}
REQUIRED_TOP_LEVEL_FIELDS = TOP_LEVEL_FIELDS - {"flow_graph"}


def report() -> str:
    return run_scan(
        ScanRequest(path=Path("examples/report-fixture"), output_format="json")
    ).rendered


def payload() -> dict[str, object]:
    return cast(dict[str, object], json.loads(report()))


def test_public_api_models_are_strict_frozen_and_extra_forbid() -> None:
    metadata = ReportMetadata(tool_version=None)
    with pytest.raises(ValidationError):
        metadata.tool = "other"  # type: ignore[assignment]
    with pytest.raises(ValidationError):
        ReportMetadata.model_validate({"tool_version": None, "extra": True})
    with pytest.raises(ValidationError):
        ReportInputs.model_validate(
            {
                "config": None,
                "environment": None,
                "selected_roots": (),
                "include": (),
                "exclude": (),
                "fail_on": 1,
            }
        )


def test_summary_file_and_status_invariants() -> None:
    for invalid in (
        {"candidates": -1},
        {"candidate_kinds": {"python": -1}},
        {"candidates": 1, "analyzed": 0, "skipped": 0},
    ):
        with pytest.raises(ValidationError):
            ScanSummary.model_validate(invalid)
    for path in ("", "/x", "bad\\x", "../x", "a/../x"):
        with pytest.raises(ValidationError):
            ScanFile(path=path, kind="python", status="complete")

    current = parse_json_report(report())
    for status, update in (
        (ScanStatus.COMPLETE, {}),
        (ScanStatus.PARTIAL, {"partial_files": 0}),
        (ScanStatus.FAILED, {"partial_files": 0, "failed_files": 0}),
    ):
        with pytest.raises(ValidationError, match="status contradicts"):
            ScanResult.model_validate(
                current.model_dump()
                | {"status": status, "summary": current.summary.model_copy(update=update)}
            )


def test_model_canonicalizes_file_order() -> None:
    current = parse_json_report(report())
    reversed_files = tuple(reversed(current.files))
    assert (
        ScanResult.model_validate(current.model_dump() | {"files": reversed_files}).files
        == current.files
    )


def test_writer_metadata_version_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_: str) -> str:
        raise PackageNotFoundError

    monkeypatch.setattr(scan_engine, "version", missing)
    result = run_scan(ScanRequest(path=Path("examples/report-fixture")))
    assert result.exit_code == 2
    assert result.result.metadata.tool_version is None


def test_canonical_shape_metadata_inputs_null_empty_and_no_host_data() -> None:
    value = payload()
    assert set(value) == TOP_LEVEL_FIELDS
    assert value["schema_id"] == "runtime-contract/v1"
    assert value["schema_version"] == 1
    assert value["metadata"] == {
        "command": "scan",
        "tool": "runtime-contract",
        "tool_version": "0.1.0.dev0",
    }
    inputs = value["inputs"]
    assert isinstance(inputs, dict)
    assert inputs["root"] == "."
    assert inputs["environment"] is None
    assert inputs["include"] == inputs["exclude"] == []
    assert not {"generated_at", "hostname", "cwd", "pid"}.intersection(value)
    assert "consumers" not in value and "providers" not in value
    flow_graph = value["flow_graph"]
    assert isinstance(flow_graph, dict)
    assert set(flow_graph) == {"nodes", "edges"}


def test_missing_config_is_null_and_writer_has_canonical_bytes(tmp_path: Path) -> None:
    rendered = run_scan(ScanRequest(path=tmp_path, output_format="json")).rendered
    assert json.loads(rendered)["inputs"]["config"] is None
    assert rendered.endswith("\n") and not rendered.endswith("\n\n")
    assert not rendered.startswith("\ufeff")
    assert "é" in render_json(
        run_scan(ScanRequest(path=Path("examples/report-fixture"))).result.model_copy(
            update={
                "inputs": ReportInputs(
                    config="é.yaml",
                    environment=None,
                    selected_roots=("api", "web"),
                    include=(),
                    exclude=(),
                    fail_on="error",
                )
            }
        )
    )


def test_schema_is_draft_2020_12_stable_and_validates_report() -> None:
    schema = json.loads(schema_bytes())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == (
        "https://raw.githubusercontent.com/piotr-adamski/runtime-contract/main/"
        "schemas/runtime-contract-scan-result-v1.schema.json"
    )
    assert set(schema["required"]) == REQUIRED_TOP_LEVEL_FIELDS
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(payload(), schema)
    assert generate_schema_bytes() == generate_schema_bytes() == schema_bytes()


@pytest.mark.parametrize("missing", sorted(REQUIRED_TOP_LEVEL_FIELDS))
def test_every_canonical_top_level_field_is_required(missing: str) -> None:
    document = payload()
    document.pop(missing)
    schema = json.loads(schema_bytes())
    with pytest.raises(jsonschema.ValidationError) as schema_error:
        jsonschema.Draft202012Validator(schema).validate(document)
    assert missing in schema_error.value.message

    with pytest.raises(ValueError, match=r"^invalid runtime-contract JSON report$") as parser_error:
        parse_json_report(json.dumps(document))
    public_error = str(parser_error.value)
    assert "Traceback" not in public_error
    assert "SECRET_VALUE" not in public_error
    assert "/home/" not in public_error


def test_reader_rebuilds_missing_flow_graph_for_early_v1_compatibility() -> None:
    document = payload()
    expected = document.pop("flow_graph")
    summary = cast(dict[str, object], document["summary"])
    summary.pop("flow_nodes")
    summary.pop("flow_edges")

    parsed = parse_json_report(json.dumps(document))

    assert parsed.flow_graph.model_dump(mode="json") == expected
    assert parsed.summary.flow_nodes == len(parsed.flow_graph.nodes)
    assert parsed.summary.flow_edges == len(parsed.flow_graph.edges)


def test_reader_rejects_missing_graph_when_legacy_summary_is_not_an_object() -> None:
    document = payload()
    document.pop("flow_graph")
    document["summary"] = []

    with pytest.raises(ValueError, match="invalid runtime-contract JSON report"):
        parse_json_report(json.dumps(document))


def test_typed_finding_is_supported_and_summary_must_match() -> None:
    current = parse_json_report(report())
    location = SourceLocation(path="api/settings.py", start_line=1, start_column=1)
    finding = Finding(
        rule_id=RuleId.RTC001,
        severity=Severity.ERROR,
        component="api",
        phase=Phase.RUNTIME,
        primary_location=location,
        evidence_locations=(location,),
    )
    summary = current.summary.model_copy(update={"findings": 1})
    changed = current.model_copy(update={"findings": (finding,), "summary": summary})
    assert ScanResult.model_validate(changed.model_dump()).findings == (finding,)
    with pytest.raises(ValidationError, match=r"summary\.findings"):
        ScanResult.model_validate(current.model_dump() | {"findings": (finding,)})


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_reader_rejects_non_json_constants_and_duplicate_keys(constant: str) -> None:
    with pytest.raises(ValueError, match="invalid runtime-contract JSON report"):
        parse_json_report('{"schema_id":"runtime-contract/v1","x":' + constant + "}")
    with pytest.raises(ValueError):
        parse_json_report('{"schema_id":"runtime-contract/v1","schema_id":"runtime-contract/v1"}')


@pytest.mark.parametrize("value", [0, 2, "1", 1.0, None])
def test_reader_rejects_wrong_schema_versions(value: object) -> None:
    document = payload()
    document["schema_version"] = value
    with pytest.raises(ValueError):
        parse_json_report(json.dumps(document))


def test_reader_rejects_encoding_bom_unknown_fields_paths_and_schema_id() -> None:
    for invalid in (b"\xff", b"\xef\xbb\xbf{}"):
        with pytest.raises(ValueError):
            parse_json_report(invalid)
    for invalid_text in ("[]", '{"schema_id":"runtime-contract/v1"}'):
        with pytest.raises(ValueError):
            parse_json_report(invalid_text)
    for key, value in (("schema_id", "other/v1"), ("unknown", True)):
        document = payload()
        document[key] = value
        with pytest.raises(ValueError):
            parse_json_report(json.dumps(document))
    for path in ("/absolute.yaml", "bad\\path.yaml", "../escape.yaml"):
        document = payload()
        document["inputs"]["config"] = path  # type: ignore[index]
        with pytest.raises(ValueError):
            parse_json_report(json.dumps(document))


def test_exact_d1_12_legacy_normalizes_and_reserializes_canonical() -> None:
    canonical = payload()
    inputs = canonical.pop("inputs")
    canonical.pop("flow_graph")
    canonical.pop("metadata")
    canonical.pop("schema_version")
    summary = cast(dict[str, object], canonical["summary"])
    summary.pop("flow_nodes")
    summary.pop("flow_edges")
    assert isinstance(inputs, dict)
    legacy = canonical | {
        "root": inputs["root"],
        "config": inputs["config"],
        "environment": inputs["environment"],
        "selected_roots": inputs["selected_roots"],
        "effective_include": inputs["include"],
        "effective_exclude": inputs["exclude"],
        "fail_on": inputs["fail_on"],
    }
    parsed = parse_json_report(json.dumps(legacy))
    assert parsed.schema_version == 1
    assert parsed.metadata.tool_version is None
    rewritten = json.loads(render_json(parsed))
    assert set(rewritten) == TOP_LEVEL_FIELDS
    assert "inputs" in rewritten and "root" not in rewritten
    hybrid = legacy | {"schema_version": 1}
    with pytest.raises(ValueError):
        parse_json_report(json.dumps(hybrid))


def test_reader_rejects_flow_graph_inconsistent_with_contract() -> None:
    document = payload()
    graph = cast(dict[str, object], document["flow_graph"])
    graph["edges"] = []
    summary = cast(dict[str, object], document["summary"])
    summary["flow_edges"] = 0

    with pytest.raises(ValueError, match="invalid runtime-contract JSON report"):
        parse_json_report(json.dumps(document))


def test_golden_snapshot_is_exact_and_repeatable() -> None:
    first = report().encode()
    second = report().encode()
    golden = Path("examples/reports/runtime-contract-v1.json").read_bytes()
    assert first == second == golden
    value = json.loads(golden)
    assert value["diagnostics"] and value["findings"] == []
    assert value["contract"]["providers"] == []
    assert {item["component"] for item in value["contract"]["consumers"]} == {"api", "web"}
