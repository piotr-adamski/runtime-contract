"""Offline rule and finding explanations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Never, cast

import typer

from runtime_contract.commands.config import _render_errors
from runtime_contract.config.loader import ConfigValidationError, load_config
from runtime_contract.domain import Finding
from runtime_contract.rules import RuleId, get_rule
from runtime_contract.scan import ScanRequest, ScanStatus, parse_json_report, run_scan, write_atomic
from runtime_contract.security import redact_exception

_DOC_URL = "https://github.com/piotr-adamski/runtime-contract#rule-catalog"
_EXAMPLES = {
    RuleId.RTC001: "Code requires DATABASE_URL, but the selected runtime target does not deliver it.",
    RuleId.RTC002: "A sensitive API_TOKEN is delivered as a non-placeholder plain literal.",
    RuleId.RTC003: "A scanned configuration contains private-key material.",
    RuleId.RTC004: "Code consumes FEATURE_FLAG, but the component documentation omits it.",
    RuleId.RTC005: ".env.example declares LEGACY_URL with no detected consumer.",
    RuleId.RTC006: "Code computes an environment-variable name at runtime.",
    RuleId.RTC007: "Two static sources declare incompatible defaults for the same target and phase.",
    RuleId.RTC008: "An optional variable is intentionally absent from a selected target.",
    RuleId.RTC009: "An env_file may contain a required key, but static analysis cannot prove it.",
    RuleId.RTC010: "A runtime consumer has only build-time delivery.",
    RuleId.RTC011: "Pydantic Settings customises its sources through executable code.",
    RuleId.RTC012: "A Kubernetes resource kind is outside the supported workload set.",
}


def _fail(message: str) -> Never:
    typer.echo(f"Error: {message}.", err=True)
    raise typer.Exit(code=2) from None


def _location(value: Any) -> dict[str, Any]:
    return cast(dict[str, Any], value.model_dump(mode="json"))


def _document(rule_id: RuleId, finding: Finding | None) -> dict[str, Any]:
    rule = get_rule(rule_id)
    return {
        "schema_id": "runtime-contract/explanation/v1",
        "kind": "finding" if finding is not None else "rule",
        "rule_id": rule.id.value,
        "finding_id": finding.id if finding is not None else None,
        "name": rule.name,
        "title": rule.title,
        "default_severity": rule.default_severity,
        "effective_severity": finding.severity.value
        if finding is not None
        else rule.default_severity,
        "rationale": rule.rationale,
        "example": _EXAMPLES[rule.id],
        "remediation": rule.remediation,
        "documentation": _DOC_URL,
        "primary_location": _location(finding.primary_location) if finding is not None else None,
        "evidence_locations": (
            [_location(item) for item in finding.evidence_locations] if finding is not None else []
        ),
    }


def _render(document: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return (
            json.dumps(
                document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        )
    if output_format != "text":
        _fail("format must be text or json")
    lines = [
        f"{document['rule_id']} {document['name']} — {document['title']}",
        f"Kind: {document['kind']}",
        f"Severity: {document['effective_severity']} (default: {document['default_severity']})",
        f"Why: {document['rationale']}",
        f"Example: {document['example']}",
        f"Remediation: {document['remediation']}",
        f"Documentation: {document['documentation']}",
    ]
    if document["finding_id"] is not None:
        lines.insert(1, f"Finding: {document['finding_id']}")
        location = document["primary_location"]
        lines.append(
            f"Primary location: {location['path']}:{location['start_line']}:{location['start_column']}"
        )
        lines.append(f"Evidence locations: {len(document['evidence_locations'])}")
    return "\n".join(lines) + "\n"


def _finding(identifier: str, source: Path | None) -> Finding:
    if source is None:
        _fail("finding explanation requires a report JSON file or project directory")
    try:
        if source.is_file():
            result = parse_json_report(source.read_bytes())
        elif source.is_dir():
            run = run_scan(ScanRequest(path=source, command="scan"))
            result = run.result
        else:
            _fail("explanation source does not exist")
    except (OSError, ValueError, ConfigValidationError) as error:
        _fail(redact_exception(error).message)
    if result.status is not ScanStatus.COMPLETE:
        _fail("finding source analysis is incomplete")
    for finding in result.findings:
        if finding.id == identifier:
            return finding
    _fail("finding identifier was not found")


def explain(
    rule_or_finding_id: Annotated[str, typer.Argument(help="Rule ID or finding ID to explain.")],
    path: Annotated[
        Path | None,
        typer.Argument(help="Report JSON file or project directory for finding lookup."),
    ] = None,
    output_format: Annotated[
        str, typer.Option("--format", help="Output format: text or json.")
    ] = "text",
    output: Annotated[
        Path | None, typer.Option("--output", help="Write output atomically.")
    ] = None,
) -> None:
    """Explain a rule or finding offline without changing analyzed project files."""
    try:
        rule_id = RuleId(rule_or_finding_id)
        finding = None
        if path is not None:
            if not path.is_dir():
                _fail("rule explanation path must be a project directory")
            try:
                load_config(path)
            except ConfigValidationError as error:
                _render_errors(error, "text")
                raise typer.Exit(code=2) from None
    except ValueError:
        finding = _finding(rule_or_finding_id, path)
        rule_id = finding.rule_id
    rendered = _render(_document(rule_id, finding), output_format)
    if output is None:
        typer.echo(rendered, nl=False)
        return
    try:
        write_atomic(Path.cwd(), output, rendered)
    except (OSError, ValueError):
        _fail("could not write explanation")
