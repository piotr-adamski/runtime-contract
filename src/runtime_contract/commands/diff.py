"""Deterministic semantic comparison of projects or saved reports."""

from __future__ import annotations

import importlib.metadata
import json
from collections import defaultdict
from pathlib import Path
from typing import Annotated, Any, Literal, Never

import typer

from runtime_contract.commands.config import _render_errors
from runtime_contract.config.loader import ConfigValidationError
from runtime_contract.diff_report import DiffInput, DiffMetadata, DiffReport
from runtime_contract.scan import (
    ScanRequest,
    ScanResult,
    ScanStatus,
    parse_json_report,
    run_scan,
    write_atomic,
)
from runtime_contract.security import redact_exception


def _fail(message: str) -> Never:
    typer.echo(f"Error: {message}.", err=True)
    raise typer.Exit(code=2) from None


def _load(path: Path, environment: str | None) -> tuple[ScanResult, Literal["directory", "report"]]:
    kind: Literal["directory", "report"]
    try:
        if path.is_dir():
            result = run_scan(
                ScanRequest(path=path, environment=environment, command="scan")
            ).result
            kind = "directory"
        elif path.is_file():
            result = parse_json_report(path.read_bytes())
            kind = "report"
            if environment is not None and result.inputs.environment != environment:
                _fail("saved report environment does not match --environment")
        else:
            _fail("diff input does not exist")
    except ConfigValidationError as error:
        _render_errors(error, "text")
        raise typer.Exit(code=2) from None
    except (OSError, ValueError) as error:
        _fail(redact_exception(error).message)
    if result.status is not ScanStatus.COMPLETE:
        _fail("diff input analysis is incomplete")
    return result, kind


def _stable(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _records(result: ScanResult) -> dict[str, list[dict[str, Any]]]:
    keys = {item.id: item for item in result.contract.config_keys}
    environments = {item.id: item for item in result.contract.environments}
    records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for key in result.contract.config_keys:
        records["classifications"].append(
            {
                "identity": {"component": key.component, "key": key.name},
                "attributes": {
                    "secret": key.secret,
                    "secret_source": key.secret_source.value,
                    "allow_literal": key.allow_literal,
                    "severity_override": (
                        key.severity_override.value if key.severity_override is not None else None
                    ),
                    "sensitivity_reason": key.sensitivity_reason.value,
                    "sensitivity_confidence": key.sensitivity_confidence.value,
                },
            }
        )
    for consumer in result.contract.consumers:
        records["consumers"].append(
            {
                "identity": {
                    "component": consumer.component,
                    "key": keys[consumer.config_key_id].name,
                    "phase": consumer.phase.value,
                    "access_kind": consumer.access_kind.value,
                    "path": consumer.location.path,
                },
                "attributes": {
                    "required": consumer.required,
                    "requirement_source": consumer.requirement_source.value,
                    "has_literal_fallback": consumer.has_literal_fallback,
                },
            }
        )
    for provider in result.contract.providers:
        environment = environments.get(provider.environment_id or "")
        records["providers"].append(
            {
                "identity": {
                    "component": provider.component,
                    "key": keys[provider.config_key_id].name
                    if provider.config_key_id is not None
                    else None,
                    "target": environment.target if environment is not None else None,
                    "profile": environment.profile.value if environment is not None else None,
                    "role": provider.role.value,
                    "phase": provider.phase.value,
                    "mechanism": provider.mechanism.value,
                    "path": provider.location.path,
                },
                "attributes": {
                    "channel": provider.channel.value,
                    "evidence_kind": provider.evidence_kind.value,
                },
            }
        )
    for finding in result.findings:
        environment = environments.get(finding.environment_id or "")
        records["findings"].append(
            {
                "identity": {
                    "rule_id": finding.rule_id.value,
                    "component": finding.component,
                    "key": keys[finding.config_key_id].name
                    if finding.config_key_id is not None
                    else None,
                    "target": environment.target if environment is not None else None,
                    "profile": environment.profile.value if environment is not None else None,
                    "phase": finding.phase.value,
                    "path": finding.primary_location.path,
                },
                "attributes": {
                    "severity": finding.severity.value,
                    "parameters": [list(value) for value in finding.parameters],
                },
            }
        )
    return records


def _group(values: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for value in values:
        identity_key = _stable(value["identity"])
        attributes_key = _stable(value["attributes"])
        counts[(identity_key, attributes_key)] += 1
        grouped.setdefault(identity_key, {"identity": value["identity"], "variants": []})
    for (identity_key, attributes_key), count in sorted(counts.items()):
        grouped[identity_key]["variants"].append(
            {"attributes": json.loads(attributes_key), "count": count}
        )
    return grouped


def _compare(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> dict[str, Any]:
    before = _group(left)
    after = _group(right)
    added = [after[key] for key in sorted(after.keys() - before.keys())]
    removed = [before[key] for key in sorted(before.keys() - after.keys())]
    changed = [
        {
            "identity": before[key]["identity"],
            "before": before[key]["variants"],
            "after": after[key]["variants"],
        }
        for key in sorted(before.keys() & after.keys())
        if before[key]["variants"] != after[key]["variants"]
    ]
    return {"added": added, "removed": removed, "changed": changed}


def _render(document: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return _stable(document) + "\n"
    if output_format != "text":
        _fail("format must be text or json")
    lines = [f"runtime-contract diff: {document['status']}"]
    for category, changes in document["changes"].items():
        lines.append(
            f"{category}: +{len(changes['added'])} -{len(changes['removed'])} ~{len(changes['changed'])}"
        )
        for action in ("added", "removed", "changed"):
            for item in changes[action]:
                lines.append(f"  {action}: {_stable(item['identity'])}")
    return "\n".join(lines) + "\n"


def diff(
    left: Annotated[Path, typer.Argument(help="Left project directory or saved JSON report.")],
    right: Annotated[Path, typer.Argument(help="Right project directory or saved JSON report.")],
    environment: Annotated[str | None, typer.Option(help="Shared environment profile.")] = None,
    output_format: Annotated[
        str, typer.Option("--format", help="Output format: text or json.")
    ] = "text",
    output: Annotated[
        Path | None, typer.Option("--output", help="Write output atomically.")
    ] = None,
) -> None:
    """Compare two directories or two reports without invoking Git."""
    left_result, left_kind = _load(left, environment)
    right_result, right_kind = _load(right, environment)
    if left_kind != right_kind:
        _fail("diff requires two directories or two saved JSON reports")
    left_records = _records(left_result)
    right_records = _records(right_result)
    categories = ("consumers", "providers", "classifications", "findings")
    changes = {name: _compare(left_records[name], right_records[name]) for name in categories}
    different = any(any(value for value in category.values()) for category in changes.values())
    tool_version = importlib.metadata.version("runtime-contract")
    report = DiffReport(
        schema_id="runtime-contract/v1",
        schema_version=1,
        metadata=DiffMetadata(
            tool="runtime-contract", tool_version=tool_version, command="diff", policy=()
        ),
        status="different" if different else "identical",
        diagnostics=(),
        left=DiffInput(kind=left_kind, environment=left_result.inputs.environment),
        right=DiffInput(kind=right_kind, environment=right_result.inputs.environment),
        changes=changes,
    )
    document = report.model_dump(mode="json")
    rendered = _render(document, output_format)
    if output is None:
        typer.echo(rendered, nl=False)
        return
    try:
        write_atomic(Path.cwd(), output, rendered)
    except (OSError, ValueError):
        _fail("could not write diff")
