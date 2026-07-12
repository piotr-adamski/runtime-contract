"""Deterministic text, JSON, and SARIF rendering."""

from __future__ import annotations

import importlib.metadata
import json
import textwrap
from typing import Any

from runtime_contract.domain import Severity
from runtime_contract.rules import RULE_CATALOG, get_rule
from runtime_contract.scan.models import ScanResult, ScanStatus


def render_json(result: ScanResult) -> str:
    return (
        json.dumps(
            result.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )


_COLORS = {
    "error": "31",
    "warning": "33",
    "info": "36",
    "complete": "32",
    "partial": "33",
    "failed": "31",
}
_SYMBOLS = {"error": "✖", "warning": "!", "info": "i"}


def _paint(value: str, role: str, enabled: bool) -> str:
    return f"\x1b[{_COLORS[role]}m{value}\x1b[0m" if enabled else value


def _wrapped(lines: list[str], prefix: str, value: str, width: int) -> None:
    available = max(10, width - len(prefix))
    parts = textwrap.wrap(value, width=available, break_long_words=False, break_on_hyphens=False)
    lines.append(prefix + (parts[0] if parts else ""))
    lines.extend(" " * len(prefix) + part for part in parts[1:])


def render_text(
    result: ScanResult,
    verbosity: int = 0,
    *,
    color: bool = False,
    emoji: bool = False,
    width: int = 100,
) -> str:
    summary = result.summary
    if verbosity < 0:
        return f"Result: {result.status.value} — {summary.consumers} consumers, {summary.config_keys} config keys\n"
    lines = [
        f"runtime-contract {result.metadata.command}",
        "",
        "Root: .",
        f"Config: {result.inputs.config or '-'}",
        f"Environment: {result.inputs.environment or '-'}",
        f"Selected roots: {', '.join(result.inputs.selected_roots) or '-'}",
        "",
        "Summary",
        f"  Candidates: {summary.candidates}",
        f"  Analyzed: {summary.analyzed}",
        f"  Skipped: {summary.skipped}",
        f"  Config keys: {summary.config_keys}",
        f"  Consumers: {summary.consumers}",
        f"  Flow nodes: {summary.flow_nodes}",
        f"  Flow edges: {summary.flow_edges}",
        f"  Precedence providers: {summary.precedence_providers}",
        f"  Precedence conflicts: {summary.precedence_conflicts}",
        f"  Diagnostics: {summary.diagnostics}",
        f"  Findings: {summary.findings}",
    ]
    if result.contract.consumers:
        lines.extend(["", "Consumers"])
        keys = {key.id: key for key in result.contract.config_keys}
        for consumer in result.contract.consumers:
            key = keys[consumer.config_key_id]
            location = consumer.location
            position = (
                f":{location.start_line}:{location.start_column}" if location.start_line else ""
            )
            classification = "secret" if key.secret else "plain"
            lines.append(
                f"  {consumer.component}  {key.name}  {location.path}{position}  "
                f"{'required' if consumer.required else 'optional'}  {classification}"
            )
    else:
        lines.extend(["", "No supported consumers found."])
    if result.diagnostics:
        lines.extend(["", "Diagnostics"])
        for diagnostic in result.diagnostics:
            location = diagnostic.primary_location
            position = (
                f":{location.start_line}:{location.start_column}" if location.start_line else ""
            )
            rule = f"{diagnostic.rule_id.value} " if diagnostic.rule_id is not None else ""
            lines.append(
                f"  {diagnostic.severity.value} {rule}{diagnostic.code.value.upper()} "
                f"{location.path}{position}"
            )
    if result.findings:
        lines.extend(["", "Findings"])
        keys = {key.id: key for key in result.contract.config_keys}
        environments = {item.id: item for item in result.contract.environments}
        severity_order = (Severity.ERROR, Severity.WARNING, Severity.INFO)
        for severity in severity_order:
            findings = tuple(item for item in result.findings if item.severity is severity)
            if not findings:
                continue
            label = severity.value.upper()
            lines.append(f"  {_paint(label, severity.value, color)} ({len(findings)})")
            for component in sorted({item.component for item in findings}):
                lines.append(f"    {component}")
                for finding in (item for item in findings if item.component == component):
                    location = finding.primary_location
                    position = (
                        f":{location.start_line}:{location.start_column}"
                        if location.start_line
                        else ""
                    )
                    finding_key = keys.get(finding.config_key_id or "")
                    environment = environments.get(finding.environment_id or "")
                    symbol = f"{_SYMBOLS[severity.value]} " if emoji else ""
                    _wrapped(
                        lines,
                        "      " + symbol,
                        f"{finding.rule_id.value} {get_rule(finding.rule_id).title}",
                        width,
                    )
                    _wrapped(
                        lines,
                        "        at ",
                        f"{location.path}{position} | target={environment.target if environment else '-'} "
                        f"key={finding_key.name if finding_key else '-'} phase={finding.phase.value}",
                        width,
                    )
                    _wrapped(
                        lines,
                        "        suggestion: ",
                        get_rule(finding.rule_id).remediation,
                        width,
                    )
    if result.metadata.policy:
        lines.extend(["", "Policy"])
        for record in result.metadata.policy:
            severity_suffix = (
                f" {record.original_severity.value}->{record.effective_severity.value}"
                if record.original_severity is not None and record.effective_severity is not None
                else ""
            )
            lines.append(
                f"  {record.status} {record.rule_id} {record.id}{severity_suffix} "
                f"{record.pointer} reason={record.reason}"
            )
    if verbosity >= 1:
        lines.extend(["", "Files"])
        for item in result.files:
            suffix = f" ({item.reason})" if item.reason else ""
            lines.append(f"  {item.status}  {item.kind}  {item.path}{suffix}")
    if verbosity >= 2:
        lines.extend(
            [
                "",
                "Effective scope",
                f"  Named roots: {', '.join(result.inputs.selected_roots)}",
                f"  Include: {', '.join(result.inputs.include) or '-'}",
                f"  Exclude: {', '.join(result.inputs.exclude) or '-'}",
                f"  Fail on: {result.inputs.fail_on}",
                "  Candidate kinds: "
                + (
                    ", ".join(
                        f"{name}={count}"
                        for name, count in sorted(result.summary.candidate_kinds.items())
                    )
                    or "-"
                ),
                "  Skip reasons: "
                + (
                    ", ".join(
                        f"{name}={count}"
                        for name, count in sorted(result.summary.skipped_reasons.items())
                    )
                    or "-"
                ),
            ]
        )
    if result.status is ScanStatus.PARTIAL:
        lines.extend(["", "Scan completed with partial coverage; see diagnostics."])
    elif result.status is ScanStatus.FAILED:
        lines.extend(["", "Scan could not produce a reliable complete result; see diagnostics."])
    lines.extend(
        [
            "",
            f"Result: {_paint(result.status.value, result.status.value, color)} — "
            f"{summary.consumers} consumers, {summary.config_keys} config keys",
        ]
    )
    return "\n".join(lines) + "\n"


def render_sarif(result: ScanResult) -> str:
    try:
        version = importlib.metadata.version("runtime-contract")
    except importlib.metadata.PackageNotFoundError:
        version = "0.0.0-unknown"
    version = version.replace(".dev", "-dev.")
    diagnostic_rule_pairs = {
        (
            item.rule_id.value if item.rule_id is not None else item.code.value,
            item.code.value,
        )
        for item in result.diagnostics
    }
    sarif_levels = {"info": "note", "warning": "warning", "error": "error"}
    rules: list[dict[str, Any]] = [
        {
            "id": definition.id.value,
            "name": definition.name,
            "shortDescription": {"text": definition.title},
            "fullDescription": {"text": definition.rationale},
            "help": {"text": definition.remediation},
            "defaultConfiguration": {"level": sarif_levels[definition.default_severity]},
        }
        for definition in RULE_CATALOG.values()
    ]
    catalog_ids = {item["id"] for item in rules}
    rules.extend(
        {"id": rule_id, "name": name}
        for rule_id, name in sorted(diagnostic_rule_pairs)
        if rule_id not in catalog_ids
    )
    rules.sort(key=lambda item: item["id"])
    levels = {Severity.INFO: "note", Severity.WARNING: "warning", Severity.ERROR: "error"}
    sarif_results: list[dict[str, Any]] = []
    for diagnostic in result.diagnostics:
        location = diagnostic.primary_location
        diagnostic_physical: dict[str, Any] = {
            "artifactLocation": {"uri": location.path, "uriBaseId": "PROJECTROOT"}
        }
        if location.start_line is not None:
            region: dict[str, int] = {"startLine": location.start_line}
            if location.start_column is not None:
                region["startColumn"] = location.start_column
            diagnostic_physical["region"] = region
        sarif_results.append(
            {
                "ruleId": (
                    diagnostic.rule_id.value
                    if diagnostic.rule_id is not None
                    else diagnostic.code.value
                ),
                "level": levels[diagnostic.severity],
                "message": {"text": diagnostic.code.value.replace("_", " ")},
                "locations": [{"physicalLocation": diagnostic_physical}],
                "partialFingerprints": {"runtimeContract/v1": diagnostic.id},
            }
        )
    for finding in result.findings:
        location = finding.primary_location
        finding_physical: dict[str, Any] = {
            "artifactLocation": {"uri": location.path, "uriBaseId": "PROJECTROOT"}
        }
        if location.start_line is not None:
            finding_region = {"startLine": location.start_line}
            if location.start_column is not None:
                finding_region["startColumn"] = location.start_column
            finding_physical["region"] = finding_region
        sarif_results.append(
            {
                "ruleId": finding.rule_id.value,
                "level": levels[finding.severity],
                "message": {"text": get_rule(finding.rule_id).title},
                "locations": [{"physicalLocation": finding_physical}],
                "partialFingerprints": {"runtimeContract/v1": finding.id},
                "properties": {
                    "component": finding.component,
                    "environment_id": finding.environment_id or "",
                    "config_key_id": finding.config_key_id or "",
                    "phase": finding.phase.value,
                },
            }
        )
    sarif_results.sort(
        key=lambda item: (
            item["ruleId"],
            item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
    )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "runtime-contract",
                        "semanticVersion": version,
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {"PROJECTROOT": {"uri": "./"}},
                "results": sarif_results,
                "properties": {
                    "schema_id": result.schema_id,
                    "status": result.status.value,
                    "summary": result.summary.model_dump(mode="json"),
                    "selected_roots": list(result.inputs.selected_roots),
                    "policy": [item.model_dump(mode="json") for item in result.metadata.policy],
                },
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def render(
    result: ScanResult,
    output_format: str,
    verbosity: int = 0,
    *,
    color: bool = False,
    emoji: bool = False,
    width: int = 100,
) -> str:
    if output_format == "json":
        return render_json(result)
    if output_format == "sarif":
        return render_sarif(result)
    return render_text(result, verbosity, color=color, emoji=emoji, width=width)


__all__ = ["render", "render_json", "render_sarif", "render_text"]
