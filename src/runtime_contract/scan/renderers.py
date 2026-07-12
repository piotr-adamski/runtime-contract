"""Deterministic text, JSON, and SARIF rendering."""

from __future__ import annotations

import importlib.metadata
import json
from typing import Any

from runtime_contract.domain import Severity
from runtime_contract.rules import get_rule
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


def render_text(result: ScanResult, verbosity: int = 0) -> str:
    summary = result.summary
    if verbosity < 0:
        return f"Result: {result.status.value} — {summary.consumers} consumers, {summary.config_keys} config keys\n"
    lines = [
        "runtime-contract scan",
        "",
        "Root: .",
        f"Config: {result.inputs.config or '-'}",
        f"Environment: {result.inputs.environment or '-'}",
        f"Selected roots: {', '.join(result.inputs.selected_roots)}",
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
        for finding in result.findings:
            location = finding.primary_location
            position = (
                f":{location.start_line}:{location.start_column}" if location.start_line else ""
            )
            finding_key = keys.get(finding.config_key_id or "")
            environment = environments.get(finding.environment_id or "")
            lines.append(
                f"  {finding.severity.value} {finding.rule_id.value} "
                f"{get_rule(finding.rule_id).title}  "
                f"{finding.component}/{environment.target if environment else '-'}  "
                f"{finding_key.name if finding_key else '-'}  {finding.phase.value}  "
                f"{location.path}{position}"
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
            f"Result: {result.status.value} — {summary.consumers} consumers, {summary.config_keys} config keys",
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
    rules: list[dict[str, Any]] = [
        {"id": rule_id, "name": name} for rule_id, name in sorted(diagnostic_rule_pairs)
    ]
    rules.extend(
        {
            "id": finding.rule_id.value,
            "name": get_rule(finding.rule_id).name,
            "shortDescription": {"text": get_rule(finding.rule_id).title},
            "help": {"text": get_rule(finding.rule_id).remediation},
        }
        for finding in result.findings
        if finding.rule_id.value not in {item["id"] for item in rules}
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
                },
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def render(result: ScanResult, output_format: str, verbosity: int = 0) -> str:
    if output_format == "json":
        return render_json(result)
    if output_format == "sarif":
        return render_sarif(result)
    return render_text(result, verbosity)


__all__ = ["render", "render_json", "render_sarif", "render_text"]
