"""Strict, pure reader for canonical and legacy v1 JSON scan reports."""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from runtime_contract.domain import Contract
from runtime_contract.flow import build_flow_graph
from runtime_contract.precedence import analyze_precedence
from runtime_contract.scan.models import ScanResult

_LEGACY_KEYS = {
    "schema_id",
    "root",
    "config",
    "environment",
    "selected_roots",
    "effective_include",
    "effective_exclude",
    "fail_on",
    "status",
    "summary",
    "contract",
    "diagnostics",
    "findings",
    "files",
}


class _InvalidReport(ValueError):
    pass


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _InvalidReport
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise _InvalidReport


def _decode(value: str | bytes) -> str:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _InvalidReport from exc
    if value.startswith("\ufeff"):
        raise _InvalidReport
    return value


def _normalize_legacy(document: dict[str, Any]) -> dict[str, Any]:
    if set(document) != _LEGACY_KEYS or document.get("schema_id") != "runtime-contract/v1":
        raise _InvalidReport
    return {
        "schema_id": document["schema_id"],
        "schema_version": 1,
        "metadata": {"tool": "runtime-contract", "tool_version": None, "command": "scan"},
        "inputs": {
            "root": document["root"],
            "config": document["config"],
            "environment": document["environment"],
            "selected_roots": document["selected_roots"],
            "include": document["effective_include"],
            "exclude": document["effective_exclude"],
            "fail_on": document["fail_on"],
        },
        **{
            key: document[key]
            for key in ("status", "summary", "contract", "diagnostics", "findings", "files")
        },
    }


def parse_json_report(value: str | bytes) -> ScanResult:
    """Parse a strict v1 report without I/O and return its canonical model."""
    try:
        document = json.loads(_decode(value), object_pairs_hook=_object, parse_constant=_constant)
        if not isinstance(document, dict):
            raise _InvalidReport
        markers = {"schema_version", "metadata", "inputs"}
        if not markers.intersection(document):
            document = _normalize_legacy(document)
        elif not markers.issubset(document):
            raise _InvalidReport
        schema_version = document.get("schema_version")
        if type(schema_version) is not int or schema_version != 1:
            raise _InvalidReport
        if "flow_graph" not in document or "precedence" not in document:
            contract = Contract.model_validate_json(
                json.dumps(document.get("contract"), ensure_ascii=False, allow_nan=False),
                strict=True,
            )
            graph = build_flow_graph(contract)
            precedence = analyze_precedence(contract)
            summary = document.get("summary")
            if not isinstance(summary, dict):
                raise _InvalidReport
            document["summary"] = {
                **summary,
                "flow_nodes": len(graph.nodes),
                "flow_edges": len(graph.edges),
                "precedence_providers": len(precedence.providers),
                "precedence_conflicts": len(precedence.conflicts),
            }
            document.setdefault("flow_graph", graph.model_dump(mode="json"))
            document.setdefault("precedence", precedence.model_dump(mode="json"))
        return ScanResult.model_validate_json(
            json.dumps(document, ensure_ascii=False, allow_nan=False), strict=True
        )
    except (_InvalidReport, json.JSONDecodeError, ValidationError, TypeError, ValueError):
        raise ValueError("invalid runtime-contract JSON report") from None


__all__ = ["parse_json_report"]
