"""Deterministic ScanResult JSON Schema generation."""

import json

from runtime_contract.scan.models import ScanResult


def generate_schema_bytes() -> bytes:
    return (
        json.dumps(ScanResult.model_json_schema(), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


__all__ = ["generate_schema_bytes"]
