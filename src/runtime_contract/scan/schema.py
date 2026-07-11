"""Deterministic ScanResult JSON Schema generation."""

import json
from importlib.resources import files

from runtime_contract.scan.models import ScanResult


def generate_schema_bytes() -> bytes:
    schema = ScanResult.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = (
        "https://raw.githubusercontent.com/piotr-adamski/runtime-contract/main/"
        "schemas/runtime-contract-scan-result-v1.schema.json"
    )
    return (json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def schema_bytes() -> bytes:
    return (
        files("runtime_contract.schemas")
        .joinpath("runtime-contract-scan-result-v1.schema.json")
        .read_bytes()
    )


__all__ = ["generate_schema_bytes", "schema_bytes"]
