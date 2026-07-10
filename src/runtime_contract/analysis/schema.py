"""Deterministic AnalysisResult JSON Schema generation and resource access."""

from __future__ import annotations

import json
from importlib.resources import files

from runtime_contract.analysis.models import AnalysisResult

SCHEMA_URN = "urn:runtime-contract:analysis-result:v1"
RESOURCE_NAME = "runtime-contract-analysis-result-v1.schema.json"


def generate_schema_bytes() -> bytes:
    schema = AnalysisResult.model_json_schema(mode="serialization", ref_template="#/$defs/{model}")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = SCHEMA_URN
    schema["title"] = "runtime-contract analysis result version 1"
    return (json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def schema_bytes() -> bytes:
    return files("runtime_contract.schemas").joinpath(RESOURCE_NAME).read_bytes()
