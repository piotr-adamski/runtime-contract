"""Deterministic public JSON Schema generation and resource access."""

from __future__ import annotations

import json
from importlib.resources import files

from runtime_contract.config.models import RuntimeContractConfig

SCHEMA_ID = "https://raw.githubusercontent.com/piotr-adamski/runtime-contract/main/schemas/runtime-contract.schema.json"


def generate_schema_bytes() -> bytes:
    schema = RuntimeContractConfig.model_json_schema(
        mode="validation",
        ref_template="#/$defs/{model}",
    )
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = SCHEMA_ID
    schema["title"] = "runtime-contract.yaml version 1"
    schema["description"] = "Strict configuration contract for the runtime-contract CLI."
    return (json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def schema_bytes() -> bytes:
    """Read the bundled schema through ``importlib.resources``."""

    return files("runtime_contract.schemas").joinpath("runtime-contract.schema.json").read_bytes()
