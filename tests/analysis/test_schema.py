"""Committed schema, golden data, and package-resource tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from runtime_contract.analysis.schema import SCHEMA_URN, generate_schema_bytes, schema_bytes

ROOT = Path(__file__).resolve().parents[2]
ROOT_SCHEMA = ROOT / "schemas" / "runtime-contract-analysis-result-v1.schema.json"
PACKAGE_SCHEMA = (
    ROOT / "src/runtime_contract/schemas/runtime-contract-analysis-result-v1.schema.json"
)


def test_schema_is_draft_2020_12_with_own_urn_and_no_drift() -> None:
    raw = generate_schema_bytes()
    schema = json.loads(raw)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == SCHEMA_URN
    assert ROOT_SCHEMA.read_bytes() == PACKAGE_SCHEMA.read_bytes() == schema_bytes() == raw


def test_schema_generator_check() -> None:
    subprocess.run(
        [sys.executable, "scripts/generate_analysis_schema.py", "--check"],
        cwd=ROOT,
        check=True,
    )
