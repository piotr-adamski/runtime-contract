"""Generate the committed Contract JSON Schema deterministically."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_contract.domain import Contract  # noqa: E402

SCHEMA_PATH = ROOT / "schemas" / "runtime-contract-contract-v1.schema.json"


def rendered_schema() -> str:
    schema = Contract.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "urn:runtime-contract:contract:v1"
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered_schema()
    if args.check:
        return 0 if SCHEMA_PATH.is_file() and SCHEMA_PATH.read_text() == expected else 1
    SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_PATH.write_text(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
