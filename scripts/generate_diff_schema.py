#!/usr/bin/env python3
"""Generate or check the committed DiffReport JSON Schema."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_contract.diff_report import DiffReport  # noqa: E402

PATHS = (
    ROOT / "schemas" / "runtime-contract-diff-result-v1.schema.json",
    ROOT / "src/runtime_contract/schemas" / "runtime-contract-diff-result-v1.schema.json",
)


def generate_schema_bytes() -> bytes:
    schema = DiffReport.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = (
        "https://raw.githubusercontent.com/piotr-adamski/runtime-contract/main/"
        "schemas/runtime-contract-diff-result-v1.schema.json"
    )
    return (json.dumps(schema, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = generate_schema_bytes()
    if args.check:
        stale = [str(path) for path in PATHS if not path.is_file() or path.read_bytes() != expected]
        if stale:
            print(f"Diff schema drift: {', '.join(stale)}", file=sys.stderr)
            return 1
        print("Diff schema: PASS")
        return 0
    for path in PATHS:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected)
    print("Diff schema generated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
