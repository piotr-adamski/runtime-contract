#!/usr/bin/env python3
"""Generate or check the tracked runtime configuration schema."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from runtime_contract.config.schema import generate_schema_bytes

ROOT_SCHEMA = Path("schemas/runtime-contract.schema.json")
PACKAGE_SCHEMA = Path("src/runtime_contract/schemas/runtime-contract.schema.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = generate_schema_bytes()
    if args.check:
        stale = [
            str(path)
            for path in (ROOT_SCHEMA, PACKAGE_SCHEMA)
            if not path.is_file() or path.read_bytes() != expected
        ]
        if stale:
            print(f"Schema drift: {', '.join(stale)}", file=sys.stderr)
            return 1
        print("Configuration schema: PASS")
        return 0
    for path in (ROOT_SCHEMA, PACKAGE_SCHEMA):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected)
    print("Configuration schema generated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
