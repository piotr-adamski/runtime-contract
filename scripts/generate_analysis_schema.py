#!/usr/bin/env python3
"""Generate or check the committed AnalysisResult JSON Schema."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_contract.analysis.schema import generate_schema_bytes  # noqa: E402

PATHS = (
    ROOT / "schemas" / "runtime-contract-analysis-result-v1.schema.json",
    ROOT
    / "src"
    / "runtime_contract"
    / "schemas"
    / "runtime-contract-analysis-result-v1.schema.json",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = generate_schema_bytes()
    if args.check:
        stale = [str(path) for path in PATHS if not path.is_file() or path.read_bytes() != expected]
        if stale:
            print(f"Analysis schema drift: {', '.join(stale)}", file=sys.stderr)
            return 1
        print("Analysis schema: PASS")
        return 0
    for path in PATHS:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected)
    print("Analysis schema generated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
