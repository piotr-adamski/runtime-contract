#!/usr/bin/env python3
"""Profile a representative static monorepo and enforce a generous RC budget."""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from pathlib import Path

from runtime_contract.scan import ScanRequest, run_scan


def create_fixture(root: Path, components: int) -> None:
    for number in range(components):
        component = root / "apps" / f"service-{number:04d}"
        component.mkdir(parents=True)
        key = f"SERVICE_{number:04d}_URL"
        (component / "settings.py").write_text(
            f'import os\nos.getenv("{key}", "safe-placeholder")\n', encoding="utf-8"
        )
        (component / ".env.example").write_text(f"{key}=\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--components", type=int, default=500)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--max-median-seconds", type=float, default=8.0)
    args = parser.parse_args()
    if args.components < 1 or args.runs < 2 or args.max_median_seconds <= 0:
        parser.error("components, runs, and time budget must be positive")

    with tempfile.TemporaryDirectory(prefix="runtime-contract-profile-") as value:
        root = Path(value)
        create_fixture(root, args.components)
        durations = []
        baseline = None
        for _ in range(args.runs):
            started = time.perf_counter()
            run = run_scan(ScanRequest(path=root, output_format="json"))
            durations.append(time.perf_counter() - started)
            if run.exit_code != 0 or run.result.status.value != "complete":
                raise RuntimeError("representative monorepo scan was not complete")
            if baseline is None:
                baseline = run.rendered
            elif run.rendered != baseline:
                raise RuntimeError("representative monorepo result is not deterministic")
        median = statistics.median(durations)
        result = {
            "components": args.components,
            "files": args.components * 2,
            "runs": args.runs,
            "median_seconds": round(median, 6),
            "files_per_second": round((args.components * 2) / median, 2),
            "budget_seconds": args.max_median_seconds,
        }
        print(json.dumps(result, sort_keys=True))
        if median > args.max_median_seconds:
            raise RuntimeError("representative monorepo exceeded the RC performance budget")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
