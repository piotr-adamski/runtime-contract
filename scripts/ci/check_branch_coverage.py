#!/usr/bin/env python3
"""Fail closed unless a coverage.py XML report meets the branch threshold."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from decimal import Decimal, InvalidOperation
from pathlib import Path

THRESHOLD = Decimal("0.90")


def read_branch_rate(report: Path) -> Decimal:
    """Return the exact global branch rate from a valid coverage XML report."""
    try:
        root = ET.parse(report).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValueError(f"cannot read valid coverage XML: {exc}") from exc

    raw_rate = root.get("branch-rate")
    if raw_rate is None:
        raise ValueError("coverage XML is missing the global branch-rate attribute")
    try:
        rate = Decimal(raw_rate)
    except InvalidOperation as exc:
        raise ValueError(f"coverage XML has a non-numeric branch-rate: {raw_rate!r}") from exc
    if not rate.is_finite() or rate < 0 or rate > 1:
        raise ValueError(f"coverage XML has an invalid branch-rate: {raw_rate!r}")
    return rate


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", nargs="?", type=Path, default=Path("coverage.xml"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        rate = read_branch_rate(args.report)
    except ValueError as exc:
        print(f"Branch coverage: ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Branch coverage: actual={rate} threshold={THRESHOLD}")
    if rate < THRESHOLD:
        print("Branch coverage is below the required threshold.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
