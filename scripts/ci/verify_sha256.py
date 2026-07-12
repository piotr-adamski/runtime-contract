#!/usr/bin/env python3
"""Verify a portable SHA256SUMS manifest without platform-specific shell tools."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def verify(manifest: Path) -> None:
    root = manifest.resolve(strict=True).parent
    for raw_line in manifest.read_text(encoding="ascii").splitlines():
        digest, separator, name = raw_line.partition("  ")
        if not separator or len(digest) != 64 or Path(name).name != name:
            raise ValueError("invalid SHA256SUMS entry")
        artifact = root / name
        if hashlib.sha256(artifact.read_bytes()).hexdigest() != digest:
            raise ValueError(f"SHA-256 mismatch: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        verify(args.manifest)
    except (OSError, ValueError) as exc:
        print(f"SHA-256 manifest: ERROR: {exc}", file=sys.stderr)
        return 1
    print("SHA-256 manifest: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
