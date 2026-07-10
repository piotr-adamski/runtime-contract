#!/usr/bin/env python3
"""Validate the D1.04 distribution set and write its SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import sys
import tarfile
import zipfile
from pathlib import Path

EXPECTED_VERSION = "0.1.0.dev0"


def distribution_version(path: Path) -> str:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            metadata_files = [
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            ]
            if len(metadata_files) != 1:
                raise ValueError(f"wheel must contain exactly one METADATA file: {path.name}")
            text = archive.read(metadata_files[0]).decode("utf-8")
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            members = [
                member for member in archive.getmembers() if member.name.endswith("/PKG-INFO")
            ]
            if len(members) != 1:
                raise ValueError(f"sdist must contain exactly one PKG-INFO file: {path.name}")
            extracted = archive.extractfile(members[0])
            if extracted is None:
                raise ValueError(f"cannot read sdist metadata: {path.name}")
            text = extracted.read().decode("utf-8")
    else:
        raise ValueError(f"unsupported distribution: {path.name}")
    for line in text.splitlines():
        if line.startswith("Version: "):
            return line.removeprefix("Version: ").strip()
    raise ValueError(f"distribution metadata has no version: {path.name}")


def validate_distributions(directory: Path) -> tuple[Path, Path]:
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError(
            f"expected exactly one wheel and one sdist, found {len(wheels)} wheel(s) and {len(sdists)} sdist(s)"
        )
    for path in (*wheels, *sdists):
        version = distribution_version(path)
        if version != EXPECTED_VERSION:
            raise ValueError(f"{path.name} has version {version!r}, expected {EXPECTED_VERSION!r}")
    return wheels[0], sdists[0]


def write_manifest(directory: Path, distributions: tuple[Path, Path]) -> Path:
    manifest = directory / "SHA256SUMS"
    lines = []
    for path in distributions:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}\n")
        print(f"Artifact SHA-256: {path.name} {digest}")
    manifest.write_text("".join(lines), encoding="ascii")
    return manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path, default=Path("dist"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        distributions = validate_distributions(args.directory)
        manifest = write_manifest(args.directory, distributions)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"Artifacts: ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Artifacts: PASS: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
