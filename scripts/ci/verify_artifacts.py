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
SCHEMAS = (
    Path("schemas/runtime-contract.schema.json"),
    Path("schemas/runtime-contract-analysis-result-v1.schema.json"),
    Path("schemas/runtime-contract-scan-result-v1.schema.json"),
)


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


def distribution_schema(path: Path, schema: Path = SCHEMAS[0]) -> bytes:
    """Read the package schema from a wheel or sdist without extraction."""

    suffix = f"runtime_contract/schemas/{schema.name}"
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = [name for name in archive.namelist() if name.endswith(suffix)]
            if len(names) != 1:
                raise ValueError(
                    f"wheel must contain exactly one configuration schema: {path.name}"
                )
            return archive.read(names[0])
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            members = [member for member in archive.getmembers() if member.name.endswith(suffix)]
            if len(members) != 1:
                raise ValueError(f"sdist must contain exactly one package schema: {path.name}")
            extracted = archive.extractfile(members[0])
            if extracted is None:
                raise ValueError(f"cannot read configuration schema: {path.name}")
            return extracted.read()
    raise ValueError(f"unsupported distribution: {path.name}")


def distribution_names(path: Path) -> tuple[str, ...]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return tuple(archive.namelist())
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return tuple(member.name for member in archive.getmembers())
    raise ValueError(f"unsupported distribution: {path.name}")


def validate_schemas(distributions: tuple[Path, Path]) -> None:
    for schema in SCHEMAS:
        expected = schema.read_bytes()
        for distribution in distributions:
            if distribution_schema(distribution, schema) != expected:
                raise ValueError(f"{schema.name} differs in {distribution.name}")


def validate_no_test_doubles(distributions: tuple[Path, Path]) -> None:
    for distribution in distributions:
        forbidden = [name for name in distribution_names(distribution) if "tests/analysis" in name]
        if forbidden:
            raise ValueError(f"test doubles leaked into {distribution.name}")


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
        validate_schemas(distributions)
        validate_no_test_doubles(distributions)
        manifest = write_manifest(args.directory, distributions)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"Artifacts: ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Artifacts: PASS: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
