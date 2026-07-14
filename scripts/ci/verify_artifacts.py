#!/usr/bin/env python3
"""Validate the D1.04 distribution set and write its SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import sys
import tarfile
import zipfile
from email.parser import Parser
from pathlib import Path

EXPECTED_VERSION = "0.1.2"
SCHEMAS = (
    Path("schemas/runtime-contract.schema.json"),
    Path("schemas/runtime-contract-analysis-result-v1.schema.json"),
    Path("schemas/runtime-contract-scan-result-v1.schema.json"),
    Path("schemas/runtime-contract-diff-result-v1.schema.json"),
)
EXPECTED_METADATA = {
    "Name": "runtime-contract",
    "Version": EXPECTED_VERSION,
    "Requires-Python": ">=3.11",
    "License-Expression": "Apache-2.0",
}
EXPECTED_URL_LABELS = {"Changelog", "Documentation", "Issues", "Repository"}
EXPECTED_CLASSIFIERS = {
    "License :: OSI Approved :: Apache Software License",
    "Programming Language :: Python :: 3 :: Only",
    *(
        f"Programming Language :: Python :: {version}"
        for version in ("3.11", "3.12", "3.13", "3.14")
    ),
}


def distribution_version(path: Path) -> str:
    text = distribution_metadata(path)
    for line in text.splitlines():
        if line.startswith("Version: "):
            return line.removeprefix("Version: ").strip()
    raise ValueError(f"distribution metadata has no version: {path.name}")


def distribution_metadata(path: Path) -> str:
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
    return text


def validate_metadata(distributions: tuple[Path, Path]) -> None:
    for distribution in distributions:
        metadata = Parser().parsestr(distribution_metadata(distribution), headersonly=True)
        for field, expected in EXPECTED_METADATA.items():
            if metadata.get(field) != expected:
                raise ValueError(
                    f"{distribution.name} metadata {field!r} is {metadata.get(field)!r}, expected {expected!r}"
                )
        if "Piotr Adamski" not in metadata.get_all("Author", []):
            raise ValueError(f"{distribution.name} metadata has no canonical author")
        if "Piotr Adamski" not in metadata.get_all("Maintainer", []):
            raise ValueError(f"{distribution.name} metadata has no canonical maintainer")
        classifiers = set(metadata.get_all("Classifier", []))
        if missing := EXPECTED_CLASSIFIERS - classifiers:
            raise ValueError(f"{distribution.name} metadata lacks classifiers: {sorted(missing)}")
        url_labels = {
            value.partition(",")[0].strip() for value in metadata.get_all("Project-URL", [])
        }
        if missing := EXPECTED_URL_LABELS - url_labels:
            raise ValueError(f"{distribution.name} metadata lacks project URLs: {sorted(missing)}")


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


def validate_no_private_artifacts(distributions: tuple[Path, Path]) -> None:
    forbidden_parts = {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
        "tests",
    }
    forbidden_names = {
        ".env",
        ".env.local",
        ".npmrc",
        ".pypirc",
        "AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        "coverage.xml",
    }
    forbidden_suffixes = (".key", ".pem", ".p12", ".pfx", ".pyc", ".pyo")
    for distribution in distributions:
        forbidden = [
            name
            for name in distribution_names(distribution)
            if forbidden_parts.intersection(Path(name).parts)
            or Path(name).name in forbidden_names
            or Path(name).name.startswith(".env.")
            or name.endswith(forbidden_suffixes)
        ]
        if forbidden:
            raise ValueError(f"private build artifacts leaked into {distribution.name}")


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
        validate_metadata(distributions)
        validate_schemas(distributions)
        validate_no_private_artifacts(distributions)
        manifest = write_manifest(args.directory, distributions)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"Artifacts: ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Artifacts: PASS: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
