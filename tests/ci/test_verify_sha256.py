"""Tests for portable distribution checksum verification."""

import hashlib
from pathlib import Path

import pytest

from scripts.ci.verify_sha256 import verify


def test_verifies_manifest_on_every_platform(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.whl"
    artifact.write_bytes(b"portable artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{digest}  {artifact.name}\n", encoding="ascii")

    verify(manifest)


@pytest.mark.parametrize(
    "entry",
    ["not-a-hash  artifact.whl", f"{'0' * 64}  ../artifact.whl"],
)
def test_rejects_malformed_or_traversing_entries(tmp_path: Path, entry: str) -> None:
    manifest = tmp_path / "SHA256SUMS"
    manifest.write_text(f"{entry}\n", encoding="ascii")

    with pytest.raises(ValueError, match="invalid"):
        verify(manifest)
