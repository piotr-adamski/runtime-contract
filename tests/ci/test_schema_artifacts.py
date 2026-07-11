"""Build distributions and prove their configuration schema bytes."""

import subprocess
import zipfile
from pathlib import Path

import pytest

from scripts.ci.verify_artifacts import distribution_schema, validate_no_private_artifacts


def test_built_wheel_and_sdist_contain_the_tracked_schema(tmp_path: Path) -> None:
    subprocess.run(
        ["uv", "build", "--out-dir", str(tmp_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    expected = Path("schemas/runtime-contract.schema.json").read_bytes()
    wheel = next(tmp_path.glob("*.whl"))
    sdist = next(tmp_path.glob("*.tar.gz"))
    assert distribution_schema(wheel) == expected
    assert distribution_schema(sdist) == expected
    analysis_schema = Path("schemas/runtime-contract-analysis-result-v1.schema.json")
    assert distribution_schema(wheel, analysis_schema) == analysis_schema.read_bytes()
    assert distribution_schema(sdist, analysis_schema) == analysis_schema.read_bytes()
    scan_schema = Path("schemas/runtime-contract-scan-result-v1.schema.json")
    assert distribution_schema(wheel, scan_schema) == scan_schema.read_bytes()
    assert distribution_schema(sdist, scan_schema) == scan_schema.read_bytes()


def test_distribution_rejects_private_build_artifacts(tmp_path: Path) -> None:
    wheel = tmp_path / "fixture.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("runtime_contract/__init__.py", "")
        archive.writestr("tests/analysis/private_fixture.py", "")

    with pytest.raises(ValueError, match="private build artifacts"):
        validate_no_private_artifacts((wheel, wheel))
