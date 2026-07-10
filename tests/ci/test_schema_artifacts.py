"""Build distributions and prove their configuration schema bytes."""

import subprocess
from pathlib import Path

from scripts.ci.verify_artifacts import distribution_schema


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
