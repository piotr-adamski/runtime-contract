"""Lock the public operating-system, Python, and dependency-range CI contract."""

import tomllib
from pathlib import Path
from typing import Any, cast

import yaml

WORKFLOW = Path(__file__).parents[2] / ".github/workflows/ci.yml"


def workflow() -> dict[str, Any]:
    loaded = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError("CI workflow must be a mapping")
    return cast(dict[str, Any], loaded)


def test_compatibility_matrix_covers_every_supported_os_and_python() -> None:
    jobs = workflow()["jobs"]
    matrix = jobs["compatibility"]["strategy"]["matrix"]

    assert matrix["os"] == ["ubuntu-24.04", "macos-15", "windows-2025"]
    assert matrix["python"] == ["3.11", "3.12", "3.13", "3.14"]
    assert jobs["compatibility"]["runs-on"] == "${{ matrix.os }}"


def test_dependency_range_jobs_cover_minimum_and_latest_compatible() -> None:
    jobs = workflow()["jobs"]
    ranges = jobs["dependency-range"]["strategy"]["matrix"]["include"]

    assert ranges == [
        {
            "profile": "minimum",
            "resolution": "lowest-direct",
            "python": "3.11",
            "constraints": "scripts/ci/minimum-constraints.txt",
        },
        {
            "profile": "latest-compatible",
            "resolution": "highest",
            "python": "3.14",
            "constraints": "",
        },
    ]
    assert "dependency-range" in jobs["quality"]["needs"]


def test_portable_artifact_and_platform_path_checks_are_required() -> None:
    jobs = workflow()["jobs"]
    step_text = "\n".join(
        f"{step.get('name', '')}\n{step.get('run', '')}" for step in jobs["compatibility"]["steps"]
    )

    assert "verify_sha256.py" in step_text
    assert "entry point, paths, encodings" in step_text
    assert "e2e_wheel.py" in step_text


def test_sdist_smoke_asserts_the_frozen_project_version() -> None:
    project = tomllib.loads((WORKFLOW.parents[2] / "pyproject.toml").read_text(encoding="utf-8"))
    step_text = "\n".join(
        str(step.get("run", "")) for step in workflow()["jobs"]["compatibility"]["steps"]
    )

    assert f'== "{project["project"]["version"]}"' in step_text
    assert ".dev0" not in step_text


def test_minimum_constraints_equal_project_lower_bounds() -> None:
    project = tomllib.loads((WORKFLOW.parents[2] / "pyproject.toml").read_text(encoding="utf-8"))
    expected = {
        dependency.split(">=", 1)[0]: dependency.split(">=", 1)[1].split(",", 1)[0]
        for dependency in project["project"]["dependencies"]
    }
    constraints = {
        name: version
        for line in (WORKFLOW.parents[2] / "scripts/ci/minimum-constraints.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        for name, version in [line.split("==", 1)]
    }

    assert constraints == expected
