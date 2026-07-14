"""Lock the public GitHub Action metadata and supply-chain contract."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]
SHA_ACTION = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def metadata() -> dict[str, object]:
    loaded = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_metadata_exposes_the_stable_public_contract() -> None:
    action = metadata()
    inputs = action["inputs"]
    outputs = action["outputs"]

    assert isinstance(inputs, dict)
    assert isinstance(outputs, dict)
    assert action["runs"]["using"] == "composite"  # type: ignore[index]
    assert inputs["command"]["default"] == "check"
    assert inputs["path"]["default"] == "."
    assert inputs["format"]["default"] == "text"
    assert inputs["fail-on"]["default"] == "error"
    assert inputs["version"]["default"] == "0.1.0"
    assert set(inputs) == {
        "command",
        "path",
        "format",
        "fail-on",
        "config",
        "version",
        "output",
        "rule",
        "left",
        "right",
        "environment",
    }
    assert set(outputs) == {"exit-code", "result-file", "runtime-contract-version"}
    assert action["branding"] == {"icon": "shield", "color": "blue"}


def test_every_external_action_is_sha_pinned() -> None:
    steps = metadata()["runs"]["steps"]  # type: ignore[index]
    external = [step["uses"] for step in steps if "uses" in step]

    assert external
    assert all(SHA_ACTION.fullmatch(reference) for reference in external)


def test_inputs_cross_the_shell_only_as_environment_values() -> None:
    step = metadata()["runs"]["steps"][1]  # type: ignore[index]
    run = step["run"]

    assert run == (
        'uv run --no-project --python 3.11.15 python "$GITHUB_ACTION_PATH/scripts/action/runner.py"'
    )
    assert "${{ inputs." not in run
    assert all(str(value).startswith("${{ inputs.") for value in step["env"].values())
