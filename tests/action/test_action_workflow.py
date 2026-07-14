"""Lock consumer-style Action E2E and operating-system coverage."""

from pathlib import Path
from typing import Any, cast

import yaml

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml"


def workflow() -> dict[str, Any]:
    loaded = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return cast(dict[str, Any], loaded)


def test_action_is_required_on_all_claimed_operating_systems() -> None:
    jobs = workflow()["jobs"]
    compatibility = jobs["action-compatibility"]

    assert compatibility["strategy"]["matrix"]["os"] == [
        "ubuntu-24.04",
        "macos-15",
        "windows-2025",
    ]
    assert compatibility["runs-on"] == "${{ matrix.os }}"
    assert "action-compatibility" in jobs["quality"]["needs"]
    assert "action-e2e" in jobs["quality"]["needs"]


def test_e2e_uses_the_action_and_covers_required_failure_boundaries() -> None:
    steps = workflow()["jobs"]["action-e2e"]["steps"]
    local_action_steps = [step for step in steps if step.get("uses") == "./"]
    text = WORKFLOW.read_text(encoding="utf-8")

    assert len(local_action_steps) >= 7
    assert "consumer-clean" in text
    assert "consumer-broken" in text
    assert "runtime-contract.json" in text
    assert "runtime-contract.sarif" in text
    assert "command: diff" in text
    assert "config: runtime-contract.yaml" in text
    assert "consumer space żółć; touch ACTION_PWNED" in text
    assert "command: check; touch ACTION_PWNED" in text
    assert "version: 999999.0.0" in text
    assert "snapshot(base / name)" in text
