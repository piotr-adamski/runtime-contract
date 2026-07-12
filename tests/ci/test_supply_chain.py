"""Lock the supply-chain update and blocking scan contract."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]
SHA_ACTION = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def test_security_workflow_has_blocking_sca_sast_and_secret_scan() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/security.yml").read_text())
    jobs = workflow["jobs"]
    text = (ROOT / ".github/workflows/security.yml").read_text()

    assert workflow["permissions"] == {"contents": "read"}
    assert set(jobs) == {"python-security", "secret-scan"}
    assert "pip-audit==2.10.1" in text
    assert "bandit==1.9.4" in text
    assert "GITLEAKS_ENABLE_SUMMARY" in text
    assert "GITHUB_TOKEN: ${{ github.token }}" in text
    for job in jobs.values():
        for step in job["steps"]:
            if action := step.get("uses"):
                assert SHA_ACTION.fullmatch(action)


def test_dependabot_updates_python_and_actions_weekly() -> None:
    config = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    updates = config["updates"]

    assert [item["package-ecosystem"] for item in updates] == ["pip", "github-actions"]
    assert all(item["schedule"]["interval"] == "weekly" for item in updates)


def test_gitleaks_allowlist_is_limited_to_generated_json_fixtures() -> None:
    config = (ROOT / ".gitleaks.toml").read_text()

    assert "useDefault = true" in config
    assert "src/" not in config
    assert "README" not in config
