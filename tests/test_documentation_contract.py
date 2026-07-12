"""Keep public v0.1 reference documentation synchronized with runtime sources."""

import json
from pathlib import Path
from typing import Any

from typer.main import get_command

from runtime_contract.cli import app
from runtime_contract.rules import RULE_CATALOG

ROOT = Path(__file__).parents[1]


def test_rule_reference_covers_every_runtime_rule_and_required_sections() -> None:
    text = (ROOT / "docs/rules.md").read_text(encoding="utf-8")

    for rule in RULE_CATALOG.values():
        section = text.split(f"## {rule.id.value} —", 1)[1].split("\n## ", 1)[0]
        assert rule.title in section
        assert f"(`{rule.default_severity}`)" in section
        for label in ("**Why:**", "**Incorrect:**", "**Correct:**", "**Remediation:**"):
            assert label in section


def test_configuration_reference_names_every_schema_property() -> None:
    schema = json.loads((ROOT / "schemas/runtime-contract.schema.json").read_text())
    properties: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("properties"), dict):
                properties.update(value["properties"])
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(schema)
    text = (ROOT / "docs/runtime-contract-yaml.md").read_text(encoding="utf-8")
    assert properties
    assert not {name for name in properties if f"`{name}`" not in text}


def test_cli_and_format_references_cover_public_contract() -> None:
    cli = (ROOT / "docs/cli-reference.md").read_text(encoding="utf-8")
    formats = (ROOT / "docs/output-formats.md").read_text(encoding="utf-8")
    for command in ("scan", "check", "explain", "diff", "config validate", "config explain"):
        assert command in cli
    options: set[str] = set()

    def visit_command(command: Any) -> None:
        for parameter in command.params:
            if hasattr(parameter, "opts"):
                options.update(option for option in parameter.opts if option.startswith("--"))
        if hasattr(command, "commands"):
            for child in command.commands.values():
                visit_command(child)

    visit_command(get_command(app))
    assert options
    for option in options:
        assert option in cli
    for contract in (
        "Terminal text",
        "Canonical JSON",
        "SARIF 2.1.0",
        "Heuristics",
        "Suppressions",
        "Limits of static analysis",
    ):
        assert contract in formats


def test_github_code_scanning_example_is_minimal_and_fail_closed() -> None:
    workflow = (ROOT / ".github/workflows/code-scanning.yml").read_text(encoding="utf-8")
    guide = (ROOT / "docs/github-code-scanning.md").read_text(encoding="utf-8")

    assert "contents: read" in workflow
    assert "security-events: write" in workflow
    assert "runtime-contract check ." in workflow
    assert "--format sarif" in workflow
    assert "upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9" in workflow
    assert "retention-days: 7" in workflow
    assert "if [[ $status -gt 1 ]]" in workflow
    assert "secrets." not in workflow
    assert "GITHUB_TOKEN" in guide
