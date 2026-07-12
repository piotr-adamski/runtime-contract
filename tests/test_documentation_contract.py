"""Keep public v0.1 reference documentation synchronized with runtime sources."""

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from runtime_contract.cli import app
from runtime_contract.rules import RULE_CATALOG

ROOT = Path(__file__).parents[1]
RUNNER = CliRunner()


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
    help_commands = (
        ("--help",),
        ("scan", "--help"),
        ("check", "--help"),
        ("explain", "--help"),
        ("diff", "--help"),
        ("config", "validate", "--help"),
        ("config", "explain", "--help"),
    )
    options: set[str] = set()
    for arguments in help_commands:
        result = RUNNER.invoke(app, list(arguments), color=False)
        assert result.exit_code == 0
        options.update(re.findall(r"--[a-z][a-z-]*", result.stdout))
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
