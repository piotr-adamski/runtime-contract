"""Keep public v0.1 reference documentation synchronized with runtime sources."""

import json
import re
from pathlib import Path
from typing import Any

from typer.main import get_command

from runtime_contract.cli import app
from runtime_contract.rules import RULE_CATALOG

ROOT = Path(__file__).parents[1]
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


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


def test_reference_docs_own_details_removed_from_readme() -> None:
    analyzers = (ROOT / "docs/analyzer-api.md").read_text(encoding="utf-8")
    formats = (ROOT / "docs/output-formats.md").read_text(encoding="utf-8")
    security = (ROOT / "docs/security-and-privacy.md").read_text(encoding="utf-8")
    risks = (ROOT / "docs/known-risks.md").read_text(encoding="utf-8")
    analyzer_prose = " ".join(analyzers.split())

    for contract in (
        "## Built-in analyzer boundaries",
        "### Python",
        "### JavaScript and TypeScript",
        "### `.env.example`",
        "### Dockerfile",
        "### Docker Compose and merge semantics",
        "### Kubernetes",
        "Plugin discovery and dynamic analyzer loading remain outside v0.1.0",
    ):
        assert contract in analyzer_prose
    for contract in (
        "### Versioning and compatibility",
        "parse_json_report(str | bytes)",
        "runtime-contract/v2",
        "runtime-contract-scan-result-v1.schema.json",
        "runtime-contract-diff-result-v1.schema.json",
    ):
        assert contract in formats
    for contract in ("## Resource budgets", "4 MiB", "8 MiB", "256 documents"):
        assert contract in security
    assert "There is no tag, GitHub Release, PyPI publication" not in risks


def test_all_local_markdown_links_resolve() -> None:
    markdown_files = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]

    for document in markdown_files:
        text = document.read_text(encoding="utf-8")
        for raw_target in MARKDOWN_LINK.findall(text):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_text = target.split("#", 1)[0]
            assert path_text, f"empty local path in {document.relative_to(ROOT)}: {target}"
            resolved = (document.parent / path_text).resolve()
            assert resolved.is_relative_to(ROOT.resolve()), (
                f"link escapes repository in {document.relative_to(ROOT)}: {target}"
            )
            assert resolved.exists(), f"broken link in {document.relative_to(ROOT)}: {target}"
            if "#" in target:
                fragment = target.split("#", 1)[1]
                headings = resolved.read_text(encoding="utf-8").splitlines()
                anchors = {
                    re.sub(r"[^a-z0-9 _-]", "", heading.lstrip("# ").casefold()).replace(" ", "-")
                    for heading in headings
                    if heading.startswith("#")
                }
                assert fragment in anchors, (
                    f"broken anchor in {document.relative_to(ROOT)}: {target}"
                )


def test_github_code_scanning_example_is_minimal_and_fail_closed() -> None:
    workflow = (ROOT / ".github/workflows/code-scanning.yml").read_text(encoding="utf-8")
    guide = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "contents: read" in workflow
    assert "security-events: write" in workflow
    assert "pull_request:" not in workflow
    assert "workflow_dispatch:" in workflow
    assert "runtime-contract check ." in workflow
    assert "--format sarif" in workflow
    assert "upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9" in workflow
    assert "retention-days: 7" in workflow
    assert "uv tool install --python 3.14 ." in workflow
    assert "if [[ $status -gt 1 ]]" in workflow
    assert "secrets." not in workflow
    assert "needs no repository secret" in guide
