"""Executable contract for the concise public product entrypoint."""

from pathlib import Path

REPO = Path(__file__).parents[1]
README = REPO / "README.md"


def test_readme_contains_complete_neutral_first_use_contract() -> None:
    text = README.read_text(encoding="utf-8")
    prose = " ".join(text.split())

    for section in (
        "## The problem",
        "## Example: required variable not delivered",
        "## Supported in v0.1.0",
        "## Installation",
        "## Quickstart",
        "## Main commands",
        "## Exit codes",
        "## Minimal GitHub Actions integration",
        "## Important limitations",
        "## Reference documentation",
        "## Contributing, security, and license",
    ):
        assert section in text
    for command in (
        "pipx install runtime-contract==0.1.0",
        "python -m pip install runtime-contract==0.1.0",
        "runtime-contract scan examples/scan-flow",
        "runtime-contract check examples/scan-flow",
        "runtime-contract check .",
        "runtime-contract explain RTC001",
        "runtime-contract diff BEFORE AFTER",
        "runtime-contract config validate PATH",
    ):
        assert command in text
    for concept in (
        "offline static-analysis CLI",
        "correct build or runtime phase",
        "never executes the analyzed code",
        "reads secret values",
        "deterministic",
        "canonical JSON",
        "SARIF 2.1.0",
        "Exit `2`",
        "Apache-2.0",
        "Python 3.11",
    ):
        assert concept in prose
    assert "RTC001 Required variable not provided" in text
    assert "api/settings.py:3:16 | target=api key=DATABASE_URL phase=runtime" in text
    assert len(text.split()) <= 1_700
    for stale_claim in (
        "Until the first PyPI release",
        "Publication is still pending",
        "currently no release or PyPI publication",
    ):
        assert stale_claim not in text


def test_readme_does_not_present_closed_or_private_scope_as_current() -> None:
    text = README.read_text(encoding="utf-8")

    assert "D2.14 records the current" not in text
    assert "Brillnet" not in text
    assert "GRC" not in text
    assert "general-purpose configuration drift" not in text


def test_release_public_docs_do_not_regress_to_prepublication_claims() -> None:
    release_notes = (REPO / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    issue_template = (REPO / ".github/ISSUE_TEMPLATE/bug_report.yml").read_text(encoding="utf-8")

    assert release_notes.startswith("# runtime-contract v0.1.0\n")
    assert "release candidate" not in release_notes.casefold()
    assert "PENDING D4.14" not in release_notes
    assert "No release exists yet" not in issue_template
