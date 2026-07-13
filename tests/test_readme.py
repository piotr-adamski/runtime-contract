"""Executable contract for the public five-minute README path."""

from pathlib import Path

REPO = Path(__file__).parents[1]
README = REPO / "README.md"


def test_readme_contains_complete_neutral_quickstart_contract() -> None:
    text = README.read_text(encoding="utf-8")

    for section in (
        "## Five-minute quickstart",
        "## Scope and non-goals",
        "## Project status",
        "## Development",
        "## Project information",
    ):
        assert section in text
    for command in (
        "pipx install runtime-contract==0.1.0",
        "python -m pip install runtime-contract==0.1.0",
        "runtime-contract scan examples/scan-flow",
        "runtime-contract check examples/scan-flow",
        "python -m pip install runtime-contract",
        "runtime-contract check .",
    ):
        assert command in text
    for concept in ("Exit `2`", "Apache-2.0", "telemetry", "Python 3.11"):
        assert concept in text
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


def test_release_public_docs_do_not_regress_to_prepublication_claims() -> None:
    release_notes = (REPO / "RELEASE_NOTES.md").read_text(encoding="utf-8")
    issue_template = (REPO / ".github/ISSUE_TEMPLATE/bug_report.yml").read_text(encoding="utf-8")

    assert release_notes.startswith("# runtime-contract v0.1.0\n")
    assert "release candidate" not in release_notes.casefold()
    assert "PENDING D4.14" not in release_notes
    assert "No release exists yet" not in issue_template
