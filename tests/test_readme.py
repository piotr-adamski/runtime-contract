"""Executable contract for the public five-minute README path."""

from pathlib import Path

README = Path(__file__).parents[1] / "README.md"


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
        "pipx install .",
        "python -m pip install .",
        "runtime-contract scan examples/scan-flow",
        "runtime-contract check examples/scan-flow",
        "python -m pip install runtime-contract",
        "runtime-contract check .",
    ):
        assert command in text
    for concept in ("Exit `2`", "Apache-2.0", "telemetry", "Python 3.11"):
        assert concept in text


def test_readme_does_not_present_closed_or_private_scope_as_current() -> None:
    text = README.read_text(encoding="utf-8")

    assert "D2.14 records the current" not in text
    assert "Brillnet" not in text
    assert "GRC" not in text
