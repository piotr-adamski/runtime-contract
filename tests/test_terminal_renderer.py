"""D3.10 human-readable, value-safe terminal rendering."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app
from runtime_contract.scan import ScanRequest, run_scan
from runtime_contract.scan.models import ScanResult
from runtime_contract.scan.renderers import render_text

runner = CliRunner()
FIXTURE = Path("tests/fixtures/terminal-renderer")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def result() -> ScanResult:
    return run_scan(ScanRequest(path=FIXTURE)).result


def test_plain_ci_snapshot_groups_findings_and_never_leaks_values() -> None:
    rendered = render_text(result(), color=False, emoji=False, width=100)
    assert rendered == Path("tests/fixtures/terminal-renderer-ci.txt").read_text(encoding="utf-8")
    assert "SUPER_SECRET_CANARY" not in rendered
    assert "Findings\n  ERROR" in rendered
    assert "\n  WARNING" in rendered
    assert "\n    default\n" in rendered
    assert "suggestion:" in rendered
    assert "app.py:3:1" in rendered


def test_tty_snapshot_has_controlled_color_and_emoji() -> None:
    rendered = render_text(result(), color=True, emoji=True, width=100)
    assert rendered.replace("\x1b", "<ESC>") == Path(
        "tests/fixtures/terminal-renderer-tty.txt"
    ).read_text(encoding="utf-8")
    assert "\x1b[31mERROR\x1b[0m" in rendered
    assert "✖ RTC001" in rendered
    assert "! RTC005" in rendered


def test_narrow_terminal_wraps_without_breaking_words_or_exceeding_width() -> None:
    rendered = render_text(result(), color=True, emoji=True, width=50)
    visible = ANSI.sub("", rendered)
    assert max(len(line) for line in visible.splitlines()) <= 50
    assert "REQUIRED_NOT_PROVIDED" not in visible
    assert "suggestion:" in visible


@pytest.mark.parametrize("command", ["scan", "check"])
def test_cli_color_modes_and_no_emoji(command: str) -> None:
    always = runner.invoke(
        app,
        [command, str(FIXTURE), "--color", "always", "--no-emoji", "--width", "60"],
        color=True,
    )
    assert "\x1b[" in always.stdout
    assert "✖" not in always.stdout
    never = runner.invoke(app, [command, str(FIXTURE), "--color", "never"])
    assert "\x1b[" not in never.stdout


@pytest.mark.parametrize(
    "arguments",
    [
        ["--color", "sometimes"],
        ["--width", "39"],
        ["--width", "241"],
    ],
)
@pytest.mark.parametrize("command", ["scan", "check"])
def test_invalid_terminal_options_fail_closed(arguments: list[str], command: str) -> None:
    result = runner.invoke(app, [command, str(FIXTURE), *arguments])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.startswith("Error:")


def test_json_and_sarif_are_byte_stable_across_terminal_options() -> None:
    for output_format in ("json", "sarif"):
        plain = runner.invoke(app, ["scan", str(FIXTURE), "--format", output_format])
        styled = runner.invoke(
            app,
            [
                "scan",
                str(FIXTURE),
                "--format",
                output_format,
                "--color",
                "always",
                "--width",
                "40",
            ],
        )
        assert plain.stdout == styled.stdout
