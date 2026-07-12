"""D3.09 deterministic semantic contract comparison."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app

runner = CliRunner()


def write(root: Path, path: str, content: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def scan(root: Path, report: Path) -> None:
    result = runner.invoke(app, ["scan", str(root), "--format", "json"])
    assert result.exit_code == 0
    report.write_text(result.stdout)


def test_directory_diff_reports_semantic_changes_and_never_exits_one(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    write(before, "app.py", 'import os\nos.getenv("OLD")\n')
    write(before, ".env.example", "OLD=\nSTALE=\n")
    write(after, "app.py", '\n\nimport os\nos.getenv("OLD", "fallback")\nos.getenv("NEW")\n')
    write(after, ".env.example", "OLD=\nNEW=\n")

    result = runner.invoke(app, ["diff", str(before), str(after), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "different"
    assert payload["schema_id"] == "runtime-contract/diff/v1"
    assert payload["changes"]["consumers"]["changed"]
    assert payload["changes"]["consumers"]["added"]
    assert payload["changes"]["classifications"]["added"]
    assert payload["changes"]["classifications"]["removed"]
    assert payload["changes"]["findings"]
    assert "/tmp/" not in result.stdout


def test_saved_report_diff_is_stable_and_ignores_array_order(tmp_path: Path) -> None:
    project = tmp_path / "project"
    write(project, "app.py", 'import os\nos.getenv("KEY")\n')
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    scan(project, first)
    document = json.loads(first.read_text())
    for field in ("findings", "diagnostics", "files"):
        document[field] = list(reversed(document[field]))
    second.write_text(json.dumps(document))

    one = runner.invoke(app, ["diff", str(first), str(second), "--format", "json"])
    two = runner.invoke(app, ["diff", str(first), str(second), "--format", "json"])
    assert one.exit_code == two.exit_code == 0
    assert one.stdout == two.stdout
    assert json.loads(one.stdout)["status"] == "identical"


def test_line_shift_does_not_create_semantic_noise(tmp_path: Path) -> None:
    before = tmp_path / "before"
    after = tmp_path / "after"
    write(before, "app.py", 'import os\nos.getenv("KEY")\n')
    write(after, "app.py", '\n\nimport os\nos.getenv("KEY")\n')
    result = runner.invoke(app, ["diff", str(before), str(after), "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "identical"


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_diff_renders_both_formats(tmp_path: Path, output_format: str) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    write(left, "app.py", 'import os\nos.getenv("A")\n')
    write(right, "app.py", 'import os\nos.getenv("B")\n')
    result = runner.invoke(app, ["diff", str(left), str(right), "--format", output_format])
    assert result.exit_code == 0
    assert "different" in result.stdout


def test_invalid_mixed_incomplete_environment_format_and_output_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    valid = tmp_path / "valid"
    write(valid, "app.py", 'import os\nos.getenv("KEY")\n')
    report = tmp_path / "report.json"
    scan(valid, report)
    mixed = runner.invoke(app, ["diff", str(valid), str(report)])
    assert mixed.exit_code == 2

    partial = tmp_path / "partial"
    write(partial, "app.py", "import os\nname = 'X'\nos.getenv(name)\n")
    assert runner.invoke(app, ["diff", str(valid), str(partial)]).exit_code == 2
    assert runner.invoke(app, ["diff", "missing", str(valid)]).exit_code == 2
    invalid_report = tmp_path / "invalid.json"
    invalid_report.write_text("not json")
    assert runner.invoke(app, ["diff", str(invalid_report), str(report)]).exit_code == 2
    assert runner.invoke(app, ["diff", str(valid), str(valid), "--format", "sarif"]).exit_code == 2
    assert (
        runner.invoke(app, ["diff", str(report), str(report), "--environment", "prod"]).exit_code
        == 2
    )

    monkeypatch.chdir(tmp_path)
    written = runner.invoke(app, ["diff", str(valid), str(valid), "--output", "result.txt"])
    assert written.exit_code == 0 and (tmp_path / "result.txt").exists()
    unavailable = runner.invoke(
        app, ["diff", str(valid), str(valid), "--output", "missing/result.txt"]
    )
    assert unavailable.exit_code == 2
