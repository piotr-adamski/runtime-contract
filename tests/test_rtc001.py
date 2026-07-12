"""D3.02 RTC001 required-provider evaluation and check behavior."""

from __future__ import annotations

import json
from importlib import import_module
from pathlib import Path

import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app

runner = CliRunner()


def write(root: Path, path: str, content: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def scan(root: Path, output_format: str = "json"):  # type: ignore[no-untyped-def]
    return runner.invoke(app, ["scan", str(root), "--format", output_format])


def test_required_without_target_delivery_is_one_rtc001_and_blocks_check(
    tmp_path: Path,
) -> None:
    write(tmp_path, "settings.py", 'import os\nos.getenv("REQUIRED")\n')

    result = scan(tmp_path)
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "complete"
    assert payload["summary"]["findings"] == 1
    finding = payload["findings"][0]
    assert finding["rule_id"] == "RTC001"
    assert finding["severity"] == "error"
    assert finding["phase"] == "runtime"
    assert dict(finding["parameters"])["target"] == "default"
    assert len(finding["evidence_locations"]) == 1

    checked = runner.invoke(app, ["check", str(tmp_path), "--format", "json"])
    assert checked.exit_code == 1
    checked_payload = json.loads(checked.stdout)
    assert checked_payload["metadata"]["command"] == "check"
    assert checked_payload["findings"] == payload["findings"]


def test_optional_literal_fallback_does_not_emit_false_error(tmp_path: Path) -> None:
    write(tmp_path, "settings.py", 'import os\nos.getenv("OPTIONAL", "fallback")\n')
    result = runner.invoke(app, ["check", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["findings"] == []


def test_each_compose_service_is_checked_as_an_independent_target(tmp_path: Path) -> None:
    write(tmp_path, "settings.py", 'import os\nos.environ["REQUIRED"]\n')
    write(
        tmp_path,
        "compose.yaml",
        "services:\n  supplied:\n    environment:\n      REQUIRED: value\n  missing:\n    image: example\n",
    )
    payload = json.loads(scan(tmp_path).stdout)
    assert len(payload["findings"]) == 1
    finding = payload["findings"][0]
    environment = next(
        item
        for item in payload["contract"]["environments"]
        if item["id"] == finding["environment_id"]
    )
    assert environment["target"] == "missing"


def test_wrong_phase_provider_is_nearby_evidence_but_not_delivery(tmp_path: Path) -> None:
    write(tmp_path, "settings.py", 'import os\nos.environ["BUILD_ONLY"]\n')
    write(tmp_path, "Dockerfile", "ARG BUILD_ONLY\n")
    payload = json.loads(scan(tmp_path).stdout)
    finding = payload["findings"][0]
    assert finding["rule_id"] == "RTC001"
    assert len(finding["evidence_locations"]) == 2
    assert {item["path"] for item in finding["evidence_locations"]} == {
        "Dockerfile",
        "settings.py",
    }


def test_unresolved_bulk_defers_to_rtc009_without_parallel_rtc001(tmp_path: Path) -> None:
    write(tmp_path, "settings.py", 'import os\nos.environ["BULK_KEY"]\n')
    write(tmp_path, "compose.yaml", "services:\n  app:\n    env_file: runtime.env\n")
    payload = json.loads(scan(tmp_path).stdout)
    assert payload["findings"] == []


def test_dynamic_reference_remains_partial_without_a_guessed_rtc001(tmp_path: Path) -> None:
    write(tmp_path, "settings.py", "import os\nname = 'X'\nos.getenv(name)\n")
    result = scan(tmp_path)
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "partial"
    assert all(item["rule_id"] != "RTC001" for item in payload["findings"])
    assert [item["rule_id"] for item in payload["findings"]] == ["RTC006"]


def test_text_and_sarif_render_the_rtc001_finding_without_values(tmp_path: Path) -> None:
    write(tmp_path, "settings.py", 'import os\nos.getenv("MISSING")\n')
    text = scan(tmp_path, "text")
    assert text.exit_code == 0
    assert "RTC001 Required variable not provided" in text.stdout
    sarif = scan(tmp_path, "sarif")
    assert sarif.exit_code == 0
    payload = json.loads(sarif.stdout)
    assert payload["runs"][0]["results"][0]["ruleId"] == "RTC001"
    assert "MISSING" not in sarif.stdout


def test_check_output_paths_and_write_failures_are_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path, "settings.py", 'import os\nos.getenv("OPTIONAL", "x")\n')
    conflict = runner.invoke(
        app,
        ["check", str(tmp_path), "--output", "one.json", "--report", "two.json"],
    )
    assert conflict.exit_code == 2
    assert "--output and --report" in conflict.stderr

    written = runner.invoke(
        app, ["check", str(tmp_path), "--format", "json", "--output", "report.json"]
    )
    assert written.exit_code == 0
    assert written.stdout == ""
    assert json.loads((tmp_path / "report.json").read_text())["metadata"]["command"] == "check"

    module = import_module("runtime_contract.commands.check")

    def fail_write(*args: object, **kwargs: object) -> None:
        raise OSError("redacted")

    monkeypatch.setattr(module, "write_atomic", fail_write)
    failed = runner.invoke(
        app, ["check", str(tmp_path), "--format", "json", "--output", "other.json"]
    )
    assert failed.exit_code == 2
    assert failed.stderr == "Error: could not write report.\n"
