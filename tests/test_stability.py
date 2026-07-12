"""D3.15 release-candidate resilience matrix."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app

runner = CliRunner()


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("compose.yaml", b"services: [unterminated"),
        ("kubernetes.json", b'{"apiVersion":"v1","kind":'),
    ],
)
def test_invalid_yaml_and_json_fail_with_value_safe_structured_report(
    tmp_path: Path, name: str, content: bytes
) -> None:
    (tmp_path / name).write_bytes(content + b" SUPER_SECRET_CANARY")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 2 and result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["status"] in {"partial", "failed"}
    assert payload["diagnostics"]
    assert "SUPER_SECRET_CANARY" not in result.stdout


@pytest.mark.skipif(os.name != "posix", reason="permission bits are a POSIX contract")
def test_unreadable_supported_file_fails_closed_without_value_leak(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text('import os\nos.getenv("SUPER_SECRET_CANARY")\n', encoding="utf-8")
    target.chmod(0)
    try:
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    finally:
        target.chmod(0o600)
    assert result.exit_code == 2 and result.stderr == ""
    payload = json.loads(result.stdout)
    assert any(item["code"] == "read_error" for item in payload["diagnostics"])
    assert "SUPER_SECRET_CANARY" not in result.stdout


def test_keyboard_interrupt_uses_process_code_130_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupted(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("runtime_contract.commands.scan.run_scan", interrupted)
    result = runner.invoke(app, ["scan", "."])
    assert result.exit_code == 130
    assert result.stdout == result.stderr == ""
    assert "Traceback" not in result.output
