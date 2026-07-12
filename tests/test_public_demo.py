"""D4.04 public broken/fixed demo contract."""

from __future__ import annotations

import json

from runtime_contract.scan import ScanRequest, run_scan
from scripts.generate_demo_outputs import DEMO, FORMATS, OUTPUTS, render

PRIVATE_MARKERS = ("brillnet", "pulsar", "crewshift", "manuquest", "/home/piotr")


def test_demo_is_domain_neutral_value_safe_and_complete() -> None:
    files = [path for path in DEMO.rglob("*") if path.is_file()]
    public_text = "\n".join(path.read_text(encoding="utf-8") for path in files)
    assert all(marker not in public_text.casefold() for marker in PRIVATE_MARKERS)
    assert "unsafe-demo-literal" not in "\n".join(
        path.read_text(encoding="utf-8") for path in OUTPUTS.iterdir()
    )
    for state in ("broken", "fixed"):
        names = {path.relative_to(DEMO / state).as_posix() for path in (DEMO / state).rglob("*")}
        assert {
            ".env.example",
            "Dockerfile",
            "app/settings.py",
            "compose.yaml",
            "kubernetes.yaml",
            "runtime-contract.yaml",
            "web/config.ts",
        } <= names


def test_demo_states_prove_the_remediation() -> None:
    broken = run_scan(ScanRequest(path=DEMO / "broken", output_format="json"))
    fixed = run_scan(ScanRequest(path=DEMO / "fixed", output_format="json"))
    assert broken.result.status.value == fixed.result.status.value == "complete"
    assert {finding.rule_id.value for finding in broken.result.findings} >= {"RTC001", "RTC002"}
    assert not fixed.result.findings


def test_committed_demo_outputs_are_exact_and_machine_readable() -> None:
    for state in ("broken", "fixed"):
        for extension, output_format in FORMATS.items():
            output = OUTPUTS / f"{state}.{extension}"
            canonical_checkout_bytes = output.read_text(encoding="utf-8").encode("utf-8")
            assert b"\r" not in canonical_checkout_bytes
            assert canonical_checkout_bytes == render(state, output_format)
        assert (
            json.loads((OUTPUTS / f"{state}.json").read_text())["schema_id"]
            == "runtime-contract/v1"
        )
        sarif = json.loads((OUTPUTS / f"{state}.sarif").read_text())
        assert sarif["version"] == "2.1.0"
