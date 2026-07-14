#!/usr/bin/env python3
"""Generate or check the public all-rules output golden files."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_contract.domain import Contract, Finding, Phase, Severity, SourceLocation  # noqa: E402
from runtime_contract.rules import RULE_CATALOG  # noqa: E402
from runtime_contract.scan import (  # noqa: E402
    ReportInputs,
    ReportMetadata,
    ScanResult,
    ScanStatus,
    ScanSummary,
    render,
)

OUTPUTS = {
    "terminal": ROOT / "tests/fixtures/output-goldens/all-rules-terminal.txt",
    "json": ROOT / "tests/fixtures/output-goldens/all-rules.json",
    "sarif": ROOT / "tests/fixtures/output-goldens/all-rules.sarif",
}


def all_rules_result(*, command: Literal["scan", "check"] = "scan") -> ScanResult:
    findings = []
    for number, definition in enumerate(RULE_CATALOG.values(), start=1):
        location = SourceLocation(
            path=f"rules/{definition.id.value.lower()}.py",
            start_line=number,
            start_column=1,
        )
        findings.append(
            Finding(
                rule_id=definition.id,
                severity=Severity(definition.default_severity),
                component=f"component-{number:02d}",
                phase=Phase.RUNTIME,
                primary_location=location,
                evidence_locations=(location,),
            )
        )
    return ScanResult(
        schema_id="runtime-contract/v1",
        schema_version=1,
        metadata=ReportMetadata(tool_version="0.1.2", command=command, policy=()),
        inputs=ReportInputs(
            config=None,
            environment=None,
            selected_roots=(),
            include=(),
            exclude=(),
            fail_on="error",
        ),
        status=ScanStatus.COMPLETE,
        summary=ScanSummary(findings=len(findings)),
        contract=Contract(),
        diagnostics=(),
        findings=tuple(findings),
        files=(),
    )


def generated() -> dict[str, bytes]:
    result = all_rules_result()
    return {
        "terminal": render(result, "text", width=100).encode(),
        "json": render(result, "json").encode(),
        "sarif": render(result, "sarif").encode(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = generated()
    if args.check:
        stale = [
            str(OUTPUTS[name])
            for name, content in expected.items()
            if not OUTPUTS[name].is_file() or OUTPUTS[name].read_bytes() != content
        ]
        if stale:
            print(f"Output golden drift: {', '.join(stale)}", file=sys.stderr)
            return 1
        print("Output goldens: PASS")
        return 0
    for name, content in expected.items():
        OUTPUTS[name].parent.mkdir(parents=True, exist_ok=True)
        OUTPUTS[name].write_bytes(content)
    print("Output goldens generated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
