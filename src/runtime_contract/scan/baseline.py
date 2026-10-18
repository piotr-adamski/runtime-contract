"""Value-blind, line-independent comparison against a trusted complete report."""

from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from pathlib import Path

from runtime_contract.domain import Finding, Severity
from runtime_contract.errors import PublicError
from runtime_contract.scan.models import BaselineAssessment, ScanResult, ScanStatus
from runtime_contract.scan.parser import parse_json_report

MAX_BASELINE_BYTES = 32 * 1_048_576
_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.ERROR: 2}


def blocks(findings: tuple[Finding, ...], threshold: str) -> bool:
    """Apply the effective failure threshold without changing report severities."""
    return threshold != "never" and any(
        _RANK[item.severity] >= _RANK[Severity(threshold)] for item in findings
    )


def _identity(finding: Finding, report: ScanResult) -> tuple[str, ...]:
    keys = {item.id: item.name for item in report.contract.config_keys}
    environments = {item.id: item for item in report.contract.environments}
    environment = environments.get(finding.environment_id or "")
    return (
        finding.rule_id.value,
        finding.component,
        keys.get(finding.config_key_id or "", ""),
        finding.phase.value,
        finding.primary_location.path,
        environment.kind.value if environment else "",
        environment.target if environment else "",
        environment.profile.value if environment else "",
    )


def compare_baseline(path: Path, current: ScanResult) -> BaselineAssessment:
    """Reject incompatible inputs; compare occurrence counts and severity independently of lines."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_BASELINE_BYTES + 1)
        if len(raw) > MAX_BASELINE_BYTES:
            raise ValueError
        baseline = parse_json_report(raw)
    except (OSError, ValueError, RecursionError):
        raise PublicError(
            "baseline must be a readable, bounded runtime-contract JSON report"
        ) from None
    if baseline.status is not ScanStatus.COMPLETE or current.status is not ScanStatus.COMPLETE:
        raise PublicError("baseline comparison requires two complete analyses")
    if (
        not current.metadata.tool_version
        or baseline.metadata.tool_version != current.metadata.tool_version
        or not baseline.metadata.analysis_fingerprint
        or baseline.metadata.analysis_fingerprint != current.metadata.analysis_fingerprint
        or baseline.inputs != current.inputs
    ):
        raise PublicError(
            "baseline version, analysis scope, environment, or policy is incompatible"
        )
    previous: dict[tuple[str, ...], list[Finding]] = defaultdict(list)
    for finding in baseline.findings:
        previous[_identity(finding, baseline)].append(finding)
    new, worsened, existing = [], [], []
    for finding in sorted(current.findings, key=lambda item: (-_RANK[item.severity], item.id)):
        matches = previous[_identity(finding, current)]
        if not matches:
            new.append(finding.id)
            continue
        # Consume the weakest adequate occurrence first; one old occurrence cannot hide two new ones.
        adequate = [item for item in matches if _RANK[item.severity] >= _RANK[finding.severity]]
        if adequate:
            matched = min(adequate, key=lambda item: (_RANK[item.severity], item.id))
            existing.append(finding.id)
        else:
            matched = max(matches, key=lambda item: (_RANK[item.severity], item.id))
            worsened.append(finding.id)
        matches.remove(matched)
    return BaselineAssessment(
        report_sha256=sha256(raw).hexdigest(),
        new=tuple(sorted(new)),
        worsened=tuple(sorted(worsened)),
        existing=tuple(sorted(existing)),
        resolved=tuple(sorted(item.id for matches in previous.values() for item in matches)),
    )
