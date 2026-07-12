# Known risks and limitations

This register describes the implemented day-one vertical slice. Missing future functionality is
listed as planned scope, not as a product defect. No open risk is rated critical or high.

## Open risks

| ID | Description | Severity | Status | Impact | Control or mitigation | Owner | Target milestone | Evidence or test |
|---|---|---|---|---|---|---|---|---|
| RISK-001 | Defensive filesystem-mutation branches are platform and race dependent. | low | accepted | A concurrent mutation can make an individual file fail analysis. | Fail closed with redacted diagnostics, atomic output rollback, and containment checks. | Maintainer | v0.1.0 | `tests/test_discovery.py`, `tests/test_scan.py` |
| RISK-002 | Static analyzers intentionally do not resolve dynamic aliases, computed names, or cross-module value flow. | medium | accepted | Some environment-variable uses produce partial diagnostics or remain unsupported instead of being guessed. | Deterministic partial status, explicit diagnostics, and documented syntax boundaries. | Maintainer | post-v0.1.0 | analyzer unit tests and `README.md` limitations |
| RISK-003 | A damaged Tree-sitter parse may retain only unambiguous observations before or around recovery nodes. | medium | accepted | A credible partial report can contain fewer facts than a complete parse. | Partial status, structural diagnostics, no source execution, and recovery regression tests. | Maintainer | v0.1.0 | `test_tree_sitter_recovery_preserves_safe_static_and_dynamic_reads` |

## Intentional v0.1.0 limitations

| ID | Description | Severity | Status | Impact | Control or mitigation | Owner | Target milestone | Evidence or test |
|---|---|---|---|---|---|---|---|---|
| LIMIT-002 | The rules engine and generated RTC findings are not implemented. | none | planned | `findings` remains an empty typed sequence. | `ScanResult` already owns the stable typed findings seam. | Maintainer | later v0.1.0 work | scan schema and `tests/test_scan_format.py` |
| LIMIT-003 | `check`, `explain`, and `diff` remain fail-closed placeholders. | none | planned | These commands exit 2 and cannot be mistaken for successful analysis. | CLI placeholder regression tests. | Maintainer | later v0.1.0 work | `tests/test_cli.py` |
| LIMIT-004 | There is no tag, GitHub Release, PyPI publication, deployment, telemetry, or network reporting. | none | planned | Installation remains build-from-source or artifact based. | Local-only operation and explicit release gates. | Maintainer | release milestone | README status and clean-install smoke |

## Closed D1.15 regressions

| ID | Description | Severity | Status | Impact | Control or mitigation | Owner | Target milestone | Evidence or test |
|---|---|---|---|---|---|---|---|---|
| REG-001 | Public exports were not protected by one exact readable contract snapshot. | medium | closed | Accidental exports or removals could have changed supported imports unnoticed. | Exact `__all__` and documented-import tests plus installed-distribution import smoke. | Maintainer | D1.15 | `tests/test_public_api.py` |
| REG-002 | The clean-install gate did not itself run `uv pip check` and a real scan in every artifact environment. | medium | closed | Dependency or installed-entry-point regressions could have escaped the local gate. | Wheel checks on Python 3.11–3.14 and independent sdist check on 3.14 now scan a copied fixture in all formats outside the repository. | Maintainer | D1.15 | `scripts/quality-gates.sh --full` |
| REG-003 | Analyzer API prose and the changelog lagged behind the implemented analyzers and report flow. | medium | closed | Users could infer obsolete module boundaries or an incomplete delivery history. | Documentation aligned to the current public seams and tested implementation. | Maintainer | D1.15 | `docs/analyzer-api.md`, `CHANGELOG.md` |
