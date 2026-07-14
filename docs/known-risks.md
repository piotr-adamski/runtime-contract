# Known risks and limitations

This register describes the implemented day-one vertical slice. Missing future functionality is
listed as planned scope, not as a product defect. No open risk is rated critical or high.

## Open risks

| ID | Description | Severity | Status | Impact | Control or mitigation | Owner | Target milestone | Evidence or test |
|---|---|---|---|---|---|---|---|---|
| RISK-001 | Defensive filesystem-mutation branches are platform and race dependent. | low | accepted | A concurrent mutation can make an individual file fail analysis. | Fail closed with redacted diagnostics, atomic output rollback, and containment checks. | Maintainer | v0.1.0 | `tests/test_discovery.py`, `tests/test_scan.py` |
| RISK-002 | Static analyzers intentionally do not resolve dynamic aliases, computed names, or cross-module value flow. | medium | accepted | Some environment-variable uses produce partial diagnostics or remain unsupported instead of being guessed. | Deterministic partial status, explicit diagnostics, and documented syntax boundaries. | Maintainer | post-v0.1.0 | analyzer unit tests and `docs/analyzer-api.md` |
| RISK-003 | A damaged Tree-sitter parse may retain only unambiguous observations before or around recovery nodes. | medium | accepted | A credible partial report can contain fewer facts than a complete parse. | Partial status, structural diagnostics, no source execution, and recovery regression tests. | Maintainer | v0.1.0 | `test_tree_sitter_recovery_preserves_safe_static_and_dynamic_reads` |

## Intentional v0.1.0 limitations

| ID | Description | Severity | Status | Impact | Control or mitigation | Owner | Target milestone | Evidence or test |
|---|---|---|---|---|---|---|---|---|
| LIMIT-004 | Plugin discovery and dynamic analyzer loading are not implemented. | none | accepted | Extensions use the public analyzer API but must be registered by an embedding application. | Stable `Analyzer`/`AnalyzerRegistry` seam and explicit documentation. | Maintainer | post-v0.1.0 | `docs/analyzer-api.md`, `tests/analysis/test_base.py` |

## Closed D1.15 regressions

| ID | Description | Severity | Status | Impact | Control or mitigation | Owner | Target milestone | Evidence or test |
|---|---|---|---|---|---|---|---|---|
| REG-001 | Public exports were not protected by one exact readable contract snapshot. | medium | closed | Accidental exports or removals could have changed supported imports unnoticed. | Exact `__all__` and documented-import tests plus installed-distribution import smoke. | Maintainer | D1.15 | `tests/test_public_api.py` |
| REG-002 | The clean-install gate did not itself run `uv pip check` and a real scan in every artifact environment. | medium | closed | Dependency or installed-entry-point regressions could have escaped the local gate. | Wheel checks on Python 3.11–3.14 and independent sdist check on 3.14 now scan a copied fixture in all formats outside the repository. | Maintainer | D1.15 | `scripts/quality-gates.sh --full` |
| REG-003 | Analyzer API prose and the changelog lagged behind the implemented analyzers and report flow. | medium | closed | Users could infer obsolete module boundaries or an incomplete delivery history. | Documentation aligned to the current public seams and tested implementation. | Maintainer | D1.15 | `docs/analyzer-api.md`, `CHANGELOG.md` |

## Closed D2.15 integration regressions

| ID | Description | Severity | Status | Impact | Control or mitigation | Owner | Target milestone | Evidence or test |
|---|---|---|---|---|---|---|---|---|
| REG-004 | Analyzer-local sensitivity decisions could disagree for the same key when Kubernetes Secret metadata was stronger than a name heuristic. | high | closed | Strict normalization failed and discarded the otherwise valid project contract. | A deterministic project reconciliation selects explicit configuration first, then structural Secret metadata, while the normalizer remains strict for every other conflict. | Maintainer | D2.15 | `tests/test_full_stack_fixture.py`, `tests/test_scan.py` |
| REG-005 | End-to-end scan analyzed Compose files independently instead of applying caller-ordered multi-file project semantics. | high | closed | Overrides and merged services could be represented as unrelated providers. | Compose candidates are resolved once per explicit component root with fail-closed per-file reporting and the existing size limit. | Maintainer | D2.15 | `tests/test_full_stack_fixture.py`, `test_engine_failures_return_failed_reports_and_continue` |
| REG-006 | Approved v0.1 parser scope lacked Pydantic Settings v1/v2 and static `import.meta.env`. | high | closed | A full-stack scan could miss runtime requirements or classify Vite requirements in the wrong phase. | Static alias/prefix parsing, custom-source diagnostics, Vite builtin exclusions, build/runtime phase tests, and no source execution. | Maintainer | D2.15 | `tests/analysis/test_python_ast.py`, `tests/analysis/test_javascript_typescript.py` |

## Closed D3.07 CLI regressions

| ID | Description | Severity | Status | Impact | Control or mitigation | Owner | Target milestone | Evidence or test |
|---|---|---|---|---|---|---|---|---|
| REG-007 | Public documentation still described `check` and the rules engine as placeholders after both became operational. | medium | closed | CI users could ignore a supported command or misinterpret its process status. | One documented `0/1/2` matrix aligned with executable tests for clean, warning/info, active error, policy, partial, configuration, and usage cases. | Maintainer | D3.07 | `tests/test_check.py`, `README.md` |
