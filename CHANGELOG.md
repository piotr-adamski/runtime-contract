# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

- Add bounded Kubernetes `env` and `envFrom` extraction plus end-to-end workload delivery analysis,
  preserving only source selectors, optional/prefix metadata, and locations while proving literal
  values cannot reach public models or text, JSON, and SARIF output.
- Make `scan` fail closed with exit code 2 for partial as well as failed analysis while still
  emitting the safe report for diagnosis.
- Add explicit in-memory Docker Compose project resolution with ordered multi-file merge,
  profiles, `!reset`/`!override`, local include/extends, interpolation-source precedence, atomic
  failures, and field-level value-blind provenance.
- Add an end-to-end, non-executing Docker Compose analyzer for service `environment`, `env_file`,
  and `build.args` delivery facts without reading referenced files or retaining values.
- Add a deterministic, non-executing Dockerfile analyzer for explicit multi-stage `ARG` and `ENV`
  delivery facts, recovery diagnostics, and bounded parsing.

### Added

- Added the end-to-end `scan` flow with effective configuration, named-root discovery, Python and
  JavaScript/TypeScript analysis, normalization, deterministic text/JSON/SARIF rendering, atomic
  output, safe diagnostics, and complete/partial/failed exit-code semantics.
- Established the public repository and its community, contribution, conduct, and security files.
- Added the installable Python package and fail-closed CLI skeleton for `scan`, `check`, `explain`,
  and `diff`.
- Added the strict, versioned `runtime-contract.yaml` v1 model, safe YAML diagnostics, deterministic
  Draft 2020-12 JSON Schema, packaged schema resource, validation CLI, examples, and documentation.
- Added deterministic, language-independent normalization from analyzer observations to a
  facts-only `Contract`, including Unicode NFC/POSIX location canonicalization, deduplication,
  conflict detection, reference validation, and typed redacted technical errors.
- Added the public `Analyzer`/`AnalyzerRegistry` extension contract and immutable
  `AnalyzerInput` → `AnalysisResult` → `FactObservation` models.
- Added the static Python AST analyzer and JavaScript/TypeScript Tree-sitter analyzer without
  importing or executing analyzed project code.
- Added the versioned `runtime-contract/v1` JSON report, Draft 2020-12 schema, exact D1.12 reader,
  typed `ScanResult` findings seam, and deterministic golden documents.
- Added cross-analyzer and day-one vertical-slice tests covering Python and JavaScript/TypeScript
  discovery, analysis, normalization, text/JSON/SARIF rendering, schema validation, atomic output,
  redaction, non-execution, and byte determinism.

### Fixed

- Stabilized the public import surface with readable exact `__all__` snapshots and installed
  distribution import checks.
- Extended clean wheel and sdist verification with `uv pip check`, real artifact-installed `scan`
  smokes, packaged-schema validation, deterministic output checks, and private-artifact rejection.
- Aligned analyzer API documentation and this changelog with the implemented D1.01–D1.15 state.
