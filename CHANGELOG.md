# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
