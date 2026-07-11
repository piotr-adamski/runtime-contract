# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Established the public repository and its community, contribution, conduct, and security files.
- Added the installable Python package and fail-closed CLI skeleton for `scan`, `check`, `explain`,
  and `diff`.
- Added the strict, versioned `runtime-contract.yaml` v1 model, safe YAML diagnostics, deterministic
  Draft 2020-12 JSON Schema, packaged schema resource, validation CLI, examples, and documentation.
- Added deterministic, language-independent normalization from analyzer observations to a
  facts-only `Contract`, including Unicode NFC/POSIX location canonicalization, deduplication,
  conflict detection, reference validation, and typed redacted technical errors.
