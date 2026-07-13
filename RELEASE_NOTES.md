# runtime-contract v0.1.0

These notes define the immutable v0.1.0 release contents. Release artifacts are built and tested
once, attested, and published to PyPI through GitHub OIDC Trusted Publishing; no PyPI API token is
used. The same notes are used for the signed tag and GitHub Release.

## Release contents

- static, offline Python and JavaScript/TypeScript consumer analysis;
- value-blind `.env.example`, Dockerfile, Docker Compose, and Kubernetes provider analysis;
- deterministic contract normalization, precedence, source-to-sink graph, and RTC001–RTC012 rules;
- `scan`, `check`, `explain`, and `diff` with terminal, canonical JSON, and SARIF output;
- strict `runtime-contract.yaml` v1 and versioned report schemas;
- fail-closed parser, filesystem, redaction, and resource-limit controls;
- Linux, macOS, and Windows support on Python 3.11–3.14;
- wheel and sdist validation, isolated install E2E, supply-chain checks, and Code Scanning.

## Freeze checklist

| Area | RC evidence | Status |
| --- | --- | --- |
| Approved v0.1 functions and parsers | Complete public commands, RTC001–RTC012, full-stack fixture | PASS |
| Tests and determinism | 1156 tests before the version freeze; golden, monorepo, phase, profile, secret, and exit-code coverage | PASS |
| Documentation and examples | README, CLI/config/output/rules/security docs, demo and full-stack fixtures | PASS |
| License and community | Apache-2.0, contribution, conduct, support, and security policy | PASS |
| Security and privacy | Offline/no-telemetry runtime, value-blind models, redaction, audit, SAST, Gitleaks | PASS |
| Distribution | wheel/sdist build, checksums, metadata, clean pipx/wheel/sdist E2E | PASS |
| Release pipeline | OIDC-only publishing, single verified artifact set, checksums and attestations | READY |

## Feature freeze and open work

No open GitHub issue is a v0.1.0 blocker at freeze time. Open automated dependency PRs #60 and #61
are classified as post-v0.1.0 backlog because the locked, audited dependency set is green and the
updates are not correctness or security blockers. After this commit, v0.1.0 accepts only fixes for
release-blocking correctness, security, packaging, or publication failures. New behavior belongs
to `[Unreleased]` after v0.1.0.

## Known limitations

The analyzers are intentionally static and do not execute project code, resolve dynamic aliases,
render Helm/Kustomize, contact runtime platforms, or prove deployed values. Resource budgets are
fail-closed CI and parser controls, not an arbitrary-repository latency guarantee. See
[`known-risks.md`](known-risks.md) and the README for the complete v0.1 boundary.
