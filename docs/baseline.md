# Gate new findings against a baseline

The source version adds `check --baseline REPORT.json`. Install this checkout with `uv sync --locked`
to use unreleased features; public 0.1.2 predates baseline comparison. Use the same CLI version,
configuration and scope for baseline creation and checking.

```sh
runtime-contract scan . --format json --output accepted-runtime-contract.json
runtime-contract check . --baseline accepted-runtime-contract.json
runtime-contract check . --baseline accepted-runtime-contract.json --format sarif --output current.sarif
```

Review the first report before committing it on a protected branch. A baseline is trusted input:
protect it and `runtime-contract.yaml` in code review. Never regenerate it automatically in a PR.
The tool does not attest provenance, invoke Git or download branches. Consumer workflows must
obtain the accepted file from a trusted base revision, using ordinary `pull_request` and read-only
permissions. Never execute PR code with `pull_request_target` or write tokens.

All current findings remain visible. Only **new** findings or **increased severity** fail the gate
when they reach `--fail-on` (`error`, `warning`, `info`, or `never`). A complete compatible comparison
returns `0` or `1`. Existing debt can be fixed incrementally. Without a baseline, `check` gates all
active findings; `diff` retains informational exit `0` for valid comparisons.

Match rule, component, key name, phase, relative source path and semantic target identity (kind,
name, profile). Ignore line/column shifts. Preserve occurrence counts: one previous occurrence
cannot accept two current occurrences. File renames and target changes create new identities.
Indistinguishable occurrences are compared by severity counts, not individual AST node identity.

JSON adds `metadata.analysis_fingerprint`, a SHA-256 of normalized non-presentation configuration
and expired suppression IDs. Baseline mode adds `metadata.baseline`: accepted report digest and
sorted `new`, `worsened`, `existing`, `resolved` finding IDs. Resolved IDs refer to the baseline;
the other sets refer to current findings. Text adds counts; SARIF retains all current results
and marks `baselineState` as `new`, `updated` or `unchanged`.

Both reports must be complete, with the same exact nonempty tool version, fingerprint and report
inputs (selected roots, include/exclude, environment, config path and failure threshold). Reject
legacy reports without a fingerprint, changed policy/scope/version, malformed or duplicate-field
JSON, unreadable files and reports over 32 MiB with exit `2`. Partial/failed analysis returns `2`
even with `--fail-on never`. Comparison errors use redacted stderr and emit no comparison report.
The output cannot overwrite the baseline. Presentation/output destination changes remain compatible.

The current reader supports older v1 reports for inspection and `diff`. Older strict-schema
readers cannot consume the new metadata. Regenerate and explicitly review accepted baselines
after a tool, scope, environment or policy change.

## GitHub Action

The source Action adds `baseline`, valid only with `command: check`, passed as one argv element.
It still installs an exact public PyPI release. Until a compatible release is published, default
0.1.2 rejects `--baseline` with exit `2`. Install this checkout in CI for immediate use. Before
moving `v0`, publish the matching CLI and pass consumer E2E against that public package.
