# Output formats and static-analysis limits

This is the canonical v0.1 format reference. The authoritative machine schemas are
[`runtime-contract-scan-result-v1.schema.json`](../schemas/runtime-contract-scan-result-v1.schema.json),
[`runtime-contract-diff-result-v1.schema.json`](../schemas/runtime-contract-diff-result-v1.schema.json),
and the packaged SARIF 2.1.0 schema used by tests.

## Terminal text

Text is for humans. It groups safe findings by severity and component, includes relative source
locations and manual remediation, and ends with a stable result line. Color, symbols, verbosity,
quiet mode, and width affect only text. Non-TTY output is plain by default.

## Canonical JSON

Scan and check emit `schema_id: runtime-contract/v1`, integer `schema_version: 1`, metadata,
inputs, summary, facts-only contract, findings, file completeness, diagnostics, flow graph, and
precedence analysis. Diff uses the same envelope plus left/right metadata and semantic changes.

Serialization is UTF-8 without BOM, sorted keys, compact separators, no NaN/Infinity, deterministic
arrays, relative NFC POSIX paths, and exactly one final LF. It contains no timestamp, duration,
UUID, hostname, username, PID, cwd, absolute path, source snippet, file content, or provider value.

## SARIF 2.1.0

`scan` and `check` emit one SARIF run. RTC001–RTC012 map to stable driver rules; errors map to
`error`, warnings to `warning`, and info to `note`. Locations are project-relative and findings
carry a deterministic `runtimeContract/v1` partial fingerprint. Policy, status, selected roots, and
safe summary remain run properties. `explain`, `diff`, and `config validate` do not support SARIF.

SARIF output with findings is still emitted before `check` exits `1`. A partial/failed scan emits a
safe structured report and exits `2`; a usage error emits no report.

## Heuristics and suppressions

Sensitivity starts with explicit YAML, then structural Kubernetes Secret evidence, then bounded
name heuristics. Recognized terminal name forms include token, password, secret, private key, API
key, and credential variants. Negative forms such as `TOKEN_COUNT`, `PASSWORD_LENGTH`,
`SECRET_NAME`, and `CREDENTIAL_TYPE` remain non-sensitive. Values are never inspected.

Suppressions match a stable rule plus at least one explicit selector. They remove only matching
active findings before `check` decides its exit. Expired suppressions do not apply and emit a
warning. Suppressions cannot hide parser failures, unsafe paths, or private-key handling outside
their rule contract. See [configuration reference](runtime-contract-yaml.md).

## Limits of static analysis

- Code, shells, Docker, Compose, Git, package managers, and Kubernetes are never executed.
- Dynamic names, aliases, reflection, computed destructuring, custom settings sources, and
  framework-specific environment APIs may be diagnosed as partial or unsupported.
- `.env.example` is analyzed; real `.env*` files are excluded.
- Compose service `env_file` is unresolved bulk evidence and is never opened.
- Helm, Kustomize, CRDs/operators, cluster state, image contents, and remote references are not
  resolved.
- Static presence proves source configuration, not that a deployed process received a value.
- A complete result is deterministic for supported inputs; it is not a runtime availability or
  secret-validity guarantee.

Exact public examples are stored under [`examples/reports`](../examples/reports) and exact terminal,
JSON, and SARIF goldens are checked byte-for-byte by CI.
