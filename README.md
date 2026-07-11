# runtime-contract

[![CI](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml)

Static, local CLI for finding inconsistencies between environment variables used in application code and how they are documented and supplied at build and runtime.

> **Status:** `runtime-contract scan` performs deterministic static Python and
> JavaScript/TypeScript analysis end to end. `check`, `explain`, and `diff` remain fail-closed
> placeholders.

An independent open-source project maintained by Piotr Adamski.

The planned v0.1.0 inputs are:

- Python;
- JavaScript and TypeScript;
- `.env.example`;
- Dockerfile;
- Docker Compose;
- standard Kubernetes manifests.

Scan a project and render text, canonical JSON, or SARIF 2.1.0:

```text
runtime-contract scan .
runtime-contract scan . --root api --format json
runtime-contract scan PATH --format json
runtime-contract scan PATH --format json --output report.json
runtime-contract scan . --format sarif --output reports/runtime-contract.sarif
```

`scan` returns 0 for complete and credible partial analysis, and 2 when it cannot produce a
reliable result. It never returns 1. Reports go to stdout unless `--output` (or configured
`execution.report`) selects an atomic file write. Technical CLI errors go to stderr. `check`,
`explain`, and `diff` continue to fail closed with exit code 2.

The JSON report is the versioned public automation API `runtime-contract/v1` with integer
`schema_version: 1`. Its canonical structure, compatibility policy, deterministic serialization,
schema location, and reference snapshot are documented in
[`docs/json-report-v1.md`](docs/json-report-v1.md).

Local-only operation without telemetry or data transmission remains a project requirement. There is
currently no release or PyPI publication.

The strict local configuration contract is documented in
[`docs/runtime-contract-yaml.md`](docs/runtime-contract-yaml.md). Validate it without scanning:

```text
runtime-contract config validate .
runtime-contract config validate . --format json
```

The public, parser-independent analyzer extension contract is documented in
[`docs/analyzer-api.md`](docs/analyzer-api.md). `PythonAstAnalyzer` implements that contract with
static Python source analysis. It recognizes literal keys used through `os.getenv`,
`os.environ.get`, and `os.environ[...]`, including supported `os`, `getenv`, and `environ` import
aliases. Source is decoded according to Python coding-cookie rules and parsed with the standard
library AST; analyzed project code is never imported or executed.

Analyzer observations can be aggregated through the pure `runtime_contract.normalization` API.
It canonicalizes relative source locations, deduplicates identical facts, rejects conflicts and
invalid references with typed technical errors, and returns a deterministic facts-only `Contract`.
See [`docs/normalization-api.md`](docs/normalization-api.md).

`JavaScriptTypeScriptAnalyzer` uses the Python Tree-sitter bindings and distributed JavaScript,
TypeScript, and TSX grammars for `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, and `.tsx`.
It recognizes direct `process.env.NAME` and literal `process.env["NAME"]` reads, including optional
chaining, TypeScript assertions/wrappers, and direct object destructuring from `process.env`.
Lexically shadowed `process` bindings are excluded. Parser recovery preserves unambiguous reads and
reports a partial result for damaged syntax; dynamic computed names, computed destructuring keys,
and rest destructuring also produce partial diagnostics instead of guessed keys.

Dynamic environment-variable names are not guessed and produce a partial analysis diagnostic.
The analyzer intentionally does not follow aliases created by assignment, resolve key names from
variables, propagate values between modules, handle mapping mutation methods such as `setdefault`
or `update`, or detect Pydantic settings. The JavaScript/TypeScript analyzer likewise does not
follow aliases or constants and does not inspect `import.meta.env`, Deno, Bun, dotenv, bundlers, or
framework-specific APIs. Neither analyzer imports or executes analyzed project code. Deployment-file
analyzers and findings remain future work.

## Development

Use Python 3.11 or newer and `uv >=0.11.28,<0.12`:

```text
uv sync --locked --all-groups
./scripts/quality-gates.sh
```

## Project information

- Maintainer: Piotr Adamski
- License: [Apache-2.0](LICENSE)
- Changes: [CHANGELOG.md](CHANGELOG.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Code of Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Security: [SECURITY.md](SECURITY.md)
