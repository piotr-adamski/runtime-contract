# runtime-contract

[![CI](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml)

Static, local CLI for finding inconsistencies between environment variables used in application code and how they are documented and supplied at build and runtime.

> **Status:** An installable package and CLI skeleton exist. The Python AST analyzer is available
> as a library API; the read-only analysis commands are not wired to analyzers yet.

An independent open-source project maintained by Piotr Adamski.

The planned v0.1.0 inputs are:

- Python;
- JavaScript and TypeScript;
- `.env.example`;
- Dockerfile;
- Docker Compose;
- standard Kubernetes manifests.

The CLI registers the planned read-only commands `scan`, `check`, `explain`, and `diff`.
Their help is available, but every analysis command currently fails closed with exit code 2 rather
than producing a misleading report.

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

Dynamic environment-variable names are not guessed and produce a partial analysis diagnostic.
The analyzer intentionally does not follow aliases created by assignment, resolve key names from
variables, propagate values between modules, handle mapping mutation methods such as `setdefault`
or `update`, or detect Pydantic settings. JavaScript, deployment-file analyzers, multi-file
aggregation, findings, and CLI integration remain future work.

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
