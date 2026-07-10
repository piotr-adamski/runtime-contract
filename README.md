# runtime-contract

[![CI](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml)

Static, local CLI for finding inconsistencies between environment variables used in application code and how they are documented and supplied at build and runtime.

> **Status:** An installable package and CLI skeleton exist. Analysis is not implemented yet.

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
