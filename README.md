# runtime-contract

[![CI](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml)

`runtime-contract` is an offline static-analysis CLI that checks whether environment variables used
by a specific application component are actually supplied to that component in the correct build or
runtime phase.

It analyzes application code and deployment declarations together. It never executes the analyzed
code, reads secret values, or contacts a runtime environment. Results are deterministic and can be
rendered as terminal text, canonical JSON, or SARIF 2.1.0.

## GitHub Action

Add one `uses:` step to run the released CLI. The Action prepares its own pinned Python environment
and installs the exact `runtime-contract` version from public PyPI; consumers do not install Python,
`pip`, `pipx`, `uv`, or this package themselves.

```yaml
- name: Check runtime configuration contract
  uses: piotr-adamski/runtime-contract@v0
  with:
    command: check
    path: .
    format: text
    fail-on: error
```

The repository must already be checked out. A complete minimal job, with every third-party Action
pinned to an immutable commit, is:

```yaml
jobs:
  runtime-contract:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
        with:
          persist-credentials: false
      - uses: piotr-adamski/runtime-contract@v0
        with:
          command: check
          path: .
          fail-on: error
```

For higher-assurance organizations, replace `@v0` with the full 40-character commit SHA advertised
by the corresponding release. The immutable `v0.x.y` tag is the reproducible semver reference;
`v0` moves only after full CI and release verification. There is no `latest` tag.

### Code Scanning with SARIF

The CLI writes SARIF atomically, so installer and Action logs never enter the report:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
    with:
      persist-credentials: false
  - name: Run runtime-contract
    id: runtime-contract
    uses: piotr-adamski/runtime-contract@v0
    with:
      command: check
      path: .
      format: sarif
      output: runtime-contract.sarif
  - name: Upload SARIF
    uses: github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9
    with:
      sarif_file: runtime-contract.sarif
```

### Action inputs

| Input | Default | Contract |
|---|---|---|
| `command` | `check` | `scan`, `check`, `explain`, or `diff`. |
| `path` | `.` | Project directory for `scan`/`check`; optional project/report source for `explain`. Not used by `diff`. |
| `format` | `text` | `text`, `json`, or `sarif` for `scan`/`check`; `text` or `json` for `explain`/`diff`. |
| `fail-on` | `error` | `error`, `warning`, `info`, or `never` for `scan`/`check`. Must stay at the default for other commands. |
| `config` | empty | Configuration path relative to `path` for `scan`/`check`. |
| `version` | `0.1.0` | One exact public PyPI release. Moving values such as `latest` and URLs are rejected. |
| `output` | empty | Report path passed as one `--output` argument. For `scan`/`check`, it is relative to `path`. |
| `rule` | empty | Rule or finding identifier required by `explain`. |
| `left` | empty | Left project directory or saved JSON report required by `diff`. |
| `right` | empty | Right project directory or saved JSON report required by `diff`. |
| `environment` | empty | Optional environment profile for `scan`, `check`, or `diff`. |

### Action outputs

| Output | Contract |
|---|---|
| `exit-code` | Exact CLI exit code; `2` when Action input validation or installation fails. |
| `result-file` | Absolute requested report path, or an empty string when `output` is not set. |
| `runtime-contract-version` | Version verified through the installed CLI, or empty when setup fails. |

Product exit codes are preserved. A blocking `check` therefore fails the Action with exit `1`, and
invalid usage, partial analysis, or technical failure exits `2`. Use the step's
`continue-on-error: true` only when a later workflow step intentionally needs to inspect a negative
test result.

The Action is required in CI on Ubuntu, macOS, and Windows GitHub-hosted runners. It uses
`astral-sh/setup-uv` pinned to a full SHA, `uv==0.11.28`, managed Python `3.11.15`, an isolated
virtual environment, and `runtime-contract==<version>` from `https://pypi.org/simple`. The installed
CLI version and dependency consistency are checked before analysis. Basic use needs no secret,
token, telemetry, private index, or executable code from the analyzed repository.

## The problem

An environment variable can exist in documentation, a neighboring service, or a build stage and
still be unavailable to the process that needs it. File-by-file checks miss that relationship.
`runtime-contract` maps consumers and providers to components, targets, and phases so it can detect
missing delivery, build/runtime mismatches, unsafe literals, and other contract errors before
deployment.

It does **not** compare a live cluster or production environment with the repository. It checks the
static contract represented by the selected repository files.

## Example: required variable not delivered

Application code requires `DATABASE_URL`:

```python
# api/settings.py
import os

DATABASE_URL = os.environ["DATABASE_URL"]
```

But Compose starts the `api` component without passing that variable:

```yaml
# compose.yaml
services:
  api:
    build: ./api
    environment:
      LOG_LEVEL: info
```

Running `runtime-contract check .` reports the component-specific error and exits `1`:

```text
RTC001 Required variable not provided
  at api/settings.py:3:16 | target=api key=DATABASE_URL phase=runtime
Result: complete
```

## Supported in v0.1.2

- Consumers: Python and JavaScript/TypeScript.
- Providers and declarations: `.env.example`, Dockerfile, Docker Compose, and standard Kubernetes
  workload manifests.
- Build-time and runtime phase matching, component/target mapping, and RTC001–RTC012 evaluation.
- Offline, read-only analysis with deterministic terminal, JSON, and SARIF output.
- Project configuration, classifications, severity overrides, and targeted suppressions.

## Installation

Python 3.11 or newer is required. Install the released package in an isolated environment:

```console
pipx install runtime-contract==0.1.2
runtime-contract --version
```

Or install it in an active virtual environment:

```console
python -m pip install runtime-contract==0.1.2
runtime-contract --version
```

Pin the version in automation to keep CLI and output-schema behavior reproducible.

## Quickstart

From the root of the repository you want to inspect:

```console
runtime-contract scan .
runtime-contract check .
```

`scan` inventories the contract and always remains non-blocking for findings. `check` evaluates the
same result as a policy gate. A configuration file is optional; add `runtime-contract.yaml` when the
repository needs multiple component roots, environments, explicit classifications, severity
overrides, or suppressions.

For a self-contained first run from this source repository:

```console
runtime-contract scan examples/scan-flow
runtime-contract check examples/scan-flow
```

The second command intentionally exits `1` because the example contains active errors.

## Main commands

```console
runtime-contract scan PATH
runtime-contract check PATH
runtime-contract explain RTC001
runtime-contract diff BEFORE AFTER
runtime-contract config validate PATH
```

Use JSON or SARIF for integrations:

```console
runtime-contract scan . --format json --output runtime-contract.json
runtime-contract check . --format sarif --output runtime-contract.sarif
```

See the [complete CLI reference](docs/cli-reference.md) for every command and option.

## Exit codes

| Exit | Meaning |
|---:|---|
| `0` | Successful, reliable command. For `check`, no active finding reaches the failure threshold. |
| `1` | Complete, reliable `check` with an active finding at or above the failure threshold. |
| `2` | Invalid usage/configuration, technical failure, or partial/failed analysis. |
| `130` | Interrupted by the user. |

`scan` never returns `1`. Structured partial or failed analysis is still emitted when safe, but Exit
`2` prevents CI from treating it as reliable. Reports go to stdout or the selected `--output` file;
usage and technical errors go to stderr.

For line-level GitHub Code Scanning alerts, adapt the complete
[SARIF workflow](.github/workflows/code-scanning.yml) and its
[configuration](.github/runtime-contract-code-scanning.yaml). It needs no repository secret.

## Important limitations

- Static analysis cannot prove what a deployed process actually received.
- Dynamic variable names, aliases, reflection, generated manifests, and framework-specific APIs may
  be partial or unsupported instead of guessed.
- Compose `env_file` contents, Helm/Kustomize output, cluster state, image contents, and remote
  references are not resolved.
- Real `.env*` files are excluded; only the exact `.env.example` filename is analyzed.
- Parser and resource budgets fail closed on oversized or structurally unsafe input.
- The Action needs outbound access to GitHub Actions distribution and public PyPI during each
  invocation. Organizations that allowlist Actions must also allow its SHA-pinned
  `astral-sh/setup-uv` dependency.

See [known risks](docs/known-risks.md) and the
[full static-analysis limits](docs/output-formats.md#limits-of-static-analysis).

## Reference documentation

- [CLI commands, options, streams, and exits](docs/cli-reference.md)
- [RTC001–RTC012 rule reference](docs/rules.md)
- [`runtime-contract.yaml`, classifications, and suppressions](docs/runtime-contract-yaml.md)
- [Terminal, JSON, SARIF, schemas, and compatibility](docs/output-formats.md)
- [Security, privacy, parser controls, and resource budgets](docs/security-and-privacy.md)
- [Known risks and intentional limitations](docs/known-risks.md)
- [GitHub Action release and Marketplace checklist](docs/github-action-release.md)
- [Analyzer extension API and built-in analyzer behavior](docs/analyzer-api.md)
- [Domain model](docs/domain-model.md) and [normalization API](docs/normalization-api.md)
- [Offline broken/fixed demo](examples/demo/README.md)

## Contributing, security, and license

Contributions use the [DCO](CONTRIBUTING.md). Report vulnerabilities through the process in
[SECURITY.md](SECURITY.md). The project is licensed under [Apache-2.0](LICENSE); see the
[Code of Conduct](CODE_OF_CONDUCT.md) and [changelog](CHANGELOG.md) for project governance and
release history.
