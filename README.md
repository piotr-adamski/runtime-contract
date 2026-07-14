# runtime-contract

[![CI](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml)

`runtime-contract` is an offline static-analysis CLI that checks whether environment variables used
by a specific application component are actually supplied to that component in the correct build or
runtime phase.

It analyzes application code and deployment declarations together. It never executes the analyzed
code, reads secret values, or contacts a runtime environment. Results are deterministic and can be
rendered as terminal text, canonical JSON, or SARIF 2.1.0.

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

## Supported in v0.1.0

- Consumers: Python and JavaScript/TypeScript.
- Providers and declarations: `.env.example`, Dockerfile, Docker Compose, and standard Kubernetes
  workload manifests.
- Build-time and runtime phase matching, component/target mapping, and RTC001–RTC012 evaluation.
- Offline, read-only analysis with deterministic terminal, JSON, and SARIF output.
- Project configuration, classifications, severity overrides, and targeted suppressions.

## Installation

Python 3.11 or newer is required. Install the released package in an isolated environment:

```console
pipx install runtime-contract==0.1.0
runtime-contract --version
```

Or install it in an active virtual environment:

```console
python -m pip install runtime-contract==0.1.0
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

## Minimal GitHub Actions integration

```yaml
name: Runtime contract
on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check environment-variable delivery
        run: |
          python -m pip install runtime-contract==0.1.0
          runtime-contract check .
```

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

See [known risks](docs/known-risks.md) and the
[full static-analysis limits](docs/output-formats.md#limits-of-static-analysis).

## Reference documentation

- [CLI commands, options, streams, and exits](docs/cli-reference.md)
- [RTC001–RTC012 rule reference](docs/rules.md)
- [`runtime-contract.yaml`, classifications, and suppressions](docs/runtime-contract-yaml.md)
- [Terminal, JSON, SARIF, schemas, and compatibility](docs/output-formats.md)
- [Security, privacy, parser controls, and resource budgets](docs/security-and-privacy.md)
- [Known risks and intentional limitations](docs/known-risks.md)
- [Analyzer extension API and built-in analyzer behavior](docs/analyzer-api.md)
- [Domain model](docs/domain-model.md) and [normalization API](docs/normalization-api.md)
- [Offline broken/fixed demo](examples/demo/README.md)

## Contributing, security, and license

Contributions use the [DCO](CONTRIBUTING.md). Report vulnerabilities through the process in
[SECURITY.md](SECURITY.md). The project is licensed under [Apache-2.0](LICENSE); see the
[Code of Conduct](CODE_OF_CONDUCT.md) and [changelog](CHANGELOG.md) for project governance and
release history.
