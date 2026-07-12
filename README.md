# runtime-contract

[![CI](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml)

Static, local CLI for finding inconsistencies between environment variables used in application code and how they are documented and supplied at build and runtime.

`runtime-contract` answers a practical question before deployment: does every application
component receive the environment variables it consumes, in the right target and phase? It scans
source and deployment files as data, reports missing or conflicting delivery, and never executes
the analyzed project.

## Five-minute quickstart

Requires Python 3.11 or newer. Until the first PyPI release, install from a checked-out source tree;
the same commands accept `runtime-contract` from PyPI after v0.1.0 is published.

Isolated application install with pipx:

```console
pipx install .
runtime-contract --version
```

Or install into an active virtual environment with pip:

```console
python -m pip install .
runtime-contract --version
```

Run the bundled, domain-neutral example from the repository root:

```console
runtime-contract scan examples/scan-flow
runtime-contract check examples/scan-flow
```

`scan` prints the complete inventory and findings. It exits `0` for complete analysis even when
findings exist. `check` runs the same analysis but exits `1` when an active `error` finding exists,
which is the expected result for this deliberately inconsistent example. Exit `2` means the result
is not reliable because of invalid input, configuration, usage, or a technical failure.

For machine-readable output:

```console
runtime-contract scan examples/scan-flow --format json --output scan.json
runtime-contract check examples/scan-flow --format sarif --output runtime-contract.sarif
```

Minimal GitHub Actions step:

```yaml
- name: Check environment-variable delivery
  run: |
    python -m pip install runtime-contract
    runtime-contract check .
```

The CI snippet becomes directly installable from PyPI with v0.1.0. Before publication, replace the
install target with the checked-out package or a verified wheel produced by this repository.

## Scope and non-goals

v0.1 analyzes Python, JavaScript/TypeScript, `.env.example`, Dockerfile, Docker Compose, and plain
Kubernetes YAML/JSON. It emits terminal text, canonical JSON, or SARIF 2.1.0 and operates offline.

It does not execute or import application code, load real `.env*` files, resolve secret values,
contact Docker or Kubernetes, render Helm/Kustomize, invoke Git, modify analyzed files, or send
telemetry. It is a static contract checker, not a deployment engine, secret manager, runtime
monitor, or general-purpose SAST scanner.

## Project status

The v0.1 feature set is release-candidate complete and remains on version `0.1.0.dev0` until the
release workflow publishes the immutable v0.1.0 artifacts. All supported commands are implemented:
`scan`, `check`, `explain`, and `diff`.

Kubernetes manifests are traversed statically and locally from caller-provided YAML (including
multi-document streams) or JSON. Supported workload kinds are `Pod`, `Deployment`,
`StatefulSet`, `DaemonSet`, `Job`, and `CronJob`; traversal inventories `containers` and
`initContainers` together with value-blind `env` and `envFrom` metadata. For `env.value`, only the
environment name and source kind survive. `secretKeyRef`, `configMapKeyRef`, `fieldRef`, and
`resourceFieldRef` retain only the selectors needed to explain delivery. ConfigMap `data` and
`binaryData` plus Secret `data` and `stringData` are indexed by object identity and key name only.
References resolve only to a same-component, same-namespace object of the expected kind. A local
`envFrom` becomes one resolved-bulk provider per observed key; an external or mismatched reference
remains exactly one unresolved-bulk provider. Literal and encoded values never enter public result
models, reprs, reports, diagnostics, or logs. CRDs, operator resources, `List`, and other unsupported
resources produce informational `RTC012`. Helm, Kustomize, cluster access, manifest-directed file
reads, and value resolution are outside this boundary. Extension-based `scan` ignores generic YAML/JSON mappings that have
neither `apiVersion` nor `kind`; direct traversal remains fail-closed unless the caller explicitly
requests that unmarked-document behavior.

> **Status:** `runtime-contract scan` and `runtime-contract check` perform deterministic static
> Python, JavaScript/TypeScript, `.env.example`, Dockerfile, Docker Compose, and Kubernetes analysis
> end to end. `explain` provides offline rule and finding guidance; `diff` compares semantic
> contracts from two directories or two saved reports.

An independent open-source project maintained by Piotr Adamski.

The public test fixture at `tests/fixtures/full-stack` combines every supported input family and
documents valid flows, a missing delivery, an unused provider, competing deliveries, and a
sensitive key delivered through ConfigMap. Its machine-readable golden file is deliberately not a
Kubernetes-discoverable `.json` input.

The v0.1.0 inputs are:

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

Human-readable text groups findings by severity and component, includes source locations and safe
manual suggestions, and never renders provider values. `--color auto|always|never` controls ANSI
color (`auto` requires a TTY and respects `NO_COLOR`), `--no-emoji` disables TTY symbols, and
`--width 40..240` provides deterministic wrapping for narrow terminals. Non-TTY CI output is plain
by default. These terminal options do not change JSON or SARIF bytes and are available for both
`scan` and `check`.

`scan` returns 0 only for complete analysis and 2 for partial, failed, or technically invalid
analysis. Partial and failed runs still emit their structured report so callers can inspect the
safe evidence; they are never represented as successful process exits. `scan` never returns 1.
Reports go to stdout unless `--output` (or configured `execution.report`) selects an atomic file
write. Technical CLI errors go to stderr. `check` runs the same analysis and rule pipeline as
`scan`, then uses the following stable process contract:

| Exit | Meaning |
|---:|---|
| `0` | Complete, reliable analysis with no active `error` finding. `warning` and `info` do not block. |
| `1` | Complete, reliable analysis with at least one active `error` finding. |
| `2` | Invalid use/configuration, technical failure, or partial/failed analysis. |

Suppressions remove only their exact active matches before this decision. Severity overrides are
also applied first, so downgrading an error to warning makes a complete check non-blocking. Findings
are written to the selected terminal, canonical JSON, or SARIF output for exits `0` and `1`;
structured partial/failed reports are retained for exit `2`.

Explain any v0.1 rule offline, or resolve a finding from a canonical JSON report or a project scan:

```text
runtime-contract explain RTC001
runtime-contract explain RTC001 --format json
runtime-contract explain RTC001-<sha256> report.json
runtime-contract explain RTC001-<sha256> PROJECT
```

The explanation includes rationale, default and effective severity, an example, safe manual
remediation, documentation, and finding locations where applicable. Unknown IDs, missing findings,
invalid reports, and incomplete scans exit `2`.

Compare two project directories or two canonical JSON reports without invoking Git:

```text
runtime-contract diff BEFORE AFTER
runtime-contract diff before.json after.json --format json
runtime-contract diff BEFORE AFTER --environment prod --output contract-diff.json
```

The deterministic result groups added, removed, and changed consumers, providers,
classifications, and findings. Semantic identities use component/key/phase/target/mechanism and
relative paths; generated IDs, array order, line shifts, and absolute host paths do not create
noise. A successful comparison returns `0` even when differences exist. Invalid, mixed-kind, or
incomplete inputs return `2`.

The JSON reports for `scan`, `check`, and `diff` share the versioned public automation envelope
`runtime-contract/v1` with integer `schema_version: 1`, `metadata.tool`,
`metadata.tool_version`, `metadata.command`, `status`, and `diagnostics`. Structured reports go to
stdout (or only to an explicit `--output` path); usage, configuration, and technical errors go to
stderr. A complete `check` with error findings still emits schema-valid JSON before exit `1`.

For `scan` and `check`, the remaining required top-level fields are `inputs`, `summary`, `contract`,
`findings`, and `files`. The optional
`flow_graph` field is derived deterministically from canonical fact IDs and is rebuilt when an
early v1 document omits it. The optional `precedence` field records value-blind provider
dispositions and pairwise conflicts and is rebuilt under the same compatibility rule. Consumers
and providers remain exclusively inside the facts-only
`contract`; findings use their public typed shape and are generated by the deterministic RTC rule
pipeline.

Optional scalars without a value are JSON `null`; empty sequences are `[]`, empty maps are `{}`,
and required fields are never omitted. Paths are NFC, relative POSIX paths contained by the scan
root; the public root is always `.`. Reports contain no timestamp, duration, UUID, hostname, user,
process ID, current working directory, absolute host path, source snippet, or file content.

Canonical serialization is UTF-8 without BOM, recursively sorted object keys, compact separators,
no NaN or infinities, deterministic array ordering, and exactly one final LF. This is the
runtime-contract canonical format, not an RFC 8785/JCS claim. The Draft 2020-12 schema is
[`schemas/runtime-contract-scan-result-v1.schema.json`](schemas/runtime-contract-scan-result-v1.schema.json).
The `diff` payload keeps its deterministic `left`, `right`, and `changes` body and validates against
[`schemas/runtime-contract-diff-result-v1.schema.json`](schemas/runtime-contract-diff-result-v1.schema.json),
and the golden document is
[`examples/reports/runtime-contract-v1.json`](examples/reports/runtime-contract-v1.json).

A newer v1 reader must accept older v1 documents. Public `parse_json_report(str | bytes)` accepts
the original flat v1 shape and normalizes it to the canonical nested v1 model; writers emit only
the canonical shape. A new
optional v1 field is permitted only with a deterministic default for older documents. Removing,
renaming, retyping, changing meaning or requiredness, identity or sorting, `null` interpretation,
or an enum in a way that changes automation interpretation requires `runtime-contract/v2`. Version
2 requires a separate model, `$id`, schema file, and explicit adapter. Package and JSON format
versions evolve independently; older readers need not read newer v1 documents.

Local-only operation without telemetry or data transmission remains a project requirement. There is
currently no release or PyPI publication.

The runtime package imports no network, subprocess, dynamic-execution, or logging capability.
Analyzed code is data only. Real `.env*` files are excluded except the exact `.env.example` name;
source candidates are identity-checked immediately before reading. Public technical errors pass
through one redaction boundary that retains neither exception text, arguments, causes, reprs, nor
tracebacks. Reports are read-only unless the caller explicitly selects an atomic `--output` path.

Sensitivity classification is deterministic and value-blind. `classify_sensitivity()` recognizes
terminal name forms such as `*_TOKEN`, `*_PASSWORD`, `*_SECRET`, `*_PRIVATE_KEY`, `*_API_KEY`,
`*APIKEY`, and `*_CREDENTIAL(S)` across underscore, hyphen, dot, whitespace, and camel-case
separators. Explicit configuration overrides take priority; Kubernetes Secret references and
resolved Secret `envFrom` keys are classified from structural metadata. Every `ConfigKey` records
the classification reason and confidence. Bounded negative forms such as `TOKEN_COUNT`,
`PASSWORD_LENGTH`, `SECRET_NAME`, and `CREDENTIAL_TYPE` remain non-secret to reduce obvious false
positives. Values, fragments, lengths, hashes, and contents are never inspected by this classifier.
Project YAML may override the heuristic with scoped `sensitive`, `public`, or `ignore` decisions
selected by an exact name, glob, or bounded full-match regex. Public/ignored exceptions require a
reason; contradictory declarations fail closed and a scan reports rules unused by observed keys.

The strict local configuration contract is documented in
[`docs/runtime-contract-yaml.md`](docs/runtime-contract-yaml.md). Validate it without scanning:

```text
runtime-contract config validate .
runtime-contract config validate . --format json
```

Canonical references:

- [CLI options and exit/stream contract](docs/cli-reference.md)
- [configuration fields and suppressions](docs/runtime-contract-yaml.md)
- [offline broken/fixed full-stack demo](examples/demo/README.md)
- [terminal, JSON, SARIF, heuristics, and static-analysis limits](docs/output-formats.md)
- [RTC001–RTC012 reasons, examples, and remediation](docs/rules.md)

The public, parser-independent analyzer extension contract is documented in
[`docs/analyzer-api.md`](docs/analyzer-api.md). `PythonAstAnalyzer` implements that contract with
static Python source analysis. It recognizes literal keys used through `os.getenv`,
`os.environ.get`, and `os.environ[...]`, including supported `os`, `getenv`, and `environ` import
aliases. Source is decoded according to Python coding-cookie rules and parsed with the standard
library AST; analyzed project code is never imported or executed.

`DotenvAnalyzer` inventories declarations only from files named exactly `.env.example`.
Discovery never opens `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.test`,
or any other `.env.*` variant. Includes and file contents cannot override this boundary.

The accepted syntax covers ASCII variable names matching `[A-Za-z_][A-Za-z0-9_]*`, optional
`export`, whitespace around the first `=`, empty and unquoted values, single quotes, double quotes,
backticks, matching escaped quotes, inline comments, LF/CRLF, a leading UTF-8 BOM, and quoted
multiline values. Duplicate declarations remain separate declaration facts with their own source
locations. Syntax errors produce redacted partial-analysis diagnostics while preserving other
unambiguous declarations; invalid encoding and safety-limit failures fail closed.

Values, value fragments, lengths, hashes, snippets, comments, and inferred value types never enter
the result. `$NAME`, `${NAME}`, and the supported `:-`, `-`, `:+`, and `+` braced forms are
recognized in unquoted and double-quoted values but are not expanded; default and alternate text is
not recursively analyzed. Single-quoted and backtick values are literal. Escaped dollars do not
create references, and `$(...)` is opaque text that is never executed. This is intentional static
syntax compatibility with a common dotenv subset, not runtime compatibility with dotenv libraries
and not an environment loader.

`DockerfileAnalyzer` statically recognizes case-insensitive `FROM`, `ARG`, and `ENV`
instructions in `Dockerfile` and `Dockerfile.*`. Each explicit `ARG` is build-phase delivery and
each explicit `ENV` pair is runtime-phase delivery into one implicit component environment.
Multi-stage aliases are matched case-insensitively and local-stage state is inherited privately;
inherited declarations never create synthetic provider evidence. Global `ARG` names are available
to later `FROM` instructions but enter a stage only after an explicit stage-local declaration.

The Dockerfile lexer supports UTF-8 with an optional BOM, LF/CRLF, parser `# escape=` directives,
logical-line continuations, quoted and legacy `ENV` forms, and bounded heredoc skipping. It
recognizes substitutions without expanding them. Values, base-image references, source snippets,
and substitution-only variable names are never emitted or retained as facts. Malformed local
instructions recover as redacted partial diagnostics when boundaries remain trustworthy; invalid
encoding and safety-limit violations fail closed. Docker, BuildKit, shells, commands, files named
by the Dockerfile, host environment variables, and network resources are never invoked or read.

The public `runtime_contract.compose` API loads one in-memory Docker Compose YAML document from
immutable relative-path and byte input. It returns frozen models for static service names,
profiles, interpolation variable names, one-based locations, and redacted diagnostics. The loader
supports bounded standard anchors, aliases, and mapping merges, but never expands variables,
consults the host environment, opens referenced files, invokes Compose or Docker, or retains YAML
values and snippets.
`ComposeAnalyzer` turns each static service into one `compose_service` environment. Static
`environment` names are explicit runtime delivery providers, and static `build.args` names are
explicit build delivery providers. Map, list, empty, null, and bare passthrough declarations are
inventoried without consulting the host environment. The delivered key is always the declaration
name; interpolation inputs and literal fallback text never become keys or leave the parser.

Each safe static `env_file` reference becomes unresolved-bulk runtime evidence for its service.
The referenced file is never opened, resolved, checked for existence, or followed through a
symlink, and no variable names are inferred from it. Later entries retain higher declared
precedence, while `environment` declarations override all `env_file` entries structurally,
including empty, null, and passthrough declarations.

`resolve_compose_project(ComposeProjectInput)` adds an explicit, closed-bundle project path while
preserving the one-file behavior above. Files merge in caller order; `environment` and
`build.args` use key-level last-wins semantics, `env_file` appends, and `profiles` appends with
stable first-occurrence deduplication. Safe `!reset` and Compose 2.24.4+ `!override` tags are
handled without object construction. Local `include` (including its dedicated override path
list) and `extends` resolve only against caller-supplied bytes. Missing, cyclic, remote, absolute,
escaping, Windows, or backslash references fail atomically.

Project results retain every service with `always_enabled`, `profile_enabled`, or
`profile_disabled` activation and expose field/key-level, value-blind resolution traces. Explicit
shell names take interpolation-source precedence, then caller-ordered CLI env files; project
`.env` is considered only when no CLI env file is supplied. These sources are model-interpolation
inputs only. A service `env_file` remains unresolved-bulk runtime delivery and is never read.
Interpolation values and fallbacks are never expanded or returned. `ComposeAnalyzer.analyze_project`
emits provider facts only for enabled services. The API accepts no cwd, filesystem callback,
resolver, ambient environment, Docker, subprocess, shell, or network capability.

Analyzer observations can be aggregated through the pure `runtime_contract.normalization` API.
It canonicalizes relative source locations, deduplicates identical facts, rejects conflicts and
invalid references with typed technical errors, and returns a deterministic facts-only `Contract`.
See [`docs/normalization-api.md`](docs/normalization-api.md).

The immutable `runtime_contract.rules` API publishes the complete `RTC001`–`RTC012` catalog with
stable names, default severities, rationale, and manual remediation. Technical parser and safety
diagnostics remain a separate `runtime_contract.analysis.DIAGNOSTIC_CATALOG`.

| IDs | Default severity |
|---|---|
| `RTC001` REQUIRED_NOT_PROVIDED, `RTC002` SECRET_LITERAL, `RTC003` PRIVATE_KEY_CONTENT | error |
| `RTC004` UNDOCUMENTED_VARIABLE, `RTC005` UNUSED_DECLARATION, `RTC006` DYNAMIC_REFERENCE, `RTC007` CONFLICTING_DEFAULT | warning |
| `RTC008` OPTIONAL_NOT_PROVIDED | info |
| `RTC009` DELIVERY_UNVERIFIABLE, `RTC010` PHASE_MISMATCH | error |
| `RTC011` CUSTOM_SETTINGS_SOURCE | warning |
| `RTC012` UNSUPPORTED_K8S_RESOURCE | info |

Published RTC identifiers are never reused. Their condition, default severity, rationale meaning,
and remediation meaning are stable within v0.1.x; a semantic change requires a documented breaking
release decision. A new rule requires a new ID, catalog entry, golden fixture, tests, and format
metadata. Configuration may change effective policy, but never mutates the catalog default.

The pure `runtime_contract.flow` API derives a value-blind source-to-sink graph from a canonical
`Contract`. It connects consumer → configuration key → delivery provider → declaration provider
and delivery provider → environment using fact IDs, never variable-name matching. Component,
environment, and phase context remains on each edge; unresolved bulk providers target only their
environment and never claim a key. `ScanResult` rejects a supplied graph that differs from the
graph derived from its embedded contract; the strict reader reconstructs the graph when an early
v1 report omits it.

The pure `runtime_contract.precedence` API marks providers `active`, `overridden`, or
`incomparable` and returns both provider IDs, an optional winner, and a closed reason code. Compose
`environment` overrides a same-service `env_file`; Kubernetes `env` overrides same-workload
`envFrom`; later declarations win only inside one ordered source file. Independent environments,
unordered files, and synthetic cross-platform contexts remain incomparable. No global platform
order is guessed.

`JavaScriptTypeScriptAnalyzer` uses the Python Tree-sitter bindings and distributed JavaScript,
TypeScript, and TSX grammars for `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, and `.tsx`.
It recognizes direct `process.env.NAME` and literal `process.env["NAME"]` reads, including optional
chaining, TypeScript assertions/wrappers, and direct object destructuring from `process.env`.
Lexically shadowed `process` bindings are excluded. Parser recovery preserves unambiguous reads and
reports a partial result for damaged syntax; dynamic computed names, computed destructuring keys,
and rest destructuring also produce partial diagnostics instead of guessed keys.

Dynamic environment-variable names are not guessed and produce a partial analysis diagnostic.
The Python analyzer intentionally does not follow aliases created by assignment, resolve key names
from variables, propagate values between modules, or handle mapping mutation methods such as
`setdefault` or `update`. It recognizes the supported static Pydantic Settings forms but reports
custom source hooks as dynamic. The JavaScript/TypeScript analyzer likewise does not follow aliases
or constants and does not inspect `import.meta.env`, Deno, Bun, dotenv, bundlers, or
framework-specific APIs. No analyzer imports or executes analyzed project code.

`KubernetesAnalyzer` creates one `kubernetes_workload` environment per stable
`namespace/Kind/name` target. It analyzes all Kubernetes candidates in one selected component as a
linked local manifest set while preserving exact per-file completeness. Every static `env` name becomes an explicit runtime provider with
mechanism `kubernetes_env`, independent of whether its source is a literal, key reference, field
selector, or resource selector. Every `envFrom` entry uses mechanism `kubernetes_env_from`: a
same-namespace local ConfigMap/Secret produces value-blind `resolved_bulk` providers for its key
names, including the declared prefix, while an absent, wrong-kind, cross-namespace, or
cross-component object remains `unresolved_bulk`. Container-level source kinds, selectors,
`optional`, prefix, declaration index, and source locations remain available through the public
`runtime_contract.kubernetes` traversal API. That API also exposes deterministic presence objects,
source statuses, and reference-resolution records without being widened into value-bearing facts.
Malformed environment structures produce redacted partial or failed analysis while preserving
safe sibling facts. The analyzer reads only caller-supplied bytes and never contacts a cluster,
opens referenced files, reads ambient environment variables, or invokes `kubectl` or any process.

## Development

Use Python 3.11 or newer and `uv >=0.11.28,<0.12`:

```text
uv sync --locked --all-groups
./scripts/quality-gates.sh
```

## Project information

- Maintainer: Piotr Adamski
- Repository: [piotr-adamski/runtime-contract](https://github.com/piotr-adamski/runtime-contract)
- Questions and bug reports: [GitHub Issues](https://github.com/piotr-adamski/runtime-contract/issues)
- License: [Apache-2.0](LICENSE)
- Changes: [CHANGELOG.md](CHANGELOG.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Code of Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Security: [SECURITY.md](SECURITY.md)
