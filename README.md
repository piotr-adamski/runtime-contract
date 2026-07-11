# runtime-contract

[![CI](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml/badge.svg)](https://github.com/piotr-adamski/runtime-contract/actions/workflows/ci.yml)

Static, local CLI for finding inconsistencies between environment variables used in application code and how they are documented and supplied at build and runtime.

Kubernetes manifests are traversed statically and locally from caller-provided YAML (including
multi-document streams) or JSON. Supported workload kinds are `Pod`, `Deployment`,
`StatefulSet`, `DaemonSet`, `Job`, and `CronJob`; traversal inventories `containers` and
`initContainers` without reading or exposing their values. CRDs, operator resources, `List`, and
other unsupported resources produce informational `RTC012`. Helm, Kustomize, cluster access, and
manifest-directed file reads are outside this boundary.

> **Status:** `runtime-contract scan` performs deterministic static Python,
> JavaScript/TypeScript, `.env.example`, Dockerfile, and Docker Compose analysis end to end. `check`, `explain`, and `diff`
> remain fail-closed placeholders.

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
`schema_version: 1`. Its required top-level fields are `schema_id`, `schema_version`, `metadata`,
`inputs`, `status`, `summary`, `contract`, `diagnostics`, `findings`, and `files`. Consumers and
providers remain exclusively inside the facts-only `contract`; findings have their public typed
shape but remain empty until the rules engine is implemented.

Optional scalars without a value are JSON `null`; empty sequences are `[]`, empty maps are `{}`,
and required fields are never omitted. Paths are NFC, relative POSIX paths contained by the scan
root; the public root is always `.`. Reports contain no timestamp, duration, UUID, hostname, user,
process ID, current working directory, absolute host path, source snippet, or file content.

Canonical serialization is UTF-8 without BOM, recursively sorted object keys, compact separators,
no NaN or infinities, deterministic array ordering, and exactly one final LF. This is the
runtime-contract canonical format, not an RFC 8785/JCS claim. The Draft 2020-12 schema is
[`schemas/runtime-contract-scan-result-v1.schema.json`](schemas/runtime-contract-scan-result-v1.schema.json),
and the golden document is
[`examples/reports/runtime-contract-v1.json`](examples/reports/runtime-contract-v1.json).

A newer v1 reader must accept older v1 documents. Public `parse_json_report(str | bytes)` accepts
the exact flat D1.12 shape and normalizes it to D1.13; writers emit only the canonical shape. A new
optional v1 field is permitted only with a deterministic default for older documents. Removing,
renaming, retyping, changing meaning or requiredness, identity or sorting, `null` interpretation,
or an enum in a way that changes automation interpretation requires `runtime-contract/v2`. Version
2 requires a separate model, `$id`, schema file, and explicit adapter. Package and JSON format
versions evolve independently; older readers need not read newer v1 documents.

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
framework-specific APIs. No analyzer imports or executes analyzed project code. Compose,
Kubernetes, and findings remain future work.

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
