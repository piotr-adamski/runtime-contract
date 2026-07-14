# Analyzer API

`runtime_contract.analysis` is the stable, language-independent extension contract for analyzers.
It defines immutable analysis inputs, observations over the existing domain facts, structural parser
diagnostics, deterministic results, configuration classification, and analyzer registration.

An analyzer is a synchronous, pure function. It receives already verified bytes and a relative POSIX
path. It must not read files, environment variables, the network, Git, clocks, or randomness. It must
not emit file contents, fallback values, source snippets, absolute paths, host data, or secrets.

```python
from runtime_contract.analysis import AnalysisCompleteness, AnalysisResult, AnalyzerInput
from runtime_contract.discovery import CandidateKind


class ExampleAnalyzer:
    analyzer_id = "example.config"
    supported_kinds = frozenset({CandidateKind.CONFIG})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        # Parse input.content without I/O and return structural facts/diagnostics.
        return AnalysisResult(completeness=AnalysisCompleteness.COMPLETE)
```

Register and invoke it through the deterministic registry:

```python
from runtime_contract.analysis import AnalyzerRegistry

registry = AnalyzerRegistry([ExampleAnalyzer()])
result = registry.analyze(analyzer_input)
```

`AnalysisResult` serializes as `runtime-contract/analysis-result/v1`. Its committed Draft 2020-12
JSON Schema is available from `runtime_contract.analysis.schema.schema_bytes()` and as
`schemas/runtime-contract-analysis-result-v1.schema.json`.

`PythonAstAnalyzer`, `JavaScriptTypeScriptAnalyzer`, `DotenvAnalyzer`, `DockerfileAnalyzer`,
`ComposeAnalyzer`, and `KubernetesAnalyzer` are the built-in
implementations registered by `scan`. `DotenvAnalyzer` accepts only the `ENV_EXAMPLE` candidate
kind produced for the exact `.env.example` filename. It inventories declaration facts without
retaining values, expanding interpolation, evaluating command substitution, or performing I/O.
`DockerfileAnalyzer` statically inventories explicit `ARG` build delivery and `ENV` runtime
delivery across multi-stage Dockerfiles. It tracks local-stage inheritance privately, recognizes
line continuations and parser escape directives, and never retains values or executes Dockerfile
content. `ComposeAnalyzer` inventories static service `environment` and `build.args` names as
explicit runtime/build providers and static `env_file` references as unresolved bulk providers.
It never reads an env file or retains values, interpolation fallbacks, or host data. Service
`environment` has higher declared precedence than every `env_file`. The public
`resolve_compose_project` API resolves explicit multi-file bundles, profile activation,
`!reset`/`!override`, local include/extends, interpolation-source names, and value-blind provenance.
`ComposeAnalyzer.analyze_project` converts only enabled effective services into provider facts;
the ordinary one-file `analyze` contract is unchanged.

`KubernetesAnalyzer` uses the bounded `runtime_contract.kubernetes` traversal API. It emits one
`kubernetes_workload` environment for each `namespace/Kind/name` target, explicit
`kubernetes_env` runtime providers for static `env` names. `analyze_project` links the caller-supplied
Kubernetes candidates of one component, then emits `resolved_bulk` `kubernetes_env_from` providers
for key names from a same-namespace local ConfigMap/Secret or one `unresolved_bulk` provider when
the expected object is absent. The traversal models retain value-blind
source metadata: key-reference name/key/optional, field and resource selectors, and envFrom
reference name/optional/prefix/location. Presence models retain object kind/name/namespace and only
the names and locations of keys from ConfigMap `data`/`binaryData` and Secret `data`/`stringData`.
Reference-resolution records prove same-namespace object and key presence without values. Duplicate
object identities fail closed; resolution never crosses component, namespace, or kind. Literal and
encoded values are discarded during parsing and cannot enter an observation, diagnostic, repr,
JSON, text, SARIF, or log. The analyzer performs no filesystem, environment, process, cluster, or
network access.

Additional analyzers can use the same `Analyzer` and `AnalyzerRegistry` seam without changing
`FactObservation`, normalization, `Contract`, or `ScanResult`. Plugin discovery and dynamic
analyzer loading remain outside v0.1.0's implemented slice.

## Built-in analyzer boundaries

### Python

`PythonAstAnalyzer` decodes source according to Python coding-cookie rules and uses the standard
library AST without importing the project. It recognizes literal keys passed to `os.getenv`,
`os.environ.get`, and `os.environ[...]`, including supported direct import aliases. Supported static
Pydantic Settings v1/v2 declarations are also mapped to runtime consumers; custom settings-source
hooks are diagnosed as dynamic.

Assignment aliases, variable-computed keys, cross-module value flow, reflection, and mapping
mutation methods such as `setdefault` or `update` are not resolved. A dynamic key produces a partial
diagnostic rather than a guessed consumer.

### JavaScript and TypeScript

`JavaScriptTypeScriptAnalyzer` uses the distributed Tree-sitter JavaScript, TypeScript, and TSX
grammars for `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, and `.tsx`. It recognizes direct
`process.env.NAME`, literal `process.env["NAME"]`, optional chaining, supported TypeScript wrappers,
direct destructuring, and static `import.meta.env` access. Vite built-ins are excluded; `VITE_*`
consumers are build-phase requirements. Lexically shadowed `process` bindings are ignored.

Aliases, constant propagation, computed keys/destructuring, rest destructuring, and unsupported
Deno, Bun, dotenv, bundler, or framework APIs are not inferred. Tree-sitter recovery retains only
unambiguous observations and marks damaged input partial.

### `.env.example`

`DotenvAnalyzer` accepts only the exact `.env.example` filename. It supports ASCII variable names,
optional `export`, whitespace around the first `=`, empty/unquoted/single-quoted/double-quoted/
backtick values, inline comments, LF/CRLF, UTF-8 BOM, escaped matching quotes, and quoted multiline
values. Duplicate declarations remain separate facts with their own locations.

Unquoted and double-quoted `$NAME`, `${NAME}`, and the `:-`, `-`, `:+`, and `+` braced forms are
recognized but never expanded; alternate/default text is not recursively analyzed. Single-quoted
and backtick values are literal, escaped dollars create no reference, and `$(...)` is opaque text.
Values, fragments, lengths, hashes, comments, snippets, and inferred types never leave the parser.
Syntax recovery retains only unambiguous declarations; invalid encoding and safety-limit failures
fail closed.

### Dockerfile

`DockerfileAnalyzer` recognizes case-insensitive `FROM`, `ARG`, and `ENV` in `Dockerfile` and
`Dockerfile.*`. Explicit `ARG` is build-phase delivery and explicit `ENV` is runtime delivery for an
implicit component environment. Multi-stage aliases are case-insensitive; local-stage state is
inherited privately without creating synthetic provider facts. Global `ARG` names enter a stage only
after an explicit stage-local declaration.

The lexer supports UTF-8 BOM, LF/CRLF, parser `# escape=` directives, logical continuations, quoted
and legacy `ENV`, and bounded heredoc skipping. Substitutions are recognized without expansion.
Values, base-image references, snippets, and substitution-only names are not retained. Docker,
BuildKit, shells, commands, referenced files, host variables, and network resources are never used.

### Docker Compose and merge semantics

The public `runtime_contract.compose` loader consumes immutable relative paths and bytes. It returns
frozen models for service names, profiles, interpolation names, locations, and redacted diagnostics.
Bounded standard anchors, aliases, and mapping merges are supported without expanding variables,
consulting the host environment, opening referenced files, or invoking Compose/Docker.

`ComposeAnalyzer` maps each static service to one `compose_service` environment. `environment` names
are explicit runtime providers and `build.args` names are explicit build providers. Map, list, empty,
null, and bare pass-through forms are inventoried value-blind. Each safe static service `env_file`
reference is one unresolved-bulk provider: the file is never opened or checked. Later `env_file`
entries have higher declared precedence, while `environment` structurally overrides them.

`resolve_compose_project(ComposeProjectInput)` merges caller-supplied files in order.
`environment` and `build.args` use key-level last-wins semantics; `env_file` appends; profiles append
with stable first-occurrence deduplication. Safe `!reset`, Compose 2.24.4+ `!override`, local
`include` (including override paths), and `extends` resolve only against the closed byte bundle.
Missing, cyclic, remote, absolute, escaping, Windows, and backslash references fail atomically.

Shell names have interpolation-source precedence over caller-ordered CLI env files; project `.env`
is considered only when no CLI env file is supplied. These are model-interpolation inputs only.
Values and fallbacks are never expanded or returned, and only enabled effective services emit facts.

### Kubernetes

`KubernetesAnalyzer` accepts caller-supplied YAML (including bounded multi-document streams) and JSON.
Supported workloads are `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, and `CronJob`, with
both `containers` and `initContainers`. One environment is created per stable
`namespace/Kind/name` target.

Static `env` names become explicit runtime providers. `secretKeyRef`, `configMapKeyRef`, `fieldRef`,
and `resourceFieldRef` retain only value-blind selectors. ConfigMap `data`/`binaryData` and Secret
`data`/`stringData` retain object identity and key names only. A same-component, same-namespace object
of the expected kind resolves `envFrom` to one provider per observed key; absent, wrong-kind,
cross-namespace, or cross-component references remain one unresolved-bulk provider. Duplicate object
identities fail closed.

CRDs, operators, `List`, and unsupported resources produce `RTC012`. Helm, Kustomize, cluster access,
manifest-directed reads, and values are outside the boundary. Extension-based discovery ignores
generic YAML/JSON without both Kubernetes markers; direct traversal remains fail-closed unless the
caller explicitly enables unmarked documents.

## Downstream contracts

Analyzer observations feed the deterministic [normalization API](normalization-api.md), then the
[domain model](domain-model.md), flow graph, precedence analysis, and [RTC rules](rules.md). Provider
precedence marks facts `active`, `overridden`, or `incomparable`: Compose `environment` overrides a
same-service `env_file`, Kubernetes `env` overrides same-workload `envFrom`, and later declarations
win only inside one ordered source. Independent environments and unordered files remain
incomparable; no global platform order is guessed.
