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

`PythonAstAnalyzer`, `JavaScriptTypeScriptAnalyzer`, `DotenvAnalyzer`, `DockerfileAnalyzer`, and
`ComposeAnalyzer` are the built-in
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
the ordinary one-file `analyze` contract is unchanged. Additional analyzers can use the same
`Analyzer` and `AnalyzerRegistry`
seam without changing `FactObservation`, normalization, `Contract`, or `ScanResult`. Plugin
discovery and Kubernetes analysis remain outside v0.1.0's implemented slice.
