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

`PythonAstAnalyzer` and `JavaScriptTypeScriptAnalyzer` are the built-in implementations registered
by `scan`. Additional analyzers can use the same `Analyzer` and `AnalyzerRegistry` seam without
changing `FactObservation`, normalization, `Contract`, or `ScanResult`. Plugin discovery and
deployment-file analyzers remain outside v0.1.0's implemented day-one slice.
