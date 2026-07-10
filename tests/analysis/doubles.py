"""Test-only analyzer doubles and shared semantic fixtures."""

from __future__ import annotations

from dataclasses import dataclass, field

from runtime_contract.analysis import (
    AnalysisCompleteness,
    AnalysisDiagnostic,
    AnalysisResult,
    AnalyzerInput,
    Confidence,
    DecisionSource,
    DiagnosticCode,
    EffectiveClassification,
    FactKind,
    FactObservation,
)
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    ConsumerAccessKind,
    Phase,
    RequirementSource,
    SecretSource,
    Severity,
    SourceLocation,
)


@dataclass(frozen=True, slots=True)
class StaticResolver:
    classification: EffectiveClassification = field(default_factory=EffectiveClassification)

    def classify(self, variable: str) -> EffectiveClassification:
        del variable
        return self.classification


class FixtureAnalyzer:
    analyzer_id = "test.fixture"
    supported_kinds = frozenset({CandidateKind.PYTHON})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        text = input.content.decode("utf-8")
        location = SourceLocation(path=input.path, start_line=1)
        if text == "dynamic":
            diagnostic = AnalysisDiagnostic(
                code=DiagnosticCode.DYNAMIC_NAME,
                severity=Severity.WARNING,
                primary_location=location,
            )
            return AnalysisResult(
                completeness=AnalysisCompleteness.PARTIAL,
                diagnostics=(diagnostic,),
            )
        literal = text.startswith("literal")
        optional = text == "optional" or literal
        inferred = text == "inferred"
        resolved = input.resolver.classify("API_KEY")
        required = (
            resolved.required
            if resolved.required_source is DecisionSource.CONFIG_OVERRIDE
            else not optional
        )
        requirement_source = (
            RequirementSource.CONFIG_OVERRIDE
            if resolved.required_source is DecisionSource.CONFIG_OVERRIDE
            else RequirementSource.LITERAL_FALLBACK
            if literal
            else RequirementSource.DETECTED_DEFAULT
        )
        key = ConfigKey(
            name="API_KEY",
            component=input.component,
            secret=False,
            secret_source=SecretSource.NOT_SECRET,
            allow_literal=resolved.allow_literal or False,
        )
        consumer = Consumer(
            config_key_id=key.id,
            component=input.component,
            phase=Phase.RUNTIME,
            required=bool(required),
            requirement_source=requirement_source,
            access_kind=ConsumerAccessKind.PYTHON_OS_GETENV,
            location=location,
            has_literal_fallback=literal,
        )
        confidence = Confidence.INFERRED if inferred else Confidence.EXACT
        return AnalysisResult(
            completeness=AnalysisCompleteness.COMPLETE,
            observations=(
                FactObservation(fact_kind=FactKind.CONFIG_KEY, confidence=confidence, fact=key),
                FactObservation(fact_kind=FactKind.CONSUMER, confidence=confidence, fact=consumer),
            ),
        )


class RaisingAnalyzer:
    analyzer_id = "test.raising"
    supported_kinds = frozenset({CandidateKind.PYTHON})

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        del input
        raise self.error


class InvalidResultAnalyzer:
    analyzer_id = "test.invalid-result"
    supported_kinds = frozenset({CandidateKind.PYTHON})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        del input
        return None  # type: ignore[return-value]


def assert_analyzer_contract(analyzer: FixtureAnalyzer, input: AnalyzerInput) -> None:
    """Reusable harness: the same input must produce byte-identical output."""

    first = analyzer.analyze(input).model_dump_json(exclude_none=False)
    second = analyzer.analyze(input).model_dump_json(exclude_none=False)
    assert first.encode() == second.encode()
