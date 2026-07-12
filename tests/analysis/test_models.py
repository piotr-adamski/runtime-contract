"""AnalysisResult, observation, diagnostic, and input contract tests."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from pydantic import ValidationError

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
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
    ProviderRole,
    RequirementSource,
    RuleId,
    SecretSource,
    Severity,
    SourceLocation,
)
from tests.analysis.doubles import FixtureAnalyzer, StaticResolver, assert_analyzer_contract

FIXTURES = Path(__file__).parent / "fixtures"


def facts() -> tuple[ConfigKey, Environment, Consumer, Provider]:
    location = SourceLocation(path="src/app.py", start_line=2)
    key = ConfigKey(
        name="API_KEY",
        component="api",
        secret=True,
        secret_source=SecretSource.HEURISTIC,
        allow_literal=False,
    )
    environment = Environment(
        component="api", target="web", kind=EnvironmentKind.COMPOSE_SERVICE, profile=Profile.PROD
    )
    consumer = Consumer(
        config_key_id=key.id,
        component="api",
        phase=Phase.RUNTIME,
        required=True,
        requirement_source=RequirementSource.DETECTED_DEFAULT,
        access_kind=ConsumerAccessKind.PYTHON_OS_GETENV,
        location=location,
        has_literal_fallback=False,
    )
    provider = Provider(
        config_key_id=key.id,
        component="api",
        environment_id=environment.id,
        role=ProviderRole.DELIVERY,
        phase=Phase.RUNTIME,
        mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
        evidence_kind=EvidenceKind.EXPLICIT_KEY,
        location=SourceLocation(path="compose.yaml", start_line=3),
    )
    return key, environment, consumer, provider


@pytest.mark.parametrize("kind", list(FactKind))
@pytest.mark.parametrize("confidence", list(Confidence))
def test_each_fact_kind_and_confidence(kind: FactKind, confidence: Confidence) -> None:
    fact = facts()[list(FactKind).index(kind)]
    observation = FactObservation(fact_kind=kind, confidence=confidence, fact=fact)
    assert observation.fact is fact


@pytest.mark.parametrize("wrong_kind", list(FactKind)[1:])
def test_fact_kind_must_match_concrete_model(wrong_kind: FactKind) -> None:
    with pytest.raises(ValidationError, match="fact_kind"):
        FactObservation(fact_kind=wrong_kind, confidence=Confidence.EXACT, fact=facts()[0])


@pytest.mark.parametrize(
    ("code", "severity"),
    [
        (DiagnosticCode.INVALID_ENCODING, Severity.ERROR),
        (DiagnosticCode.SYNTAX_ERROR, Severity.ERROR),
        (DiagnosticCode.DYNAMIC_NAME, Severity.WARNING),
        (DiagnosticCode.UNSUPPORTED_CONSTRUCT, Severity.WARNING),
        (DiagnosticCode.PARTIAL_ANALYSIS, Severity.WARNING),
        (DiagnosticCode.ANALYZER_NOT_REGISTERED, Severity.ERROR),
    ],
)
def test_each_diagnostic_code_has_constant_severity_and_stable_id(
    code: DiagnosticCode, severity: Severity
) -> None:
    location = SourceLocation(path="app.py", start_line=1)
    first = AnalysisDiagnostic(code=code, severity=severity, primary_location=location)
    second = AnalysisDiagnostic(code=code, severity=severity, primary_location=location)
    assert first.id == second.id
    assert first.model_dump().keys() == {
        "id",
        "code",
        "severity",
        "rule_id",
        "primary_location",
        "related_locations",
        "parameters",
    }
    wrong = Severity.WARNING if severity is Severity.ERROR else Severity.ERROR
    with pytest.raises(ValidationError, match="require"):
        AnalysisDiagnostic(code=code, severity=wrong, primary_location=location)


def test_rtc012_is_required_only_for_unsupported_kubernetes_resources() -> None:
    location = SourceLocation(path="service.yaml", start_line=2)
    diagnostic = AnalysisDiagnostic(
        code=DiagnosticCode.UNSUPPORTED_K8S_RESOURCE,
        severity=Severity.INFO,
        rule_id=RuleId.RTC012,
        primary_location=location,
    )
    assert diagnostic.rule_id is RuleId.RTC012
    assert diagnostic.id == AnalysisDiagnostic.calculate_id(
        diagnostic.code,
        location,
        rule_id=RuleId.RTC012,
    )
    with pytest.raises(ValidationError, match="require RTC012"):
        AnalysisDiagnostic(
            code=DiagnosticCode.UNSUPPORTED_K8S_RESOURCE,
            severity=Severity.INFO,
            primary_location=location,
        )
    with pytest.raises(ValidationError, match="only unsupported"):
        AnalysisDiagnostic(
            code=DiagnosticCode.SYNTAX_ERROR,
            severity=Severity.ERROR,
            rule_id=RuleId.RTC012,
            primary_location=location,
        )


def test_diagnostic_canonicalizes_structural_fields() -> None:
    diagnostic = AnalysisDiagnostic(
        code=DiagnosticCode.SYNTAX_ERROR,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path="z.py"),
        related_locations=(SourceLocation(path="z.py"), SourceLocation(path="a.py")),
        parameters=(("z", "last"), ("a", "first")),
    )
    assert tuple(item.path for item in diagnostic.related_locations) == ("a.py", "z.py")
    assert diagnostic.parameters == (("a", "first"), ("z", "last"))


def test_diagnostic_rejects_duplicate_related_locations_parameters_and_wrong_id() -> None:
    location = SourceLocation(path="a.py")
    with pytest.raises(ValidationError, match="related_locations"):
        AnalysisDiagnostic(
            code=DiagnosticCode.SYNTAX_ERROR,
            severity=Severity.ERROR,
            primary_location=location,
            related_locations=(location, location),
        )
    with pytest.raises(ValidationError, match="parameter keys"):
        AnalysisDiagnostic(
            code=DiagnosticCode.SYNTAX_ERROR,
            severity=Severity.ERROR,
            primary_location=location,
            parameters=(("key", "one"), ("key", "two")),
        )
    with pytest.raises(ValidationError, match="id does not match"):
        AnalysisDiagnostic(
            id="diagnostic-wrong",
            code=DiagnosticCode.SYNTAX_ERROR,
            severity=Severity.ERROR,
            primary_location=location,
        )


def test_diagnostic_identity_changes_with_code_or_primary_location() -> None:
    base = AnalysisDiagnostic(
        code=DiagnosticCode.SYNTAX_ERROR,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path="a.py", start_line=1),
    )
    other_code = AnalysisDiagnostic(
        code=DiagnosticCode.INVALID_ENCODING,
        severity=Severity.ERROR,
        primary_location=base.primary_location,
    )
    other_location = AnalysisDiagnostic(
        code=DiagnosticCode.SYNTAX_ERROR,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path="a.py", start_line=2),
    )
    assert len({base.id, other_code.id, other_location.id}) == 3


@pytest.mark.parametrize(
    ("completeness", "code", "valid"),
    [
        (AnalysisCompleteness.COMPLETE, None, True),
        (AnalysisCompleteness.COMPLETE, DiagnosticCode.DYNAMIC_NAME, False),
        (AnalysisCompleteness.PARTIAL, DiagnosticCode.DYNAMIC_NAME, True),
        (AnalysisCompleteness.PARTIAL, DiagnosticCode.INVALID_ENCODING, False),
        (AnalysisCompleteness.FAILED, DiagnosticCode.INVALID_ENCODING, True),
    ],
)
def test_completeness_invariants(
    completeness: AnalysisCompleteness, code: DiagnosticCode | None, valid: bool
) -> None:
    diagnostics = (
        ()
        if code is None
        else (
            AnalysisDiagnostic(
                code=code,
                severity=(
                    Severity.ERROR
                    if code
                    in {
                        DiagnosticCode.INVALID_ENCODING,
                        DiagnosticCode.SYNTAX_ERROR,
                        DiagnosticCode.ANALYZER_NOT_REGISTERED,
                    }
                    else Severity.WARNING
                ),
                primary_location=SourceLocation(path="a.py"),
            ),
        )
    )
    if valid:
        AnalysisResult(completeness=completeness, diagnostics=diagnostics)
    else:
        with pytest.raises(ValidationError):
            AnalysisResult(completeness=completeness, diagnostics=diagnostics)


def test_partial_can_have_or_omit_observations() -> None:
    diagnostic = AnalysisDiagnostic(
        code=DiagnosticCode.PARTIAL_ANALYSIS,
        severity=Severity.WARNING,
        primary_location=SourceLocation(path="a.py"),
    )
    observation = FactObservation(
        fact_kind=FactKind.CONFIG_KEY, confidence=Confidence.EXACT, fact=facts()[0]
    )
    assert AnalysisResult(
        completeness=AnalysisCompleteness.PARTIAL,
        observations=(observation,),
        diagnostics=(diagnostic,),
    ).observations
    assert not AnalysisResult(
        completeness=AnalysisCompleteness.PARTIAL, diagnostics=(diagnostic,)
    ).observations


def test_failed_rejects_observations() -> None:
    observation = FactObservation(
        fact_kind=FactKind.CONFIG_KEY, confidence=Confidence.EXACT, fact=facts()[0]
    )
    with pytest.raises(ValidationError, match="failed"):
        AnalysisResult(completeness=AnalysisCompleteness.FAILED, observations=(observation,))


def test_result_canonical_sorting_and_duplicate_rejection() -> None:
    key, environment, *_ = facts()
    observations = (
        FactObservation(
            fact_kind=FactKind.ENVIRONMENT, confidence=Confidence.EXACT, fact=environment
        ),
        FactObservation(fact_kind=FactKind.CONFIG_KEY, confidence=Confidence.EXACT, fact=key),
    )
    d1 = AnalysisDiagnostic(
        code=DiagnosticCode.INVALID_ENCODING,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path="z.py"),
    )
    d2 = AnalysisDiagnostic(
        code=DiagnosticCode.ANALYZER_NOT_REGISTERED,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path="a.py"),
    )
    result = AnalysisResult(
        completeness=AnalysisCompleteness.COMPLETE,
        observations=observations,
        diagnostics=(d1, d2),
    )
    assert [item.fact_kind for item in result.observations] == [
        FactKind.CONFIG_KEY,
        FactKind.ENVIRONMENT,
    ]
    assert list(result.diagnostics) == sorted((d1, d2), key=lambda item: item.id)
    with pytest.raises(ValidationError, match="duplicate fact"):
        AnalysisResult(
            completeness=AnalysisCompleteness.COMPLETE,
            observations=(
                observations[0],
                observations[0].model_copy(update={"confidence": Confidence.INFERRED}),
            ),
        )
    with pytest.raises(ValidationError, match="duplicate diagnostic"):
        AnalysisResult(completeness=AnalysisCompleteness.COMPLETE, diagnostics=(d1, d1))


@pytest.mark.parametrize("field", ["secret", "required", "allow_literal"])
def test_effective_classification_requires_value_source_pairs(field: str) -> None:
    with pytest.raises(ValidationError):
        EffectiveClassification.model_validate({field: True})
    with pytest.raises(ValidationError):
        EffectiveClassification.model_validate({f"{field}_source": DecisionSource.DEFAULT})


def test_analyzer_input_is_frozen_safe_and_not_a_pydantic_model(
    analyzer_input: AnalyzerInput,
) -> None:
    assert not hasattr(analyzer_input, "model_dump")
    with pytest.raises(FrozenInstanceError):
        analyzer_input.path = "other.py"  # type: ignore[misc]
    for path in ("/etc/passwd", "../secret", "a\\b"):
        with pytest.raises(ValueError):
            AnalyzerInput(
                path, CandidateKind.PYTHON, b"", "app", "root", Profile.DEFAULT, StaticResolver()
            )
    with pytest.raises(TypeError):
        AnalyzerInput(
            "a.py",
            CandidateKind.PYTHON,
            bytearray(),  # type: ignore[arg-type]
            "app",
            "root",
            Profile.DEFAULT,
            StaticResolver(),
        )
    with pytest.raises(ValueError, match="component and root"):
        AnalyzerInput(
            "a.py", CandidateKind.PYTHON, b"", "", "root", Profile.DEFAULT, StaticResolver()
        )


@pytest.mark.parametrize(
    ("content", "required", "source", "fallback", "completeness"),
    [
        (
            b"required",
            True,
            RequirementSource.DETECTED_DEFAULT,
            False,
            AnalysisCompleteness.COMPLETE,
        ),
        (
            b"optional",
            False,
            RequirementSource.DETECTED_DEFAULT,
            False,
            AnalysisCompleteness.COMPLETE,
        ),
        (
            b"literal",
            False,
            RequirementSource.LITERAL_FALLBACK,
            True,
            AnalysisCompleteness.COMPLETE,
        ),
        (b"dynamic", None, None, None, AnalysisCompleteness.PARTIAL),
    ],
)
def test_shared_fixture_semantics(
    analyzer_input: AnalyzerInput,
    content: bytes,
    required: bool | None,
    source: RequirementSource | None,
    fallback: bool | None,
    completeness: AnalysisCompleteness,
) -> None:
    result = FixtureAnalyzer().analyze(
        analyzer_input.__class__(
            analyzer_input.path,
            analyzer_input.kind,
            content,
            analyzer_input.component,
            analyzer_input.root,
            analyzer_input.profile,
            analyzer_input.resolver,
        )
    )
    assert result.completeness is completeness
    consumers = [item.fact for item in result.observations if item.fact_kind is FactKind.CONSUMER]
    if consumers:
        consumer = consumers[0]
        assert isinstance(consumer, Consumer)
        assert (consumer.required, consumer.requirement_source, consumer.has_literal_fallback) == (
            required,
            source,
            fallback,
        )
    else:
        assert required is None


def test_fixture_never_emits_fallback_content_or_source_snippet(
    analyzer_input: AnalyzerInput,
) -> None:
    changed = analyzer_input.__class__(
        analyzer_input.path,
        analyzer_input.kind,
        b"literal=DO_NOT_EMIT",
        analyzer_input.component,
        analyzer_input.root,
        analyzer_input.profile,
        analyzer_input.resolver,
    )
    dumped = FixtureAnalyzer().analyze(changed).model_dump_json()
    assert "DO_NOT_EMIT" not in dumped and "snippet" not in dumped


def test_repeated_execution_is_byte_identical(analyzer_input: AnalyzerInput) -> None:
    assert_analyzer_contract(FixtureAnalyzer(), analyzer_input)


def test_fixture_has_a_controlled_inferred_observation(analyzer_input: AnalyzerInput) -> None:
    changed = analyzer_input.__class__(
        analyzer_input.path,
        analyzer_input.kind,
        b"inferred",
        analyzer_input.component,
        analyzer_input.root,
        analyzer_input.profile,
        analyzer_input.resolver,
    )
    result = FixtureAnalyzer().analyze(changed)
    assert result.observations
    assert {item.confidence for item in result.observations} == {Confidence.INFERRED}


def test_analyzer_protocol_is_not_runtime_checkable() -> None:
    from runtime_contract.analysis import Analyzer

    assert not getattr(Analyzer, "_is_runtime_protocol", False)
    with pytest.raises(TypeError):
        isinstance(FixtureAnalyzer(), Analyzer)  # type: ignore[misc]


def test_config_override_wins_and_maps_to_consumer_requirement_source(
    analyzer_input: AnalyzerInput,
) -> None:
    resolver = StaticResolver(
        EffectiveClassification(
            required=False,
            required_source=DecisionSource.CONFIG_OVERRIDE,
        )
    )
    changed = analyzer_input.__class__(
        analyzer_input.path,
        analyzer_input.kind,
        b"required",
        analyzer_input.component,
        analyzer_input.root,
        analyzer_input.profile,
        resolver,
    )
    result = FixtureAnalyzer().analyze(changed)
    consumers = [item.fact for item in result.observations if item.fact_kind is FactKind.CONSUMER]
    assert len(consumers) == 1 and isinstance(consumers[0], Consumer)
    assert consumers[0].required is False
    assert consumers[0].requirement_source is RequirementSource.CONFIG_OVERRIDE


@pytest.mark.parametrize("fixture", ["minimal.json", "full.json"])
def test_golden_fixture_exact_round_trip(fixture: str) -> None:
    raw = (FIXTURES / fixture).read_text()
    result = AnalysisResult.model_validate_json(raw)
    assert result.model_dump(mode="json", exclude_none=False) == json.loads(raw)


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        AnalysisResult.model_validate({"completeness": "complete", "message": "no"})
