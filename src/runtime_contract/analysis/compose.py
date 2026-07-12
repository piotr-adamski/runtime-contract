"""Static Docker Compose delivery analysis without value or env_file reads."""

from __future__ import annotations

from runtime_contract.analysis.models import (
    AnalysisCompleteness,
    AnalysisDiagnostic,
    AnalysisResult,
    Confidence,
    DiagnosticCode,
    FactKind,
    FactObservation,
)
from runtime_contract.analysis.protocols import AnalyzerInput
from runtime_contract.compose import (
    ComposeBindingKind,
    ComposeDiagnosticCode,
    ComposeInput,
    ComposeLoadStatus,
    ComposeProjectInput,
    ComposeServiceActivation,
    load_compose,
    resolve_compose_project,
)
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    ConfigKey,
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Provider,
    ProviderMechanism,
    ProviderRole,
    Severity,
)
from runtime_contract.sensitivity import classify_sensitivity


class ComposeAnalyzer:
    """Inventory Compose environment, env_file, and build.args delivery facts."""

    analyzer_id = "compose"
    supported_kinds = frozenset({CandidateKind.COMPOSE})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        if input.kind is not CandidateKind.COMPOSE:
            raise ValueError("ComposeAnalyzer requires CandidateKind.COMPOSE")
        loaded = load_compose(ComposeInput(path=input.path, content=input.content))
        diagnostics = tuple(_diagnostic(item.code, item.location) for item in loaded.diagnostics)
        if loaded.status is ComposeLoadStatus.FAILED:
            return AnalysisResult(
                completeness=AnalysisCompleteness.FAILED,
                diagnostics=diagnostics,
            )
        observations: list[FactObservation] = []
        keys: dict[str, FactObservation] = {}
        for service in loaded.services:
            environment = Environment(
                component=input.component,
                target=service.name,
                kind=EnvironmentKind.COMPOSE_SERVICE,
                profile=input.profile,
            )
            observations.append(_observation(FactKind.ENVIRONMENT, environment))
            _append_service_observations(input, service, environment, keys, observations)
        return AnalysisResult(
            completeness=(
                AnalysisCompleteness.PARTIAL if diagnostics else AnalysisCompleteness.COMPLETE
            ),
            observations=(*keys.values(), *observations),
            diagnostics=diagnostics,
        )

    def analyze_project(
        self, source: ComposeProjectInput, input: AnalyzerInput, /
    ) -> AnalysisResult:
        """Analyze an explicit project bundle using caller-owned analysis context."""

        if input.kind is not CandidateKind.COMPOSE:
            raise ValueError("ComposeAnalyzer requires CandidateKind.COMPOSE")
        resolved = resolve_compose_project(source)
        diagnostics = tuple(_diagnostic(item.code, item.location) for item in resolved.diagnostics)
        if resolved.status is ComposeLoadStatus.FAILED:
            return AnalysisResult(
                completeness=AnalysisCompleteness.FAILED,
                diagnostics=diagnostics,
            )
        observations: list[FactObservation] = []
        keys: dict[str, FactObservation] = {}
        for service in resolved.services:
            if service.activation is ComposeServiceActivation.PROFILE_DISABLED:
                continue
            environment = Environment(
                component=input.component,
                target=service.name,
                kind=EnvironmentKind.COMPOSE_SERVICE,
                profile=input.profile,
            )
            observations.append(_observation(FactKind.ENVIRONMENT, environment))
            _append_service_observations(input, service, environment, keys, observations)
        return AnalysisResult(
            completeness=(
                AnalysisCompleteness.PARTIAL if diagnostics else AnalysisCompleteness.COMPLETE
            ),
            observations=(*keys.values(), *observations),
            diagnostics=diagnostics,
        )


def _observation(kind: FactKind, fact: ConfigKey | Environment | Provider) -> FactObservation:
    return FactObservation(fact_kind=kind, confidence=Confidence.EXACT, fact=fact)


def _append_service_observations(
    input: AnalyzerInput,
    service: object,
    environment: Environment,
    keys: dict[str, FactObservation],
    observations: list[FactObservation],
) -> None:
    from runtime_contract.compose import ComposeService

    assert isinstance(service, ComposeService)
    for binding in service.bindings:
        resolved = input.resolver.classify(binding.name)
        sensitivity = classify_sensitivity(binding.name, override=resolved.secret)
        key = ConfigKey(
            name=binding.name,
            component=input.component,
            secret=sensitivity.sensitive,
            secret_source=sensitivity.source,
            sensitivity_reason=sensitivity.reason,
            sensitivity_confidence=sensitivity.confidence,
            allow_literal=(
                resolved.allow_literal
                if resolved.allow_literal is not None
                else not sensitivity.sensitive
            ),
        )
        keys.setdefault(key.id, _observation(FactKind.CONFIG_KEY, key))
        phase = Phase.RUNTIME if binding.kind is ComposeBindingKind.ENVIRONMENT else Phase.BUILD
        mechanism = (
            ProviderMechanism.COMPOSE_ENVIRONMENT
            if binding.kind is ComposeBindingKind.ENVIRONMENT
            else ProviderMechanism.COMPOSE_BUILD_ARGS
        )
        observations.append(
            _observation(
                FactKind.PROVIDER,
                Provider(
                    config_key_id=key.id,
                    component=input.component,
                    environment_id=environment.id,
                    role=ProviderRole.DELIVERY,
                    phase=phase,
                    mechanism=mechanism,
                    evidence_kind=EvidenceKind.EXPLICIT_KEY,
                    location=binding.location,
                ),
            )
        )
    for env_file in service.env_files:
        observations.append(
            _observation(
                FactKind.PROVIDER,
                Provider(
                    component=input.component,
                    environment_id=environment.id,
                    role=ProviderRole.DELIVERY,
                    phase=Phase.RUNTIME,
                    mechanism=ProviderMechanism.COMPOSE_ENV_FILE,
                    evidence_kind=EvidenceKind.UNRESOLVED_BULK,
                    location=env_file.location,
                ),
            )
        )


def _diagnostic(code: ComposeDiagnosticCode, location: object) -> AnalysisDiagnostic:
    from runtime_contract.domain import SourceLocation

    assert isinstance(location, SourceLocation)
    mapped = {
        ComposeDiagnosticCode.INVALID_ENCODING: DiagnosticCode.INVALID_ENCODING,
        ComposeDiagnosticCode.INVALID_YAML: DiagnosticCode.SYNTAX_ERROR,
        ComposeDiagnosticCode.MULTIPLE_DOCUMENTS: DiagnosticCode.SYNTAX_ERROR,
        ComposeDiagnosticCode.SAFETY_LIMIT: DiagnosticCode.SAFETY_LIMIT,
        ComposeDiagnosticCode.DYNAMIC_NAME: DiagnosticCode.DYNAMIC_NAME,
    }.get(code, DiagnosticCode.UNSUPPORTED_CONSTRUCT)
    return AnalysisDiagnostic(
        code=mapped,
        severity=Severity.ERROR
        if mapped
        in {
            DiagnosticCode.INVALID_ENCODING,
            DiagnosticCode.SYNTAX_ERROR,
            DiagnosticCode.SAFETY_LIMIT,
        }
        else Severity.WARNING,
        primary_location=location,
        parameters=(("compose_code", code.value),),
    )


__all__ = ["ComposeAnalyzer"]
