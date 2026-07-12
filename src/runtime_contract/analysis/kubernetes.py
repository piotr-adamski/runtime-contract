"""Static Kubernetes ``env`` and ``envFrom`` delivery analysis without value access."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

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
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    ConfigKey,
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Provider,
    ProviderChannel,
    ProviderMechanism,
    ProviderRole,
    RuleId,
    Severity,
)
from runtime_contract.kubernetes import (
    KubernetesDiagnostic,
    KubernetesDiagnosticCode,
    KubernetesEnvFromSource,
    KubernetesEnvFromSourceKind,
    KubernetesEnvSourceKind,
    KubernetesInput,
    KubernetesLoadStatus,
    KubernetesObjectKind,
    traverse_kubernetes_workloads,
)
from runtime_contract.sensitivity import classify_sensitivity


@dataclass(frozen=True, slots=True)
class KubernetesProjectAnalysis:
    """One project-wide result plus exact per-source completeness."""

    result: AnalysisResult
    file_completeness: tuple[tuple[str, AnalysisCompleteness], ...]


class KubernetesAnalyzer:
    """Inventory per-workload runtime delivery from static container declarations."""

    analyzer_id = "kubernetes"
    supported_kinds = frozenset({CandidateKind.KUBERNETES})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        return self.analyze_project((input,)).result

    def analyze_project(self, inputs: Iterable[AnalyzerInput], /) -> KubernetesProjectAnalysis:
        """Analyze one component's caller-supplied manifest set as a linked local project."""

        sources = tuple(sorted(inputs, key=lambda item: item.path.encode("utf-8")))
        if not sources:
            raise ValueError("KubernetesAnalyzer requires at least one input")
        if any(item.kind is not CandidateKind.KUBERNETES for item in sources):
            raise ValueError("KubernetesAnalyzer requires CandidateKind.KUBERNETES")
        first = sources[0]
        if any(
            (item.component, item.root, item.profile)
            != (first.component, first.root, first.profile)
            for item in sources[1:]
        ):
            raise ValueError("Kubernetes project inputs must share component, root, and profile")
        loaded = traverse_kubernetes_workloads(
            tuple(KubernetesInput(path=item.path, content=item.content) for item in sources),
            ignore_unmarked=True,
        )
        diagnostics = tuple(_diagnostic(item) for item in loaded.diagnostics)
        file_completeness = tuple(
            (item.path, _analysis_completeness(item.status)) for item in loaded.sources
        )
        if loaded.status is KubernetesLoadStatus.FAILED:
            return KubernetesProjectAnalysis(
                result=AnalysisResult(
                    completeness=AnalysisCompleteness.FAILED,
                    diagnostics=diagnostics,
                ),
                file_completeness=file_completeness,
            )
        objects = {item.identity(): item for item in loaded.objects}
        keys: dict[str, FactObservation] = {}
        environments: dict[str, FactObservation] = {}
        providers: list[FactObservation] = []
        for context in loaded.contexts:
            environment = Environment(
                component=first.component,
                target=(
                    f"{context.namespace}/{context.workload_kind.value}/{context.workload_name}"
                ),
                kind=EnvironmentKind.KUBERNETES_WORKLOAD,
                profile=first.profile,
            )
            environments.setdefault(
                environment.id,
                _observation(FactKind.ENVIRONMENT, environment),
            )
            for binding in context.env:
                key = _config_key(
                    first,
                    binding.name,
                    secret_metadata=(binding.source_kind is KubernetesEnvSourceKind.SECRET_KEY_REF),
                )
                if key is None:
                    continue
                keys.setdefault(key.id, _observation(FactKind.CONFIG_KEY, key))
                providers.append(
                    _observation(
                        FactKind.PROVIDER,
                        Provider(
                            config_key_id=key.id,
                            component=first.component,
                            environment_id=environment.id,
                            role=ProviderRole.DELIVERY,
                            phase=Phase.RUNTIME,
                            mechanism=ProviderMechanism.KUBERNETES_ENV,
                            channel=_kubernetes_env_channel(binding.source_kind),
                            evidence_kind=EvidenceKind.EXPLICIT_KEY,
                            location=binding.location,
                        ),
                    )
                )
            for source in context.env_from:
                object_kind = (
                    KubernetesObjectKind.SECRET
                    if source.source_kind is KubernetesEnvFromSourceKind.SECRET_REF
                    else KubernetesObjectKind.CONFIG_MAP
                )
                resolved = objects.get(
                    (context.namespace, object_kind.value, source.reference_name)
                )
                if resolved is None:
                    providers.append(_bulk_provider(first, environment, source))
                    continue
                for object_key in resolved.keys:
                    key = _config_key(
                        first,
                        f"{source.prefix}{object_key.name}",
                        secret_metadata=object_kind is KubernetesObjectKind.SECRET,
                    )
                    if key is None:
                        continue
                    keys.setdefault(key.id, _observation(FactKind.CONFIG_KEY, key))
                    providers.append(
                        _observation(
                            FactKind.PROVIDER,
                            Provider(
                                config_key_id=key.id,
                                component=first.component,
                                environment_id=environment.id,
                                role=ProviderRole.DELIVERY,
                                phase=Phase.RUNTIME,
                                mechanism=ProviderMechanism.KUBERNETES_ENV_FROM,
                                channel=(
                                    ProviderChannel.SECRET_BULK
                                    if object_kind is KubernetesObjectKind.SECRET
                                    else ProviderChannel.CONFIG_MAP_BULK
                                ),
                                evidence_kind=EvidenceKind.RESOLVED_BULK,
                                location=source.location,
                            ),
                        )
                    )
        return KubernetesProjectAnalysis(
            result=AnalysisResult(
                completeness=_analysis_completeness(loaded.status),
                observations=(*keys.values(), *environments.values(), *providers),
                diagnostics=diagnostics,
            ),
            file_completeness=file_completeness,
        )


def _observation(kind: FactKind, fact: ConfigKey | Environment | Provider) -> FactObservation:
    return FactObservation(fact_kind=kind, confidence=Confidence.EXACT, fact=fact)


def _analysis_completeness(status: KubernetesLoadStatus) -> AnalysisCompleteness:
    return AnalysisCompleteness(status.value)


def _config_key(
    input: AnalyzerInput, name: str, *, secret_metadata: bool = False
) -> ConfigKey | None:
    resolved = input.resolver.classify(name)
    if resolved.ignored:
        return None
    sensitivity = classify_sensitivity(
        name, override=resolved.secret, secret_metadata=secret_metadata
    )
    return ConfigKey(
        name=name,
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


def _bulk_provider(
    input: AnalyzerInput,
    environment: Environment,
    source: KubernetesEnvFromSource,
) -> FactObservation:
    return _observation(
        FactKind.PROVIDER,
        Provider(
            component=input.component,
            environment_id=environment.id,
            role=ProviderRole.DELIVERY,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.KUBERNETES_ENV_FROM,
            channel=(
                ProviderChannel.SECRET_BULK
                if source.source_kind is KubernetesEnvFromSourceKind.SECRET_REF
                else ProviderChannel.CONFIG_MAP_BULK
            ),
            evidence_kind=EvidenceKind.UNRESOLVED_BULK,
            location=source.location,
        ),
    )


def _kubernetes_env_channel(source: KubernetesEnvSourceKind) -> ProviderChannel:
    return {
        KubernetesEnvSourceKind.VALUE: ProviderChannel.PLAIN_LITERAL,
        KubernetesEnvSourceKind.SECRET_KEY_REF: ProviderChannel.SECRET_REFERENCE,
        KubernetesEnvSourceKind.CONFIG_MAP_KEY_REF: ProviderChannel.CONFIG_MAP_REFERENCE,
        KubernetesEnvSourceKind.FIELD_REF: ProviderChannel.PLATFORM_REFERENCE,
        KubernetesEnvSourceKind.RESOURCE_FIELD_REF: ProviderChannel.PLATFORM_REFERENCE,
    }[source]


def _diagnostic(item: KubernetesDiagnostic) -> AnalysisDiagnostic:
    if item.code is KubernetesDiagnosticCode.INVALID_ENCODING:
        code = DiagnosticCode.INVALID_ENCODING
    elif item.code is KubernetesDiagnosticCode.SAFETY_LIMIT:
        code = DiagnosticCode.SAFETY_LIMIT
    elif item.code is KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE:
        code = DiagnosticCode.UNSUPPORTED_K8S_RESOURCE
    else:
        code = DiagnosticCode.SYNTAX_ERROR
    parameters = (("kubernetes_code", item.code.value),)
    return AnalysisDiagnostic(
        code=code,
        severity=(
            Severity.INFO if code is DiagnosticCode.UNSUPPORTED_K8S_RESOURCE else Severity.ERROR
        ),
        rule_id=RuleId.RTC012 if item.rule_id is not None else None,
        primary_location=item.location,
        parameters=parameters,
    )


__all__ = ["KubernetesAnalyzer", "KubernetesProjectAnalysis"]
