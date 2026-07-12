"""Static Kubernetes ``env`` and ``envFrom`` delivery analysis without value access."""

from __future__ import annotations

import re

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
    ProviderMechanism,
    ProviderRole,
    RuleId,
    SecretSource,
    Severity,
)
from runtime_contract.kubernetes import (
    KubernetesDiagnostic,
    KubernetesDiagnosticCode,
    KubernetesEnvBinding,
    KubernetesEnvFromSource,
    KubernetesInput,
    KubernetesLoadStatus,
    traverse_kubernetes_workloads,
)

_SECRET_NAME = re.compile(r"(?:^|_)(?:TOKEN|PASSWORD|SECRET|PRIVATE_KEY)$")


class KubernetesAnalyzer:
    """Inventory per-workload runtime delivery from static container declarations."""

    analyzer_id = "kubernetes"
    supported_kinds = frozenset({CandidateKind.KUBERNETES})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        if input.kind is not CandidateKind.KUBERNETES:
            raise ValueError("KubernetesAnalyzer requires CandidateKind.KUBERNETES")
        loaded = traverse_kubernetes_workloads(
            KubernetesInput(path=input.path, content=input.content),
            ignore_unmarked=True,
        )
        diagnostics = tuple(_diagnostic(item) for item in loaded.diagnostics)
        if loaded.status is KubernetesLoadStatus.FAILED:
            return AnalysisResult(
                completeness=AnalysisCompleteness.FAILED,
                diagnostics=diagnostics,
            )
        keys: dict[str, FactObservation] = {}
        environments: dict[str, FactObservation] = {}
        providers: list[FactObservation] = []
        for context in loaded.contexts:
            environment = Environment(
                component=input.component,
                target=(
                    f"{context.namespace}/{context.workload_kind.value}/{context.workload_name}"
                ),
                kind=EnvironmentKind.KUBERNETES_WORKLOAD,
                profile=input.profile,
            )
            environments.setdefault(
                environment.id,
                _observation(FactKind.ENVIRONMENT, environment),
            )
            for binding in context.env:
                key = _config_key(input, binding)
                keys.setdefault(key.id, _observation(FactKind.CONFIG_KEY, key))
                providers.append(
                    _observation(
                        FactKind.PROVIDER,
                        Provider(
                            config_key_id=key.id,
                            component=input.component,
                            environment_id=environment.id,
                            role=ProviderRole.DELIVERY,
                            phase=Phase.RUNTIME,
                            mechanism=ProviderMechanism.KUBERNETES_ENV,
                            evidence_kind=EvidenceKind.EXPLICIT_KEY,
                            location=binding.location,
                        ),
                    )
                )
            for source in context.env_from:
                providers.append(_bulk_provider(input, environment, source))
        return AnalysisResult(
            completeness=(
                AnalysisCompleteness.PARTIAL
                if loaded.status is KubernetesLoadStatus.PARTIAL
                else AnalysisCompleteness.COMPLETE
            ),
            observations=(*keys.values(), *environments.values(), *providers),
            diagnostics=diagnostics,
        )


def _observation(kind: FactKind, fact: ConfigKey | Environment | Provider) -> FactObservation:
    return FactObservation(fact_kind=kind, confidence=Confidence.EXACT, fact=fact)


def _config_key(input: AnalyzerInput, binding: KubernetesEnvBinding) -> ConfigKey:
    resolved = input.resolver.classify(binding.name)
    heuristic_secret = bool(_SECRET_NAME.search(binding.name))
    secret = resolved.secret if resolved.secret is not None else heuristic_secret
    return ConfigKey(
        name=binding.name,
        component=input.component,
        secret=secret,
        secret_source=(
            SecretSource.CONFIG_OVERRIDE
            if resolved.secret is not None
            else SecretSource.HEURISTIC
            if heuristic_secret
            else SecretSource.NOT_SECRET
        ),
        allow_literal=(
            resolved.allow_literal if resolved.allow_literal is not None else not secret
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
            evidence_kind=EvidenceKind.UNRESOLVED_BULK,
            location=source.location,
        ),
    )


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


__all__ = ["KubernetesAnalyzer"]
