"""Pure deterministic evaluation of runtime-contract finding rules."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping

from runtime_contract.analysis import AnalysisDiagnostic, DiagnosticCode
from runtime_contract.domain import (
    Consumer,
    Contract,
    EvidenceKind,
    Finding,
    Phase,
    ProviderChannel,
    ProviderRole,
    SensitivityConfidence,
    Severity,
    SourceLocation,
)
from runtime_contract.precedence import (
    PrecedenceAnalysis,
    PrecedenceReason,
    PrecedenceRelation,
    ProviderDisposition,
)
from runtime_contract.rules import RuleId


def evaluate_required_not_provided(contract: Contract, /) -> tuple[Finding, ...]:
    """Evaluate RTC001 once per required key, phase, and selected target."""

    consumers: dict[tuple[str, str, str], list[Consumer]] = defaultdict(list)
    for consumer in contract.consumers:
        consumers[(consumer.component, consumer.config_key_id, consumer.phase.value)].append(
            consumer
        )

    environments = defaultdict(list)
    for environment in contract.environments:
        environments[environment.component].append(environment)

    findings: list[Finding] = []
    for (component, key_id, _), group in sorted(consumers.items()):
        required = sorted((item for item in group if item.required), key=lambda item: item.id)
        if not required:
            continue
        phase = required[0].phase
        consumer_locations = {item.location for item in group}
        nearby = {item.location for item in contract.providers if item.config_key_id == key_id}
        for environment in sorted(environments[component], key=lambda item: item.id):
            exact = any(
                item.role is ProviderRole.DELIVERY
                and item.config_key_id == key_id
                and item.environment_id == environment.id
                and item.phase is phase
                for item in contract.providers
            )
            if exact:
                continue
            unresolved_bulk = any(
                item.role is ProviderRole.DELIVERY
                and item.config_key_id is None
                and item.environment_id == environment.id
                and item.phase is phase
                and item.evidence_kind is EvidenceKind.UNRESOLVED_BULK
                for item in contract.providers
            )
            if unresolved_bulk:
                continue
            primary = required[0].location
            findings.append(
                Finding(
                    rule_id=RuleId.RTC001,
                    severity=Severity.ERROR,
                    component=component,
                    environment_id=environment.id,
                    config_key_id=key_id,
                    phase=phase,
                    primary_location=primary,
                    evidence_locations=tuple(consumer_locations | nearby),
                    parameters=(
                        ("consumer_count", str(len(group))),
                        ("target", environment.target),
                    ),
                )
            )
    return tuple(sorted(findings, key=lambda item: item.id))


def evaluate_unused_providers(
    contract: Contract,
    precedence: PrecedenceAnalysis,
    /,
    *,
    has_dynamic_uncertainty: bool = False,
) -> tuple[Finding, ...]:
    """Evaluate value-blind RTC005 findings without guessing through dynamic access."""

    if has_dynamic_uncertainty:
        return ()
    consumed = {item.config_key_id for item in contract.consumers}
    components_with_consumers = {item.component for item in contract.consumers}
    dispositions = {item.provider_id: item.disposition for item in precedence.providers}
    findings: list[Finding] = []
    for provider in contract.providers:
        if provider.config_key_id is None:
            continue
        disposition = dispositions[provider.id]
        if disposition is ProviderDisposition.OVERRIDDEN:
            context = "shadowed"
        elif provider.component not in components_with_consumers:
            context = "unassigned"
        elif provider.config_key_id not in consumed:
            context = "unused"
        else:
            continue
        findings.append(
            Finding(
                rule_id=RuleId.RTC005,
                severity=Severity.WARNING,
                component=provider.component,
                environment_id=provider.environment_id,
                config_key_id=provider.config_key_id,
                phase=provider.phase,
                primary_location=provider.location,
                evidence_locations=(provider.location,),
                parameters=(
                    ("context", context),
                    ("mechanism", provider.mechanism.value),
                    ("provider_role", provider.role.value),
                ),
            )
        )
    return tuple(sorted(findings, key=lambda item: item.id))


def evaluate_unsafe_secret_sources(contract: Contract, /) -> tuple[Finding, ...]:
    """Evaluate RTC002 from value-free, high-confidence provider channel metadata."""

    keys = {item.id: item for item in contract.config_keys}
    unsafe = {
        ProviderChannel.PLAIN_LITERAL,
        ProviderChannel.CONFIG_MAP_REFERENCE,
        ProviderChannel.CONFIG_MAP_BULK,
    }
    findings: list[Finding] = []
    for provider in contract.providers:
        if provider.config_key_id is None or provider.channel not in unsafe:
            continue
        key = keys[provider.config_key_id]
        if (
            not key.secret
            or key.allow_literal
            or key.sensitivity_confidence
            not in {SensitivityConfidence.CERTAIN, SensitivityConfidence.HIGH}
        ):
            continue
        findings.append(
            Finding(
                rule_id=RuleId.RTC002,
                severity=Severity.ERROR,
                component=provider.component,
                environment_id=provider.environment_id,
                config_key_id=provider.config_key_id,
                phase=provider.phase,
                primary_location=provider.location,
                evidence_locations=(provider.location,),
                parameters=(
                    ("channel", provider.channel.value),
                    ("classification", key.sensitivity_reason.value),
                    ("confidence", key.sensitivity_confidence.value),
                    ("recommended_source", ProviderChannel.SECRET_REFERENCE.value),
                ),
            )
        )
    return tuple(sorted(findings, key=lambda item: item.id))


def evaluate_ambiguities(
    contract: Contract,
    precedence: PrecedenceAnalysis,
    diagnostics: tuple[AnalysisDiagnostic, ...],
    component_by_path: Mapping[str, str],
    /,
) -> tuple[Finding, ...]:
    """Evaluate grouped RTC006/RTC007 findings without duplicating resolved overrides."""

    findings = [*_dynamic_findings(diagnostics, component_by_path)]
    providers = {item.id: item for item in contract.providers}
    conflicts: dict[tuple[str, str, Phase, str], set[SourceLocation]] = defaultdict(set)
    for conflict in precedence.conflicts:
        if (
            conflict.relation is not PrecedenceRelation.INCOMPARABLE
            or conflict.reason is PrecedenceReason.INDEPENDENT_ENVIRONMENTS
        ):
            continue
        left = providers[conflict.left_provider_id]
        right = providers[conflict.right_provider_id]
        environment_id = left.environment_id if left.environment_id == right.environment_id else ""
        conflicts[
            (left.component, conflict.config_key_id, left.phase, environment_id or "")
        ].update((left.location, right.location))
    for (component, key_id, phase, environment_id), locations in sorted(conflicts.items()):
        evidence = tuple(locations)
        primary = min(evidence, key=_location_sort_key)
        findings.append(
            Finding(
                rule_id=RuleId.RTC007,
                severity=Severity.WARNING,
                component=component,
                environment_id=environment_id or None,
                config_key_id=key_id,
                phase=phase,
                primary_location=primary,
                evidence_locations=evidence,
                parameters=(
                    ("issue", "competing_sources"),
                    ("provider_count", str(len(evidence))),
                ),
            )
        )
    findings.extend(_duplicate_findings(diagnostics, component_by_path))
    return tuple(sorted(findings, key=lambda item: item.id))


def _dynamic_findings(
    diagnostics: tuple[AnalysisDiagnostic, ...], component_by_path: Mapping[str, str]
) -> tuple[Finding, ...]:
    groups: dict[tuple[str, Phase], set[SourceLocation]] = defaultdict(set)
    for item in diagnostics:
        if item.code is not DiagnosticCode.DYNAMIC_NAME:
            continue
        parameters = dict(item.parameters)
        phase = (
            Phase.BUILD
            if parameters.get("access_kind") == "vite_import_meta_env"
            else Phase.RUNTIME
        )
        component = component_by_path.get(item.primary_location.path, "default")
        groups[(component, phase)].add(item.primary_location)
    findings = []
    for (component, phase), locations in sorted(groups.items()):
        evidence = tuple(locations)
        primary = min(evidence, key=_location_sort_key)
        findings.append(
            Finding(
                rule_id=RuleId.RTC006,
                severity=Severity.WARNING,
                component=component,
                phase=phase,
                primary_location=primary,
                evidence_locations=evidence,
                parameters=(
                    ("issue", "dynamic_reference"),
                    ("location_count", str(len(evidence))),
                ),
            )
        )
    return tuple(findings)


def _duplicate_findings(
    diagnostics: tuple[AnalysisDiagnostic, ...], component_by_path: Mapping[str, str]
) -> tuple[Finding, ...]:
    groups: dict[str, set[SourceLocation]] = defaultdict(set)
    for item in diagnostics:
        codes = dict(item.parameters).values()
        if not any("duplicate" in value or value == "merge_conflict" for value in codes):
            continue
        component = component_by_path.get(item.primary_location.path, "default")
        groups[component].add(item.primary_location)
    findings = []
    for component, locations in sorted(groups.items()):
        evidence = tuple(locations)
        primary = min(evidence, key=_location_sort_key)
        findings.append(
            Finding(
                rule_id=RuleId.RTC007,
                severity=Severity.INFO,
                component=component,
                phase=Phase.NOT_APPLICABLE,
                primary_location=primary,
                evidence_locations=evidence,
                parameters=(
                    ("issue", "duplicate_declaration"),
                    ("location_count", str(len(evidence))),
                ),
            )
        )
    return tuple(findings)


def _location_sort_key(location: SourceLocation) -> tuple[str, int, int, int, int]:
    return (
        location.path,
        location.start_line or 0,
        location.start_column or 0,
        location.end_line or 0,
        location.end_column or 0,
    )


__all__ = [
    "evaluate_ambiguities",
    "evaluate_required_not_provided",
    "evaluate_unsafe_secret_sources",
    "evaluate_unused_providers",
]
