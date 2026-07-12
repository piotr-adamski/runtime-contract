"""Pure deterministic evaluation of runtime-contract finding rules."""

from __future__ import annotations

from collections import defaultdict

from runtime_contract.domain import (
    Consumer,
    Contract,
    EvidenceKind,
    Finding,
    ProviderRole,
    Severity,
)
from runtime_contract.precedence import PrecedenceAnalysis, ProviderDisposition
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


__all__ = ["evaluate_required_not_provided", "evaluate_unused_providers"]
