"""Pure explicit provider precedence without cross-environment guessing."""

from __future__ import annotations

from itertools import combinations

from runtime_contract.domain import Contract, Provider, ProviderMechanism
from runtime_contract.precedence.models import (
    PrecedenceAnalysis,
    PrecedenceReason,
    PrecedenceRelation,
    ProviderConflict,
    ProviderDisposition,
    ProviderPrecedence,
)


def analyze_precedence(contract: Contract, /) -> PrecedenceAnalysis:
    conflicts: list[ProviderConflict] = []
    conflict_ids: dict[str, list[str]] = {item.id: [] for item in contract.providers}
    lost: set[str] = set()
    incomparable: set[str] = set()
    for first, second in combinations(contract.providers, 2):
        if _potential_conflict(first, second):
            conflict = _compare(first, second)
            conflicts.append(conflict)
            conflict_ids[first.id].append(conflict.id)
            conflict_ids[second.id].append(conflict.id)
            if conflict.winner_provider_id is None:
                incomparable.update((first.id, second.id))
            else:
                loser = second if conflict.winner_provider_id == first.id else first
                if loser.config_key_id is not None:
                    lost.add(loser.id)
    rows = []
    for provider in contract.providers:
        disposition = (
            ProviderDisposition.OVERRIDDEN
            if provider.id in lost
            else ProviderDisposition.INCOMPARABLE
            if provider.id in incomparable
            else ProviderDisposition.ACTIVE
        )
        rows.append(
            ProviderPrecedence(
                provider_id=provider.id,
                disposition=disposition,
                conflict_ids=tuple(conflict_ids[provider.id]),
            )
        )
    return PrecedenceAnalysis(providers=tuple(rows), conflicts=tuple(conflicts))


def _potential_conflict(first: Provider, second: Provider) -> bool:
    if first.component != second.component or first.phase is not second.phase:
        return False
    if first.config_key_id == second.config_key_id and first.config_key_id is not None:
        return True
    return (
        first.environment_id == second.environment_id
        and first.environment_id is not None
        and (first.config_key_id is None) != (second.config_key_id is None)
    )


def _compare(first: Provider, second: Provider) -> ProviderConflict:
    left, right = sorted((first, second), key=lambda item: item.id)
    winner: Provider | None = None
    if left.environment_id != right.environment_id:
        reason = PrecedenceReason.INDEPENDENT_ENVIRONMENTS
    else:
        left_family = _family(left.mechanism)
        right_family = _family(right.mechanism)
        if left_family != right_family:
            reason = PrecedenceReason.CROSS_PLATFORM
        elif left_family == "compose" and {left.mechanism, right.mechanism} == {
            ProviderMechanism.COMPOSE_ENVIRONMENT,
            ProviderMechanism.COMPOSE_ENV_FILE,
        }:
            reason = PrecedenceReason.COMPOSE_EXPLICIT_OVER_ENV_FILE
            winner = left if left.mechanism is ProviderMechanism.COMPOSE_ENVIRONMENT else right
        elif left_family == "kubernetes" and {left.mechanism, right.mechanism} == {
            ProviderMechanism.KUBERNETES_ENV,
            ProviderMechanism.KUBERNETES_ENV_FROM,
        }:
            reason = PrecedenceReason.KUBERNETES_ENV_OVER_ENV_FROM
            winner = left if left.mechanism is ProviderMechanism.KUBERNETES_ENV else right
        elif left.location.path == right.location.path:
            reason = PrecedenceReason.LATER_SOURCE_DECLARATION
            winner = max((left, right), key=_location_order)
        else:
            reason = PrecedenceReason.UNORDERED_SOURCES
    return ProviderConflict(
        left_provider_id=left.id,
        right_provider_id=right.id,
        config_key_id=left.config_key_id or right.config_key_id or "",
        relation=(
            PrecedenceRelation.OVERRIDES if winner is not None else PrecedenceRelation.INCOMPARABLE
        ),
        reason=reason,
        winner_provider_id=winner.id if winner is not None else None,
    )


def _family(mechanism: ProviderMechanism) -> str:
    return mechanism.value.split("_", 1)[0]


def _location_order(provider: Provider) -> tuple[int, int, int, int, str]:
    location = provider.location
    return (
        location.start_line or 0,
        location.start_column or 0,
        location.end_line or 0,
        location.end_column or 0,
        provider.id,
    )


__all__ = ["analyze_precedence"]
