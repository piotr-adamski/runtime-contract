"""D2.10 explicit provider precedence and conflict behavior."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from runtime_contract.domain import (
    ConfigKey,
    Contract,
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
    ProviderRole,
    SecretSource,
    SourceLocation,
)
from runtime_contract.precedence import (
    PrecedenceAnalysis,
    PrecedenceReason,
    PrecedenceRelation,
    ProviderConflict,
    ProviderDisposition,
    ProviderPrecedence,
    analyze_precedence,
)


def key() -> ConfigKey:
    return ConfigKey(
        name="SETTING",
        component="api",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=True,
    )


def environment(target: str, kind: EnvironmentKind) -> Environment:
    return Environment(component="api", target=target, kind=kind, profile=Profile.STAGING)


def provider(
    item: ConfigKey | None,
    target: Environment,
    mechanism: ProviderMechanism,
    *,
    line: int,
    path: str = "input.yaml",
    evidence: EvidenceKind = EvidenceKind.EXPLICIT_KEY,
) -> Provider:
    return Provider(
        config_key_id=item.id if item else None,
        component="api",
        environment_id=target.id,
        role=ProviderRole.DELIVERY,
        phase=Phase.RUNTIME,
        mechanism=mechanism,
        evidence_kind=evidence,
        location=SourceLocation(path=path, start_line=line),
    )


def test_compose_explicit_overrides_unresolved_env_file() -> None:
    item = key()
    target = environment("compose/api", EnvironmentKind.COMPOSE_SERVICE)
    bulk = provider(
        None,
        target,
        ProviderMechanism.COMPOSE_ENV_FILE,
        line=1,
        evidence=EvidenceKind.UNRESOLVED_BULK,
    )
    explicit = provider(item, target, ProviderMechanism.COMPOSE_ENVIRONMENT, line=2)

    result = analyze_precedence(
        Contract(config_keys=(item,), environments=(target,), providers=(bulk, explicit))
    )

    conflict = result.conflicts[0]
    assert conflict.relation is PrecedenceRelation.OVERRIDES
    assert conflict.reason is PrecedenceReason.COMPOSE_EXPLICIT_OVER_ENV_FILE
    assert conflict.winner_provider_id == explicit.id
    rows = {row.provider_id: row for row in result.providers}
    assert rows[explicit.id].disposition is ProviderDisposition.ACTIVE
    assert rows[bulk.id].disposition is ProviderDisposition.ACTIVE
    assert conflict.config_key_id == item.id


def test_kubernetes_env_overrides_env_from_and_shows_both_sources() -> None:
    item = key()
    target = environment("default/Deployment/api", EnvironmentKind.KUBERNETES_WORKLOAD)
    env_from = provider(item, target, ProviderMechanism.KUBERNETES_ENV_FROM, line=1)
    env = provider(item, target, ProviderMechanism.KUBERNETES_ENV, line=2)
    result = analyze_precedence(
        Contract(config_keys=(item,), environments=(target,), providers=(env_from, env))
    )
    assert result.conflicts[0].winner_provider_id == env.id
    assert result.conflicts[0].reason is PrecedenceReason.KUBERNETES_ENV_OVER_ENV_FROM


def test_later_dockerfile_declaration_wins_only_inside_same_source() -> None:
    item = key()
    target = environment("api", EnvironmentKind.IMPLICIT)
    early = provider(item, target, ProviderMechanism.DOCKERFILE_ENV, line=3, path="Dockerfile")
    late = provider(item, target, ProviderMechanism.DOCKERFILE_ENV, line=9, path="Dockerfile")
    result = analyze_precedence(
        Contract(config_keys=(item,), environments=(target,), providers=(late, early))
    )
    assert result.conflicts[0].winner_provider_id == late.id
    assert result.conflicts[0].reason is PrecedenceReason.LATER_SOURCE_DECLARATION


def test_independent_environments_are_incomparable() -> None:
    item = key()
    first_target = environment("compose/api", EnvironmentKind.COMPOSE_SERVICE)
    second_target = environment("default/Deployment/api", EnvironmentKind.KUBERNETES_WORKLOAD)
    first = provider(item, first_target, ProviderMechanism.COMPOSE_ENVIRONMENT, line=1)
    second = provider(item, second_target, ProviderMechanism.KUBERNETES_ENV, line=1)
    result = analyze_precedence(
        Contract(
            config_keys=(item,),
            environments=(first_target, second_target),
            providers=(first, second),
        )
    )
    assert result.conflicts[0].relation is PrecedenceRelation.INCOMPARABLE
    assert result.conflicts[0].reason is PrecedenceReason.INDEPENDENT_ENVIRONMENTS
    assert result.conflicts[0].winner_provider_id is None
    assert all(row.disposition is ProviderDisposition.INCOMPARABLE for row in result.providers)


def test_unrelated_keys_do_not_conflict_and_output_is_deterministic() -> None:
    first_key = key()
    second_key = first_key.model_copy(update={"id": "", "name": "OTHER"})
    second_key = ConfigKey.model_validate(second_key.model_dump())
    target = environment("compose/api", EnvironmentKind.COMPOSE_SERVICE)
    first = provider(first_key, target, ProviderMechanism.COMPOSE_ENVIRONMENT, line=1)
    second = provider(second_key, target, ProviderMechanism.COMPOSE_ENVIRONMENT, line=2)
    left = analyze_precedence(
        Contract(
            config_keys=(first_key, second_key),
            environments=(target,),
            providers=(first, second),
        )
    )
    right = analyze_precedence(
        Contract(
            config_keys=(second_key, first_key),
            environments=(target,),
            providers=(second, first),
        )
    )
    assert left == right
    assert left.conflicts == ()
    assert all(row.disposition is ProviderDisposition.ACTIVE for row in left.providers)

    declaration = Provider(
        config_key_id=first_key.id,
        component="api",
        role=ProviderRole.DECLARATION,
        phase=Phase.NOT_APPLICABLE,
        mechanism=ProviderMechanism.ENV_EXAMPLE,
        evidence_kind=EvidenceKind.EXPLICIT_KEY,
        location=SourceLocation(path=".env.example", start_line=1),
    )
    mixed_phase = analyze_precedence(
        Contract(
            config_keys=(first_key,),
            environments=(target,),
            providers=(first, declaration),
        )
    )
    assert mixed_phase.conflicts == ()


def test_later_dotenv_declaration_wins_in_one_file_but_files_are_unordered() -> None:
    item = key()

    def declaration(path: str, line: int) -> Provider:
        return Provider(
            config_key_id=item.id,
            component="api",
            role=ProviderRole.DECLARATION,
            phase=Phase.NOT_APPLICABLE,
            mechanism=ProviderMechanism.ENV_EXAMPLE,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=SourceLocation(path=path, start_line=line),
        )

    early = declaration(".env.example", 1)
    late = declaration(".env.example", 3)
    other = declaration("nested/.env.example", 5)
    result = analyze_precedence(Contract(config_keys=(item,), providers=(early, late, other)))
    by_pair = {
        frozenset((row.left_provider_id, row.right_provider_id)): row for row in result.conflicts
    }
    assert by_pair[frozenset((early.id, late.id))].winner_provider_id == late.id
    assert by_pair[frozenset((early.id, other.id))].reason is PrecedenceReason.UNORDERED_SOURCES


def test_cross_platform_in_one_environment_is_explicitly_incomparable() -> None:
    item = key()
    target = environment("synthetic", EnvironmentKind.IMPLICIT)
    docker = provider(item, target, ProviderMechanism.DOCKERFILE_ENV, line=1)
    compose = provider(item, target, ProviderMechanism.COMPOSE_ENVIRONMENT, line=2)
    result = analyze_precedence(
        Contract(config_keys=(item,), environments=(target,), providers=(docker, compose))
    )
    assert result.conflicts[0].reason is PrecedenceReason.CROSS_PLATFORM
    assert result.conflicts[0].winner_provider_id is None


def test_precedence_models_reject_invalid_identity_winner_and_references() -> None:
    with pytest.raises(ValidationError, match="provider IDs"):
        ProviderConflict(
            left_provider_id="",
            right_provider_id="z",
            config_key_id="key",
            relation=PrecedenceRelation.INCOMPARABLE,
            reason=PrecedenceReason.UNORDERED_SOURCES,
        )
    with pytest.raises(ValidationError, match="config_key_id"):
        ProviderConflict(
            left_provider_id="a",
            right_provider_id="z",
            config_key_id="",
            relation=PrecedenceRelation.INCOMPARABLE,
            reason=PrecedenceReason.UNORDERED_SOURCES,
        )
    with pytest.raises(ValidationError, match="canonical"):
        ProviderConflict(
            left_provider_id="z",
            right_provider_id="a",
            config_key_id="key",
            relation=PrecedenceRelation.INCOMPARABLE,
            reason=PrecedenceReason.UNORDERED_SOURCES,
        )
    with pytest.raises(ValidationError, match="only overrides"):
        ProviderConflict(
            left_provider_id="a",
            right_provider_id="z",
            config_key_id="key",
            relation=PrecedenceRelation.OVERRIDES,
            reason=PrecedenceReason.LATER_SOURCE_DECLARATION,
        )
    with pytest.raises(ValidationError, match="winner must belong"):
        ProviderConflict(
            left_provider_id="a",
            right_provider_id="z",
            config_key_id="key",
            relation=PrecedenceRelation.OVERRIDES,
            reason=PrecedenceReason.LATER_SOURCE_DECLARATION,
            winner_provider_id="other",
        )
    valid = ProviderConflict(
        left_provider_id="a",
        right_provider_id="z",
        config_key_id="key",
        relation=PrecedenceRelation.INCOMPARABLE,
        reason=PrecedenceReason.UNORDERED_SOURCES,
    )
    with pytest.raises(ValidationError, match="ProviderConflict identity"):
        ProviderConflict.model_validate(valid.model_dump() | {"id": "wrong"})
    with pytest.raises(ValidationError, match="provider_id"):
        ProviderPrecedence(provider_id="", disposition=ProviderDisposition.ACTIVE)
    with pytest.raises(ValidationError, match="unique"):
        ProviderPrecedence(
            provider_id="provider",
            disposition=ProviderDisposition.ACTIVE,
            conflict_ids=(valid.id, valid.id),
        )
    ordered = ProviderPrecedence(
        provider_id="provider",
        disposition=ProviderDisposition.ACTIVE,
        conflict_ids=("z", "a"),
    )
    assert ordered.conflict_ids == ("a", "z")
    row = ProviderPrecedence(
        provider_id="provider", disposition=ProviderDisposition.ACTIVE, conflict_ids=("missing",)
    )
    with pytest.raises(ValidationError, match="missing conflict"):
        PrecedenceAnalysis(providers=(row,))
    valid_row = ProviderPrecedence(
        provider_id="provider",
        disposition=ProviderDisposition.INCOMPARABLE,
        conflict_ids=(valid.id,),
    )
    with pytest.raises(ValidationError, match="rows must be unique"):
        PrecedenceAnalysis(providers=(valid_row, valid_row), conflicts=(valid,))
    with pytest.raises(ValidationError, match="conflicts must be unique"):
        PrecedenceAnalysis(providers=(valid_row,), conflicts=(valid, valid))
    second_row = ProviderPrecedence(provider_id="another", disposition=ProviderDisposition.ACTIVE)
    canonical = PrecedenceAnalysis(providers=(valid_row, second_row), conflicts=(valid,))
    assert tuple(item.provider_id for item in canonical.providers) == ("another", "provider")
