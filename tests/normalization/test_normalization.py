"""D1.11 fact and source-location normalization contract tests."""

from __future__ import annotations

import itertools
import random
import unicodedata
from collections.abc import Iterator

import pytest

from runtime_contract.analysis import (
    AnalyzerInput,
    Confidence,
    FactKind,
    FactObservation,
    PythonAstAnalyzer,
)
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    ConsumerAccessKind,
    Contract,
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
    ProviderRole,
    RequirementSource,
    SecretSource,
    SourceLocation,
)
from runtime_contract.normalization import (
    NormalizationError,
    NormalizationErrorCode,
    normalize_observations,
)
from tests.analysis.doubles import StaticResolver


def key(name: str = "API_TOKEN", component: str = "api", *, secret: bool = True) -> ConfigKey:
    return ConfigKey(
        name=name,
        component=component,
        secret=secret,
        secret_source=SecretSource.HEURISTIC if secret else SecretSource.NOT_SECRET,
        allow_literal=not secret,
    )


def environment(component: str = "api") -> Environment:
    return Environment(
        component=component,
        target="web",
        kind=EnvironmentKind.COMPOSE_SERVICE,
        profile=Profile.PROD,
    )


def consumer(config_key: ConfigKey, path: str = "src/app.py", component: str = "api") -> Consumer:
    return Consumer(
        config_key_id=config_key.id,
        component=component,
        phase=Phase.RUNTIME,
        required=True,
        requirement_source=RequirementSource.DETECTED_DEFAULT,
        access_kind=ConsumerAccessKind.PYTHON_OS_GETENV,
        location=SourceLocation(path=path, start_line=2, start_column=3, end_line=2, end_column=9),
        has_literal_fallback=False,
    )


def provider(
    config_key: ConfigKey,
    target: Environment,
    path: str = "compose.yaml",
    component: str = "api",
) -> Provider:
    return Provider(
        config_key_id=config_key.id,
        component=component,
        environment_id=target.id,
        role=ProviderRole.DELIVERY,
        phase=Phase.RUNTIME,
        mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
        evidence_kind=EvidenceKind.EXPLICIT_KEY,
        location=SourceLocation(path=path, start_line=8),
    )


def observation(
    fact: ConfigKey | Environment | Consumer | Provider,
    confidence: Confidence = Confidence.EXACT,
) -> FactObservation:
    kinds = {
        ConfigKey: FactKind.CONFIG_KEY,
        Environment: FactKind.ENVIRONMENT,
        Consumer: FactKind.CONSUMER,
        Provider: FactKind.PROVIDER,
    }
    return FactObservation(fact_kind=kinds[type(fact)], confidence=confidence, fact=fact)


def graph() -> tuple[FactObservation, ...]:
    config_key = key()
    target = environment()
    return tuple(
        observation(item)
        for item in (config_key, target, consumer(config_key), provider(config_key, target))
    )


def constructed_consumer_location(path: str, **positions: int | None) -> FactObservation:
    config_key = key()
    valid = consumer(config_key)
    location = SourceLocation.model_construct(
        path=path,
        start_line=positions.get("start_line"),
        start_column=positions.get("start_column"),
        end_line=positions.get("end_line"),
        end_column=positions.get("end_column"),
    )
    fact = Consumer.model_construct(**{**valid.model_dump(), "location": location})
    return FactObservation.model_construct(
        fact_kind=FactKind.CONSUMER, confidence=Confidence.EXACT, fact=fact
    )


def test_empty_single_and_full_graph() -> None:
    assert normalize_observations(()).model_dump() == Contract().model_dump()
    config_key = key()
    assert normalize_observations((observation(config_key),)).config_keys == (config_key,)
    result = normalize_observations(graph())
    assert tuple(
        map(len, (result.config_keys, result.environments, result.consumers, result.providers))
    ) == (1, 1, 1, 1)


def test_generator_and_single_consumption() -> None:
    class Once:
        calls = 0

        def __iter__(self) -> Iterator[FactObservation]:
            self.calls += 1
            if self.calls > 1:
                raise AssertionError("iterable consumed more than once")
            yield from graph()

    values = Once()
    assert normalize_observations(item for item in values).consumers
    assert values.calls == 1


def test_permutations_duplicates_and_serialization_are_deterministic() -> None:
    values = graph()
    expected = normalize_observations(values).model_dump_json()
    permutations = list(itertools.permutations(values))
    random.Random(11).shuffle(permutations)
    for items in permutations:
        assert normalize_observations(items).model_dump_json() == expected
    assert normalize_observations(values + values).model_dump_json() == expected
    mixed = tuple(
        FactObservation(fact_kind=item.fact_kind, confidence=Confidence.INFERRED, fact=item.fact)
        for item in values
    )
    assert normalize_observations(values + mixed).model_dump_json() == expected


def test_conflict_is_order_independent_and_confidence_has_no_priority() -> None:
    exact = key(secret=True)
    conflicting = ConfigKey(
        name=exact.name,
        component=exact.component,
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=True,
    )
    observations = (
        observation(exact, Confidence.EXACT),
        observation(conflicting, Confidence.INFERRED),
    )
    for ordered in (observations, observations[::-1]):
        with pytest.raises(NormalizationError) as caught:
            normalize_observations(ordered)
        assert caught.value.code is NormalizationErrorCode.CONFLICTING_FACT
        assert caught.value.fact_id == exact.id
        assert "API_TOKEN" not in str(caught.value)


@pytest.mark.parametrize(
    "invalid",
    [
        lambda k, e: consumer(key("MISSING")),
        lambda k, e: Provider.model_validate(
            {**provider(k, e).model_dump(), "id": "", "config_key_id": key("MISSING").id}
        ),
        lambda k, e: Provider.model_validate(
            {**provider(k, e).model_dump(), "id": "", "environment_id": environment("other").id}
        ),
        lambda k, e: consumer(k, component="other"),
    ],
)
def test_invalid_references_map_to_typed_error(invalid) -> None:  # type: ignore[no-untyped-def]
    config_key = key()
    target = environment()
    facts = (observation(config_key), observation(target), observation(invalid(config_key, target)))
    with pytest.raises(NormalizationError) as caught:
        normalize_observations(facts)
    assert caught.value.code is NormalizationErrorCode.INVALID_FACT_REFERENCE


def test_case_sensitive_names_remain_distinct() -> None:
    names = ("API_TOKEN", "api_token", "Api_Token")
    result = normalize_observations(observation(key(name)) for name in names)
    assert {item.name for item in result.config_keys} == set(names)
    assert len({item.id for item in result.config_keys}) == 3


def test_unicode_posix_normalization_collision_and_id_recalculation() -> None:
    config_key = key()
    target = environment()
    nfc = "src/café.py"
    nfd = unicodedata.normalize("NFD", nfc)
    first = consumer(config_key, nfc)
    decomposed = Consumer.model_construct(
        **{
            **first.model_dump(),
            "id": "stale",
            "location": SourceLocation.model_construct(
                path=nfd,
                start_line=2,
                start_column=3,
                end_line=2,
                end_column=9,
            ),
        }
    )
    redundant = Consumer.model_construct(
        **{
            **first.model_dump(),
            "id": "stale",
            "location": SourceLocation.model_construct(
                path="src/./x/../café.py",
                start_line=2,
                start_column=3,
                end_line=2,
                end_column=9,
            ),
        }
    )
    decomposed_observation = FactObservation.model_construct(
        fact_kind=FactKind.CONSUMER, confidence=Confidence.EXACT, fact=decomposed
    )
    redundant_observation = FactObservation.model_construct(
        fact_kind=FactKind.CONSUMER, confidence=Confidence.EXACT, fact=redundant
    )
    normalized = normalize_observations(
        (observation(config_key), decomposed_observation, redundant_observation)
    )
    assert len(normalized.consumers) == 1
    assert normalized.consumers[0].location.path == nfc
    assert normalized.consumers[0].id == first.id

    canonical_provider = provider(config_key, target, "deploy/compose.yaml")
    original_provider = Provider.model_construct(
        **{
            **canonical_provider.model_dump(),
            "id": "stale",
            "location": SourceLocation.model_construct(
                path="deploy/x/../compose.yaml", start_line=8
            ),
        }
    )
    provider_observation = FactObservation.model_construct(
        fact_kind=FactKind.PROVIDER, confidence=Confidence.EXACT, fact=original_provider
    )
    result = normalize_observations(
        (observation(config_key), observation(target), provider_observation)
    )
    assert result.providers[0].location.path == "deploy/compose.yaml"
    assert result.providers[0].id == canonical_provider.id


def test_canonical_fact_ids_remain_unchanged() -> None:
    values = graph()
    result = normalize_observations(values)
    assert {
        item.id
        for item in result.config_keys + result.environments + result.consumers + result.providers
    } == {item.fact.id for item in values}


@pytest.mark.parametrize(
    ("path", "positions"),
    [
        ("../escape.py", {}),
        ("/absolute.py", {}),
        ("a\\b.py", {}),
        ("", {}),
        ("a.py", {"start_line": 0}),
        ("a.py", {"start_line": -1}),
        ("a.py", {"start_line": 2, "end_line": 1}),
        ("a.py", {"start_column": 1}),
    ],
)
def test_invalid_locations_fail_closed(path: str, positions: dict[str, int | None]) -> None:
    config_key = key()
    with pytest.raises(NormalizationError) as caught:
        normalize_observations(
            (observation(config_key), constructed_consumer_location(path, **positions))
        )
    assert caught.value.code is NormalizationErrorCode.INVALID_LOCATION


def test_location_shapes_preserve_inclusive_coordinates() -> None:
    config_key = key()
    locations = (
        SourceLocation(path="only.py"),
        SourceLocation(path="multi.py", start_line=2, start_column=3, end_line=4, end_column=7),
    )
    facts = []
    for index, location in enumerate(locations):
        base = consumer(config_key, f"unused-{index}.py")
        facts.append(Consumer.model_validate({**base.model_dump(), "id": "", "location": location}))
    result = normalize_observations(
        (observation(config_key), *(observation(item) for item in facts))
    )
    assert {item.location for item in result.consumers} == set(locations)


def test_unsupported_fact_and_mismatched_kind_fail_closed() -> None:
    config_key = key()
    mismatched = FactObservation.model_construct(
        fact_kind=FactKind.PROVIDER, confidence=Confidence.EXACT, fact=config_key
    )
    unsupported = FactObservation.model_construct(
        fact_kind=FactKind.CONFIG_KEY, confidence=Confidence.EXACT, fact=object()
    )
    for item in (mismatched, unsupported):
        with pytest.raises(NormalizationError) as caught:
            normalize_observations((item,))
        assert caught.value.code is NormalizationErrorCode.UNSUPPORTED_FACT


def test_invalid_supported_fact_content_fails_closed() -> None:
    invalid_key = ConfigKey.model_construct(
        id="key-redacted",
        name="",
        component="api",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=True,
        severity_override=None,
    )
    invalid = FactObservation.model_construct(
        fact_kind=FactKind.CONFIG_KEY, confidence=Confidence.EXACT, fact=invalid_key
    )
    with pytest.raises(NormalizationError) as caught:
        normalize_observations((invalid,))
    assert caught.value.code is NormalizationErrorCode.UNSUPPORTED_FACT
    assert caught.value.fact_id == "key-redacted"


def test_errors_are_redacted_and_contract_has_no_analysis_metadata() -> None:
    secret_value = "super-secret-value"
    invalid = constructed_consumer_location("../" + secret_value)
    with pytest.raises(NormalizationError) as caught:
        normalize_observations((invalid,))
    message = str(caught.value)
    assert secret_value not in message
    assert "snippet" not in message
    dumped = normalize_observations(graph()).model_dump()
    assert set(dumped) == {"schema_id", "config_keys", "environments", "consumers", "providers"}
    assert "findings" not in dumped and "diagnostics" not in dumped and "confidence" not in dumped


def test_integration_with_python_ast_analyzer_and_semantic_idempotence() -> None:
    analyzer = PythonAstAnalyzer()
    result = analyzer.analyze(
        AnalyzerInput(
            path="src/app.py",
            kind=CandidateKind.PYTHON,
            content=b'import os\nvalue = os.getenv("API_TOKEN")\n',
            component="api",
            root="default",
            profile=Profile.PROD,
            resolver=StaticResolver(),
        )
    )
    contract = normalize_observations(result.observations)
    assert len(contract.config_keys) == len(contract.consumers) == 1
    replay = tuple(
        observation(item)
        for item in contract.config_keys
        + contract.environments
        + contract.consumers
        + contract.providers
    )
    assert normalize_observations(replay).model_dump_json() == contract.model_dump_json()
