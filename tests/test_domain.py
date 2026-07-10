"""Domain model contract tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    ConsumerAccessKind,
    Contract,
    ContractSchemaId,
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Finding,
    FindingParameter,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
    ProviderRole,
    RequirementSource,
    RuleId,
    SafeIdentifier,
    SecretSource,
    Severity,
    SourceLocation,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "domain"


def models() -> tuple[ConfigKey, Environment, Consumer, Provider, Finding, Contract]:
    location = SourceLocation(
        path="src/settings.py", start_line=3, start_column=5, end_line=3, end_column=11
    )
    key = ConfigKey(
        name="API_KEY",
        component="api",
        secret=True,
        secret_source=SecretSource.HEURISTIC,
        allow_literal=False,
    )
    environment = Environment(
        component="api",
        target="web",
        kind=EnvironmentKind.COMPOSE_SERVICE,
        profile=Profile.PROD,
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
        location=SourceLocation(path="compose.yaml", start_line=8),
    )
    finding = Finding(
        rule_id=RuleId.RTC001,
        severity=Severity.ERROR,
        component="api",
        environment_id=environment.id,
        config_key_id=key.id,
        phase=Phase.RUNTIME,
        primary_location=location,
        evidence_locations=(location,),
        parameters=(("key", "API_KEY"),),
    )
    contract = Contract(
        config_keys=(key,),
        environments=(environment,),
        consumers=(consumer,),
        providers=(provider,),
    )
    return key, environment, consumer, provider, finding, contract


def test_public_imports_and_aliases() -> None:
    assert all((ConfigKey, Consumer, Contract, Environment, Finding, Provider, SourceLocation))
    assert ContractSchemaId and FindingParameter
    assert SafeIdentifier is not None


@pytest.mark.parametrize("index", range(6))
def test_exact_json_round_trip_for_every_model(index: int) -> None:
    model = models()[index]
    dumped = model.model_dump_json(exclude_none=False)
    assert type(model).model_validate_json(dumped) == model
    assert json.loads(dumped) == model.model_dump(mode="json", exclude_none=False)


@pytest.mark.parametrize("fixture", ["minimal-v1.json", "full-v1.json", "oldest-v1.json"])
def test_contract_fixture_exact_round_trip(fixture: str) -> None:
    fixture_text = (FIXTURES / fixture).read_text()
    raw = json.loads(fixture_text)
    contract = Contract.model_validate_json(fixture_text)
    assert contract.model_dump(mode="json", exclude_none=False) == raw


def test_models_and_nested_state_are_frozen() -> None:
    key, _, _, _, _, contract = models()
    with pytest.raises(ValidationError):
        key.name = "OTHER"
    assert isinstance(contract.config_keys, tuple)
    with pytest.raises(TypeError):
        contract.config_keys[0] = key  # type: ignore[index]


@pytest.mark.parametrize(
    ("model", "data"),
    [
        (SourceLocation, {"path": 1}),
        (
            ConfigKey,
            {
                "name": "KEY",
                "component": "app",
                "secret": 1,
                "secret_source": "not_secret",
                "allow_literal": False,
            },
        ),
        (
            Environment,
            {"component": "app", "target": "app", "kind": "implicit", "profile": "default"},
        ),
    ],
)
def test_strict_type_and_enum_rejection(model: type[Any], data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(data)


def test_unknown_field_rejection() -> None:
    with pytest.raises(ValidationError):
        SourceLocation(path="file.py", snippet="secret")  # type: ignore[call-arg]


def test_config_key_preserves_case_and_rejects_only_forbidden_names() -> None:
    upper = ConfigKey(
        name="API_KEY",
        component="app",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=False,
    )
    lower = ConfigKey(
        name="api_key",
        component="app",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=False,
    )
    assert upper.name == "API_KEY" and lower.name == "api_key" and upper.id != lower.id
    for name in ("", "A\0B", "A=B"):
        with pytest.raises(ValidationError):
            ConfigKey(
                name=name,
                component="app",
                secret=False,
                secret_source=SecretSource.NOT_SECRET,
                allow_literal=False,
            )


def test_source_location_posix_normalization_and_file_only() -> None:
    assert SourceLocation(path="src/./app.py").path == "src/app.py"
    assert SourceLocation(path="src/../app.py").path == "app.py"
    assert SourceLocation(path="app.py").model_dump(mode="json") == {
        "path": "app.py",
        "start_line": None,
        "start_column": None,
        "end_line": None,
        "end_column": None,
    }


@pytest.mark.parametrize("path", ["/etc/passwd", "..", "../a", "a\\b"])
def test_source_location_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        SourceLocation(path=path)


@pytest.mark.parametrize(
    "data",
    [
        {"path": "a", "start_line": 0},
        {"path": "a", "start_column": 1},
        {"path": "a", "end_column": 1},
        {"path": "a", "end_line": 2},
        {"path": "a", "start_line": 2, "end_line": 1},
        {"path": "a", "start_line": 2, "start_column": 4, "end_line": 2, "end_column": 3},
    ],
)
def test_source_location_rejects_incoherent_ranges(data: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SourceLocation.model_validate(data)


def test_identifier_vectors_and_identity_changes() -> None:
    vectors = json.loads((FIXTURES / "identity-vectors.json").read_text())
    key, environment, consumer, provider, finding, _ = models()
    assert {
        "config_key": key.id,
        "environment": environment.id,
        "consumer": consumer.id,
        "provider": provider.id,
        "finding": finding.id,
    } == vectors
    assert key.id == ConfigKey.model_validate(key.model_dump()).id
    changed = key.model_copy(update={"name": "OTHER", "id": ""})
    assert ConfigKey.model_validate(changed.model_dump()).id != key.id


def test_consumer_rejects_not_applicable_phase() -> None:
    _, _, consumer, _, _, _ = models()
    data = {**consumer.model_dump(), "id": "", "phase": Phase.NOT_APPLICABLE}
    with pytest.raises(ValidationError):
        Consumer.model_validate(data)


def test_finding_identity_exclusions_and_canonical_nested_tuples() -> None:
    *_, finding, _ = models()
    other = Finding.model_validate({**finding.model_dump(), "severity": Severity.WARNING})
    assert other.id == finding.id
    location = SourceLocation(path="a.py")
    reordered = Finding(
        rule_id=RuleId.RTC002,
        severity=Severity.ERROR,
        component="app",
        phase=Phase.RUNTIME,
        primary_location=location,
        evidence_locations=(SourceLocation(path="b.py"), location),
        parameters=(("z", "two"), ("a", "one")),
    )
    assert reordered.evidence_locations == (location, SourceLocation(path="b.py"))
    assert reordered.parameters == (("a", "one"), ("z", "two"))


def test_finding_rejects_duplicate_or_missing_evidence_and_parameters() -> None:
    location = SourceLocation(path="a.py")
    base = dict(
        rule_id=RuleId.RTC001,
        severity=Severity.ERROR,
        component="app",
        phase=Phase.RUNTIME,
        primary_location=location,
    )
    for extras in (
        {"evidence_locations": (location, location)},
        {"evidence_locations": (SourceLocation(path="b.py"),)},
        {"evidence_locations": (location,), "parameters": (("a", "one"), ("a", "two"))},
        {"evidence_locations": (location,), "parameters": (("unsafe key", "one"),)},
    ):
        with pytest.raises(ValidationError):
            Finding.model_validate({**base, **extras})


def test_contract_sorts_collections_and_rejects_duplicate_ids() -> None:
    first = ConfigKey(
        name="A",
        component="app",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=False,
    )
    second = ConfigKey(
        name="B",
        component="app",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=False,
    )
    contract = Contract(config_keys=(second, first))
    assert tuple(key.id for key in contract.config_keys) == tuple(sorted((first.id, second.id)))
    with pytest.raises(ValidationError):
        Contract(config_keys=(first, first))


def test_contract_sorts_every_entity_collection() -> None:
    key, environment, consumer, provider, _, _ = models()
    second_key = ConfigKey(
        name="SECOND",
        component="api",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=False,
    )
    second_environment = Environment(
        component="api",
        target="worker",
        kind=EnvironmentKind.COMPOSE_SERVICE,
        profile=Profile.PROD,
    )
    second_consumer = Consumer(
        config_key_id=second_key.id,
        component="api",
        phase=Phase.RUNTIME,
        required=False,
        requirement_source=RequirementSource.LITERAL_FALLBACK,
        access_kind=ConsumerAccessKind.NODE_PROCESS_ENV,
        location=SourceLocation(path="src/worker.ts"),
        has_literal_fallback=True,
    )
    second_provider = Provider(
        config_key_id=second_key.id,
        component="api",
        environment_id=second_environment.id,
        role=ProviderRole.DELIVERY,
        phase=Phase.RUNTIME,
        mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
        evidence_kind=EvidenceKind.EXPLICIT_KEY,
        location=SourceLocation(path="compose.yaml", start_line=20),
    )
    contract = Contract(
        config_keys=(second_key, key),
        environments=(second_environment, environment),
        consumers=(second_consumer, consumer),
        providers=(second_provider, provider),
    )
    for collection in (
        contract.config_keys,
        contract.environments,
        contract.consumers,
        contract.providers,
    ):
        assert tuple(item.id for item in collection) == tuple(
            sorted(item.id for item in collection)
        )


def test_contract_reference_and_component_validation() -> None:
    key, environment, consumer, provider, _, _ = models()
    bad_consumer = consumer.model_copy(update={"config_key_id": "key-missing", "id": ""})
    bad_provider = provider.model_copy(update={"environment_id": "env-missing", "id": ""})
    cross_key = key.model_copy(update={"component": "other", "id": ""})
    for contract in (
        Contract.model_construct(
            config_keys=(key,),
            environments=(),
            consumers=(Consumer.model_validate(bad_consumer.model_dump()),),
            providers=(),
        ),
        Contract.model_construct(
            config_keys=(key,),
            environments=(environment,),
            consumers=(),
            providers=(Provider.model_validate(bad_provider.model_dump()),),
        ),
        Contract.model_construct(
            config_keys=(ConfigKey.model_validate(cross_key.model_dump()),),
            environments=(environment,),
            consumers=(consumer,),
            providers=(),
        ),
    ):
        with pytest.raises(ValidationError):
            Contract.model_validate(contract.model_dump())


def test_contract_rejects_all_provider_and_component_reference_failures() -> None:
    key, environment, consumer, provider, _, _ = models()
    missing_key_provider = Provider.model_validate(
        {**provider.model_dump(), "id": "", "config_key_id": "key-missing"}
    )
    cross_consumer = consumer.model_copy(update={"component": "other"})
    cross_provider = provider.model_copy(update={"component": "other"})
    other_environment = Environment(
        component="other",
        target="web",
        kind=EnvironmentKind.COMPOSE_SERVICE,
        profile=Profile.PROD,
    )
    cross_environment_provider = Provider.model_validate(
        {**provider.model_dump(), "id": "", "environment_id": other_environment.id}
    )
    invalid_contracts = (
        dict(config_keys=(key,), environments=(environment,), providers=(missing_key_provider,)),
        dict(config_keys=(key,), environments=(environment,), consumers=(cross_consumer,)),
        dict(config_keys=(key,), environments=(environment,), providers=(cross_provider,)),
        dict(
            config_keys=(key,),
            environments=(other_environment,),
            providers=(cross_environment_provider,),
        ),
    )
    for data in invalid_contracts:
        with pytest.raises(ValidationError):
            Contract.model_validate(data)


def test_provider_role_and_evidence_invariants() -> None:
    key, environment, _, _, _, _ = models()
    location = SourceLocation(path="compose.yaml")
    unresolved = Provider(
        component="api",
        environment_id=environment.id,
        role=ProviderRole.DELIVERY,
        phase=Phase.RUNTIME,
        mechanism=ProviderMechanism.COMPOSE_ENV_FILE,
        evidence_kind=EvidenceKind.UNRESOLVED_BULK,
        location=location,
    )
    assert unresolved.config_key_id is None
    declaration = Provider(
        config_key_id=key.id,
        component="api",
        role=ProviderRole.DECLARATION,
        phase=Phase.NOT_APPLICABLE,
        mechanism=ProviderMechanism.ENV_EXAMPLE,
        evidence_kind=EvidenceKind.EXPLICIT_KEY,
        location=SourceLocation(path=".env.example"),
    )
    assert declaration.environment_id is None
    invalid = [
        dict(
            config_key_id=key.id,
            component="api",
            role=ProviderRole.DECLARATION,
            phase=Phase.NOT_APPLICABLE,
            mechanism=ProviderMechanism.DOCKERFILE_ENV,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=location,
        ),
        dict(
            component="api",
            environment_id=environment.id,
            role=ProviderRole.DELIVERY,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
            evidence_kind=EvidenceKind.UNRESOLVED_BULK,
            location=location,
        ),
        dict(
            config_key_id=key.id,
            component="api",
            role=ProviderRole.DECLARATION,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.ENV_EXAMPLE,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=location,
        ),
        dict(
            config_key_id=key.id,
            component="api",
            role=ProviderRole.DELIVERY,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=location,
        ),
        dict(
            component="api",
            environment_id=environment.id,
            role=ProviderRole.DELIVERY,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=location,
        ),
        dict(
            config_key_id=key.id,
            component="api",
            environment_id=environment.id,
            role=ProviderRole.DELIVERY,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.COMPOSE_ENV_FILE,
            evidence_kind=EvidenceKind.UNRESOLVED_BULK,
            location=location,
        ),
    ]
    for data in invalid:
        with pytest.raises(ValidationError):
            Provider.model_validate(data)


def test_contract_has_no_findings_and_serializes_nulls_and_empty_arrays() -> None:
    assert "findings" not in Contract.model_fields
    dumped = Contract().model_dump(mode="json", exclude_none=False)
    assert dumped == {
        "schema_id": "runtime-contract/contract/v1",
        "config_keys": [],
        "environments": [],
        "consumers": [],
        "providers": [],
    }
    with pytest.raises(ValidationError):
        Contract(findings=())  # type: ignore[call-arg]


def test_serialization_contains_no_value_or_snippet_fields() -> None:
    payload = json.dumps(models()[-1].model_dump(mode="json", exclude_none=False))
    assert not any(
        token in payload for token in ('"value"', '"snippet"', '"message"', '"findings"')
    )


def test_schema_is_current_and_validates_expected_shapes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/generate_domain_schema.py", "--check"], cwd=ROOT, check=False
    )
    assert result.returncode == 0
    schema = json.loads((ROOT / "schemas/runtime-contract-contract-v1.schema.json").read_text())
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "urn:runtime-contract:contract:v1"
    assert schema["additionalProperties"] is False


def test_explicit_inconsistent_identifiers_are_rejected() -> None:
    key, environment, consumer, provider, finding, _ = models()
    for model in (key, environment, consumer, provider, finding):
        data = model.model_dump()
        data["id"] = "wrong"
        with pytest.raises(ValidationError):
            type(model).model_validate(data)
