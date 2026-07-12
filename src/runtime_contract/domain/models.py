"""Stable, parser-independent domain models for contract facts and findings."""

from __future__ import annotations

import hashlib
import json
import posixpath
from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from runtime_contract.rules import RuleId


class Phase(StrEnum):
    BUILD = "build"
    RUNTIME = "runtime"
    NOT_APPLICABLE = "not_applicable"


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class Profile(StrEnum):
    DEFAULT = "default"
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class EnvironmentKind(StrEnum):
    IMPLICIT = "implicit"
    COMPOSE_SERVICE = "compose_service"
    KUBERNETES_WORKLOAD = "kubernetes_workload"


class ProviderRole(StrEnum):
    DECLARATION = "declaration"
    DELIVERY = "delivery"


class EvidenceKind(StrEnum):
    EXPLICIT_KEY = "explicit_key"
    RESOLVED_BULK = "resolved_bulk"
    UNRESOLVED_BULK = "unresolved_bulk"


class RequirementSource(StrEnum):
    DETECTED_DEFAULT = "detected_default"
    LITERAL_FALLBACK = "literal_fallback"
    CONFIG_OVERRIDE = "config_override"


class SecretSource(StrEnum):
    HEURISTIC = "heuristic"
    CONFIG_OVERRIDE = "config_override"
    NOT_SECRET = "not_secret"


class SensitivityReason(StrEnum):
    CONFIG_OVERRIDE = "config_override"
    TOKEN = "token"
    PASSWORD = "password"
    SECRET = "secret"
    PRIVATE_KEY = "private_key"
    API_KEY = "api_key"
    CREDENTIAL = "credential"
    SECRET_METADATA = "secret_metadata"
    NO_MATCH = "no_match"


class SensitivityConfidence(StrEnum):
    CERTAIN = "certain"
    HIGH = "high"
    NONE = "none"


class ConsumerAccessKind(StrEnum):
    PYTHON_OS_ENVIRON = "python_os_environ"
    PYTHON_OS_ENVIRON_GET = "python_os_environ_get"
    PYTHON_OS_GETENV = "python_os_getenv"
    PYDANTIC_SETTINGS = "pydantic_settings"
    NODE_PROCESS_ENV = "node_process_env"
    VITE_IMPORT_META_ENV = "vite_import_meta_env"


class ProviderMechanism(StrEnum):
    ENV_EXAMPLE = "env_example"
    DOCKERFILE_ARG = "dockerfile_arg"
    DOCKERFILE_ENV = "dockerfile_env"
    COMPOSE_BUILD_ARGS = "compose_build_args"
    COMPOSE_ENVIRONMENT = "compose_environment"
    COMPOSE_ENV_FILE = "compose_env_file"
    KUBERNETES_ENV = "kubernetes_env"
    KUBERNETES_ENV_FROM = "kubernetes_env_from"


SafeIdentifier = Annotated[str, Field(min_length=1, pattern=r"^[A-Za-z0-9_.:/@+-]+$")]
FindingParameter = tuple[SafeIdentifier, SafeIdentifier]


class DomainModel(BaseModel):
    """Common strict and immutable model policy."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


def _canonical_id(prefix: str, fields: tuple[tuple[str, Any], ...]) -> str:
    """Hash a fixed-order identity object using compact UTF-8 JSON."""

    payload = {key: value for key, value in fields}
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    return f"{prefix}{hashlib.sha256(encoded).hexdigest()}"


class SourceLocation(DomainModel):
    path: str
    start_line: int | None = None
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        if not value or "\\" in value or value.startswith("/"):
            raise ValueError("path must be a non-empty relative POSIX path")
        normalized = posixpath.normpath(value)
        if normalized in ("", ".", "..") or normalized.startswith("../"):
            raise ValueError("path must remain within the analysis root")
        return normalized

    @field_validator("start_line", "start_column", "end_line", "end_column")
    @classmethod
    def positions_are_one_based(cls, value: int | None) -> int | None:
        if value is not None and value < 1:
            raise ValueError("source positions are 1-based")
        return value

    @model_validator(mode="after")
    def validate_range(self) -> Self:
        if self.start_column is not None and self.start_line is None:
            raise ValueError("start_column requires start_line")
        if self.end_column is not None and self.end_line is None:
            raise ValueError("end_column requires end_line")
        if self.end_line is not None and self.start_line is None:
            raise ValueError("end_line requires start_line")
        if self.start_line is not None and self.end_line is not None:
            start = (self.start_line, self.start_column or 1)
            end = (self.end_line, self.end_column or 1)
            if end < start:
                raise ValueError("end position cannot precede start position")
        return self

    def identity(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=False)


class ConfigKey(DomainModel):
    id: str = ""
    name: str
    component: str
    secret: bool
    secret_source: SecretSource
    allow_literal: bool
    severity_override: Severity | None = None
    sensitivity_reason: SensitivityReason = SensitivityReason.NO_MATCH
    sensitivity_confidence: SensitivityConfidence = SensitivityConfidence.NONE

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not value or "\0" in value or "=" in value:
            raise ValueError("name must be non-empty and cannot contain NUL or '='")
        return value

    @model_validator(mode="after")
    def validate_id(self) -> Self:
        expected = self.calculate_id(self.component, self.name)
        if self.id and self.id != expected:
            raise ValueError("id does not match ConfigKey identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(component: str, name: str) -> str:
        return _canonical_id("key-", (("component", component), ("name", name)))


class Environment(DomainModel):
    id: str = ""
    component: str
    target: str
    kind: EnvironmentKind
    profile: Profile

    @model_validator(mode="after")
    def validate_id(self) -> Self:
        expected = self.calculate_id(self.component, self.kind, self.target, self.profile)
        if self.id and self.id != expected:
            raise ValueError("id does not match Environment identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(component: str, kind: EnvironmentKind, target: str, profile: Profile) -> str:
        return _canonical_id(
            "env-",
            (
                ("component", component),
                ("kind", kind.value),
                ("target", target),
                ("profile", profile.value),
            ),
        )


class Consumer(DomainModel):
    id: str = ""
    config_key_id: str
    component: str
    phase: Phase
    required: bool
    requirement_source: RequirementSource
    access_kind: ConsumerAccessKind
    location: SourceLocation
    has_literal_fallback: bool

    @model_validator(mode="after")
    def validate_id(self) -> Self:
        if self.phase is Phase.NOT_APPLICABLE:
            raise ValueError("Consumer phase must be build or runtime")
        expected = self.calculate_id(
            self.config_key_id, self.phase, self.access_kind, self.location
        )
        if self.id and self.id != expected:
            raise ValueError("id does not match Consumer identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(
        config_key_id: str,
        phase: Phase,
        access_kind: ConsumerAccessKind,
        location: SourceLocation,
    ) -> str:
        return _canonical_id(
            "consumer-",
            (
                ("config_key_id", config_key_id),
                ("phase", phase.value),
                ("access_kind", access_kind.value),
                ("location", location.identity()),
            ),
        )


class Provider(DomainModel):
    id: str = ""
    config_key_id: str | None = None
    component: str
    environment_id: str | None = None
    role: ProviderRole
    phase: Phase
    mechanism: ProviderMechanism
    evidence_kind: EvidenceKind
    location: SourceLocation

    @model_validator(mode="after")
    def validate_invariants_and_id(self) -> Self:
        if self.role is ProviderRole.DECLARATION:
            if self.environment_id is not None or self.phase is not Phase.NOT_APPLICABLE:
                raise ValueError("declarations have no environment and use not_applicable phase")
            if self.mechanism is not ProviderMechanism.ENV_EXAMPLE:
                raise ValueError("only .env.example is a declaration mechanism")
        elif self.environment_id is None or self.phase is Phase.NOT_APPLICABLE:
            raise ValueError("delivery requires an environment and build or runtime phase")
        if self.evidence_kind is EvidenceKind.UNRESOLVED_BULK:
            if self.config_key_id is not None:
                raise ValueError("unresolved bulk evidence cannot reference a key")
            if self.mechanism not in {
                ProviderMechanism.COMPOSE_ENV_FILE,
                ProviderMechanism.KUBERNETES_ENV_FROM,
            }:
                raise ValueError("unresolved bulk is limited to env_file and envFrom")
        elif self.config_key_id is None:
            raise ValueError("explicit and resolved evidence require a ConfigKey")
        expected = self.calculate_id(
            self.role,
            self.config_key_id,
            self.environment_id,
            self.phase,
            self.mechanism,
            self.evidence_kind,
            self.location,
        )
        if self.id and self.id != expected:
            raise ValueError("id does not match Provider identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(
        role: ProviderRole,
        config_key_id: str | None,
        environment_id: str | None,
        phase: Phase,
        mechanism: ProviderMechanism,
        evidence_kind: EvidenceKind,
        location: SourceLocation,
    ) -> str:
        return _canonical_id(
            "provider-",
            (
                ("role", role.value),
                ("config_key_id", config_key_id or ""),
                ("environment_id", environment_id or ""),
                ("phase", phase.value),
                ("mechanism", mechanism.value),
                ("evidence_kind", evidence_kind.value),
                ("location", location.identity()),
            ),
        )


class Finding(DomainModel):
    id: str = ""
    rule_id: RuleId
    severity: Severity
    component: str
    environment_id: str | None = None
    config_key_id: str | None = None
    phase: Phase
    primary_location: SourceLocation
    evidence_locations: tuple[SourceLocation, ...]
    parameters: tuple[FindingParameter, ...] = ()

    @model_validator(mode="after")
    def validate_invariants_and_id(self) -> Self:
        canonical_evidence = tuple(
            sorted(
                self.evidence_locations,
                key=lambda item: json.dumps(item.identity(), sort_keys=True),
            )
        )
        if len(set(canonical_evidence)) != len(canonical_evidence):
            raise ValueError("evidence locations must be unique")
        if self.primary_location not in canonical_evidence:
            raise ValueError("primary_location must occur in evidence_locations")
        if self.evidence_locations != canonical_evidence:
            object.__setattr__(self, "evidence_locations", canonical_evidence)
        canonical_parameters = tuple(sorted(self.parameters))
        if len({key for key, _ in canonical_parameters}) != len(canonical_parameters):
            raise ValueError("parameter keys must be unique")
        if self.parameters != canonical_parameters:
            object.__setattr__(self, "parameters", canonical_parameters)
        expected = self.calculate_id(
            self.rule_id,
            self.component,
            self.environment_id,
            self.config_key_id,
            self.phase,
            self.primary_location,
        )
        if self.id and self.id != expected:
            raise ValueError("id does not match Finding identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(
        rule_id: RuleId,
        component: str,
        target: str | None,
        config_key: str | None,
        phase: Phase,
        primary_location: SourceLocation,
    ) -> str:
        return _canonical_id(
            f"{rule_id.value}-",
            (
                ("rule_id", rule_id.value),
                ("component", component),
                ("target", target or ""),
                ("config_key", config_key or ""),
                ("phase", phase.value),
                ("primary_location", primary_location.identity()),
            ),
        )


class Contract(DomainModel):
    SCHEMA_ID: ClassVar[str] = "runtime-contract/contract/v1"

    schema_id: Literal["runtime-contract/contract/v1"] = "runtime-contract/contract/v1"
    config_keys: tuple[ConfigKey, ...] = ()
    environments: tuple[Environment, ...] = ()
    consumers: tuple[Consumer, ...] = ()
    providers: tuple[Provider, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> Self:
        collections = ("config_keys", "environments", "consumers", "providers")
        for name in collections:
            values = getattr(self, name)
            ordered = tuple(sorted(values, key=lambda value: value.id))
            if len({value.id for value in ordered}) != len(ordered):
                raise ValueError(f"duplicate IDs in {name}")
            if values != ordered:
                object.__setattr__(self, name, ordered)

        keys = {key.id: key for key in self.config_keys}
        environments = {environment.id: environment for environment in self.environments}
        for consumer in self.consumers:
            key = keys.get(consumer.config_key_id)
            if key is None:
                raise ValueError("Consumer references a missing ConfigKey")
            if key.component != consumer.component:
                raise ValueError("Consumer and ConfigKey components differ")
        for provider in self.providers:
            if provider.config_key_id is not None:
                key = keys.get(provider.config_key_id)
                if key is None:
                    raise ValueError("Provider references a missing ConfigKey")
                if key.component != provider.component:
                    raise ValueError("Provider and ConfigKey components differ")
            if provider.environment_id is not None:
                environment = environments.get(provider.environment_id)
                if environment is None:
                    raise ValueError("Provider references a missing Environment")
                if environment.component != provider.component:
                    raise ValueError("Provider and Environment components differ")
        return self


ContractSchemaId = Literal["runtime-contract/contract/v1"]
