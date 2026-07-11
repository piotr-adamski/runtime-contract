"""Public immutable models for static Docker Compose loading."""

from __future__ import annotations

import posixpath
import re
import unicodedata
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from runtime_contract.domain import SourceLocation


class _ComposeModel(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class ComposeLoadStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class ComposeInterpolationOperator(StrEnum):
    DIRECT = "direct"
    DEFAULT_IF_UNSET_OR_EMPTY = "default_if_unset_or_empty"
    DEFAULT_IF_UNSET = "default_if_unset"
    ERROR_IF_UNSET_OR_EMPTY = "error_if_unset_or_empty"
    ERROR_IF_UNSET = "error_if_unset"
    ALTERNATE_IF_SET_AND_NONEMPTY = "alternate_if_set_and_nonempty"
    ALTERNATE_IF_SET = "alternate_if_set"


class ComposeInterpolationResolution(StrEnum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    FALLBACK = "fallback"


class ComposeDiagnosticCode(StrEnum):
    INVALID_ENCODING = "invalid_encoding"
    INVALID_YAML = "invalid_yaml"
    MULTIPLE_DOCUMENTS = "multiple_documents"
    MISSING_SERVICES = "missing_services"
    INVALID_SERVICES = "invalid_services"
    INVALID_SERVICE = "invalid_service"
    INVALID_PROFILES = "invalid_profiles"
    DUPLICATE_KEY = "duplicate_key"
    DYNAMIC_NAME = "dynamic_name"
    UNSUPPORTED_CONSTRUCT = "unsupported_construct"
    UNSUPPORTED_INTERPOLATION = "unsupported_interpolation"
    UNSUPPORTED_EXTERNAL_REFERENCE = "unsupported_external_reference"
    INVALID_MERGE = "invalid_merge"
    CYCLIC_ALIAS = "cyclic_alias"
    SAFETY_LIMIT = "safety_limit"
    INVALID_PROJECT_INPUT = "invalid_project_input"
    DUPLICATE_PROJECT_PATH = "duplicate_project_path"
    MISSING_REFERENCE = "missing_reference"
    CYCLIC_REFERENCE = "cyclic_reference"
    REMOTE_REFERENCE = "remote_reference"
    INVALID_PROFILE = "invalid_profile"
    INVALID_OVERRIDE_TAG = "invalid_override_tag"
    MERGE_CONFLICT = "merge_conflict"
    PROVENANCE_LIMIT = "provenance_limit"
    PROJECT_SIZE_LIMIT = "project_size_limit"


class ComposeSourceKind(StrEnum):
    COMPOSE_FILE = "compose_file"
    INCLUDE_FILE = "include_file"
    EXTENDS_FILE = "extends_file"
    CLI_ENV_FILE = "cli_env_file"
    PROJECT_DOTENV = "project_dotenv"
    EXPLICIT_SHELL_NAME = "explicit_shell_name"


class ComposeVariableSourceKind(StrEnum):
    CLI_ENV_FILE = "cli_env_file"
    PROJECT_DOTENV = "project_dotenv"


class ComposeProvenanceOperation(StrEnum):
    INTRODUCED = "introduced"
    MERGED = "merged"
    REPLACED = "replaced"
    SUPERSEDED = "superseded"
    RESET = "reset"
    REMOVED = "removed"
    RETAINED = "retained"


class ComposeProvenanceOutcome(StrEnum):
    EFFECTIVE = "effective"
    SUPERSEDED = "superseded"
    REMOVED = "removed"


class ComposeServiceActivation(StrEnum):
    ALWAYS_ENABLED = "always_enabled"
    PROFILE_ENABLED = "profile_enabled"
    PROFILE_DISABLED = "profile_disabled"


class ComposeInput(_ComposeModel):
    path: str
    content: bytes = Field(repr=False)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        value = unicodedata.normalize("NFC", value)
        if (
            not value
            or "\0" in value
            or "\\" in value
            or value.startswith("/")
            or re.match(r"^[A-Za-z]:", value)
        ):
            raise ValueError("path must be a non-empty relative POSIX path")
        normalized = posixpath.normpath(value)
        if normalized in {"", ".", ".."} or normalized.startswith("../"):
            raise ValueError("path must remain within the logical root")
        return normalized


class ComposeInterpolation(_ComposeModel):
    name: str
    operator: ComposeInterpolationOperator
    location: SourceLocation
    service: str | None = None
    resolved_source_kind: ComposeSourceKind | None = None
    resolved_source_path: str | None = None
    resolution: ComposeInterpolationResolution | None = None

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not re.fullmatch(r"[_A-Za-z][_A-Za-z0-9]*", value):
            raise ValueError("invalid interpolation variable name")
        return value


class ComposeBindingKind(StrEnum):
    ENVIRONMENT = "environment"
    BUILD_ARG = "build_arg"


class ComposeBinding(_ComposeModel):
    name: str
    kind: ComposeBindingKind
    location: SourceLocation
    priority: int

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not re.fullmatch(r"[_A-Za-z][_A-Za-z0-9]*", value):
            raise ValueError("invalid Compose binding name")
        return value


class ComposeEnvFile(_ComposeModel):
    path: str
    required: bool = True
    format: str | None = None
    location: SourceLocation
    priority: int

    @field_validator("path")
    @classmethod
    def safe_static_path(cls, value: str) -> str:
        value = unicodedata.normalize("NFC", value)
        if (
            not value
            or "\0" in value
            or "\\" in value
            or value.startswith("/")
            or re.match(r"^[A-Za-z]:", value)
        ):
            raise ValueError("env_file path must be a safe relative POSIX path")
        normalized = posixpath.normpath(value)
        if normalized in {"", ".", ".."} or normalized.startswith("../"):
            raise ValueError("env_file path must remain within the logical root")
        return normalized


class ComposeService(_ComposeModel):
    name: str
    location: SourceLocation
    profiles: tuple[str, ...] = ()
    profile_locations: tuple[SourceLocation, ...] = ()
    interpolations: tuple[ComposeInterpolation, ...] = ()
    bindings: tuple[ComposeBinding, ...] = ()
    env_files: tuple[ComposeEnvFile, ...] = ()
    activation: ComposeServiceActivation = ComposeServiceActivation.ALWAYS_ENABLED

    @model_validator(mode="after")
    def aligned_profiles(self) -> Self:
        if len(self.profiles) != len(self.profile_locations):
            raise ValueError("profiles and profile_locations must be aligned")
        return self


class ComposeDiagnostic(_ComposeModel):
    code: ComposeDiagnosticCode
    location: SourceLocation
    message: str


class ComposeLoadResult(_ComposeModel):
    status: ComposeLoadStatus
    services: tuple[ComposeService, ...] = ()
    interpolations: tuple[ComposeInterpolation, ...] = ()
    diagnostics: tuple[ComposeDiagnostic, ...] = ()

    @model_validator(mode="after")
    def failed_is_empty(self) -> Self:
        if self.status is ComposeLoadStatus.FAILED and (self.services or self.interpolations):
            raise ValueError("failed Compose load cannot expose parsed data")
        return self


class ComposeVariableSourceInput(_ComposeModel):
    kind: ComposeVariableSourceKind
    path: str
    content: bytes = Field(repr=False)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return ComposeInput.normalize_path(value)


class ComposeProjectInput(_ComposeModel):
    files: tuple[ComposeInput, ...]
    active_profiles: tuple[str, ...] = ()
    interpolation_sources: tuple[ComposeVariableSourceInput, ...] = ()
    shell_variable_names: tuple[str, ...] = ()

    @field_validator("files")
    @classmethod
    def files_not_empty(cls, value: tuple[ComposeInput, ...]) -> tuple[ComposeInput, ...]:
        if not value:
            raise ValueError("files must not be empty")
        return value


class ComposeProvenanceStep(_ComposeModel):
    source_kind: ComposeSourceKind
    source_path: str
    source_index: int
    location: SourceLocation
    operation: ComposeProvenanceOperation
    outcome: ComposeProvenanceOutcome


class ComposeResolutionTrace(_ComposeModel):
    subject: str
    contributions: tuple[ComposeProvenanceStep, ...]
    winner_index: int | None


class ComposeUsedSource(_ComposeModel):
    kind: ComposeSourceKind
    path: str | None
    source_index: int


class ComposeProjectResult(_ComposeModel):
    status: ComposeLoadStatus
    services: tuple[ComposeService, ...] = ()
    interpolations: tuple[ComposeInterpolation, ...] = ()
    diagnostics: tuple[ComposeDiagnostic, ...] = ()
    resolution_traces: tuple[ComposeResolutionTrace, ...] = ()
    used_sources: tuple[ComposeUsedSource, ...] = ()

    @model_validator(mode="after")
    def failed_is_atomic(self) -> Self:
        if self.status is ComposeLoadStatus.FAILED and (
            self.services or self.interpolations or self.resolution_traces
        ):
            raise ValueError("failed Compose project resolution cannot expose partial data")
        return self


__all__ = [
    "ComposeBinding",
    "ComposeBindingKind",
    "ComposeDiagnostic",
    "ComposeDiagnosticCode",
    "ComposeEnvFile",
    "ComposeInput",
    "ComposeInterpolation",
    "ComposeInterpolationOperator",
    "ComposeInterpolationResolution",
    "ComposeLoadResult",
    "ComposeLoadStatus",
    "ComposeProjectInput",
    "ComposeProjectResult",
    "ComposeProvenanceOperation",
    "ComposeProvenanceOutcome",
    "ComposeProvenanceStep",
    "ComposeResolutionTrace",
    "ComposeService",
    "ComposeServiceActivation",
    "ComposeSourceKind",
    "ComposeUsedSource",
    "ComposeVariableSourceInput",
    "ComposeVariableSourceKind",
]
