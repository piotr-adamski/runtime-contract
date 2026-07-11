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

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not re.fullmatch(r"[_A-Za-z][_A-Za-z0-9]*", value):
            raise ValueError("invalid interpolation variable name")
        return value


class ComposeService(_ComposeModel):
    name: str
    location: SourceLocation
    profiles: tuple[str, ...] = ()
    profile_locations: tuple[SourceLocation, ...] = ()
    interpolations: tuple[ComposeInterpolation, ...] = ()

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


__all__ = [
    "ComposeDiagnostic",
    "ComposeDiagnosticCode",
    "ComposeInput",
    "ComposeInterpolation",
    "ComposeInterpolationOperator",
    "ComposeLoadResult",
    "ComposeLoadStatus",
    "ComposeService",
]
