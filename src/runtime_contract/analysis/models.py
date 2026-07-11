"""Stable, language-independent models returned by analyzers."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, model_validator

from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    Environment,
    Provider,
    Severity,
    SourceLocation,
)


class AnalysisModel(BaseModel):
    """Strict immutable policy shared by serialized analysis models."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class AnalysisCompleteness(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class DiagnosticCode(StrEnum):
    INVALID_ENCODING = "invalid_encoding"
    SYNTAX_ERROR = "syntax_error"
    DYNAMIC_NAME = "dynamic_name"
    UNSUPPORTED_CONSTRUCT = "unsupported_construct"
    PARTIAL_ANALYSIS = "partial_analysis"
    ANALYZER_NOT_REGISTERED = "analyzer_not_registered"
    ANALYZER_CONTRACT = "analyzer_contract"
    FILESYSTEM_MUTATION = "filesystem_mutation"
    NORMALIZATION_ERROR = "normalization_error"
    READ_ERROR = "read_error"


class Confidence(StrEnum):
    EXACT = "exact"
    INFERRED = "inferred"


class FactKind(StrEnum):
    CONFIG_KEY = "config_key"
    ENVIRONMENT = "environment"
    CONSUMER = "consumer"
    PROVIDER = "provider"


class DecisionSource(StrEnum):
    DEFAULT = "default"
    HEURISTIC = "heuristic"
    CONFIG_OVERRIDE = "config_override"
    SYNTAX = "syntax"


class EffectiveClassification(AnalysisModel):
    secret: bool | None = None
    secret_source: DecisionSource | None = None
    required: bool | None = None
    required_source: DecisionSource | None = None
    allow_literal: bool | None = None
    allow_literal_source: DecisionSource | None = None

    @model_validator(mode="after")
    def values_and_sources_are_paired(self) -> Self:
        for field in ("secret", "required", "allow_literal"):
            value = getattr(self, field)
            source = getattr(self, f"{field}_source")
            if (value is None) != (source is None):
                raise ValueError(f"{field} and {field}_source must both be set or both be null")
        return self


Fact = ConfigKey | Environment | Consumer | Provider


class FactObservation(AnalysisModel):
    fact_kind: FactKind
    confidence: Confidence
    fact: Fact

    @model_validator(mode="after")
    def kind_matches_fact(self) -> Self:
        expected = {
            ConfigKey: FactKind.CONFIG_KEY,
            Environment: FactKind.ENVIRONMENT,
            Consumer: FactKind.CONSUMER,
            Provider: FactKind.PROVIDER,
        }
        if expected[type(self.fact)] is not self.fact_kind:
            raise ValueError("fact_kind does not match the concrete fact model")
        return self


DiagnosticParameter = tuple[str, str]

DIAGNOSTIC_SEVERITY: dict[DiagnosticCode, Severity] = {
    DiagnosticCode.INVALID_ENCODING: Severity.ERROR,
    DiagnosticCode.SYNTAX_ERROR: Severity.ERROR,
    DiagnosticCode.DYNAMIC_NAME: Severity.WARNING,
    DiagnosticCode.UNSUPPORTED_CONSTRUCT: Severity.WARNING,
    DiagnosticCode.PARTIAL_ANALYSIS: Severity.WARNING,
    DiagnosticCode.ANALYZER_NOT_REGISTERED: Severity.ERROR,
    DiagnosticCode.ANALYZER_CONTRACT: Severity.ERROR,
    DiagnosticCode.FILESYSTEM_MUTATION: Severity.ERROR,
    DiagnosticCode.NORMALIZATION_ERROR: Severity.ERROR,
    DiagnosticCode.READ_ERROR: Severity.ERROR,
}


class AnalysisDiagnostic(AnalysisModel):
    id: str = ""
    code: DiagnosticCode
    severity: Severity
    primary_location: SourceLocation
    related_locations: tuple[SourceLocation, ...] = ()
    parameters: tuple[DiagnosticParameter, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_identify(self) -> Self:
        if self.severity is not DIAGNOSTIC_SEVERITY[self.code]:
            raise ValueError(
                f"{self.code.value} diagnostics require {DIAGNOSTIC_SEVERITY[self.code].value} severity"
            )
        related = tuple(sorted(self.related_locations, key=_location_key))
        if len(set(related)) != len(related):
            raise ValueError("related_locations must be unique")
        parameters = tuple(sorted(self.parameters))
        if len({key for key, _ in parameters}) != len(parameters):
            raise ValueError("diagnostic parameter keys must be unique")
        if related != self.related_locations:
            object.__setattr__(self, "related_locations", related)
        if parameters != self.parameters:
            object.__setattr__(self, "parameters", parameters)
        expected = self.calculate_id(self.code, self.primary_location, parameters)
        if self.id and self.id != expected:
            raise ValueError("id does not match diagnostic identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(
        code: DiagnosticCode,
        primary_location: SourceLocation,
        parameters: tuple[DiagnosticParameter, ...] = (),
    ) -> str:
        payload = {
            "code": code.value,
            "primary_location": primary_location.identity(),
            "parameters": parameters,
        }
        encoded = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
        return f"diagnostic-{hashlib.sha256(encoded).hexdigest()}"


_LOSS_CODES = frozenset(
    {
        DiagnosticCode.SYNTAX_ERROR,
        DiagnosticCode.DYNAMIC_NAME,
        DiagnosticCode.UNSUPPORTED_CONSTRUCT,
        DiagnosticCode.PARTIAL_ANALYSIS,
    }
)


class AnalysisResult(AnalysisModel):
    SCHEMA_ID: ClassVar[str] = "runtime-contract/analysis-result/v1"

    schema_id: Literal["runtime-contract/analysis-result/v1"] = (
        "runtime-contract/analysis-result/v1"
    )
    completeness: AnalysisCompleteness
    observations: tuple[FactObservation, ...] = ()
    diagnostics: tuple[AnalysisDiagnostic, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> Self:
        observations = tuple(
            sorted(self.observations, key=lambda item: (item.fact_kind.value, item.fact.id))
        )
        diagnostics = tuple(sorted(self.diagnostics, key=lambda item: item.id))
        if len({item.fact.id for item in observations}) != len(observations):
            raise ValueError("duplicate fact.id in observations")
        if len({item.id for item in diagnostics}) != len(diagnostics):
            raise ValueError("duplicate diagnostic.id")
        if self.completeness is AnalysisCompleteness.FAILED and observations:
            raise ValueError("failed analysis cannot contain observations")
        loss = any(item.code in _LOSS_CODES for item in diagnostics)
        if self.completeness is AnalysisCompleteness.COMPLETE and loss:
            raise ValueError("complete analysis cannot contain fact-loss diagnostics")
        if self.completeness is AnalysisCompleteness.PARTIAL and not loss:
            raise ValueError("partial analysis requires a fact-loss diagnostic")
        if observations != self.observations:
            object.__setattr__(self, "observations", observations)
        if diagnostics != self.diagnostics:
            object.__setattr__(self, "diagnostics", diagnostics)
        return self


AnalysisResultSchemaId = Literal["runtime-contract/analysis-result/v1"]


def _location_key(location: SourceLocation) -> str:
    return json.dumps(location.identity(), sort_keys=True, separators=(",", ":"))
