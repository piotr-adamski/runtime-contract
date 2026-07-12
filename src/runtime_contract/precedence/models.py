"""Strict value-blind provider precedence and conflict models."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class ProviderDisposition(StrEnum):
    ACTIVE = "active"
    OVERRIDDEN = "overridden"
    INCOMPARABLE = "incomparable"


class PrecedenceRelation(StrEnum):
    OVERRIDES = "overrides"
    INCOMPARABLE = "incomparable"


class PrecedenceReason(StrEnum):
    COMPOSE_EXPLICIT_OVER_ENV_FILE = "compose_explicit_over_env_file"
    KUBERNETES_ENV_OVER_ENV_FROM = "kubernetes_env_over_env_from"
    LATER_SOURCE_DECLARATION = "later_source_declaration"
    INDEPENDENT_ENVIRONMENTS = "independent_environments"
    UNORDERED_SOURCES = "unordered_sources"
    CROSS_PLATFORM = "cross_platform"


class ProviderConflict(_Model):
    id: str = ""
    left_provider_id: str
    right_provider_id: str
    config_key_id: str
    relation: PrecedenceRelation
    reason: PrecedenceReason
    winner_provider_id: str | None = None

    @model_validator(mode="after")
    def validate_identity(self) -> ProviderConflict:
        if not self.left_provider_id or not self.right_provider_id:
            raise ValueError("provider IDs must be non-empty")
        if not self.config_key_id:
            raise ValueError("config_key_id must be non-empty")
        if self.left_provider_id >= self.right_provider_id:
            raise ValueError("provider pair must be canonical and distinct")
        if (self.relation is PrecedenceRelation.OVERRIDES) != (self.winner_provider_id is not None):
            raise ValueError("only overrides relations have a winner")
        if self.winner_provider_id is not None and self.winner_provider_id not in {
            self.left_provider_id,
            self.right_provider_id,
        }:
            raise ValueError("winner must belong to the provider pair")
        expected = self.calculate_id(
            self.left_provider_id,
            self.right_provider_id,
            self.config_key_id,
            self.relation,
            self.reason,
            self.winner_provider_id,
        )
        if self.id and self.id != expected:
            raise ValueError("id does not match ProviderConflict identity")
        if not self.id:
            object.__setattr__(self, "id", expected)
        return self

    @staticmethod
    def calculate_id(
        left_provider_id: str,
        right_provider_id: str,
        config_key_id: str,
        relation: PrecedenceRelation,
        reason: PrecedenceReason,
        winner_provider_id: str | None,
    ) -> str:
        payload = {
            "left_provider_id": left_provider_id,
            "right_provider_id": right_provider_id,
            "config_key_id": config_key_id,
            "relation": relation.value,
            "reason": reason.value,
            "winner_provider_id": winner_provider_id or "",
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        return "provider-conflict-" + hashlib.sha256(encoded).hexdigest()


class ProviderPrecedence(_Model):
    provider_id: str
    disposition: ProviderDisposition
    conflict_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonicalize(self) -> ProviderPrecedence:
        if not self.provider_id:
            raise ValueError("provider_id must be non-empty")
        conflicts = tuple(sorted(self.conflict_ids))
        if len(set(conflicts)) != len(conflicts):
            raise ValueError("conflict_ids must be unique")
        if conflicts != self.conflict_ids:
            object.__setattr__(self, "conflict_ids", conflicts)
        return self


class PrecedenceAnalysis(_Model):
    providers: tuple[ProviderPrecedence, ...] = ()
    conflicts: tuple[ProviderConflict, ...] = ()

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> PrecedenceAnalysis:
        providers = tuple(sorted(self.providers, key=lambda item: item.provider_id))
        conflicts = tuple(sorted(self.conflicts, key=lambda item: item.id))
        if len({item.provider_id for item in providers}) != len(providers):
            raise ValueError("provider precedence rows must be unique")
        if len({item.id for item in conflicts}) != len(conflicts):
            raise ValueError("provider conflicts must be unique")
        conflict_ids = {item.id for item in conflicts}
        if any(not set(item.conflict_ids) <= conflict_ids for item in providers):
            raise ValueError("provider row references a missing conflict")
        if providers != self.providers:
            object.__setattr__(self, "providers", providers)
        if conflicts != self.conflicts:
            object.__setattr__(self, "conflicts", conflicts)
        return self


__all__ = [
    "PrecedenceAnalysis",
    "PrecedenceReason",
    "PrecedenceRelation",
    "ProviderConflict",
    "ProviderDisposition",
    "ProviderPrecedence",
]
