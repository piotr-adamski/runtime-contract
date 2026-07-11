"""Pure deterministic normalization from analyzer observations to contract facts."""

from __future__ import annotations

import json
import posixpath
import unicodedata
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from runtime_contract.analysis import FactKind, FactObservation
from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    Contract,
    Environment,
    Provider,
    SourceLocation,
)
from runtime_contract.normalization.errors import NormalizationError, NormalizationErrorCode

_FACT_TYPES: dict[FactKind, type[ConfigKey | Environment | Consumer | Provider]] = {
    FactKind.CONFIG_KEY: ConfigKey,
    FactKind.ENVIRONMENT: Environment,
    FactKind.CONSUMER: Consumer,
    FactKind.PROVIDER: Provider,
}


def normalize_observations(observations: Iterable[FactObservation]) -> Contract:
    """Return a canonical facts-only contract after consuming *observations* once."""

    materialized = tuple(observations)
    facts: dict[str, tuple[str, ConfigKey | Environment | Consumer | Provider, FactKind]] = {}

    for observation in materialized:
        fact, fact_kind = _normalize_observation(observation)
        serialized = json.dumps(
            fact.model_dump(mode="json", exclude_none=False),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        existing = facts.get(fact.id)
        if existing is not None and existing[0] != serialized:
            raise NormalizationError(
                NormalizationErrorCode.CONFLICTING_FACT,
                "facts with the same canonical ID have conflicting content",
                fact_id=fact.id,
                fact_kind=fact_kind,
            )
        facts[fact.id] = (serialized, fact, fact_kind)

    by_kind: dict[FactKind, list[Any]] = {kind: [] for kind in FactKind}
    for _, fact, fact_kind in facts.values():
        by_kind[fact_kind].append(fact)
    try:
        return Contract(
            config_keys=tuple(by_kind[FactKind.CONFIG_KEY]),
            environments=tuple(by_kind[FactKind.ENVIRONMENT]),
            consumers=tuple(by_kind[FactKind.CONSUMER]),
            providers=tuple(by_kind[FactKind.PROVIDER]),
        )
    except ValidationError:
        raise NormalizationError(
            NormalizationErrorCode.INVALID_FACT_REFERENCE,
            "normalized facts contain an invalid or missing reference",
        ) from None


def _normalize_observation(
    observation: FactObservation,
) -> tuple[ConfigKey | Environment | Consumer | Provider, FactKind]:
    fact = getattr(observation, "fact", None)
    fact_kind = getattr(observation, "fact_kind", None)
    safe_kind = fact_kind if type(fact_kind) is FactKind else None
    safe_id = getattr(fact, "id", None)
    safe_id = safe_id if type(safe_id) is str and safe_id else None
    expected = _FACT_TYPES.get(safe_kind) if safe_kind is not None else None
    if expected is None or type(fact) is not expected:
        raise NormalizationError(
            NormalizationErrorCode.UNSUPPORTED_FACT,
            "observation has an unsupported fact model or mismatched fact kind",
            fact_id=safe_id,
            fact_kind=safe_kind,
        )
    assert safe_kind is not None

    data = fact.model_dump(mode="python", exclude_none=False)
    data.pop("id", None)
    if isinstance(fact, (Consumer, Provider)):
        data["location"] = _normalize_location(fact.location, safe_id, safe_kind)
    try:
        normalized = expected.model_validate(data)
        return normalized, safe_kind
    except ValidationError:
        raise NormalizationError(
            NormalizationErrorCode.UNSUPPORTED_FACT,
            "fact content is invalid for its declared model",
            fact_id=safe_id,
            fact_kind=safe_kind,
        ) from None


def _normalize_location(
    location: SourceLocation, fact_id: str | None, fact_kind: FactKind
) -> SourceLocation:
    try:
        raw = location.model_dump(mode="python", exclude_none=False)
        path = raw.get("path")
        if type(path) is not str or not path or "\\" in path or path.startswith("/"):
            raise ValueError
        canonical = unicodedata.normalize("NFC", posixpath.normpath(path))
        if canonical in {"", ".", ".."} or canonical.startswith("../"):
            raise ValueError
        raw["path"] = canonical
        return SourceLocation.model_validate(raw)
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise NormalizationError(
            NormalizationErrorCode.INVALID_LOCATION,
            "fact contains an invalid source location",
            fact_id=fact_id,
            fact_kind=fact_kind,
        ) from None
