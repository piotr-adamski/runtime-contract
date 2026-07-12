"""Pure name/metadata-only sensitivity classification."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

from runtime_contract.domain import (
    SecretSource,
    SensitivityConfidence,
    SensitivityReason,
)


class SensitivityClassification(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    sensitive: bool
    source: SecretSource
    reason: SensitivityReason
    confidence: SensitivityConfidence


_SEPARATOR = re.compile(r"[^A-Za-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_SECRET_SUFFIXES = {
    ("token", "count"),
    ("token", "limit"),
    ("token", "ttl"),
    ("token", "type"),
    ("password", "length"),
    ("password", "min", "length"),
    ("password", "max", "length"),
    ("password", "policy"),
    ("secret", "name"),
    ("secret", "namespace"),
    ("credential", "type"),
}


def classify_sensitivity(
    name: str,
    /,
    *,
    override: bool | None = None,
    secret_metadata: bool = False,
) -> SensitivityClassification:
    """Classify from a key name and explicit structural metadata, never a value."""
    if override is not None:
        return SensitivityClassification(
            sensitive=override,
            source=SecretSource.CONFIG_OVERRIDE,
            reason=SensitivityReason.CONFIG_OVERRIDE,
            confidence=SensitivityConfidence.CERTAIN,
        )
    if secret_metadata:
        return SensitivityClassification(
            sensitive=True,
            source=SecretSource.HEURISTIC,
            reason=SensitivityReason.SECRET_METADATA,
            confidence=SensitivityConfidence.CERTAIN,
        )
    tokens = _tokens(name)
    if any(tokens[-len(suffix) :] == suffix for suffix in _NON_SECRET_SUFFIXES):
        return _not_sensitive()
    reason = _reason(tokens)
    if reason is None:
        return _not_sensitive()
    return SensitivityClassification(
        sensitive=True,
        source=SecretSource.HEURISTIC,
        reason=reason,
        confidence=SensitivityConfidence.HIGH,
    )


def _tokens(name: str) -> tuple[str, ...]:
    expanded = _CAMEL.sub("_", name)
    return tuple(item.casefold() for item in _SEPARATOR.split(expanded) if item)


def _reason(tokens: tuple[str, ...]) -> SensitivityReason | None:
    if len(tokens) >= 2 and tokens[-2:] == ("private", "key"):
        return SensitivityReason.PRIVATE_KEY
    if len(tokens) >= 2 and tokens[-2:] == ("api", "key"):
        return SensitivityReason.API_KEY
    if tokens and tokens[-1] in {"apikey", "apiKey".casefold()}:
        return SensitivityReason.API_KEY
    if tokens and tokens[-1] in {"credential", "credentials"}:
        return SensitivityReason.CREDENTIAL
    if tokens and tokens[-1] == "token":
        return SensitivityReason.TOKEN
    if tokens and tokens[-1] in {"password", "passwd"}:
        return SensitivityReason.PASSWORD
    if tokens and tokens[-1] == "secret":
        return SensitivityReason.SECRET
    return None


def _not_sensitive() -> SensitivityClassification:
    return SensitivityClassification(
        sensitive=False,
        source=SecretSource.NOT_SECRET,
        reason=SensitivityReason.NO_MATCH,
        confidence=SensitivityConfidence.NONE,
    )


__all__ = [
    "SensitivityClassification",
    "SensitivityConfidence",
    "SensitivityReason",
    "classify_sensitivity",
]
