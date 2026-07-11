"""Stable technical errors raised by fact normalization."""

from __future__ import annotations

from enum import StrEnum

from runtime_contract.analysis import FactKind


class NormalizationErrorCode(StrEnum):
    CONFLICTING_FACT = "conflicting_fact"
    INVALID_LOCATION = "invalid_location"
    INVALID_FACT_REFERENCE = "invalid_fact_reference"
    UNSUPPORTED_FACT = "unsupported_fact"


class NormalizationError(RuntimeError):
    """A redacted technical normalization failure."""

    def __init__(
        self,
        code: NormalizationErrorCode,
        message: str,
        *,
        fact_id: str | None = None,
        fact_kind: FactKind | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.fact_id = fact_id
        self.fact_kind = fact_kind
