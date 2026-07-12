"""Central fail-closed redaction boundary for public technical errors."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from runtime_contract.discovery import DiscoveryError
from runtime_contract.errors import PublicError
from runtime_contract.normalization import NormalizationError


class RedactedException(BaseModel):
    """Safe exception metadata that never retains message, repr, args, or traceback."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")

    category: str
    message: str


def redact_exception(error: BaseException) -> RedactedException:
    """Map an exception to closed public metadata without inspecting its text."""
    if isinstance(error, PublicError):
        return RedactedException(category="request.public", message=str(error))
    if isinstance(error, DiscoveryError):
        return RedactedException(
            category=f"discovery.{error.code.value}",
            message=f"scan failed [{error.code.value}]",
        )
    if isinstance(error, NormalizationError):
        return RedactedException(
            category=f"normalization.{error.code.value}",
            message=f"scan failed [{error.code.value}]",
        )
    if isinstance(error, ValueError):
        return RedactedException(category="request.invalid", message="invalid scan request")
    return RedactedException(category="runtime.failure", message="scan failed")


__all__ = ["RedactedException", "redact_exception"]
