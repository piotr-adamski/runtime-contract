"""Versioned public result models for a scan run."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from runtime_contract.analysis import AnalysisDiagnostic
from runtime_contract.domain import Contract


class ScanModel(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class ScanStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class ScanSummary(ScanModel):
    candidates: int = 0
    analyzed: int = 0
    skipped: int = 0
    complete_files: int = 0
    partial_files: int = 0
    failed_files: int = 0
    config_keys: int = 0
    consumers: int = 0
    providers: int = 0
    diagnostics: int = 0
    findings: int = 0
    candidate_kinds: dict[str, int] = Field(default_factory=dict)
    skipped_reasons: dict[str, int] = Field(default_factory=dict)


class ScanFile(ScanModel):
    path: str
    kind: str
    status: Literal["complete", "partial", "failed", "skipped"]
    reason: str | None = None


class ScanResult(ScanModel):
    schema_id: Literal["runtime-contract/v1"] = "runtime-contract/v1"
    status: ScanStatus
    root: Literal["."] = "."
    config: str
    environment: str | None = None
    selected_roots: tuple[str, ...]
    summary: ScanSummary
    contract: Contract
    diagnostics: tuple[AnalysisDiagnostic, ...] = ()
    findings: tuple[()] = ()
    files: tuple[ScanFile, ...] = ()
    effective_include: tuple[str, ...] = ()
    effective_exclude: tuple[str, ...] = ()
    fail_on: str = "error"


__all__ = ["ScanFile", "ScanResult", "ScanStatus", "ScanSummary"]
