"""Versioned public result models for a scan run."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from runtime_contract.analysis import AnalysisDiagnostic
from runtime_contract.domain import Contract, Finding
from runtime_contract.flow import FlowGraph, build_flow_graph
from runtime_contract.precedence import PrecedenceAnalysis, analyze_precedence


class ScanModel(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class ScanStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class ReportMetadata(ScanModel):
    tool: Literal["runtime-contract"] = "runtime-contract"
    tool_version: str | None
    command: Literal["scan", "check"] = "scan"


class ReportInputs(ScanModel):
    root: Literal["."] = "."
    config: str | None
    environment: str | None
    selected_roots: tuple[str, ...]
    include: tuple[str, ...]
    exclude: tuple[str, ...]
    fail_on: str

    @field_validator("config")
    @classmethod
    def validate_config_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value or "\\" in value or value.startswith("/"):
            raise ValueError("config must be a relative POSIX path")
        parts = value.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise ValueError("config must remain within root")
        return value


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
    flow_nodes: int = 0
    flow_edges: int = 0
    precedence_providers: int = 0
    precedence_conflicts: int = 0
    diagnostics: int = 0
    findings: int = 0
    candidate_kinds: dict[str, int] = Field(default_factory=dict)
    skipped_reasons: dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_counts(self) -> "ScanSummary":
        values = self.model_dump()
        for name, value in values.items():
            if isinstance(value, int) and value < 0:
                raise ValueError(f"{name} cannot be negative")
            if isinstance(value, dict) and any(count < 0 for count in value.values()):
                raise ValueError(f"{name} cannot contain negative counts")
        if self.candidates != self.analyzed + self.skipped:
            raise ValueError("candidate counts are inconsistent")
        return self


class ScanFile(ScanModel):
    path: str
    kind: str
    status: Literal["complete", "partial", "failed", "skipped"]
    reason: str | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not value or "\\" in value or value.startswith("/"):
            raise ValueError("file path must be a relative POSIX path")
        if value == ".." or value.startswith("../") or "/../" in value:
            raise ValueError("file path must remain within root")
        return value


class ScanResult(ScanModel):
    schema_id: Literal["runtime-contract/v1"]
    schema_version: Literal[1]
    metadata: ReportMetadata
    inputs: ReportInputs
    status: ScanStatus
    summary: ScanSummary
    contract: Contract
    flow_graph: FlowGraph = FlowGraph()
    precedence: PrecedenceAnalysis = PrecedenceAnalysis()
    diagnostics: tuple[AnalysisDiagnostic, ...]
    findings: tuple[Finding, ...]
    files: tuple[ScanFile, ...]

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "ScanResult":
        diagnostics = tuple(sorted(self.diagnostics, key=lambda item: item.id))
        findings = tuple(sorted(self.findings, key=lambda item: item.id))
        files = tuple(
            sorted(
                self.files,
                key=lambda item: (
                    item.path.encode("utf-8"),
                    item.kind,
                    item.status,
                    item.reason or "",
                ),
            )
        )
        for name, values in (
            ("diagnostics", diagnostics),
            ("findings", findings),
            ("files", files),
        ):
            if getattr(self, name) != values:
                object.__setattr__(self, name, values)
        expected = {
            "config_keys": len(self.contract.config_keys),
            "consumers": len(self.contract.consumers),
            "providers": len(self.contract.providers),
            "flow_nodes": len(self.flow_graph.nodes),
            "flow_edges": len(self.flow_graph.edges),
            "precedence_providers": len(self.precedence.providers),
            "precedence_conflicts": len(self.precedence.conflicts),
            "diagnostics": len(self.diagnostics),
            "findings": len(self.findings),
        }
        for name, count in expected.items():
            if getattr(self.summary, name) != count:
                raise ValueError(f"summary.{name} is inconsistent")
        if self.flow_graph != build_flow_graph(self.contract):
            raise ValueError("flow_graph is inconsistent with contract")
        if self.precedence != analyze_precedence(self.contract):
            raise ValueError("precedence is inconsistent with contract")
        if self.status is ScanStatus.COMPLETE and (
            self.summary.partial_files or self.summary.failed_files
        ):
            raise ValueError("complete status contradicts file counts")
        if self.status is ScanStatus.PARTIAL and (
            not self.summary.partial_files or self.summary.failed_files
        ):
            raise ValueError("partial status contradicts file counts")
        if self.status is ScanStatus.FAILED and not self.summary.failed_files:
            raise ValueError("failed status contradicts file counts")
        return self


__all__ = [
    "ReportInputs",
    "ReportMetadata",
    "ScanFile",
    "ScanResult",
    "ScanStatus",
    "ScanSummary",
]
