"""Versioned public JSON report for the diff command."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, model_validator

from runtime_contract.analysis import AnalysisDiagnostic


class DiffModel(BaseModel):
    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")


class DiffInput(DiffModel):
    kind: Literal["directory", "report"]
    environment: str | None


class DiffMetadata(DiffModel):
    tool: Literal["runtime-contract"]
    tool_version: str | None
    command: Literal["diff"]
    policy: tuple[()]


class DiffReport(DiffModel):
    schema_id: Literal["runtime-contract/v1"]
    schema_version: Literal[1]
    metadata: DiffMetadata
    status: Literal["identical", "different"]
    diagnostics: tuple[AnalysisDiagnostic, ...]
    left: DiffInput
    right: DiffInput
    changes: dict[str, dict[str, list[dict[str, Any]]]]

    @model_validator(mode="after")
    def validate_changes(self) -> DiffReport:
        if set(self.changes) != {"consumers", "providers", "classifications", "findings"}:
            raise ValueError("diff changes require every canonical category")
        expected_actions = {"added", "removed", "changed"}
        if any(set(category) != expected_actions for category in self.changes.values()):
            raise ValueError("diff categories require added, removed, and changed")
        different = any(items for category in self.changes.values() for items in category.values())
        if (self.status == "different") != different:
            raise ValueError("diff status contradicts changes")
        return self


__all__ = ["DiffInput", "DiffMetadata", "DiffReport"]
