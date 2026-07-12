"""Analyzer protocols and the non-serialized analyzer input."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Protocol

from runtime_contract.analysis.models import AnalysisResult, EffectiveClassification
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import Profile


class ClassificationResolver(Protocol):
    def classify(self, variable: str) -> EffectiveClassification: ...


@dataclass(frozen=True, slots=True)
class AnalyzerInput:
    path: str
    kind: CandidateKind
    content: bytes = field(repr=False)
    component: str
    root: str
    profile: Profile
    resolver: ClassificationResolver

    def __post_init__(self) -> None:
        normalized = posixpath.normpath(self.path)
        if not self.path or "\\" in self.path or self.path.startswith("/"):
            raise ValueError("path must be a relative POSIX path")
        if normalized in ("", ".", "..") or normalized.startswith("../"):
            raise ValueError("path must remain within the logical root")
        if type(self.content) is not bytes:
            raise TypeError("content must be exact bytes")
        if not self.component or not self.root:
            raise ValueError("component and root must be non-empty")
        object.__setattr__(self, "path", normalized)


class Analyzer(Protocol):
    analyzer_id: str
    supported_kinds: frozenset[CandidateKind]

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult: ...
