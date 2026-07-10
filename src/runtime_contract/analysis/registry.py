"""Deterministic analyzer registration, resolution, and execution."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import NoReturn

from runtime_contract.analysis.models import (
    AnalysisCompleteness,
    AnalysisDiagnostic,
    AnalysisResult,
    DiagnosticCode,
)
from runtime_contract.analysis.protocols import Analyzer, AnalyzerInput
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import Severity, SourceLocation

_ANALYZER_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")


class AnalyzerRegistryError(ValueError):
    """Base class for stable registration errors."""


class InvalidAnalyzerIdError(AnalyzerRegistryError):
    pass


class InvalidSupportedKindsError(AnalyzerRegistryError):
    pass


class InvalidAnalyzerCallableError(AnalyzerRegistryError):
    pass


class DuplicateAnalyzerIdError(AnalyzerRegistryError):
    pass


class CandidateKindConflictError(AnalyzerRegistryError):
    pass


class AnalyzerNotRegisteredError(LookupError):
    def __init__(self, kind: CandidateKind) -> None:
        super().__init__(f"no analyzer registered for CandidateKind.{kind.name}")
        self.kind = kind


class AnalyzerExecutionError(RuntimeError):
    def __init__(self, analyzer_id: str, kind: CandidateKind, cause: BaseException) -> None:
        super().__init__(
            f"analyzer {analyzer_id!r} violated its execution contract for {kind.value}"
        )
        self.analyzer_id = analyzer_id
        self.kind = kind
        self.__cause__ = cause


class AnalyzerRegistry:
    def __init__(self, analyzers: Iterable[Analyzer] = ()) -> None:
        self._by_id: dict[str, Analyzer] = {}
        self._by_kind: dict[CandidateKind, Analyzer] = {}
        for analyzer in analyzers:
            self.register(analyzer)

    def register(self, analyzer: Analyzer) -> None:
        analyzer_id = getattr(analyzer, "analyzer_id", None)
        if type(analyzer_id) is not str or not _ANALYZER_ID.fullmatch(analyzer_id):
            raise InvalidAnalyzerIdError("analyzer_id must be a stable lowercase identifier")
        kinds = getattr(analyzer, "supported_kinds", None)
        if type(kinds) is not frozenset or not kinds:
            raise InvalidSupportedKindsError("supported_kinds must be a non-empty exact frozenset")
        if any(type(kind) is not CandidateKind for kind in kinds):
            raise InvalidSupportedKindsError("supported_kinds contains an invalid CandidateKind")
        if not callable(getattr(analyzer, "analyze", None)):
            raise InvalidAnalyzerCallableError("analyze must be callable")
        if analyzer_id in self._by_id:
            raise DuplicateAnalyzerIdError(f"duplicate analyzer_id: {analyzer_id}")
        conflicts = sorted(
            (kind for kind in kinds if kind in self._by_kind), key=lambda kind: kind.value
        )
        if conflicts:
            raise CandidateKindConflictError(
                f"CandidateKind already registered: {conflicts[0].value}"
            )
        self._by_id[analyzer_id] = analyzer
        for kind in sorted(kinds, key=lambda item: item.value):
            self._by_kind[kind] = analyzer

    def resolve(self, kind: CandidateKind) -> Analyzer:
        try:
            return self._by_kind[kind]
        except KeyError:
            raise AnalyzerNotRegisteredError(kind) from None

    def analyze(self, input: AnalyzerInput) -> AnalysisResult:
        try:
            analyzer = self.resolve(input.kind)
        except AnalyzerNotRegisteredError:
            diagnostic = AnalysisDiagnostic(
                code=DiagnosticCode.ANALYZER_NOT_REGISTERED,
                severity=Severity.ERROR,
                primary_location=SourceLocation(path=input.path),
                parameters=(("candidate_kind", input.kind.value),),
            )
            return AnalysisResult(
                completeness=AnalysisCompleteness.FAILED,
                diagnostics=(diagnostic,),
            )
        try:
            result = analyzer.analyze(input)
            if type(result) is not AnalysisResult:
                raise TypeError("analyze must return an exact AnalysisResult")
            return result
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except BaseException as error:
            _raise_execution(analyzer.analyzer_id, input.kind, error)


def _raise_execution(analyzer_id: str, kind: CandidateKind, cause: BaseException) -> NoReturn:
    raise AnalyzerExecutionError(analyzer_id, kind, cause) from cause
