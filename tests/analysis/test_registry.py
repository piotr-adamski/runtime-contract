"""AnalyzerRegistry validation and fail-closed execution tests."""

from __future__ import annotations

import traceback
from typing import Any

import pytest

from runtime_contract.analysis import (
    AnalyzerExecutionError,
    AnalyzerNotRegisteredError,
    AnalyzerRegistry,
    CandidateKindConflictError,
    DuplicateAnalyzerIdError,
    InvalidAnalyzerCallableError,
    InvalidAnalyzerIdError,
    InvalidSupportedKindsError,
)
from runtime_contract.discovery import CandidateKind
from tests.analysis.doubles import FixtureAnalyzer, InvalidResultAnalyzer, RaisingAnalyzer


class MutableAnalyzer:
    analyzer_id: Any = "valid.id"
    supported_kinds: Any = frozenset({CandidateKind.PYTHON})

    def analyze(self, input: Any, /) -> Any:
        return FixtureAnalyzer().analyze(input)


def test_registration_resolve_and_multiple_kinds() -> None:
    analyzer = MutableAnalyzer()
    analyzer.supported_kinds = frozenset({CandidateKind.PYTHON, CandidateKind.JAVASCRIPT})
    registry = AnalyzerRegistry((analyzer,))
    assert registry.resolve(CandidateKind.PYTHON) is analyzer
    assert registry.resolve(CandidateKind.JAVASCRIPT) is analyzer


@pytest.mark.parametrize("analyzer_id", ["", "Upper", "space id", "a/evil", 1])
def test_invalid_analyzer_id(analyzer_id: Any) -> None:
    analyzer = MutableAnalyzer()
    analyzer.analyzer_id = analyzer_id
    with pytest.raises(InvalidAnalyzerIdError):
        AnalyzerRegistry((analyzer,))


@pytest.mark.parametrize(
    "kinds",
    [frozenset(), set([CandidateKind.PYTHON]), [CandidateKind.PYTHON], frozenset({"python"})],
)
def test_invalid_supported_kinds(kinds: Any) -> None:
    analyzer = MutableAnalyzer()
    analyzer.supported_kinds = kinds
    with pytest.raises(InvalidSupportedKindsError):
        AnalyzerRegistry((analyzer,))


def test_non_callable_analyze() -> None:
    analyzer = MutableAnalyzer()
    analyzer.analyze = None  # type: ignore[assignment]
    with pytest.raises(InvalidAnalyzerCallableError):
        AnalyzerRegistry((analyzer,))


def test_duplicate_id_and_kind_conflict() -> None:
    first = MutableAnalyzer()
    duplicate = MutableAnalyzer()
    duplicate.supported_kinds = frozenset({CandidateKind.JAVASCRIPT})
    with pytest.raises(DuplicateAnalyzerIdError):
        AnalyzerRegistry((first, duplicate))
    conflict = MutableAnalyzer()
    conflict.analyzer_id = "other.id"
    with pytest.raises(CandidateKindConflictError):
        AnalyzerRegistry((first, conflict))


def test_registration_order_does_not_change_resolution() -> None:
    python = MutableAnalyzer()
    javascript = MutableAnalyzer()
    javascript.analyzer_id = "javascript"
    javascript.supported_kinds = frozenset({CandidateKind.JAVASCRIPT})
    one = AnalyzerRegistry((python, javascript))
    two = AnalyzerRegistry((javascript, python))
    for kind in (CandidateKind.PYTHON, CandidateKind.JAVASCRIPT):
        assert one.resolve(kind).analyzer_id == two.resolve(kind).analyzer_id


def test_missing_resolve_raises_and_analyze_returns_failed(analyzer_input: Any) -> None:
    registry = AnalyzerRegistry()
    with pytest.raises(AnalyzerNotRegisteredError):
        registry.resolve(CandidateKind.PYTHON)
    result = registry.analyze(analyzer_input)
    assert result.completeness.value == "failed"
    assert result.diagnostics[0].code.value == "analyzer_not_registered"


@pytest.mark.parametrize(
    "analyzer",
    [RaisingAnalyzer(ValueError("exception-value-canary-Q7Z9")), InvalidResultAnalyzer()],
)
def test_execution_contract_failures_are_wrapped(analyzer: Any, analyzer_input: Any) -> None:
    with pytest.raises(AnalyzerExecutionError) as caught:
        AnalyzerRegistry((analyzer,)).analyze(analyzer_input)
    assert caught.value.__cause__ is None
    assert "exception-value-canary-Q7Z9" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("error", [KeyboardInterrupt(), SystemExit(), GeneratorExit()])
def test_process_control_exceptions_are_not_caught(
    error: BaseException, analyzer_input: Any
) -> None:
    with pytest.raises(type(error)):
        AnalyzerRegistry((RaisingAnalyzer(error),)).analyze(analyzer_input)


def test_registered_analyzer_result_is_returned(analyzer_input: Any) -> None:
    result = AnalyzerRegistry((FixtureAnalyzer(),)).analyze(analyzer_input)
    assert result.completeness.value == "complete"
