"""Dotenv syntax subset verified against motdotla/dotenv, python-dotenv, and dotenvx docs.

Rule sources were checked on 2026-07-11. These fixtures assert syntax compatibility only;
runtime-contract deliberately performs no expansion and never builds an environment.
"""

from __future__ import annotations

import builtins
import json
import os
import subprocess
from pathlib import Path
from typing import cast

import pytest

from runtime_contract.analysis import (
    AnalysisCompleteness,
    AnalysisResult,
    AnalyzerInput,
    DotenvAnalyzer,
    dotenv,
)
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import Profile, Provider
from runtime_contract.normalization import normalize_observations
from tests.analysis.doubles import StaticResolver

SENTINELS = (
    "s3cr3t_TEST_ONLY_A91D",
    "fixture-token-Z8Q7",
    "unicode-value-zażółć",
)
FIXTURES = Path(__file__).parent / "fixtures" / "dotenv"


def analyze(source: str | bytes) -> AnalysisResult:
    content = source if isinstance(source, bytes) else source.encode()
    return DotenvAnalyzer().analyze(
        AnalyzerInput(
            path="config/.env.example",
            kind=CandidateKind.ENV_EXAMPLE,
            content=content,
            component="api",
            root="api",
            profile=Profile.DEFAULT,
            resolver=StaticResolver(),
        )
    )


def providers(result: AnalysisResult) -> list[Provider]:
    found = [item.fact for item in result.observations if isinstance(item.fact, Provider)]
    return sorted(
        found,
        key=lambda item: (
            item.location.start_line or 0,
            item.location.start_column or 0,
        ),
    )


@pytest.mark.parametrize(
    ("source", "names"),
    [
        ("\n # comment\nKEY=value\nSPACED = value\n", ["KEY", "SPACED"]),
        ("EMPTY=\nDOUBLE=\"\"\nSINGLE=''\nBACK=``\n", ["EMPTY", "DOUBLE", "SINGLE", "BACK"]),
        ("export KEY=value\n", ["KEY"]),
        ("exportX=value\n", ["exportX"]),
        ("\ufeffFIRST=one\r\nSECOND=two\r\n", ["FIRST", "SECOND"]),
        ("A='x#y' # comment\nB=\"x#y\" # comment\nC=x#y\n", ["A", "B", "C"]),
        ('JSON={"a":1}\nURL=https://x/?a=b\n', ["JSON", "URL"]),
        ('A=\'it\\\'s\'\nB="say \\"hi\\""\nC=`tick\\``\n', ["A", "B", "C"]),
        ('MULTI="first\nsecond"\nAFTER=yes\n', ["MULTI", "AFTER"]),
        ("Case=x\nCASE=y\nCase=z\n", ["Case", "CASE", "Case"]),
        ('W="   "\nESC=\\n\\r\\t\\\\\n', ["W", "ESC"]),
        ("A=x # comment\rB=$\rC=$-\rD=${1}\r", ["A", "B", "C", "D"]),
    ],
)
def test_supported_syntax(source: str, names: list[str]) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    found = [cast(str, item.config_key_id) for item in providers(result)]
    key_names = {
        item.fact.id: item.fact.name for item in result.observations if hasattr(item.fact, "name")
    }
    assert [key_names[item] for item in found] == names


@pytest.mark.parametrize(
    "value",
    [
        "$NAME",
        "${NAME}",
        "${NAME:-default}",
        "${NAME-default}",
        "${NAME:+alternate}",
        "${NAME+alternate}",
        "prefix-$A-${B:-$IGNORED}",
        "\\$ESCAPED",
        "$(printf unsafe)",
        "$(printf '${NOT_A_REFERENCE}' && (nested))",
        "$(printf escaped\\)close)",
        "$(first\nsecond)",
        "'${LITERAL}'",
        "`${LITERAL}`",
    ],
)
def test_interpolation_is_recognized_but_never_expanded(value: str) -> None:
    result = analyze(f"KEY={value}\n")
    assert result.completeness is AnalysisCompleteness.COMPLETE
    serialized = result.model_dump_json()
    assert value not in serialized
    assert "default" not in serialized and "alternate" not in serialized


@pytest.mark.parametrize(
    ("source", "kind", "line", "column"),
    [
        ("KEY\n", "missing_separator", 1, 4),
        ("=value\n", "empty_name", 1, 1),
        ("1KEY=value\n", "invalid_name", 1, 1),
        ("BAD-NAME=value\n", "missing_separator", 1, 4),
        ("export\n", "export_without_declaration", 1, 1),
        ("KEY='value\n", "unterminated_quote", 1, 1),
        ('KEY="value\n', "unterminated_quote", 1, 1),
        ("KEY=`value\n", "unterminated_quote", 1, 1),
        ('KEY="ok" garbage\n', "trailing_garbage", 1, 10),
        ("KEY=${NAME\n", "unterminated_interpolation", 1, 5),
        ("nonsense KEY=value\n", "missing_separator", 1, 10),
    ],
)
def test_syntax_errors_are_redacted_and_located(
    source: str, kind: str, line: int, column: int
) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.PARTIAL
    diagnostic = result.diagnostics[0]
    assert dict(diagnostic.parameters) == {"syntax_kind": kind}
    assert (diagnostic.primary_location.start_line, diagnostic.primary_location.start_column) == (
        line,
        column,
    )
    if "=" in source:
        assert source.strip() not in repr(result)


def test_partial_keeps_safe_declarations_before_and_after_line_error() -> None:
    result = analyze("GOOD=one\nBROKEN\nAFTER=two\n")
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert len(providers(result)) == 2


def test_invalid_encoding_and_limits_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    assert analyze(b"\xffsentinel").completeness is AnalysisCompleteness.FAILED
    monkeypatch.setattr(dotenv, "MAX_DOTENV_BYTES", 3)
    assert analyze("KEY=x").diagnostics[0].parameters == (("limit_kind", "file_size"),)
    monkeypatch.setattr(dotenv, "MAX_DOTENV_BYTES", 100)
    monkeypatch.setattr(dotenv, "MAX_LOGICAL_DECLARATION", 3)
    assert analyze("KEY=x").completeness is AnalysisCompleteness.FAILED
    monkeypatch.setattr(dotenv, "MAX_LOGICAL_DECLARATION", 100)
    monkeypatch.setattr(dotenv, "MAX_DECLARATIONS", 1)
    assert analyze("A=x\nB=y\n").completeness is AnalysisCompleteness.FAILED
    monkeypatch.setattr(dotenv, "MAX_DECLARATIONS", 10)
    monkeypatch.setattr(dotenv, "MAX_INTERPOLATION_REFERENCES", 1)
    assert analyze("A=$X$Y\n").completeness is AnalysisCompleteness.FAILED
    assert analyze('A="$X$Y"\n').completeness is AnalysisCompleteness.FAILED
    assert analyze("A=${X}${Y}\n").completeness is AnalysisCompleteness.FAILED


def test_export_without_declaration_at_end_of_file_is_partial() -> None:
    result = analyze("export")
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert dict(result.diagnostics[0].parameters) == {"syntax_kind": "export_without_declaration"}
    assert analyze("KEY=$").completeness is AnalysisCompleteness.COMPLETE
    assert analyze("KEY=$(unterminated").completeness is AnalysisCompleteness.COMPLETE


def test_sentinels_never_escape_any_result_channel(capsys: pytest.CaptureFixture[str]) -> None:
    source = "\n".join(f"KEY_{index}={value}" for index, value in enumerate(SENTINELS))
    result = analyze(source)
    contract = normalize_observations(result.observations)
    channels = "\n".join(
        (
            repr(result),
            result.model_dump_json(),
            repr(result.diagnostics),
            repr(result.observations),
            contract.model_dump_json(),
            json.dumps(contract.model_dump(mode="json")),
            capsys.readouterr().out,
            capsys.readouterr().err,
        )
    )
    assert all(sentinel not in channels for sentinel in SENTINELS)


def test_parser_uses_no_environment_subprocess_or_code_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("forbidden execution surface")

    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(builtins, "eval", forbidden)
    monkeypatch.setattr(builtins, "exec", forbidden)
    result = analyze("KEY=$HOST\nCOMMAND=$(touch never)\n")
    assert result.completeness is AnalysisCompleteness.COMPLETE


def test_normalization_is_idempotent_and_analysis_deterministic() -> None:
    first = analyze("B=x\nA=y\nB=z\n")
    second = analyze("B=x\nA=y\nB=z\n")
    assert first == second
    normalized = normalize_observations(first.observations)
    assert normalize_observations(first.observations) == normalized


@pytest.mark.parametrize(
    "fixture",
    ["motdotla.env.example", "python-dotenv.env.example", "dotenvx.env.example"],
)
def test_documented_compatibility_fixtures(fixture: str) -> None:
    result = analyze(FIXTURES.joinpath(fixture).read_bytes())
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert providers(result)
