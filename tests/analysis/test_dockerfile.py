"""Dockerfile analyzer contract, parser, recovery, and security tests."""

from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
from collections.abc import Callable
from typing import Any

import pytest

import runtime_contract.analysis.dockerfile as dockerfile_module
from runtime_contract.analysis import (
    AnalysisCompleteness,
    AnalysisResult,
    AnalyzerInput,
    AnalyzerRegistry,
    DockerfileAnalyzer,
)
from runtime_contract.analysis.dockerfile import (
    MAX_DECLARATIONS,
    MAX_DOCKERFILE_BYTES,
    MAX_INSTRUCTIONS,
    MAX_LOGICAL_INSTRUCTION,
    MAX_STAGES,
    MAX_SUBSTITUTIONS,
    MAX_VALUE_TOKENS,
)
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    Environment,
    EnvironmentKind,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
    ProviderRole,
)
from runtime_contract.normalization import normalize_observations
from tests.analysis.doubles import StaticResolver

SENTINELS = (
    "docker-secret-value-Q7Z9",
    "private.registry.invalid/base-image-X8",
    "host-name-canary-P3",
)


def analyze(
    source: str | bytes, *, kind: CandidateKind = CandidateKind.DOCKERFILE
) -> AnalysisResult:
    content = source.encode() if isinstance(source, str) else source
    return DockerfileAnalyzer().analyze(
        AnalyzerInput(
            path="containers/Dockerfile.prod",
            kind=kind,
            content=content,
            component="api",
            root="api",
            profile=Profile.PROD,
            resolver=StaticResolver(),
        )
    )


def providers(result: AnalysisResult) -> tuple[Provider, ...]:
    return tuple(
        observation.fact
        for observation in result.observations
        if isinstance(observation.fact, Provider)
    )


def test_api_kind_and_registry_contract() -> None:
    analyzer = DockerfileAnalyzer()
    assert analyzer.analyzer_id == "dockerfile"
    assert analyzer.supported_kinds == frozenset({CandidateKind.DOCKERFILE})
    assert AnalyzerRegistry([analyzer]).resolve(CandidateKind.DOCKERFILE) is analyzer
    with pytest.raises(ValueError, match=r"CandidateKind\.DOCKERFILE"):
        analyze("", kind=CandidateKind.PYTHON)


def test_arg_and_env_emit_exact_delivery_facts_and_one_environment() -> None:
    result = analyze("ARG GLOBAL=x\nFROM scratch\nARG BUILD_ONLY\nENV RUN=x OTHER='two words'\n")
    assert result.completeness is AnalysisCompleteness.COMPLETE
    facts = [observation.fact for observation in result.observations]
    environment = next(fact for fact in facts if isinstance(fact, Environment))
    assert environment.kind is EnvironmentKind.IMPLICIT
    assert environment.component == "api"
    assert environment.target == "api"
    assert environment.profile is Profile.PROD
    actual = sorted((item.phase, item.mechanism, item.role) for item in providers(result))
    assert actual == sorted(
        [
            (Phase.BUILD, ProviderMechanism.DOCKERFILE_ARG, ProviderRole.DELIVERY),
            (Phase.BUILD, ProviderMechanism.DOCKERFILE_ARG, ProviderRole.DELIVERY),
            (Phase.RUNTIME, ProviderMechanism.DOCKERFILE_ENV, ProviderRole.DELIVERY),
            (Phase.RUNTIME, ProviderMechanism.DOCKERFILE_ENV, ProviderRole.DELIVERY),
        ]
    )
    assert sorted(
        [(item.location.start_line, item.location.start_column) for item in providers(result)]
    ) == [
        (1, 5),
        (3, 5),
        (4, 5),
        (4, 11),
    ]


@pytest.mark.parametrize(
    ("source", "expected_names"),
    [
        ("FROM x\nARG A\nARG A=x\nARG lower\nARG UPPER\n", ["A", "UPPER", "lower"]),
        ('FROM x\nENV EMPTY= EMBED=a=b QUOTED="a b"\n', ["EMBED", "EMPTY", "QUOTED"]),
        ("FROM x\nENV LEGACY a value with spaces\n", ["LEGACY"]),
        ("ARG GLOBAL\n", ["GLOBAL"]),
    ],
)
def test_supported_arg_and_env_forms(source: str, expected_names: list[str]) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    contract = normalize_observations(result.observations)
    assert sorted(item.name for item in contract.config_keys) == expected_names


def test_multistage_aliases_inheritance_and_redeclarations_have_no_synthetic_providers() -> None:
    source = """ARG BASE
FROM image AS builder
ARG SHARED
ENV RUNTIME=x
FROM builder AS child
ARG SHARED
ENV RUNTIME=y CHILD=z
FROM other AS independent
ARG OWN
"""
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert len(providers(result)) == 7
    assert len({item.id for item in providers(result)}) == 7


@pytest.mark.parametrize(
    "source",
    [
        "from image as Build\narg A\nenv B=x\nFROM build AS final\n",
        "FROM --platform=$BUILDPLATFORM image AS build\nENV A=x\n",
        "# escape=`\nFROM image`\n AS build\nENV A=x`\n B=y\n",
        "\ufeff  FrOm image\r\n\tEnV A=x B=y",
    ],
)
def test_from_case_directives_continuations_bom_and_crlf(source: str) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE


def test_dynamic_from_duplicate_alias_and_future_reference_are_partial_and_redacted() -> None:
    result = analyze(
        "ARG BASE=image\nFROM ${BASE} AS one\nARG SAFE\nFROM image AS one\nENV KEPT=x\n"
    )
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert {item.code.value for item in result.diagnostics} == {
        "syntax_error",
        "unsupported_construct",
    }
    assert sorted(
        item.name for item in normalize_observations(result.observations).config_keys
    ) == [
        "BASE",
        "SAFE",
    ]


@pytest.mark.parametrize(
    ("source", "syntax_kind"),
    [
        ("123 invalid instruction\nFROM x\n", "instruction_boundary"),
        ("FROM --unknown=x image\n", "malformed_from"),
        ("FROM --platform=x\n", "malformed_from"),
        ("FROM image extra\n", "malformed_from"),
        ("FROM image AS 1bad\n", "invalid_stage_alias"),
        ("FROM later AS first\nFROM image AS later\n", "future_stage_reference"),
        ("FROM x\nARG A B\n", "malformed_arg"),
        ("FROM x\nENV 1BAD=x\n", "invalid_env_name"),
        ("FROM x\nENV A=x TRAILING\n", "malformed_env"),
        ('FROM "unterminated\n', "unterminated_quote"),
    ],
)
def test_structural_error_categories_are_stable(source: str, syntax_kind: str) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert syntax_kind in {dict(item.parameters).get("syntax_kind") for item in result.diagnostics}


def test_invalid_escape_directive_is_ignored_and_escaped_token_is_lexed() -> None:
    invalid = analyze("# escape=!\nFROM image\nENV A=x\n")
    escaped = analyze("FROM im\\age AS build\nENV A=x\n")
    trailing_space = analyze("FROM image   \n")
    assert invalid.completeness is AnalysisCompleteness.COMPLETE
    assert escaped.completeness is AnalysisCompleteness.COMPLETE
    assert trailing_space.completeness is AnalysisCompleteness.COMPLETE


def test_heredoc_safety_limit_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dockerfile_module, "MAX_HEREDOC_LINES", 1)
    result = analyze("FROM image\nRUN <<EOF\none\ntwo\nEOF\n")
    assert result.completeness is AnalysisCompleteness.FAILED
    assert dict(result.diagnostics[0].parameters) == {"limit_kind": "heredoc_lines"}


@pytest.mark.parametrize(
    ("source", "syntax_kind"),
    [
        ("FROM x\nARG 1BAD\nARG GOOD\n", "invalid_arg_name"),
        ("FROM x\nENV BAD\nENV GOOD=x\n", "malformed_env"),
        ("ENV BAD=x\nFROM x\nENV GOOD=x\n", "env_before_from"),
        ("FROM\nARG GOOD\n", "malformed_from"),
        ("FROM x\\", "unterminated_continuation"),
    ],
)
def test_local_syntax_recovery_preserves_safe_facts(source: str, syntax_kind: str) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert syntax_kind in {dict(item.parameters).get("syntax_kind") for item in result.diagnostics}


def test_empty_comments_irrelevant_onbuild_and_heredoc_are_safe() -> None:
    source = """# syntax=docker/dockerfile:1

FROM image
RUN <<EOF
ARG FALSE
ENV FALSE=x
EOF
ONBUILD ENV ALSO_FALSE=x
COPY source target
ARG TRUE
"""
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert [item.name for item in normalize_observations(result.observations).config_keys] == [
        "TRUE"
    ]
    assert analyze("").completeness is AnalysisCompleteness.COMPLETE
    assert analyze("# comment\n").completeness is AnalysisCompleteness.COMPLETE


def test_unterminated_heredoc_is_partial_without_inner_facts() -> None:
    result = analyze("FROM image\nRUN <<EOF\nARG FALSE\n")
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert not result.observations
    assert dict(result.diagnostics[0].parameters) == {"construct_kind": "unterminated_heredoc"}


def test_invalid_utf8_and_file_size_fail_closed() -> None:
    assert analyze(b"\xff").completeness is AnalysisCompleteness.FAILED
    result = analyze(b"X" * (MAX_DOCKERFILE_BYTES + 1))
    assert result.completeness is AnalysisCompleteness.FAILED
    assert dict(result.diagnostics[0].parameters) == {"limit_kind": "file_size"}


@pytest.mark.parametrize(
    ("source", "limit_kind"),
    [
        (lambda: "#\n" + "RUN x\n" * (MAX_INSTRUCTIONS + 1), "instructions"),
        (lambda: "RUN " + "x" * MAX_LOGICAL_INSTRUCTION, "logical_instruction"),
        (lambda: "FROM x\n" * (MAX_STAGES + 1), "stages"),
        (lambda: "FROM x\n" + "ARG A\n" * (MAX_DECLARATIONS + 1), "declarations"),
        (
            lambda: "FROM x\nENV " + " ".join(f"A{i}=x" for i in range(MAX_VALUE_TOKENS + 1)),
            "value_tokens",
        ),
        (lambda: "FROM x\nENV A=" + "$A" * (MAX_SUBSTITUTIONS + 1), "substitutions"),
    ],
)
def test_every_bounded_resource_fails_closed(source: Callable[[], str], limit_kind: str) -> None:
    result = analyze(source())
    assert result.completeness is AnalysisCompleteness.FAILED
    assert limit_kind in {dict(item.parameters).get("limit_kind") for item in result.diagnostics}
    assert not result.observations


def test_values_images_substitutions_commands_and_host_data_never_escape(
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = (
        f"ARG SECRET={SENTINELS[0]}\n"
        f"FROM {SENTINELS[1]}\n"
        f"ENV VALUE={SENTINELS[2]} REF=${{SECRET:-fallback}} CMD=$(touch never)\n"
    )
    result = analyze(source)
    contract = normalize_observations(result.observations)
    channels = "\n".join(
        (
            repr(result),
            result.model_dump_json(),
            json.dumps(contract.model_dump(mode="json")),
            capsys.readouterr().out,
            capsys.readouterr().err,
        )
    )
    assert all(sentinel not in channels for sentinel in SENTINELS)
    assert "fallback" not in channels
    assert not contract.consumers


def test_parser_has_no_execution_environment_network_or_docker_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise AssertionError("forbidden execution surface")

    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(builtins, "eval", forbidden)
    monkeypatch.setattr(builtins, "exec", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    result = analyze("FROM image\nRUN docker build .\nCOPY /etc/passwd /x\nENV SAFE=$HOST\n")
    assert result.completeness is AnalysisCompleteness.COMPLETE


def test_analysis_and_normalization_are_deterministic_and_idempotent() -> None:
    source = "FROM x AS a\nARG B=x\nENV A=y B=z\nFROM a\nENV A=q\n"
    first = analyze(source)
    second = analyze(source)
    assert first == second
    normalized = normalize_observations(first.observations)
    assert normalize_observations(first.observations) == normalized
