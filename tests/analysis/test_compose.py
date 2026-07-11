"""Compose analyzer semantics and security boundaries."""

from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

from runtime_contract.analysis import (
    AnalysisCompleteness,
    AnalysisResult,
    AnalyzerInput,
    ComposeAnalyzer,
)
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    ConfigKey,
    Environment,
    EnvironmentKind,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
)
from runtime_contract.normalization import normalize_observations
from tests.analysis.doubles import StaticResolver

CANARY = "compose-secret-canary-Q7Z9"


def analyze(source: str | bytes) -> AnalysisResult:
    return ComposeAnalyzer().analyze(
        AnalyzerInput(
            path="deploy/compose.yaml",
            kind=CandidateKind.COMPOSE,
            content=source.encode() if isinstance(source, str) else source,
            component="app",
            root="root",
            profile=Profile.STAGING,
            resolver=StaticResolver(),
        )
    )


def facts(result: Any, kind: type[Any]) -> list[Any]:
    return [item.fact for item in result.observations if isinstance(item.fact, kind)]


def test_environment_build_args_env_file_and_service_isolation() -> None:
    result = analyze(
        """services:
  api:
    profiles: [debug]
    environment:
      DATABASE_URL: "${STAGING_DATABASE_URL:?required}"
      EMPTY: ""
      PASS: null
    env_file:
      - .env.base
      - path: config/runtime.env
        required: false
        format: raw
    build:
      args:
        IMAGE_VERSION: ${RELEASE_TAG:-latest}
  worker:
    environment: ["QUEUE_URL=${QUEUE_SOURCE}", BARE]
"""
    )
    assert result.completeness is AnalysisCompleteness.COMPLETE
    environments = facts(result, Environment)
    assert sorted((item.target, item.kind, item.profile) for item in environments) == [
        ("api", EnvironmentKind.COMPOSE_SERVICE, Profile.STAGING),
        ("worker", EnvironmentKind.COMPOSE_SERVICE, Profile.STAGING),
    ]
    assert sorted(item.name for item in facts(result, ConfigKey)) == [
        "BARE",
        "DATABASE_URL",
        "EMPTY",
        "IMAGE_VERSION",
        "PASS",
        "QUEUE_URL",
    ]
    providers = facts(result, Provider)
    assert sum(item.mechanism is ProviderMechanism.COMPOSE_ENV_FILE for item in providers) == 2
    assert sum(item.phase is Phase.BUILD for item in providers) == 1
    assert all(item.environment_id in {item.id for item in environments} for item in providers)
    rendered = json.dumps(result.model_dump(mode="json"), sort_keys=True)
    for forbidden in ("STAGING_DATABASE_URL", "RELEASE_TAG", "latest", "required"):
        assert forbidden not in rendered
    normalize_observations(result.observations)


@pytest.mark.parametrize(
    "environment",
    [
        "environment: {A: x, B: 1, C: true, D: null, E: ''}",
        "environment: [A=x, B=1, C=true, D, E=]",
    ],
)
def test_environment_map_and_list_are_equivalent_without_values(environment: str) -> None:
    result = analyze(f"services:\n  api:\n    {environment}\n")
    assert sorted(item.name for item in facts(result, ConfigKey)) == ["A", "B", "C", "D", "E"]


def test_duplicate_names_are_deterministic_last_wins() -> None:
    source = "services:\n  api:\n    environment: [A=first, B=x, A=last]\n"
    result = analyze(source)
    assert len(facts(result, Provider)) == 2
    assert result == analyze(source)
    assert {item.location.start_column for item in facts(result, Provider)} == {28, 33}


def test_env_file_defaults_order_and_no_filesystem_io(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("external env_file I/O attempted")

    with monkeypatch.context() as scoped:
        scoped.setattr(builtins, "open", forbidden)
        for name in ("read_bytes", "read_text", "exists", "stat", "resolve"):
            scoped.setattr(Path, name, forbidden)
        result = analyze(
            """services:
  api:
    env_file:
      - missing.env
      - path: linked.env
        required: true
      - path: optional.env
        required: false
"""
        )
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert sorted(item.location.start_line for item in facts(result, Provider)) == [4, 5, 7]


def test_unsafe_dynamic_paths_and_unknown_format_are_redacted_partial() -> None:
    result = analyze(
        f"""services:
  api:
    env_file:
      - ../../{CANARY}
      - path: ${{DYNAMIC_PATH}}
      - path: safe.env
        format: {CANARY}
"""
    )
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert len(facts(result, Provider)) == 1
    assert CANARY not in repr(result) + result.model_dump_json()


def test_invalid_encoding_fails_without_facts() -> None:
    result = analyze(b"services: \xff")
    assert result.completeness is AnalysisCompleteness.FAILED
    assert result.observations == ()


def test_invalid_service_does_not_block_safe_sibling_facts() -> None:
    result = analyze("services:\n  broken: nope\n  api:\n    environment: [SAFE]\n")
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert [item.name for item in facts(result, ConfigKey)] == ["SAFE"]


def test_no_ambient_environment_subprocess_eval_exec_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ForbiddenEnvironment(dict[str, str]):
        def __getitem__(self, key: str) -> str:
            raise AssertionError("ambient environment read")

        def get(self, key: str, default: Any = None) -> Any:
            raise AssertionError("ambient environment read")

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("forbidden capability used")

    monkeypatch.setattr(os, "environ", ForbiddenEnvironment())
    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(builtins, "eval", forbidden)
    monkeypatch.setattr(builtins, "exec", forbidden)
    result = analyze(
        f"services:\n  api:\n    environment:\n      TOKEN: ${{HOST_TOKEN:-{CANARY}}}\n"
    )
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert CANARY not in repr(result)


def test_wrong_kind_rejected() -> None:
    with pytest.raises(ValueError, match=r"CandidateKind\.COMPOSE"):
        ComposeAnalyzer().analyze(
            AnalyzerInput(
                path="compose.yaml",
                kind=CandidateKind.PYTHON,
                content=b"",
                component="app",
                root="root",
                profile=Profile.DEFAULT,
                resolver=StaticResolver(),
            )
        )
