"""Docker Compose project resolution contract tests for D2.05."""

from __future__ import annotations

import builtins
import os
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from runtime_contract.analysis import AnalyzerInput, FactKind
from runtime_contract.analysis.compose import ComposeAnalyzer
from runtime_contract.analysis.models import EffectiveClassification
from runtime_contract.compose import (
    ComposeDiagnosticCode,
    ComposeInput,
    ComposeInterpolationResolution,
    ComposeLoadStatus,
    ComposeProjectInput,
    ComposeProjectResult,
    ComposeProvenanceOperation,
    ComposeProvenanceOutcome,
    ComposeServiceActivation,
    ComposeSourceKind,
    ComposeVariableSourceInput,
    ComposeVariableSourceKind,
    resolve_compose_project,
)
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import Profile, Provider, ProviderMechanism


def compose(path: str, text: str) -> ComposeInput:
    return ComposeInput(path=path, content=text.encode())


def project(*files: ComposeInput, **kwargs: Any) -> ComposeProjectResult:
    return resolve_compose_project(ComposeProjectInput(files=files, **kwargs))


def service(result: ComposeProjectResult, name: str = "web") -> Any:
    return next(item for item in result.services if item.name == name)


def names(result: ComposeProjectResult, kind: str = "environment") -> list[str]:
    return [item.name for item in service(result).bindings if item.kind.value == kind]


BASE = compose(
    "deploy/base.yaml",
    """services:
  web:
    profiles: [debug]
    environment:
      KEEP: base
      CHANGE: base-secret-X9
    build:
      args:
        MODE: base
    env_file: [base.env]
""",
)


def test_multifile_fixture_bundle() -> None:
    root = Path(__file__).parents[1] / "fixtures" / "compose" / "project"
    result = project(
        ComposeInput(path="project/base.yaml", content=(root / "base.yaml").read_bytes()),
        ComposeInput(path="project/override.yaml", content=(root / "override.yaml").read_bytes()),
    )
    assert result.status is ComposeLoadStatus.COMPLETE
    assert names(result) == ["BASE_ONLY", "SHARED", "OVERRIDE_ONLY"]


def test_base_override_and_exact_file_order_with_new_service() -> None:
    one = compose(
        "deploy/one.yaml",
        """services:
  web:
    environment: [CHANGE=one, ONE=one]
  worker:
    environment: {WORKER: yes}
""",
    )
    two = compose(
        "deploy/two.yaml",
        """services:
  web:
    environment: {CHANGE: two, TWO: two}
""",
    )
    result = project(BASE, one, two)
    assert result.status is ComposeLoadStatus.COMPLETE
    assert [item.name for item in result.services] == ["web", "worker"]
    assert names(result) == ["KEEP", "CHANGE", "ONE", "TWO"]
    assert next(
        item for item in service(result).bindings if item.name == "CHANGE"
    ).location.path == ("deploy/two.yaml")
    trace = next(item for item in result.resolution_traces if item.subject.endswith("/CHANGE"))
    assert [item.source_path for item in trace.contributions] == [
        "deploy/base.yaml",
        "deploy/one.yaml",
        "deploy/two.yaml",
    ]
    assert [item.outcome for item in trace.contributions] == [
        ComposeProvenanceOutcome.SUPERSEDED,
        ComposeProvenanceOutcome.SUPERSEDED,
        ComposeProvenanceOutcome.EFFECTIVE,
    ]


def test_build_args_env_file_and_profiles_merge_in_semantic_order() -> None:
    override = compose(
        "deploy/override.yaml",
        """services:
  web:
    profiles: [test, debug]
    build: {args: {MODE: final, EXTRA: yes}}
    env_file: [override.env]
""",
    )
    result = project(BASE, override)
    web = service(result)
    assert web.profiles == ("debug", "test")
    debug_trace = next(item for item in result.resolution_traces if item.subject.endswith("/debug"))
    assert debug_trace.winner_index == 0
    assert [
        (item.name, item.location.path) for item in web.bindings if item.kind.value == "build_arg"
    ] == [
        ("MODE", "deploy/override.yaml"),
        ("EXTRA", "deploy/override.yaml"),
    ]
    assert [item.path for item in web.env_files] == [
        "deploy/base.env",
        "deploy/override.env",
    ]


def test_reset_key_and_reset_sequences_are_value_blind() -> None:
    override = compose(
        "deploy/reset.yaml",
        """services:
  web:
    environment:
      CHANGE: !reset ignored-secret-X9
    profiles: !reset []
    env_file: !reset []
""",
    )
    result = project(BASE, override)
    assert names(result) == ["KEEP"]
    assert service(result).profiles == ()
    assert service(result).env_files == ()
    dumped = result.model_dump_json()
    assert "ignored-secret-X9" not in dumped
    removed = next(item for item in result.resolution_traces if item.subject.endswith("/CHANGE"))
    assert removed.winner_index is None
    assert removed.contributions[-1].operation is ComposeProvenanceOperation.RESET
    assert removed.contributions[-1].outcome is ComposeProvenanceOutcome.REMOVED
    profile_trace = next(
        item for item in result.resolution_traces if item.subject.endswith("/debug")
    )
    assert profile_trace.winner_index is None


def test_override_replaces_sequences() -> None:
    override = compose(
        "deploy/override.yaml",
        """services:
  web:
    profiles: !override [prod]
    env_file: !override [only.env]
""",
    )
    result = project(BASE, override)
    assert service(result).profiles == ("prod",)
    assert [item.path for item in service(result).env_files] == ["deploy/only.env"]


@pytest.mark.parametrize(
    ("active", "expected"),
    [
        ((), ComposeServiceActivation.PROFILE_DISABLED),
        (("debug",), ComposeServiceActivation.PROFILE_ENABLED),
        (("other", "debug"), ComposeServiceActivation.PROFILE_ENABLED),
        (("*",), ComposeServiceActivation.PROFILE_ENABLED),
        (("other",), ComposeServiceActivation.PROFILE_DISABLED),
    ],
)
def test_profile_activation(active: tuple[str, ...], expected: ComposeServiceActivation) -> None:
    assert service(project(BASE, active_profiles=active)).activation is expected


def test_service_without_profiles_is_always_enabled() -> None:
    result = project(compose("compose.yaml", "services: {web: {environment: {A: x}}}\n"))
    assert service(result).activation is ComposeServiceActivation.ALWAYS_ENABLED


@pytest.mark.parametrize("profile", ["x", "bad space", "-bad", "_bad"])
def test_invalid_profile_is_atomic(profile: str) -> None:
    result = project(BASE, active_profiles=(profile,))
    assert result.status is ComposeLoadStatus.FAILED
    assert result.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROFILE
    assert not result.services and not result.interpolations and not result.resolution_traces


def test_interpolation_precedence_and_service_env_file_separation() -> None:
    source = compose(
        "compose.yaml",
        """services:
  web:
    image: ${IMAGE}
    command: ${MISSING} ${FALLBACK:-secret-fallback-X9}
    env_file: [runtime.env]
""",
    )
    cli1 = ComposeVariableSourceInput(
        kind=ComposeVariableSourceKind.CLI_ENV_FILE,
        path="first.env",
        content=b"IMAGE=first-secret-X9\n",
    )
    cli2 = ComposeVariableSourceInput(
        kind=ComposeVariableSourceKind.CLI_ENV_FILE,
        path="second.env",
        content=b"IMAGE=second-secret-X9\n",
    )
    dotenv = ComposeVariableSourceInput(
        kind=ComposeVariableSourceKind.PROJECT_DOTENV,
        path=".env",
        content=b"IMAGE=dotenv-secret-X9\n",
    )
    result = project(
        source,
        interpolation_sources=(dotenv, cli1, cli2),
        shell_variable_names=("IMAGE",),
    )
    by_name = {item.name: item for item in result.interpolations}
    assert by_name["IMAGE"].resolved_source_kind is ComposeSourceKind.EXPLICIT_SHELL_NAME
    assert by_name["MISSING"].resolution is ComposeInterpolationResolution.UNRESOLVED
    assert by_name["FALLBACK"].resolution is ComposeInterpolationResolution.FALLBACK
    assert service(result).env_files[0].path == "runtime.env"
    assert all(item.kind is not ComposeSourceKind.PROJECT_DOTENV for item in result.used_sources)
    dumped = result.model_dump_json()
    assert "first-secret-X9" not in dumped
    assert "second-secret-X9" not in dumped
    assert "dotenv-secret-X9" not in dumped
    assert "secret-fallback-X9" not in dumped


def test_later_cli_env_file_wins_and_dotenv_is_default_only() -> None:
    source = compose("compose.yaml", "services: {web: {image: '${IMAGE}'}}\n")
    first = ComposeVariableSourceInput(
        kind=ComposeVariableSourceKind.CLI_ENV_FILE, path="a.env", content=b"IMAGE=a\n"
    )
    second = ComposeVariableSourceInput(
        kind=ComposeVariableSourceKind.CLI_ENV_FILE, path="b.env", content=b"IMAGE=b\n"
    )
    result = project(source, interpolation_sources=(first, second))
    assert result.interpolations[0].resolved_source_path == "b.env"
    dotenv = first.model_copy(
        update={"kind": ComposeVariableSourceKind.PROJECT_DOTENV, "path": ".env"}
    )
    default = project(source, interpolation_sources=(dotenv,))
    assert default.interpolations[0].resolved_source_kind is ComposeSourceKind.PROJECT_DOTENV


def test_local_and_recursive_include() -> None:
    root = compose("root/compose.yaml", "include: [nested/one.yaml]\nservices: {api: {}}\n")
    one = compose("root/nested/one.yaml", "include: [two.yaml]\nservices: {worker: {}}\n")
    two = compose("root/nested/two.yaml", "services: {cron: {}}\n")
    result = project(root, one, two)
    assert result.status is ComposeLoadStatus.COMPLETE
    assert [item.name for item in result.services] == ["cron", "worker", "api"]


def test_include_conflict_missing_cycle_and_remote_are_atomic() -> None:
    conflict_root = compose("compose.yaml", "include: [lib.yaml]\nservices: {web: {}}\n")
    conflict_lib = compose("lib.yaml", "services: {web: {}}\n")
    assert project(conflict_root, conflict_lib).diagnostics[0].code is (
        ComposeDiagnosticCode.MERGE_CONFLICT
    )
    missing = project(compose("compose.yaml", "include: [missing.yaml]\nservices: {}\n"))
    assert missing.diagnostics[0].code is ComposeDiagnosticCode.MISSING_REFERENCE
    a = compose("a.yaml", "include: [b.yaml]\nservices: {}\n")
    b = compose("b.yaml", "include: [a.yaml]\nservices: {}\n")
    assert project(a, b).diagnostics[0].code is ComposeDiagnosticCode.CYCLIC_REFERENCE
    remote = project(compose("compose.yaml", "include: [https://x/y]\nservices: {}\n"))
    assert remote.diagnostics[0].code is ComposeDiagnosticCode.REMOTE_REFERENCE
    for result in (missing, project(a, b), remote):
        assert not result.services and not result.interpolations and not result.resolution_traces


def test_local_and_cross_file_extends_preserve_source_provenance() -> None:
    local = compose(
        "compose.yaml",
        """services:
  base: {environment: {BASE: x}}
  web:
    extends: {service: base}
    environment: {LOCAL: x}
""",
    )
    result = project(local)
    assert [item.name for item in service(result, "web").bindings] == ["BASE", "LOCAL"]
    root = compose(
        "root/compose.yaml",
        "services: {web: {extends: {file: shared/base.yaml, service: base}, environment: {LOCAL: x}}}\n",
    )
    shared = compose(
        "root/shared/base.yaml",
        "services: {base: {environment: {BASE: x}, env_file: [base.env]}}\n",
    )
    cross = project(root, shared)
    assert [item.name for item in service(cross).bindings] == ["BASE", "LOCAL"]
    assert service(cross).env_files[0].path == "root/shared/base.env"
    trace = next(item for item in cross.resolution_traces if item.subject.endswith("/BASE"))
    assert trace.contributions[0].source_path == "root/shared/base.yaml"


def test_extends_cycle_and_missing_are_failed() -> None:
    cyclic = compose(
        "compose.yaml",
        "services: {a: {extends: {service: b}}, b: {extends: {service: a}}}\n",
    )
    assert project(cyclic).diagnostics[0].code is ComposeDiagnosticCode.CYCLIC_REFERENCE
    missing = compose("compose.yaml", "services: {web: {extends: {service: absent}}}\n")
    assert project(missing).diagnostics[0].code is ComposeDiagnosticCode.MISSING_REFERENCE


@pytest.mark.parametrize(
    "reference",
    ["../escape.yaml", "/absolute.yaml", "C:/drive.yaml", "bad\\path.yaml", "bad\0path"],
)
def test_unsafe_reference_shapes_are_rejected(reference: str) -> None:
    text = f"include: ['{reference}']\nservices: {{}}\n"
    result = project(compose("root/compose.yaml", text))
    assert result.status is ComposeLoadStatus.FAILED


def test_duplicate_nfc_path_and_project_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        ComposeProjectInput(files=())
    duplicate = project(
        compose("de\u0301ploy/a.yaml", "services: {}\n"),
        compose("d\u00e9ploy/a.yaml", "services: {}\n"),
    )
    assert duplicate.diagnostics[0].code is ComposeDiagnosticCode.DUPLICATE_PROJECT_PATH
    monkeypatch.setattr("runtime_contract.compose.project.MAX_PROJECT_FILES", 1)
    assert project(BASE, compose("other.yaml", "services: {}\n")).diagnostics[0].code is (
        ComposeDiagnosticCode.PROJECT_SIZE_LIMIT
    )
    monkeypatch.setattr("runtime_contract.compose.project.MAX_PROJECT_FILES", 128)
    monkeypatch.setattr("runtime_contract.compose.project.MAX_PROJECT_BYTES", 1)
    assert project(BASE).diagnostics[0].code is ComposeDiagnosticCode.PROJECT_SIZE_LIMIT


def test_provenance_limit_is_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("runtime_contract.compose.project.MAX_PROVENANCE_STEPS", 0)
    result = project(BASE)
    assert result.diagnostics[0].code is ComposeDiagnosticCode.PROVENANCE_LIMIT
    assert not result.services and not result.resolution_traces


def test_reference_depth_count_and_name_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    root = compose("root.yaml", "include: [child.yaml]\nservices: {}\n")
    child = compose("child.yaml", "services: {web: {}}\n")
    monkeypatch.setattr("runtime_contract.compose.project.MAX_REFERENCE_DEPTH", 0)
    assert project(root, child).diagnostics[0].code is ComposeDiagnosticCode.CYCLIC_REFERENCE
    monkeypatch.setattr("runtime_contract.compose.project.MAX_REFERENCE_DEPTH", 32)
    monkeypatch.setattr("runtime_contract.compose.project.MAX_PROJECT_REFERENCES", 0)
    assert project(root, child).diagnostics[0].code is ComposeDiagnosticCode.PROVENANCE_LIMIT
    monkeypatch.setattr("runtime_contract.compose.project.MAX_PROJECT_REFERENCES", 1_024)
    monkeypatch.setattr("runtime_contract.compose.project.MAX_ACTIVE_PROFILES", 0)
    assert project(BASE, active_profiles=("debug",)).diagnostics[0].code is (
        ComposeDiagnosticCode.INVALID_PROFILE
    )
    monkeypatch.setattr("runtime_contract.compose.project.MAX_ACTIVE_PROFILES", 256)
    monkeypatch.setattr("runtime_contract.compose.project.MAX_SHELL_VARIABLE_NAMES", 0)
    assert project(BASE, shell_variable_names=("A",)).diagnostics[0].code is (
        ComposeDiagnosticCode.INVALID_PROJECT_INPUT
    )


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("[]\n", ComposeDiagnosticCode.INVALID_PROJECT_INPUT),
        ("services: []\n", ComposeDiagnosticCode.INVALID_SERVICES),
        ('services: {"${NAME}": {}}\n', ComposeDiagnosticCode.INVALID_SERVICE),
        ("services: {}\nservices: {}\n", ComposeDiagnosticCode.INVALID_PROJECT_INPUT),
        (
            "services: {web: {environment: !custom {A: x}}}\n",
            ComposeDiagnosticCode.INVALID_OVERRIDE_TAG,
        ),
    ],
)
def test_invalid_project_yaml_shapes(text: str, code: ComposeDiagnosticCode) -> None:
    result = project(compose("compose.yaml", text))
    assert result.status is ComposeLoadStatus.FAILED
    assert result.diagnostics[0].code is code


def test_invalid_utf8_and_multiple_documents_are_redacted() -> None:
    invalid = project(ComposeInput(path="compose.yaml", content=b"\xffsecret-X9"))
    assert invalid.diagnostics[0].code is ComposeDiagnosticCode.INVALID_YAML
    multiple = project(compose("compose.yaml", "services: {}\n---\nservices: {}\n"))
    assert multiple.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT
    assert "secret-X9" not in invalid.model_dump_json()


def test_include_mapping_and_nested_include_conflict() -> None:
    root = compose(
        "root.yaml",
        "include: [{path: one.yaml}, {path: two.yaml}]\nservices: {}\n",
    )
    one = compose("one.yaml", "services: {web: {}}\n")
    two = compose("two.yaml", "services: {web: {}}\n")
    result = project(root, one, two)
    assert result.diagnostics[0].code is ComposeDiagnosticCode.MERGE_CONFLICT
    malformed = project(compose("root.yaml", "include: [{project: x}]\nservices: {}\n"))
    assert malformed.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT


def test_dedicated_include_override_path_list_resolves_conflict() -> None:
    root = compose(
        "root.yaml",
        "include: [{path: [third/base.yaml, third/override.yaml]}]\nservices: {}\n",
    )
    base = compose("third/base.yaml", "services: {web: {environment: {A: x, B: x}}}\n")
    override = compose("third/override.yaml", "services: {web: {environment: {B: y, C: y}}}\n")
    result = project(root, base, override)
    assert result.status is ComposeLoadStatus.COMPLETE
    assert names(result) == ["A", "B", "C"]


def test_mapping_env_file_and_invalid_projection_entries() -> None:
    result = project(
        compose(
            "deploy/compose.yaml",
            """services:
  web:
    environment: ignored
    profiles: [{bad: profile}]
    env_file:
      - {path: app.env, required: false, format: raw}
""",
        )
    )
    assert result.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROFILE
    valid = project(
        compose(
            "deploy/compose.yaml",
            "services: {web: {env_file: [{path: app.env, required: false, format: raw}]}}\n",
        )
    )
    env_file = service(valid).env_files[0]
    assert (env_file.path, env_file.required, env_file.format) == (
        "deploy/app.env",
        False,
        "raw",
    )
    missing_path = project(
        compose("compose.yaml", "services: {web: {env_file: [{required: false}]}}\n")
    )
    assert missing_path.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT
    non_scalar_path = project(
        compose("compose.yaml", "services: {web: {env_file: [{path: [bad]}]}}\n")
    )
    assert non_scalar_path.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT
    non_scalar_options = project(
        compose(
            "compose.yaml",
            "services: {web: {env_file: [{path: app.env, required: [bad], format: [bad]}]}}\n",
        )
    )
    assert service(non_scalar_options).env_files[0].required is True


def test_invalid_binding_and_mapping_shapes() -> None:
    scalar = project(compose("compose.yaml", "services: {web: {environment: ignored}}\n"))
    assert scalar.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT
    invalid_name = project(
        compose("compose.yaml", "services: {web: {environment: {'bad-name': x, GOOD: x}}}\n")
    )
    assert invalid_name.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT
    invalid_profile = project(compose("compose.yaml", "services: {web: {profiles: [x]}}\n"))
    assert invalid_profile.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROFILE
    non_scalar_key = project(
        compose(
            "compose.yaml",
            "services: {web: {? [a, b]: x}}\n",
        )
    )
    assert non_scalar_key.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT


def test_yaml_anchors_and_merge_keys_resolve_before_cross_file_merge() -> None:
    source = compose(
        "compose.yaml",
        """x-env: &env
  FROM_ANCHOR: x
x-service: &service
  environment:
    <<: *env
    LOCAL: x
services:
  web:
    <<: *service
""",
    )
    result = project(source)
    assert result.status is ComposeLoadStatus.COMPLETE
    assert names(result) == ["FROM_ANCHOR", "LOCAL"]
    invalid = project(compose("compose.yaml", "services: {web: {environment: {<<: invalid}}}\n"))
    assert invalid.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT


def test_service_definition_must_be_mapping() -> None:
    result = project(compose("compose.yaml", "services: {web: image-only}\n"))
    assert result.diagnostics[0].code is ComposeDiagnosticCode.INVALID_SERVICE


def test_reference_escape_from_nested_directory() -> None:
    result = project(
        compose("root/nested/compose.yaml", "include: [../../../escape.yaml]\nservices: {}\n")
    )
    assert result.diagnostics[0].code is ComposeDiagnosticCode.REMOTE_REFERENCE


def test_invalid_extends_shapes() -> None:
    scalar = project(compose("compose.yaml", "services: {web: {extends: base}}\n"))
    assert scalar.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT
    no_service = project(compose("compose.yaml", "services: {web: {extends: {file: base.yaml}}}\n"))
    assert no_service.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT
    dynamic_file = project(
        compose("compose.yaml", "services: {web: {extends: {service: base, file: [bad]}}}\n")
    )
    assert dynamic_file.diagnostics[0].code is ComposeDiagnosticCode.INVALID_PROJECT_INPUT


def test_whole_mapping_reset_and_override_have_steps() -> None:
    reset = compose("reset.yaml", "services: {web: {environment: !reset {}}}\n")
    reset_result = project(BASE, reset)
    assert names(reset_result) == []
    trace = next(item for item in reset_result.resolution_traces if item.subject.endswith("/KEEP"))
    assert trace.contributions[-1].operation is ComposeProvenanceOperation.RESET
    override = compose("override.yaml", "services: {web: {environment: !override {ONLY: x}}}\n")
    override_result = project(BASE, override)
    assert names(override_result) == ["ONLY"]
    only = next(
        item for item in override_result.resolution_traces if item.subject.endswith("/ONLY")
    )
    assert only.contributions[-1].operation is ComposeProvenanceOperation.REPLACED


def test_invalid_dotenv_source_is_failed() -> None:
    source = compose("compose.yaml", "services: {web: {image: '${IMAGE}'}}\n")
    dotenv = ComposeVariableSourceInput(
        kind=ComposeVariableSourceKind.CLI_ENV_FILE,
        path="bad.env",
        content=b"\xffsecret-X9",
    )
    result = project(source, interpolation_sources=(dotenv,))
    assert result.status is ComposeLoadStatus.FAILED
    assert "secret-X9" not in result.model_dump_json()


def test_global_interpolation_is_reported_once() -> None:
    result = project(
        compose("compose.yaml", "name: '${PROJECT}'\nservices: {web: {image: '${IMAGE}'}}\n")
    )
    assert [(item.name, item.service) for item in result.interpolations] == [
        ("PROJECT", None),
        ("IMAGE", "web"),
    ]
    root = compose("root.yaml", "include: [child.yaml]\nservices: {}\n")
    child = compose("child.yaml", "name: '${PROJECT}'\nservices: {web: {}}\n")
    included = project(root, child)
    assert [item.name for item in included.interpolations] == ["PROJECT"]


def test_determinism_round_trip_repr_and_redacted_errors() -> None:
    source = compose("compose.yaml", "services: {web: {environment: {A: secret-X9}}}\n")
    first = project(source)
    second = project(source)
    assert first.model_dump_json() == second.model_dump_json()
    assert ComposeProjectResult.model_validate_json(first.model_dump_json()) == first
    assert "secret-X9" not in repr(source)
    bad = project(compose("bad.yaml", "services: [secret-error-X9]\n"))
    assert "secret-error-X9" not in bad.model_dump_json()


def test_no_io_environment_subprocess_socket_or_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("external capability used")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)
    result = project(BASE, shell_variable_names=("EXPLICIT",))
    assert result.status is ComposeLoadStatus.COMPLETE


class Resolver:
    def classify(self, variable: str) -> EffectiveClassification:
        return EffectiveClassification()


def test_compose_analyzer_project_emits_only_enabled_service_facts() -> None:
    source = ComposeProjectInput(
        files=(
            compose(
                "compose.yaml",
                "services: {web: {profiles: [web], environment: {A: x}}, worker: {profiles: [worker], environment: {B: x}}}\n",
            ),
        ),
        active_profiles=("web",),
    )
    context = AnalyzerInput(
        path="compose.yaml",
        kind=CandidateKind.COMPOSE,
        content=b"",
        component="app",
        root=".",
        profile=Profile.PROD,
        resolver=Resolver(),
    )
    result = ComposeAnalyzer().analyze_project(source, context)
    facts = [item.fact for item in result.observations]
    assert any(getattr(item, "target", None) == "web" for item in facts)
    assert not any(getattr(item, "target", None) == "worker" for item in facts)
    assert any(
        isinstance(item, Provider) and item.mechanism is ProviderMechanism.COMPOSE_ENVIRONMENT
        for item in facts
    )
    assert any(item.fact_kind is FactKind.CONFIG_KEY for item in result.observations)


def test_compose_analyzer_project_rejects_kind_and_maps_failed_result() -> None:
    context = AnalyzerInput(
        path="compose.yaml",
        kind=CandidateKind.DOCKERFILE,
        content=b"",
        component="app",
        root=".",
        profile=Profile.PROD,
        resolver=Resolver(),
    )
    source = ComposeProjectInput(files=(compose("compose.yaml", "services: {}\n"),))
    with pytest.raises(ValueError, match=r"CandidateKind\.COMPOSE"):
        ComposeAnalyzer().analyze_project(source, context)
    compose_context = AnalyzerInput(
        path="compose.yaml",
        kind=CandidateKind.COMPOSE,
        content=b"",
        component="app",
        root=".",
        profile=Profile.PROD,
        resolver=Resolver(),
    )
    failed = ComposeAnalyzer().analyze_project(
        ComposeProjectInput(files=(compose("compose.yaml", "services: []\n"),)),
        compose_context,
    )
    assert failed.completeness.value == "failed"


def test_failed_project_result_enforces_atomicity() -> None:
    with pytest.raises(ValidationError, match="cannot expose partial data"):
        ComposeProjectResult(
            status=ComposeLoadStatus.FAILED,
            services=project(BASE).services,
        )
