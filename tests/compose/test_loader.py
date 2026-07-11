"""Security, syntax, limit, and determinism contract for Compose loading."""

from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from runtime_contract.compose import (
    MAX_BINDING_NAME_BYTES,
    MAX_BUILD_ARG_ENTRIES,
    MAX_COMPOSE_BYTES,
    MAX_ENV_FILE_ENTRIES,
    MAX_ENV_FILE_PATH_BYTES,
    MAX_ENVIRONMENT_ENTRIES,
    ComposeBinding,
    ComposeBindingKind,
    ComposeDiagnostic,
    ComposeDiagnosticCode,
    ComposeEnvFile,
    ComposeInput,
    ComposeInterpolation,
    ComposeInterpolationOperator,
    ComposeLoadResult,
    ComposeLoadStatus,
    ComposeService,
    load_compose,
)
from runtime_contract.compose import loader as compose_loader
from runtime_contract.domain import SourceLocation


def load(text: str | bytes, path: str = "deploy/compose.yaml") -> ComposeLoadResult:
    content = text if isinstance(text, bytes) else text.encode()
    return load_compose(ComposeInput(path=path, content=content))


@pytest.mark.parametrize("path", ["", "/compose.yaml", "../compose.yaml", "a\\b.yml", "a\0b"])
def test_input_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        ComposeInput(path=path, content=b"services: {}")


def test_input_normalizes_nfc_and_requires_exact_bytes() -> None:
    assert ComposeInput(path="de\u0301ploy/compose.yaml", content=b"").path == (
        "d\u00e9ploy/compose.yaml"
    )
    with pytest.raises(ValidationError):
        ComposeInput.model_validate({"path": "compose.yaml", "content": bytearray()})


def test_public_model_invariants_are_strict_and_frozen() -> None:
    location = SourceLocation(path="compose.yaml", start_line=1, start_column=1)
    with pytest.raises(ValidationError):
        ComposeInterpolation(
            name="not-valid-name",
            operator=ComposeInterpolationOperator.DIRECT,
            location=location,
        )
    with pytest.raises(ValidationError):
        ComposeService(name="api", location=location, profiles=("prod",))
    with pytest.raises(ValidationError):
        ComposeLoadResult(
            status=ComposeLoadStatus.FAILED,
            services=(ComposeService(name="api", location=location),),
        )
    with pytest.raises(ValidationError):
        ComposeLoadResult.model_validate({"status": "complete", "extra": True})


@pytest.mark.parametrize(
    "content",
    [
        "services: {}\n",
        "\ufeffservices: {}\n",
        "services: {}\r\n",
        "services: {}",
    ],
)
def test_encoding_line_endings_bom_and_no_final_newline(content: str) -> None:
    result = load(content)
    assert result.status is ComposeLoadStatus.COMPLETE
    assert result.services == ()


def test_services_profiles_locations_sorting_and_empty_profiles() -> None:
    result = load(
        """services:
  zed:
    profiles: [prod, dev]
  api:
    profiles: []
  worker: {}
"""
    )
    assert result.status is ComposeLoadStatus.COMPLETE
    assert [item.name for item in result.services] == ["api", "worker", "zed"]
    zed = result.services[-1]
    assert zed.profiles == ("dev", "prod")
    assert (zed.location.start_line, zed.location.start_column) == (2, 3)
    assert [(item.start_line, item.start_column) for item in zed.profile_locations] == [
        (3, 22),
        (3, 16),
    ]


def test_structural_bindings_and_env_files_preserve_declared_priority() -> None:
    result = load(
        """services:
  api:
    environment: [A=first, B=x, A=last]
    env_file:
      - base.env
      - path: raw.env
        required: false
        format: raw
    build:
      args: [VERSION=one, VERSION=two, BARE]
"""
    )
    service = result.services[0]
    assert [(item.name, item.priority) for item in service.bindings] == [
        ("B", 1),
        ("A", 2),
        ("VERSION", 1),
        ("BARE", 2),
    ]
    assert [
        (item.path, item.required, item.format, item.priority) for item in service.env_files
    ] == [
        ("base.env", True, None, 0),
        ("raw.env", False, "raw", 1),
    ]


@pytest.mark.parametrize(
    ("field", "limit"),
    [
        ("environment", MAX_ENVIRONMENT_ENTRIES),
        ("build_args", MAX_BUILD_ARG_ENTRIES),
        ("env_file", MAX_ENV_FILE_ENTRIES),
    ],
)
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_new_collection_limits(field: str, limit: int, delta: int) -> None:
    count = limit + delta
    if field == "environment":
        body = "    environment:\n" + "".join(f"      K{i}: x\n" for i in range(count))
    elif field == "build_args":
        body = "    build:\n      args:\n" + "".join(f"        K{i}: x\n" for i in range(count))
    else:
        body = "    env_file:\n" + "".join(f"      - f{i}.env\n" for i in range(count))
    result = load("services:\n  api:\n" + body)
    assert (result.status is ComposeLoadStatus.FAILED) is (delta == 1)
    if delta == 1:
        assert result.services == ()
        assert result.diagnostics[0].code is ComposeDiagnosticCode.SAFETY_LIMIT


@pytest.mark.parametrize("limit_kind", ["name", "path"])
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_new_scalar_limits(limit_kind: str, delta: int) -> None:
    if limit_kind == "name":
        value = "A" * (MAX_BINDING_NAME_BYTES + delta)
        source = f"services:\n  api:\n    environment:\n      {value}: x\n"
    else:
        value = "a" * (MAX_ENV_FILE_PATH_BYTES - 4 + delta) + ".env"
        source = f"services:\n  api:\n    env_file: {value}\n"
    result = load(source)
    assert (result.status is ComposeLoadStatus.FAILED) is (delta == 1)


@pytest.mark.parametrize(
    "body",
    [
        "build: []",
        "environment: {1: x}",
        "environment: [{A: x}]",
        "environment: scalar",
        "environment: [BAD-NAME=x]",
        'env_file: {path: safe.env, required: "yes"}',
        "env_file: {required: false}",
    ],
)
def test_invalid_new_constructs_are_redacted_partial(body: str) -> None:
    result = load(f"services:\n  api:\n    {body}\n")
    assert result.status is ComposeLoadStatus.PARTIAL
    assert result.diagnostics


def test_new_public_model_validators_reject_unsafe_metadata() -> None:
    location = SourceLocation(path="compose.yaml", start_line=1, start_column=1)
    with pytest.raises(ValidationError):
        ComposeBinding(
            name="BAD-NAME",
            kind=ComposeBindingKind.ENVIRONMENT,
            location=location,
            priority=0,
        )
    for path in ("/absolute.env", "../escape.env"):
        with pytest.raises(ValidationError):
            ComposeEnvFile(path=path, location=location, priority=0)


def test_anchors_aliases_merge_and_explicit_override_preserve_source_locations() -> None:
    result = load(
        """x-defaults: &defaults
  image: image:${TAG}
  profiles: [base]
services:
  api:
    <<: *defaults
    profiles: [explicit]
  worker: *defaults
"""
    )
    assert result.status is ComposeLoadStatus.COMPLETE
    assert [service.profiles for service in result.services] == [("explicit",), ("base",)]
    assert [item.name for item in result.interpolations] == ["TAG", "TAG"]
    assert {item.service for item in result.interpolations} == {"api", "worker"}
    assert all(item.location.start_line == 2 for item in result.interpolations)


def test_all_interpolation_forms_nested_escaped_and_mapping_keys() -> None:
    result = load(
        """services:
  api:
    image: $A ${B} ${C:-x} ${D-x} ${E:?x} ${F?x} ${G:+x} ${H+x} ${OUTER:-${INNER}}
    environment:
      - CASH=$$LITERAL
      - KEY=$VALUE
    $NOT_A_VALUE: ignored
"""
    )
    assert result.status is ComposeLoadStatus.COMPLETE
    assert [item.name for item in result.interpolations] == [
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "OUTER",
        "INNER",
        "VALUE",
    ]
    assert [item.operator for item in result.interpolations[2:8]] == [
        ComposeInterpolationOperator.DEFAULT_IF_UNSET_OR_EMPTY,
        ComposeInterpolationOperator.DEFAULT_IF_UNSET,
        ComposeInterpolationOperator.ERROR_IF_UNSET_OR_EMPTY,
        ComposeInterpolationOperator.ERROR_IF_UNSET,
        ComposeInterpolationOperator.ALTERNATE_IF_SET_AND_NONEMPTY,
        ComposeInterpolationOperator.ALTERNATE_IF_SET,
    ]


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (b"\xff", ComposeDiagnosticCode.INVALID_ENCODING),
        (b"services: [", ComposeDiagnosticCode.INVALID_YAML),
        (b"", ComposeDiagnosticCode.INVALID_YAML),
        (b"[]\n", ComposeDiagnosticCode.INVALID_SERVICES),
        (b"services: {}\n---\nservices: {}\n", ComposeDiagnosticCode.MULTIPLE_DOCUMENTS),
        (b"name: value\n", ComposeDiagnosticCode.MISSING_SERVICES),
        (b"services: []\n", ComposeDiagnosticCode.INVALID_SERVICES),
        (b"services: &loop\n  api:\n    self: *loop\n", ComposeDiagnosticCode.CYCLIC_ALIAS),
        (b"services:\n  api:\n    <<: value\n", ComposeDiagnosticCode.INVALID_MERGE),
    ],
)
def test_fatal_inputs_fail_closed(content: bytes, code: ComposeDiagnosticCode) -> None:
    result = load(content)
    assert result.status is ComposeLoadStatus.FAILED
    assert result.services == ()
    assert result.interpolations == ()
    assert result.diagnostics[0].code is code


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (b"services:\n  api: value\n", ComposeDiagnosticCode.INVALID_SERVICE),
        (b"services:\n  1: {}\n", ComposeDiagnosticCode.INVALID_SERVICE),
        (b"services:\n  '${NAME}': {}\n", ComposeDiagnosticCode.DYNAMIC_NAME),
    ],
)
def test_invalid_individual_services_are_recoverable(
    content: bytes, code: ComposeDiagnosticCode
) -> None:
    result = load(content)
    assert result.status is ComposeLoadStatus.PARTIAL
    assert result.services == ()
    assert result.diagnostics[0].code is code


@pytest.mark.parametrize(
    ("fragment", "code"),
    [
        ("profiles: prod", ComposeDiagnosticCode.INVALID_PROFILES),
        ("profiles: [prod, prod]", ComposeDiagnosticCode.DUPLICATE_KEY),
        ("image: ${VAR/foo/bar}", ComposeDiagnosticCode.UNSUPPORTED_INTERPOLATION),
        ("thing: !custom value", ComposeDiagnosticCode.UNSUPPORTED_CONSTRUCT),
        ("thing: !reset []", ComposeDiagnosticCode.UNSUPPORTED_CONSTRUCT),
        ("thing: !override {}", ComposeDiagnosticCode.UNSUPPORTED_CONSTRUCT),
    ],
)
def test_partial_constructs_are_redacted(fragment: str, code: ComposeDiagnosticCode) -> None:
    result = load(f"services:\n  api:\n    {fragment}\n")
    assert result.status is ComposeLoadStatus.PARTIAL
    assert code in {item.code for item in result.diagnostics}


def test_non_scalar_mapping_key_and_profile_are_partial() -> None:
    result = load(
        "services:\n  api:\n    ? [complex, key]\n    : value\n    profiles: [[nested]]\n"
    )
    assert result.status is ComposeLoadStatus.PARTIAL
    assert {item.code for item in result.diagnostics} == {
        ComposeDiagnosticCode.INVALID_PROFILES,
        ComposeDiagnosticCode.UNSUPPORTED_CONSTRUCT,
    }


@pytest.mark.parametrize("value", ["$", "${}", "${BROKEN", "${1BAD}"])
def test_malformed_dollar_forms_are_stable(value: str) -> None:
    result = load(f"services: {{api: {{image: '{value}'}}}}\n")
    if value == "$":
        assert result.status is ComposeLoadStatus.COMPLETE
    else:
        assert result.status is ComposeLoadStatus.PARTIAL
        assert result.diagnostics[0].code is ComposeDiagnosticCode.UNSUPPORTED_INTERPOLATION


def test_duplicate_services_and_service_names_fail_but_other_duplicate_is_partial() -> None:
    assert load("services: {}\nservices: {}\n").status is ComposeLoadStatus.FAILED
    assert load("services:\n  api: {}\n  api: {}\n").status is ComposeLoadStatus.FAILED
    result = load("services:\n  api:\n    image: one\n    image: two\n")
    assert result.status is ComposeLoadStatus.PARTIAL
    assert result.diagnostics[0].code is ComposeDiagnosticCode.DUPLICATE_KEY


def test_include_and_file_extends_are_partial_without_exposing_paths() -> None:
    sentinel = "outside-secret-compose-X9.yaml"
    result = load(
        f"include: {sentinel}\nservices:\n  api:\n    extends:\n      file: {sentinel}\n      service: base\n"
    )
    assert result.status is ComposeLoadStatus.PARTIAL
    assert len(result.diagnostics) == 2
    assert all(
        item.code is ComposeDiagnosticCode.UNSUPPORTED_EXTERNAL_REFERENCE
        for item in result.diagnostics
    )
    assert sentinel not in repr(result) + result.model_dump_json()
    local = load("services: {api: {extends: {service: base}}}\n")
    assert local.status is ComposeLoadStatus.COMPLETE


def test_dynamic_profile_keeps_interpolation_but_not_profile_name() -> None:
    result = load("services:\n  api:\n    profiles: ['${PROFILE:-private-default}']\n")
    assert result.status is ComposeLoadStatus.PARTIAL
    assert result.services[0].profiles == ()
    assert [item.name for item in result.interpolations] == ["PROFILE"]
    assert "private-default" not in repr(result) + result.model_dump_json()


def test_file_and_scalar_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compose_loader, "MAX_COMPOSE_BYTES", 12)
    assert load(b"services: {}"[:11]).status is ComposeLoadStatus.FAILED
    assert load(b"services: {}"[:12]).status is ComposeLoadStatus.COMPLETE
    assert load(b"services: {}\n").diagnostics[0].code is ComposeDiagnosticCode.SAFETY_LIMIT
    monkeypatch.setattr(compose_loader, "MAX_COMPOSE_BYTES", MAX_COMPOSE_BYTES)
    monkeypatch.setattr(compose_loader, "MAX_SCALAR_BYTES", 8)
    assert load("services: {}\nx: aaaaaaa\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {}\nx: aaaaaaaa\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {}\nx: aaaaaaaaa\n").status is ComposeLoadStatus.FAILED


def test_each_structural_limit_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compose_loader, "MAX_COMPOSE_SERVICES", 2)
    assert load("services:\n  a: {}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services:\n  a: {}\n  b: {}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services:\n  a: {}\n  b: {}\n  c: {}\n").status is ComposeLoadStatus.FAILED
    monkeypatch.setattr(compose_loader, "MAX_PROFILES_PER_SERVICE", 2)
    assert load("services: {a: {profiles: [x]}}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {a: {profiles: [x, y]}}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {a: {profiles: [x, y, z]}}\n").status is ComposeLoadStatus.FAILED
    monkeypatch.setattr(compose_loader, "MAX_INTERPOLATIONS", 2)
    assert load("services: {a: {image: '$A'}}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {a: {image: '$A$B'}}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {a: {image: '$A$B$C'}}\n").status is ComposeLoadStatus.FAILED


def test_node_depth_and_alias_merge_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compose_loader, "MAX_YAML_DEPTH", 4)
    assert load("services: {}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {a: {}}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {a: {x: {y: z}}}\n").status is ComposeLoadStatus.FAILED
    monkeypatch.setattr(compose_loader, "MAX_YAML_DEPTH", 64)
    monkeypatch.setattr(compose_loader, "MAX_YAML_NODES", 7)
    assert load("services: {}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {a: {}}\n").status is ComposeLoadStatus.COMPLETE
    assert load("services: {a: {}, b: {}, c: {}}\n").status is ComposeLoadStatus.FAILED
    monkeypatch.setattr(compose_loader, "MAX_YAML_NODES", 10_000)
    monkeypatch.setattr(compose_loader, "MAX_ALIAS_MERGE_REFERENCES", 3)
    assert load("x: &x {}\nservices: {a: {<<: *x}}\n").status is ComposeLoadStatus.COMPLETE
    assert load("x: &x {}\nservices: {a: {<<: [*x, *x]}}\n").status is ComposeLoadStatus.COMPLETE
    assert load("x: &x {}\nservices: {a: {<<: [*x, *x, *x]}}\n").status is ComposeLoadStatus.FAILED
    assert (
        load("x: &x {}\nrefs: [*x, *x, *x, *x]\nservices: {}\n").status is ComposeLoadStatus.FAILED
    )


def test_canaries_never_escape_and_no_execution_or_external_reads(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    canaries = (
        "token-value-Q7Z9",
        "postgres://user:pass@host/db",
        "/private/host/path",
        "private-error-message",
        "private-default-value",
        "private-replacement-value",
    )

    def forbidden(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise AssertionError("forbidden execution or I/O surface")

    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(builtins, "eval", forbidden)
    monkeypatch.setattr(builtins, "exec", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    source = f"""include: {canaries[2]}
services:
  api:
    image: {canaries[0]}
    environment:
      - DSN={canaries[1]}
      - A=${{A:?{canaries[3]}}}
      - B=${{B:-{canaries[4]}}}
      - C=${{C:+{canaries[5]}}}
    env_file: {canaries[2]}
    build: {canaries[2]}
    configs: [{canaries[2]}]
    secrets: [{canaries[2]}]
    volumes: [{canaries[2]}]
"""
    result = load(source)
    captured = capsys.readouterr()
    channels = "\n".join(
        (
            repr(result),
            result.model_dump_json(),
            json.dumps(result.model_dump(mode="json")),
            repr(result.diagnostics),
            captured.out,
            captured.err,
        )
    )
    assert all(canary not in channels for canary in canaries)
    assert [item.name for item in result.interpolations] == ["A", "B", "C"]


def test_deterministic_across_calls_order_and_ambient_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = load("services:\n  z: {profiles: [b, a]}\n  a: {image: '$Z$A'}\n")
    second = load("services:\n  a: {image: '$Z$A'}\n  z: {profiles: [a, b]}\n")
    assert [(item.name, item.profiles) for item in first.services] == [
        (item.name, item.profiles) for item in second.services
    ]
    assert [(item.name, item.operator) for item in first.interpolations] == [
        (item.name, item.operator) for item in second.interpolations
    ]
    monkeypatch.setenv("A", "ambient-one")
    one = load("services: {a: {image: '${A:-private}'}}\n")
    monkeypatch.setenv("A", "ambient-two")
    two = load("services: {a: {image: '${A:-private}'}}\n")
    assert one == two


def test_internal_deduplication_keeps_one_diagnostic() -> None:
    location = SourceLocation(path="compose.yaml", start_line=1, start_column=1)
    item = ComposeDiagnostic(
        code=ComposeDiagnosticCode.UNSUPPORTED_CONSTRUCT,
        location=location,
        message="Custom YAML tags are not supported.",
    )
    assert compose_loader._unique_sorted([item, item], compose_loader._diagnostic_key) == (item,)
