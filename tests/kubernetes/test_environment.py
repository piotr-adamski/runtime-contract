"""Value-blind Kubernetes env/envFrom extraction contract for D2.07."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from yaml.nodes import ScalarNode

from runtime_contract.domain import SourceLocation
from runtime_contract.kubernetes import (
    KubernetesContainerContext,
    KubernetesContainerKind,
    KubernetesDiagnosticCode,
    KubernetesEnvBinding,
    KubernetesEnvFromSource,
    KubernetesEnvFromSourceKind,
    KubernetesEnvSourceKind,
    KubernetesInput,
    KubernetesLoadStatus,
    KubernetesTraversalResult,
    KubernetesWorkloadKind,
    loader,
    traverse_kubernetes_workloads,
)

FIXTURE = Path(__file__).parent / "fixtures" / "env-envfrom.yaml"
CANARIES = (
    "kubernetes-literal-value-canary-Q7Z9",
    "kubernetes-init-value-canary-Q7Z9",
)


def load(source: str | bytes) -> KubernetesTraversalResult:
    content = source.encode() if isinstance(source, str) else source
    return traverse_kubernetes_workloads(
        KubernetesInput(path="manifests/workload.yaml", content=content)
    )


def test_fixture_maps_every_env_and_env_from_source_without_values(
    capsys: pytest.CaptureFixture[str],
) -> None:
    content = FIXTURE.read_bytes()
    source = KubernetesInput(path="manifests/env-envfrom.yaml", content=content)
    result = traverse_kubernetes_workloads(source)

    assert result.status is KubernetesLoadStatus.COMPLETE
    app = next(item for item in result.contexts if item.container_name == "app")
    migrate = next(item for item in result.contexts if item.container_name == "migrate")
    assert [(item.index, item.name, item.source_kind) for item in app.env] == [
        (0, "LITERAL_VALUE", KubernetesEnvSourceKind.VALUE),
        (1, "EMPTY_DEFAULT", KubernetesEnvSourceKind.VALUE),
        (2, "SECRET_TOKEN", KubernetesEnvSourceKind.SECRET_KEY_REF),
        (3, "CONFIG_VALUE", KubernetesEnvSourceKind.CONFIG_MAP_KEY_REF),
        (4, "POD_NAME", KubernetesEnvSourceKind.FIELD_REF),
        (5, "CPU_LIMIT", KubernetesEnvSourceKind.RESOURCE_FIELD_REF),
    ]
    secret = app.env[2]
    assert (secret.reference_name, secret.reference_key, secret.optional) == (
        "missing-secret",
        "token",
        False,
    )
    config = app.env[3]
    assert (config.reference_name, config.reference_key, config.optional) == (
        "missing-config",
        "setting",
        True,
    )
    field = app.env[4]
    assert (field.field_api_version, field.field_path) == ("v1", "metadata.name")
    resource = app.env[5]
    assert (resource.resource_container, resource.resource, resource.divisor) == (
        "app",
        "limits.cpu",
        "1m",
    )
    assert [
        (item.index, item.source_kind, item.reference_name, item.optional, item.prefix)
        for item in app.env_from
    ] == [
        (0, KubernetesEnvFromSourceKind.CONFIG_MAP_REF, "missing-config-bulk", False, "CM_"),
        (1, KubernetesEnvFromSourceKind.SECRET_REF, "missing-secret-bulk", True, "SECRET_"),
    ]
    assert [(item.index, item.name) for item in migrate.env] == [(0, "INIT_READY")]
    assert all(item.location.path == source.path for item in app.env)
    assert all(item.location.path == source.path for item in app.env_from)

    public = repr(source) + source.model_dump_json() + repr(result) + result.model_dump_json()
    public += json.dumps(result.model_dump(mode="json"), sort_keys=True)
    captured = capsys.readouterr()
    public += captured.out + captured.err
    for canary in CANARIES:
        assert canary not in public
    assert "content" not in source.model_dump()


def test_external_reference_presence_is_not_resolved_in_d207() -> None:
    result = load(
        """apiVersion: v1
kind: Pod
metadata: {name: api}
spec:
  containers:
    - name: app
      env:
        - name: REQUIRED_SECRET
          valueFrom:
            secretKeyRef: {name: absent, key: token}
        - name: OPTIONAL_CONFIG
          valueFrom:
            configMapKeyRef: {name: absent, key: setting, optional: true}
      envFrom:
        - configMapRef: {name: absent}
        - secretRef: {name: absent, optional: true}
"""
    )
    assert result.status is KubernetesLoadStatus.COMPLETE
    context = result.contexts[0]
    assert [item.optional for item in context.env] == [False, True]
    assert [item.optional for item in context.env_from] == [False, True]
    assert result.diagnostics == ()


@pytest.mark.parametrize(
    ("container_fields", "code"),
    [
        ("env: invalid", KubernetesDiagnosticCode.INVALID_ENV),
        ("env: [invalid]", KubernetesDiagnosticCode.INVALID_ENV_ENTRY),
        ("env: [{value: hidden}]", KubernetesDiagnosticCode.INVALID_ENV_ENTRY),
        ("env: [{name: BAD=NAME}]", KubernetesDiagnosticCode.INVALID_ENV_ENTRY),
        (
            "env: [{name: BAD, valueFrom: invalid}]",
            KubernetesDiagnosticCode.INVALID_ENV_SOURCE,
        ),
        (
            "env: [{name: BAD, valueFrom: {}}]",
            KubernetesDiagnosticCode.INVALID_ENV_SOURCE,
        ),
        (
            "env: [{name: BOTH, value: hidden, valueFrom: {fieldRef: {fieldPath: metadata.name}}}]",
            KubernetesDiagnosticCode.INVALID_ENV_SOURCE,
        ),
        ("env: [{name: NUMBER, value: 7}]", KubernetesDiagnosticCode.INVALID_ENV_SOURCE),
        (
            "env: [{name: MISSING, valueFrom: {secretKeyRef: {name: secret}}}]",
            KubernetesDiagnosticCode.INVALID_ENV_REFERENCE,
        ),
        (
            "env: [{name: BAD, valueFrom: {secretKeyRef: invalid}}]",
            KubernetesDiagnosticCode.INVALID_ENV_REFERENCE,
        ),
        (
            "env: [{name: MISSING, valueFrom: {configMapKeyRef: {key: item}}}]",
            KubernetesDiagnosticCode.INVALID_ENV_REFERENCE,
        ),
        (
            "env: [{name: BAD, valueFrom: {fieldRef: {apiVersion: 1}}}]",
            KubernetesDiagnosticCode.INVALID_ENV_REFERENCE,
        ),
        (
            "env: [{name: BAD, valueFrom: {fieldRef: invalid}}]",
            KubernetesDiagnosticCode.INVALID_ENV_REFERENCE,
        ),
        (
            "env: [{name: BAD, valueFrom: {resourceFieldRef: {divisor: 1m}}}]",
            KubernetesDiagnosticCode.INVALID_ENV_REFERENCE,
        ),
        ("envFrom: invalid", KubernetesDiagnosticCode.INVALID_ENV_FROM),
        ("envFrom: [invalid]", KubernetesDiagnosticCode.INVALID_ENV_FROM_SOURCE),
        (
            "envFrom: [{secretRef: {name: one}, configMapRef: {name: two}}]",
            KubernetesDiagnosticCode.INVALID_ENV_FROM_SOURCE,
        ),
        (
            "envFrom: [{secretRef: {optional: true}}]",
            KubernetesDiagnosticCode.INVALID_ENV_FROM_REFERENCE,
        ),
        (
            "envFrom: [{secretRef: invalid}]",
            KubernetesDiagnosticCode.INVALID_ENV_FROM_REFERENCE,
        ),
        (
            "envFrom: [{configMapRef: {name: item, optional: nope}}]",
            KubernetesDiagnosticCode.INVALID_ENV_FROM_REFERENCE,
        ),
        (
            "envFrom: [{prefix: 7, configMapRef: {name: item}}]",
            KubernetesDiagnosticCode.INVALID_ENV_FROM_SOURCE,
        ),
    ],
)
def test_malformed_sources_are_partial_and_preserve_safe_sibling(
    container_fields: str,
    code: KubernetesDiagnosticCode,
) -> None:
    result = load(
        f"""apiVersion: v1
kind: Pod
metadata: {{name: api}}
spec:
  containers:
    - name: safe
      env:
        - name: SAFE
          value: hidden-safe-canary
    - name: broken
      {container_fields}
"""
    )
    assert result.status is KubernetesLoadStatus.PARTIAL
    assert any(item.code is code for item in result.diagnostics)
    assert (
        next(item for item in result.contexts if item.container_name == "safe").env[0].name
        == "SAFE"
    )
    assert "hidden-safe-canary" not in repr(result) + result.model_dump_json()


def test_unknown_fields_and_duplicate_names_are_partial_but_deterministic() -> None:
    source = """apiVersion: v1
kind: Pod
metadata: {name: api}
spec:
  containers:
    - name: app
      env:
        - {name: DUP, value: first}
        - {name: DUP, value: second, future: ignored}
      envFrom:
        - prefix: ""
          secretRef: {name: secret, optional: yes, future: ignored}
          future: ignored
"""
    first = load(source)
    second = load(source)
    assert first == second
    assert first.status is KubernetesLoadStatus.PARTIAL
    assert [(item.index, item.name) for item in first.contexts[0].env] == [(0, "DUP"), (1, "DUP")]
    assert first.contexts[0].env_from[0].optional is True
    assert {item.code for item in first.diagnostics} >= {
        KubernetesDiagnosticCode.DUPLICATE_ENV_NAME,
        KubernetesDiagnosticCode.INVALID_ENV_ENTRY,
        KubernetesDiagnosticCode.INVALID_ENV_FROM_SOURCE,
        KubernetesDiagnosticCode.INVALID_ENV_FROM_REFERENCE,
    }
    assert "first" not in repr(first) + first.model_dump_json()
    assert "second" not in repr(first) + first.model_dump_json()


def test_direct_traversal_fails_closed_for_an_unmarked_mapping() -> None:
    result = load('{"name":"fixture","items":[1,2,3]}')
    assert result.status is KubernetesLoadStatus.FAILED
    assert result.contexts == ()
    assert result.diagnostics[0].code is KubernetesDiagnosticCode.MISSING_API_VERSION


def test_environment_entry_limits_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    source = """apiVersion: v1
kind: Pod
metadata: {name: api}
spec:
  containers:
    - name: app
      env: [{name: A}]
      envFrom: [{secretRef: {name: secret}}]
"""
    monkeypatch.setattr(loader, "MAX_ENV_ENTRIES", 0)
    env = load(source)
    assert env.status is KubernetesLoadStatus.PARTIAL
    assert env.contexts[0].env == ()
    monkeypatch.setattr(loader, "MAX_ENV_ENTRIES", 4_096)
    monkeypatch.setattr(loader, "MAX_ENV_FROM_ENTRIES", 0)
    env_from = load(source)
    assert env_from.status is KubernetesLoadStatus.PARTIAL
    assert env_from.contexts[0].env_from == ()


def test_noncanonical_boolean_node_is_rejected_without_exposing_its_text() -> None:
    node = ScalarNode(tag="tag:yaml.org,2002:bool", value="boolean-canary-Q7Z9")
    assert loader._optional_bool((node, node)) == (False, False)


def test_environment_models_reject_cross_source_metadata_and_unsafe_locations() -> None:
    location = SourceLocation(path="a.yaml", start_line=1)
    other = SourceLocation(path="b.yaml", start_line=1)
    with pytest.raises(ValidationError, match="cannot contain NUL"):
        KubernetesEnvBinding(
            name="A\0value-canary",
            index=0,
            source_kind=KubernetesEnvSourceKind.VALUE,
            location=location,
            source_location=location,
        )
    with pytest.raises(ValidationError, match="non-empty"):
        KubernetesEnvBinding(
            name="BAD=NAME",
            index=0,
            source_kind=KubernetesEnvSourceKind.VALUE,
            location=location,
            source_location=location,
        )
    with pytest.raises(ValidationError, match="value bindings"):
        KubernetesEnvBinding(
            name="A",
            index=0,
            source_kind=KubernetesEnvSourceKind.VALUE,
            reference_name="secret",
            location=location,
            source_location=location,
        )
    with pytest.raises(ValidationError, match="key references"):
        KubernetesEnvBinding(
            name="A",
            index=0,
            source_kind=KubernetesEnvSourceKind.SECRET_KEY_REF,
            reference_name="secret",
            optional=False,
            location=location,
            source_location=location,
        )
    with pytest.raises(ValidationError, match="fieldRef"):
        KubernetesEnvBinding(
            name="A",
            index=0,
            source_kind=KubernetesEnvSourceKind.FIELD_REF,
            location=location,
            source_location=location,
        )
    with pytest.raises(ValidationError, match="resourceFieldRef"):
        KubernetesEnvBinding(
            name="A",
            index=0,
            source_kind=KubernetesEnvSourceKind.RESOURCE_FIELD_REF,
            location=location,
            source_location=location,
        )
    with pytest.raises(ValidationError, match="same path"):
        KubernetesEnvBinding(
            name="A",
            index=0,
            source_kind=KubernetesEnvSourceKind.VALUE,
            location=location,
            source_location=other,
        )
    nested = KubernetesEnvBinding(
        name="A",
        index=0,
        source_kind=KubernetesEnvSourceKind.VALUE,
        location=other,
        source_location=other,
    )
    with pytest.raises(ValidationError, match="environment locations"):
        KubernetesContainerContext(
            path="a.yaml",
            document_index=1,
            api_version="v1",
            workload_kind=KubernetesWorkloadKind.POD,
            workload_name="api",
            namespace="default",
            container_kind=KubernetesContainerKind.CONTAINER,
            container_name="app",
            container_index=0,
            workload_location=location,
            container_location=location,
            env=(nested,),
        )
    with pytest.raises(ValidationError, match="non-empty"):
        KubernetesEnvFromSource(
            source_kind=KubernetesEnvFromSourceKind.SECRET_REF,
            index=0,
            reference_name="",
            optional=False,
            location=location,
            source_location=location,
        )
    with pytest.raises(ValidationError, match="same path"):
        KubernetesEnvFromSource(
            source_kind=KubernetesEnvFromSourceKind.CONFIG_MAP_REF,
            index=0,
            reference_name="config",
            optional=False,
            location=location,
            source_location=other,
        )
