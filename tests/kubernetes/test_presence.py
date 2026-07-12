"""Presence-only ConfigMap and Secret inventory for D2.08."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from runtime_contract.domain import SourceLocation
from runtime_contract.kubernetes import (
    KubernetesDiagnosticCode,
    KubernetesInput,
    KubernetesLoadStatus,
    KubernetesObjectKeyField,
    KubernetesObjectKeyPresence,
    KubernetesObjectKind,
    KubernetesObjectPresence,
    KubernetesReferenceKind,
    KubernetesReferenceResolution,
    KubernetesSourceStatus,
    KubernetesTraversalResult,
    KubernetesWorkloadKind,
    loader,
    traverse_kubernetes_workloads,
)

SECRET_CANARY = "d208-secret-cleartext-canary-Q7Z9"
BASE64_CANARY = "ZDIwOC1zZWNyZXQtYmFzZTY0LWNhbmFyeS1RN1o5"


def source(path: str, content: str) -> KubernetesInput:
    return KubernetesInput(path=path, content=content.encode())


def test_multi_file_presence_inventory_is_names_only_and_namespace_aware(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    result = traverse_kubernetes_workloads(
        (
            source(
                "manifests/config.yaml",
                """apiVersion: v1
kind: ConfigMap
metadata: {name: app-config, namespace: tenant-a}
data:
  LOG_LEVEL: info-canary
  SHARED: first-canary
binaryData:
  CERT: Y2VydC1jYW5hcnk=
  SHARED: second-canary
""",
            ),
            source(
                "manifests/secret.yaml",
                f"""apiVersion: v1
kind: Secret
metadata: {{name: app-secret}}
data:
  TOKEN: {BASE64_CANARY}
stringData:
  PASSWORD: {SECRET_CANARY}
  TOKEN: shadowed-canary
""",
            ),
        )
    )

    assert result.status is KubernetesLoadStatus.COMPLETE
    assert [(item.path, item.status) for item in result.sources] == [
        ("manifests/config.yaml", KubernetesLoadStatus.COMPLETE),
        ("manifests/secret.yaml", KubernetesLoadStatus.COMPLETE),
    ]
    assert result.diagnostics == ()
    assert [(item.object_kind, item.namespace, item.name) for item in result.objects] == [
        (KubernetesObjectKind.CONFIG_MAP, "tenant-a", "app-config"),
        (KubernetesObjectKind.SECRET, "default", "app-secret"),
    ]
    config, secret = result.objects
    assert [(item.name, item.field) for item in config.keys] == [
        ("CERT", KubernetesObjectKeyField.BINARY_DATA),
        ("LOG_LEVEL", KubernetesObjectKeyField.DATA),
        ("SHARED", KubernetesObjectKeyField.DATA),
    ]
    assert [(item.name, item.field) for item in secret.keys] == [
        ("PASSWORD", KubernetesObjectKeyField.STRING_DATA),
        ("TOKEN", KubernetesObjectKeyField.DATA),
    ]

    captured = capsys.readouterr()
    public = repr(result) + result.model_dump_json()
    public += json.dumps(result.model_dump(mode="json"), sort_keys=True)
    public += captured.out + captured.err + caplog.text
    for forbidden in (
        SECRET_CANARY,
        BASE64_CANARY,
        "info-canary",
        "first-canary",
        "second-canary",
        "shadowed-canary",
        "Y2VydC1jYW5hcnk=",
    ):
        assert forbidden not in public


def test_configmap_and_secret_are_supported_while_other_resources_remain_rtc012() -> None:
    result = traverse_kubernetes_workloads(
        source(
            "manifests/all.yaml",
            """apiVersion: v1
kind: ConfigMap
metadata: {name: config}
data: {A: hidden}
---
apiVersion: v1
kind: Secret
metadata: {name: secret}
stringData: {B: hidden}
---
apiVersion: v1
kind: Service
metadata: {name: service}
""",
        )
    )

    assert result.status is KubernetesLoadStatus.COMPLETE
    assert len(result.objects) == 2
    assert [item.code for item in result.diagnostics] == [
        KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE
    ]


def test_references_link_only_to_same_namespace_kind_object_and_key_names() -> None:
    result = traverse_kubernetes_workloads(
        (
            source(
                "workload.yaml",
                """apiVersion: v1
kind: Pod
metadata: {name: api, namespace: tenant-a}
spec:
  containers:
    - name: app
      env:
        - name: FOUND
          valueFrom:
            secretKeyRef: {name: app-secret, key: TOKEN}
        - name: MISSING_KEY
          valueFrom:
            secretKeyRef: {name: app-secret, key: ABSENT, optional: true}
        - name: WRONG_KIND
          valueFrom:
            configMapKeyRef: {name: app-secret, key: TOKEN}
      envFrom:
        - prefix: APP_
          configMapRef: {name: app-config}
        - secretRef: {name: other-namespace}
""",
            ),
            source(
                "objects.yaml",
                """apiVersion: v1
kind: Secret
metadata: {name: app-secret, namespace: tenant-a}
data: {TOKEN: dG9rZW4tY2FuYXJ5}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: app-config, namespace: tenant-a}
data: {MODE: mode-canary}
---
apiVersion: v1
kind: Secret
metadata: {name: other-namespace, namespace: tenant-b}
data: {WRONG: wrong-canary}
""",
            ),
        )
    )

    assert result.status is KubernetesLoadStatus.COMPLETE
    assert [item.reference_kind for item in result.resolutions] == [
        KubernetesReferenceKind.CONFIG_MAP_KEY_REF,
        KubernetesReferenceKind.CONFIG_MAP_REF,
        KubernetesReferenceKind.SECRET_KEY_REF,
        KubernetesReferenceKind.SECRET_KEY_REF,
        KubernetesReferenceKind.SECRET_REF,
    ]
    by_kind_name_and_key = {
        (item.reference_kind, item.reference_name, item.reference_key): item
        for item in result.resolutions
    }
    found = by_kind_name_and_key[(KubernetesReferenceKind.SECRET_KEY_REF, "app-secret", "TOKEN")]
    assert (found.resolved_object, found.resolved_key) == (True, True)
    missing_key = by_kind_name_and_key[
        (KubernetesReferenceKind.SECRET_KEY_REF, "app-secret", "ABSENT")
    ]
    assert (missing_key.resolved_object, missing_key.resolved_key, missing_key.optional) == (
        True,
        False,
        True,
    )
    wrong_kind = next(
        item
        for item in result.resolutions
        if item.reference_kind is KubernetesReferenceKind.CONFIG_MAP_KEY_REF
    )
    assert (wrong_kind.resolved_object, wrong_kind.resolved_key) == (False, False)
    bulk = next(
        item
        for item in result.resolutions
        if item.reference_kind is KubernetesReferenceKind.CONFIG_MAP_REF
    )
    assert (bulk.resolved_object, bulk.resolved_keys, bulk.prefix) == (
        True,
        ("MODE",),
        "APP_",
    )
    cross_namespace = next(
        item
        for item in result.resolutions
        if item.reference_kind is KubernetesReferenceKind.SECRET_REF
    )
    assert not cross_namespace.resolved_object
    assert cross_namespace.resolved_keys == ()
    public = repr(result) + result.model_dump_json()
    for forbidden in ("dG9rZW4tY2FuYXJ5", "mode-canary", "wrong-canary"):
        assert forbidden not in public


def test_duplicate_identity_is_removed_and_fails_closed_without_values() -> None:
    result = traverse_kubernetes_workloads(
        (
            source(
                "a.yaml",
                """apiVersion: v1
kind: Secret
metadata: {name: duplicate, namespace: tenant-a}
stringData: {A: duplicate-one-canary}
""",
            ),
            source(
                "b.yaml",
                """apiVersion: v1
kind: Secret
metadata: {name: duplicate, namespace: tenant-a}
data: {B: ZHVwbGljYXRlLXR3by1jYW5hcnk=}
""",
            ),
        )
    )

    assert result.status is KubernetesLoadStatus.FAILED
    assert result.objects == ()
    assert [(item.path, item.status) for item in result.sources] == [
        ("a.yaml", KubernetesLoadStatus.FAILED),
        ("b.yaml", KubernetesLoadStatus.FAILED),
    ]
    assert {item.code for item in result.diagnostics} == {
        KubernetesDiagnosticCode.DUPLICATE_OBJECT_IDENTITY
    }
    public = repr(result) + result.model_dump_json()
    assert "duplicate-one-canary" not in public
    assert "ZHVwbGljYXRlLXR3by1jYW5hcnk=" not in public


@pytest.mark.parametrize(
    "document",
    [
        """apiVersion: v1
kind: ConfigMap
metadata: {name: broken}
data: invalid
""",
        """apiVersion: v1
kind: Secret
metadata: {name: broken}
stringData: [invalid]
""",
        """apiVersion: v1
kind: Secret
metadata: {name: broken}
binaryData: {BAD: forbidden-canary}
""",
        """apiVersion: v1
kind: ConfigMap
metadata: {name: broken}
data: {BAD=KEY: forbidden-canary}
""",
    ],
)
def test_invalid_key_maps_fail_closed_without_value_disclosure(document: str) -> None:
    result = traverse_kubernetes_workloads(source("broken.yaml", document))

    assert result.status is KubernetesLoadStatus.FAILED
    assert result.sources[0].status is KubernetesLoadStatus.FAILED
    assert result.objects == ()
    assert any(
        item.code is KubernetesDiagnosticCode.INVALID_OBJECT_KEYS for item in result.diagnostics
    )
    assert "forbidden-canary" not in repr(result) + result.model_dump_json()


def test_object_and_key_limits_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    document = """apiVersion: v1
kind: ConfigMap
metadata: {name: config}
data: {A: hidden}
"""
    monkeypatch.setattr(loader, "MAX_KUBERNETES_OBJECT_KEYS", 0)
    keys = traverse_kubernetes_workloads(source("keys.yaml", document))
    assert keys.status is KubernetesLoadStatus.FAILED
    assert keys.objects == ()
    assert any(item.code is KubernetesDiagnosticCode.SAFETY_LIMIT for item in keys.diagnostics)

    monkeypatch.setattr(loader, "MAX_KUBERNETES_OBJECT_KEYS", 16_384)
    monkeypatch.setattr(loader, "MAX_KUBERNETES_OBJECTS", 0)
    objects = traverse_kubernetes_workloads(source("objects.yaml", document))
    assert objects.status is KubernetesLoadStatus.FAILED
    assert objects.objects == ()
    assert any(item.code is KubernetesDiagnosticCode.SAFETY_LIMIT for item in objects.diagnostics)


def test_project_object_limit_fails_closed_across_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(loader, "MAX_KUBERNETES_OBJECTS", 1)
    result = traverse_kubernetes_workloads(
        (
            source(
                "a.yaml",
                "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\ndata: {A: hidden}\n",
            ),
            source(
                "b.yaml",
                "apiVersion: v1\nkind: Secret\nmetadata: {name: b}\ndata: {B: aGlkZGVu}\n",
            ),
        )
    )

    assert result.status is KubernetesLoadStatus.FAILED
    assert result.objects == ()
    assert all(item.status is KubernetesLoadStatus.FAILED for item in result.sources)
    assert any(item.code is KubernetesDiagnosticCode.SAFETY_LIMIT for item in result.diagnostics)


def test_key_limit_is_global_across_object_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "MAX_KUBERNETES_OBJECT_KEYS", 1)
    result = traverse_kubernetes_workloads(
        source(
            "config.yaml",
            """apiVersion: v1
kind: ConfigMap
metadata: {name: config}
data: {A: hidden-a}
binaryData: {B: aGlkZGVuLWI=}
""",
        )
    )

    assert result.status is KubernetesLoadStatus.FAILED
    assert result.objects == ()
    assert any(item.code is KubernetesDiagnosticCode.SAFETY_LIMIT for item in result.diagnostics)
    assert "hidden-a" not in repr(result) + result.model_dump_json()
    assert "aGlkZGVuLWI=" not in repr(result) + result.model_dump_json()


def test_invalid_namespace_never_falls_back_to_default_resolution() -> None:
    result = traverse_kubernetes_workloads(
        source(
            "invalid.yaml",
            """apiVersion: v1
kind: Secret
metadata: {name: secret, namespace: [invalid]}
data: {TOKEN: hidden}
""",
        )
    )

    assert result.status is KubernetesLoadStatus.FAILED
    assert result.objects == ()
    assert any(
        item.code is KubernetesDiagnosticCode.INVALID_METADATA for item in result.diagnostics
    )


def test_project_presence_and_resolution_are_input_order_independent() -> None:
    inputs = (
        source(
            "z-workload.yaml",
            """apiVersion: v1
kind: Pod
metadata: {name: api}
spec:
  containers:
    - name: app
      envFrom: [{configMapRef: {name: config}}]
""",
        ),
        source(
            "a-config.yaml",
            """apiVersion: v1
kind: ConfigMap
metadata: {name: config}
data: {KEY: hidden}
""",
        ),
    )

    assert traverse_kubernetes_workloads(inputs) == traverse_kubernetes_workloads(
        tuple(reversed(inputs))
    )


def test_presence_models_reject_ambiguous_or_cross_path_shapes_and_canonicalize() -> None:
    location = SourceLocation(path="a.yaml", start_line=1)
    other = SourceLocation(path="b.yaml", start_line=1)
    key_a = KubernetesObjectKeyPresence(
        name="A", field=KubernetesObjectKeyField.DATA, location=location
    )
    key_b = KubernetesObjectKeyPresence(
        name="B", field=KubernetesObjectKeyField.DATA, location=location
    )

    with pytest.raises(ValidationError, match="non-empty"):
        KubernetesObjectKeyPresence(
            name="BAD=KEY", field=KubernetesObjectKeyField.DATA, location=location
        )
    with pytest.raises(ValidationError, match="name and namespace"):
        KubernetesObjectPresence(
            path="a.yaml",
            document_index=1,
            api_version="v1",
            object_kind=KubernetesObjectKind.CONFIG_MAP,
            name="",
            namespace="default",
            location=location,
        )
    with pytest.raises(ValidationError, match="object locations"):
        KubernetesObjectPresence(
            path="a.yaml",
            document_index=1,
            api_version="v1",
            object_kind=KubernetesObjectKind.CONFIG_MAP,
            name="config",
            namespace="default",
            location=other,
        )
    with pytest.raises(ValidationError, match="must be unique"):
        KubernetesObjectPresence(
            path="a.yaml",
            document_index=1,
            api_version="v1",
            object_kind=KubernetesObjectKind.CONFIG_MAP,
            name="config",
            namespace="default",
            location=location,
            keys=(key_a, key_a),
        )

    def resolution(**updates: Any) -> KubernetesReferenceResolution:
        data: dict[str, Any] = {
            "path": "a.yaml",
            "document_index": 1,
            "namespace": "default",
            "workload_kind": KubernetesWorkloadKind.POD,
            "workload_name": "api",
            "container_name": "app",
            "source_index": 0,
            "reference_name": "config",
            "optional": False,
            "resolved_object": True,
            "location": location,
            "source_location": location,
            "reference_kind": KubernetesReferenceKind.CONFIG_MAP_REF,
        }
        data.update(updates)
        return KubernetesReferenceResolution.model_validate(data)

    with pytest.raises(ValidationError, match="identity fields"):
        resolution(workload_name="")
    with pytest.raises(ValidationError, match="reference locations"):
        resolution(source_location=other)
    with pytest.raises(ValidationError, match="key references"):
        resolution(
            reference_kind=KubernetesReferenceKind.CONFIG_MAP_KEY_REF,
            resolved_key=True,
        )
    with pytest.raises(ValidationError, match="bulk references"):
        resolution(reference_key="A", resolved_key=True)
    with pytest.raises(ValidationError, match="unresolved object"):
        resolution(resolved_object=False, resolved_keys=("A",))
    canonical_resolution = resolution(resolved_keys=("B", "A", "B"))
    assert canonical_resolution.resolved_keys == ("A", "B")

    object_a = KubernetesObjectPresence(
        path="a.yaml",
        document_index=1,
        api_version="v1",
        object_kind=KubernetesObjectKind.CONFIG_MAP,
        name="a",
        namespace="default",
        location=location,
        keys=(key_b, key_a),
    )
    object_b = object_a.model_copy(update={"name": "b", "document_index": 2})
    canonical = KubernetesTraversalResult(
        status=KubernetesLoadStatus.COMPLETE,
        objects=(object_b, object_a),
    )
    assert [item.name for item in canonical.objects] == ["a", "b"]
    assert [item.name for item in canonical.objects[0].keys] == ["A", "B"]
    with pytest.raises(ValidationError, match="source paths must be unique"):
        KubernetesTraversalResult(
            status=KubernetesLoadStatus.COMPLETE,
            sources=(
                KubernetesSourceStatus(path="a.yaml", status=KubernetesLoadStatus.COMPLETE),
                KubernetesSourceStatus(path="a.yaml", status=KubernetesLoadStatus.COMPLETE),
            ),
        )
