from __future__ import annotations

import pytest
import yaml

from runtime_contract.domain import Severity, SourceLocation
from runtime_contract.kubernetes import (
    KubernetesContainerContext,
    KubernetesContainerKind,
    KubernetesDiagnostic,
    KubernetesDiagnosticCode,
    KubernetesInput,
    KubernetesLoadStatus,
    KubernetesTraversalResult,
    loader,
    traverse_kubernetes_workloads,
)
from runtime_contract.kubernetes.models import KubernetesWorkloadKind


def load(content: str | bytes, path: str = "manifests/workload.yaml") -> KubernetesTraversalResult:
    payload = content.encode() if isinstance(content, str) else content
    return traverse_kubernetes_workloads(KubernetesInput(path=path, content=payload))


@pytest.mark.parametrize(
    ("kind", "body"),
    [
        ("Pod", "spec:\n  containers:\n  - name: web"),
        ("Deployment", "spec:\n  template:\n    spec:\n      containers:\n      - name: web"),
        ("StatefulSet", "spec:\n  template:\n    spec:\n      containers:\n      - name: web"),
        ("DaemonSet", "spec:\n  template:\n    spec:\n      containers:\n      - name: web"),
        ("Job", "spec:\n  template:\n    spec:\n      containers:\n      - name: web"),
        (
            "CronJob",
            "spec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n          - name: web",
        ),
    ],
)
def test_supported_workloads_return_context(kind: str, body: str) -> None:
    result = load(f"apiVersion: v1\nkind: {kind}\nmetadata:\n  name: app\n{body}\n")
    assert result.status is KubernetesLoadStatus.COMPLETE
    assert [(item.workload_kind.value, item.container_name) for item in result.contexts] == [
        (kind, "web")
    ]


def test_init_containers_and_namespace_are_explicit_and_independent() -> None:
    result = load("""apiVersion: v1
kind: Pod
metadata:
  name: app
  namespace: tenant
spec:
  initContainers:
  - name: init
  containers:
  - name: web
  - name: worker
""")
    assert [
        (item.container_kind.value, item.container_name, item.container_index, item.namespace)
        for item in result.contexts
    ] == [
        ("container", "web", 0, "tenant"),
        ("container", "worker", 1, "tenant"),
        ("init_container", "init", 0, "tenant"),
    ]


def test_json_unsupported_and_input_order_are_deterministic() -> None:
    pod = b'{"apiVersion":"v1","kind":"Pod","metadata":{"name":"z"},"spec":{"containers":[{"name":"web"}]}}'
    service = b"apiVersion: v1\nkind: Service\nmetadata:\n  name: ignored\nspec: {}\n"
    inputs = (
        KubernetesInput(path="b.yaml", content=service),
        KubernetesInput(path="a.json", content=pod),
    )
    first = traverse_kubernetes_workloads(inputs)
    second = traverse_kubernetes_workloads(tuple(reversed(inputs)))
    assert first == second
    assert first.status is KubernetesLoadStatus.COMPLETE
    assert [(item.code, item.rule_id) for item in first.diagnostics] == [
        (KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE, "RTC012")
    ]


@pytest.mark.parametrize(
    "content, code, status",
    [
        (
            "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: []}\n",
            KubernetesDiagnosticCode.INVALID_CONTAINERS,
            KubernetesLoadStatus.FAILED,
        ),
        (
            "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: [{image: ignored}]}\n",
            KubernetesDiagnosticCode.INVALID_CONTAINER,
            KubernetesLoadStatus.FAILED,
        ),
        (
            "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: [{name: a}, {name: a}]}\n",
            KubernetesDiagnosticCode.DUPLICATE_CONTAINER_NAME,
            KubernetesLoadStatus.PARTIAL,
        ),
        (
            "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\n",
            KubernetesDiagnosticCode.MISSING_POD_SPEC,
            KubernetesLoadStatus.FAILED,
        ),
    ],
)
def test_invalid_structures_fail_without_context(
    content: str, code: KubernetesDiagnosticCode, status: KubernetesLoadStatus
) -> None:
    result = load(content)
    assert result.status is status
    assert any(item.code is code for item in result.diagnostics)


def test_good_document_survives_bad_document() -> None:
    result = load("""apiVersion: v1
kind: Pod
metadata: {name: good}
spec: {containers: [{name: web}]}
---
apiVersion: v1
kind: Pod
metadata: {name: bad}
spec: {containers: []}
""")
    assert result.status is KubernetesLoadStatus.PARTIAL
    assert [item.workload_name for item in result.contexts] == ["good"]


@pytest.mark.parametrize(
    "content, code, status",
    [
        (b"\xff", KubernetesDiagnosticCode.INVALID_ENCODING, KubernetesLoadStatus.FAILED),
        (
            "apiVersion: v1\nkind: [\n",
            KubernetesDiagnosticCode.INVALID_YAML,
            KubernetesLoadStatus.FAILED,
        ),
        (
            "apiVersion: v1\napiVersion: v2\nkind: Pod\nmetadata: {name: x}\nspec: {containers: [{name: x}]}\n",
            KubernetesDiagnosticCode.DUPLICATE_KEY,
            KubernetesLoadStatus.PARTIAL,
        ),
        ("!evil value\n", KubernetesDiagnosticCode.UNSUPPORTED_TAG, KubernetesLoadStatus.FAILED),
    ],
)
def test_unsafe_input_fails_closed(
    content: str | bytes, code: KubernetesDiagnosticCode, status: KubernetesLoadStatus
) -> None:
    result = load(content)
    assert result.status is status
    assert any(item.code is code for item in result.diagnostics)


def test_paths_are_nfc_and_constrained() -> None:
    assert KubernetesInput(path="ma\u006e\u0303ifest.yaml", content=b"").path == "mañifest.yaml"
    for path in ("/a.yaml", "../a.yaml", "a\\b.yaml", "C:a.yaml", "a\0b"):
        with pytest.raises(ValueError):
            KubernetesInput(path=path, content=b"")


@pytest.mark.parametrize(
    ("content", "code"),
    [
        ("- not-a-document\n", KubernetesDiagnosticCode.INVALID_DOCUMENT),
        (
            "kind: Pod\nmetadata: {name: x}\nspec: {containers: [{name: x}]}\n",
            KubernetesDiagnosticCode.MISSING_API_VERSION,
        ),
        (
            "apiVersion: v1\nmetadata: {name: x}\nspec: {containers: [{name: x}]}\n",
            KubernetesDiagnosticCode.MISSING_KIND,
        ),
        (
            "apiVersion: v1\nkind: Pod\nmetadata: nope\nspec: {containers: [{name: x}]}\n",
            KubernetesDiagnosticCode.INVALID_METADATA,
        ),
        (
            "apiVersion: v1\nkind: Pod\nmetadata: {}\nspec: {containers: [{name: x}]}\n",
            KubernetesDiagnosticCode.MISSING_WORKLOAD_NAME,
        ),
        (
            "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: no}\n",
            KubernetesDiagnosticCode.INVALID_CONTAINERS,
        ),
        (
            "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {initContainers: no, containers: [{name: x}]}\n",
            KubernetesDiagnosticCode.INVALID_CONTAINERS,
        ),
    ],
)
def test_document_validation_diagnostics(content: str, code: KubernetesDiagnosticCode) -> None:
    result = load(content)
    assert any(item.code is code for item in result.diagnostics)


def test_non_scalar_mapping_key_is_invalid_document() -> None:
    result = load(
        "? [apiVersion]\n: v1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: [{name: x}]}\n"
    )
    assert result.status is KubernetesLoadStatus.FAILED
    assert any(
        item.code is KubernetesDiagnosticCode.INVALID_DOCUMENT for item in result.diagnostics
    )


def test_remaining_container_and_podspec_validation_paths() -> None:
    missing = load("apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {}\n")
    assert any(
        item.code is KubernetesDiagnosticCode.INVALID_CONTAINERS for item in missing.diagnostics
    )
    non_mapping = load("apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: [no]}\n")
    assert any(
        item.code is KubernetesDiagnosticCode.INVALID_CONTAINER for item in non_mapping.diagnostics
    )
    bad_spec = load("apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: no\n")
    assert any(
        item.code is KubernetesDiagnosticCode.MISSING_POD_SPEC for item in bad_spec.diagnostics
    )
    numeric = load(
        "apiVersion: 1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: [{name: x}]}\n"
    )
    assert any(
        item.code is KubernetesDiagnosticCode.MISSING_API_VERSION for item in numeric.diagnostics
    )


def test_shared_alias_and_nonfatal_duplicate_mapping_branches() -> None:
    shared = load(
        "apiVersion: v1\nkind: Pod\nmetadata: &meta {name: x}\nextra: *meta\nspec: {containers: [{name: x}]}\n"
    )
    assert shared.status is KubernetesLoadStatus.COMPLETE
    root = yaml.compose("a: 1\na: 2\n", Loader=yaml.SafeLoader)
    assert root is not None
    context = loader._Context(KubernetesInput(path="a.yaml", content=b""), [])
    assert loader._mapping(context, root, duplicate_is_error=False) is not None
    assert context.diagnostics == []


def test_alias_depth_scalar_container_and_document_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "MAX_YAML_ALIASES", 0)
    aliases = load(
        "apiVersion: v1\nkind: Pod\nmetadata: &meta {name: x}\nextra: *meta\nspec: {containers: [{name: x}]}\n"
    )
    assert any(item.code is KubernetesDiagnosticCode.SAFETY_LIMIT for item in aliases.diagnostics)
    monkeypatch.setattr(loader, "MAX_YAML_ALIASES", 256)
    monkeypatch.setattr(loader, "MAX_YAML_DEPTH", 1)
    depth = load(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: [{name: x}]}\n"
    )
    assert any(item.code is KubernetesDiagnosticCode.SAFETY_LIMIT for item in depth.diagnostics)
    monkeypatch.setattr(loader, "MAX_YAML_DEPTH", 64)
    monkeypatch.setattr(loader, "MAX_SCALAR_BYTES", 1)
    scalar = load(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: xx}\nspec: {containers: [{name: x}]}\n"
    )
    assert any(item.code is KubernetesDiagnosticCode.SAFETY_LIMIT for item in scalar.diagnostics)
    monkeypatch.setattr(loader, "MAX_SCALAR_BYTES", 64 * 1024)
    monkeypatch.setattr(loader, "MAX_CONTAINERS", 0)
    containers = load(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {containers: [{name: x}]}\n"
    )
    assert any(
        item.code is KubernetesDiagnosticCode.SAFETY_LIMIT for item in containers.diagnostics
    )
    monkeypatch.setattr(loader, "MAX_CONTAINERS", 4096)
    monkeypatch.setattr(loader, "MAX_YAML_DOCUMENTS", 1)
    documents = load(
        "---\napiVersion: v1\nkind: Service\nmetadata: {name: x}\n---\napiVersion: v1\nkind: Service\nmetadata: {name: y}\n"
    )
    assert any(item.code is KubernetesDiagnosticCode.SAFETY_LIMIT for item in documents.diagnostics)


def test_size_empty_documents_and_cyclic_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(loader, "MAX_KUBERNETES_BYTES", 1)
    oversized = load("too-large")
    assert oversized.status is KubernetesLoadStatus.FAILED
    monkeypatch.setattr(loader, "MAX_KUBERNETES_BYTES", 1024 * 1024)
    empty = load("---\n---\napiVersion: v1\nkind: Service\nmetadata: {name: x}\n---\n")
    assert empty.status is KubernetesLoadStatus.COMPLETE
    cycle = load("&a {apiVersion: v1, kind: Pod, metadata: {name: x}, spec: *a}\n")
    assert any(item.code is KubernetesDiagnosticCode.CYCLIC_ALIAS for item in cycle.diagnostics)


def test_models_enforce_invariants_and_canonicalize() -> None:
    location = SourceLocation(path="a.yaml", start_line=1, start_column=1)
    with pytest.raises(ValueError, match="locations"):
        KubernetesContainerContext(
            path="a.yaml",
            document_index=1,
            api_version="v1",
            workload_kind=KubernetesWorkloadKind.POD,
            workload_name="x",
            namespace="default",
            container_kind=KubernetesContainerKind.CONTAINER,
            container_name="x",
            container_index=0,
            workload_location=location,
            container_location=SourceLocation(path="b.yaml", start_line=1, start_column=1),
        )
    with pytest.raises(ValueError, match="severity"):
        KubernetesDiagnostic(
            code=KubernetesDiagnosticCode.INVALID_YAML, severity=Severity.INFO, location=location
        )
    with pytest.raises(ValueError, match="unique"):
        KubernetesDiagnostic(
            code=KubernetesDiagnosticCode.INVALID_YAML,
            severity=Severity.ERROR,
            location=location,
            parameters=(("a", "1"), ("a", "2")),
        )
    with pytest.raises(ValueError, match="RTC012"):
        KubernetesDiagnostic(
            code=KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE,
            severity=Severity.INFO,
            location=location,
        )
    with pytest.raises(ValueError, match="only unsupported"):
        KubernetesDiagnostic(
            code=KubernetesDiagnosticCode.INVALID_YAML,
            severity=Severity.ERROR,
            location=location,
            rule_id="RTC012",
        )
    diagnostic = KubernetesDiagnostic(
        code=KubernetesDiagnosticCode.INVALID_YAML,
        severity=Severity.ERROR,
        location=location,
        parameters=(("z", "2"), ("a", "1")),
    )
    assert diagnostic.parameters == (("a", "1"), ("z", "2"))
    with pytest.raises(ValueError, match="identity"):
        KubernetesDiagnostic(
            id="wrong",
            code=KubernetesDiagnosticCode.INVALID_YAML,
            severity=Severity.ERROR,
            location=location,
        )
    context = KubernetesContainerContext(
        path="a.yaml",
        document_index=1,
        api_version="v1",
        workload_kind=KubernetesWorkloadKind.POD,
        workload_name="x",
        namespace="default",
        container_kind=KubernetesContainerKind.CONTAINER,
        container_name="x",
        container_index=0,
        workload_location=location,
        container_location=location,
    )
    with pytest.raises(ValueError, match="failed"):
        KubernetesTraversalResult(status=KubernetesLoadStatus.FAILED, contexts=(context,))
    other_diagnostic = KubernetesDiagnostic(
        code=KubernetesDiagnosticCode.INVALID_DOCUMENT, severity=Severity.ERROR, location=location
    )
    ordered = KubernetesTraversalResult(
        status=KubernetesLoadStatus.COMPLETE,
        contexts=(context.model_copy(update={"container_name": "z"}), context),
        diagnostics=tuple(
            reversed(tuple(sorted((diagnostic, other_diagnostic), key=lambda item: item.id)))
        ),
    )
    assert [item.container_name for item in ordered.contexts] == ["x", "z"]
    assert tuple(sorted(item.id for item in ordered.diagnostics)) == tuple(
        item.id for item in ordered.diagnostics
    )
