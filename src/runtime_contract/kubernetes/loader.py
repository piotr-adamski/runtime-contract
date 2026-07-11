"""Bounded Kubernetes YAML traversal; it never reads files or evaluates manifests."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken

from runtime_contract.domain import Severity, SourceLocation
from runtime_contract.kubernetes.models import (
    KubernetesContainerContext,
    KubernetesContainerKind,
    KubernetesDiagnostic,
    KubernetesDiagnosticCode,
    KubernetesInput,
    KubernetesLoadStatus,
    KubernetesTraversalResult,
    KubernetesWorkloadKind,
)

MAX_KUBERNETES_BYTES = 1024 * 1024
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 10_000
MAX_YAML_ALIASES = 256
MAX_YAML_DOCUMENTS = 256
MAX_SCALAR_BYTES = 64 * 1024
MAX_CONTAINERS = 4_096

_SAFE_TAGS = frozenset(
    {
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:map",
    }
)
_POD_SPEC_PATHS: dict[KubernetesWorkloadKind, tuple[str, ...]] = {
    KubernetesWorkloadKind.POD: ("spec",),
    KubernetesWorkloadKind.DEPLOYMENT: ("spec", "template", "spec"),
    KubernetesWorkloadKind.STATEFUL_SET: ("spec", "template", "spec"),
    KubernetesWorkloadKind.DAEMON_SET: ("spec", "template", "spec"),
    KubernetesWorkloadKind.JOB: ("spec", "template", "spec"),
    KubernetesWorkloadKind.CRON_JOB: ("spec", "jobTemplate", "spec", "template", "spec"),
}


@dataclass(slots=True)
class _Context:
    source: KubernetesInput
    diagnostics: list[KubernetesDiagnostic]

    def location(self, node: Node) -> SourceLocation:
        return SourceLocation(
            path=self.source.path,
            start_line=node.start_mark.line + 1,
            start_column=node.start_mark.column + 1,
            end_line=node.end_mark.line + 1,
            end_column=node.end_mark.column + 1,
        )

    def diagnostic(
        self,
        code: KubernetesDiagnosticCode,
        node: Node,
        *,
        parameters: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.diagnostics.append(
            KubernetesDiagnostic(
                code=code,
                severity=(
                    Severity.INFO
                    if code is KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE
                    else Severity.ERROR
                ),
                location=self.location(node),
                parameters=parameters,
                rule_id="RTC012" if code is KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE else None,
            )
        )


def _unique_diagnostics(items: Iterable[KubernetesDiagnostic]) -> tuple[KubernetesDiagnostic, ...]:
    return tuple({item.id: item for item in sorted(items, key=lambda item: item.id)}.values())


def _mapping(
    context: _Context, node: Node, *, duplicate_is_error: bool = True
) -> dict[str, tuple[ScalarNode, Node]] | None:
    if not isinstance(node, MappingNode):
        return None
    result: dict[str, tuple[ScalarNode, Node]] = {}
    for key, value in node.value:
        if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
            context.diagnostic(KubernetesDiagnosticCode.INVALID_DOCUMENT, key)
            continue
        if key.value in result:
            if duplicate_is_error:
                context.diagnostic(KubernetesDiagnosticCode.DUPLICATE_KEY, key)
            continue
        result[key.value] = (key, value)
    return result


def _string(pair: tuple[ScalarNode, Node] | None) -> str | None:
    if pair is None:
        return None
    node = pair[1]
    if isinstance(node, ScalarNode) and node.tag == "tag:yaml.org,2002:str" and node.value:
        return str(node.value)
    return None


def _validate_graph(context: _Context, root: Node, aliases: int) -> bool:
    if aliases > MAX_YAML_ALIASES:
        context.diagnostic(KubernetesDiagnosticCode.SAFETY_LIMIT, root)
        return False
    seen: set[int] = set()
    stack: set[int] = set()
    valid = True

    def visit(node: Node, depth: int) -> None:
        nonlocal valid
        if depth > MAX_YAML_DEPTH or len(seen) > MAX_YAML_NODES:
            context.diagnostic(KubernetesDiagnosticCode.SAFETY_LIMIT, node)
            valid = False
            return
        ident = id(node)
        if ident in stack:
            context.diagnostic(KubernetesDiagnosticCode.CYCLIC_ALIAS, node)
            valid = False
            return
        if ident in seen:
            return
        seen.add(ident)
        if node.tag not in _SAFE_TAGS:
            context.diagnostic(KubernetesDiagnosticCode.UNSUPPORTED_TAG, node)
            valid = False
        if isinstance(node, ScalarNode) and len(node.value.encode("utf-8")) > MAX_SCALAR_BYTES:
            context.diagnostic(KubernetesDiagnosticCode.SAFETY_LIMIT, node)
            valid = False
        stack.add(ident)
        children: Iterable[Node]
        if isinstance(node, MappingNode):
            children = (child for pair in node.value for child in pair)
        elif isinstance(node, SequenceNode):
            children = node.value
        else:
            children = ()
        for child in children:
            visit(child, depth + 1)
        stack.remove(ident)

    visit(root, 1)
    return valid


def _pod_spec(context: _Context, root: MappingNode, kind: KubernetesWorkloadKind) -> Node | None:
    current: Node = root
    for segment in _POD_SPEC_PATHS[kind]:
        fields = _mapping(context, current)
        if fields is None or segment not in fields:
            context.diagnostic(KubernetesDiagnosticCode.MISSING_POD_SPEC, current)
            return None
        current = fields[segment][1]
    if not isinstance(current, MappingNode):
        context.diagnostic(KubernetesDiagnosticCode.MISSING_POD_SPEC, current)
        return None
    return current


def _containers(
    context: _Context,
    pod_spec: MappingNode,
    *,
    key: str,
    kind: KubernetesContainerKind,
    path: str,
    document_index: int,
    api_version: str,
    workload_kind: KubernetesWorkloadKind,
    workload_name: str,
    namespace: str,
    workload_location: SourceLocation,
) -> list[KubernetesContainerContext]:
    fields = _mapping(context, pod_spec)
    assert fields is not None
    entry = fields.get(key)
    if entry is None:
        if key == "containers":
            context.diagnostic(KubernetesDiagnosticCode.INVALID_CONTAINERS, pod_spec)
        return []
    node = entry[1]
    if not isinstance(node, SequenceNode) or (key == "containers" and not node.value):
        context.diagnostic(KubernetesDiagnosticCode.INVALID_CONTAINERS, node)
        return []
    if len(node.value) > MAX_CONTAINERS:
        context.diagnostic(KubernetesDiagnosticCode.SAFETY_LIMIT, node)
        return []
    result: list[KubernetesContainerContext] = []
    names: set[str] = set()
    for index, container in enumerate(node.value):
        if not isinstance(container, MappingNode):
            context.diagnostic(KubernetesDiagnosticCode.INVALID_CONTAINER, container)
            continue
        values = _mapping(context, container)
        assert values is not None
        name = _string(values.get("name"))
        if name is None:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_CONTAINER, container)
            continue
        if name in names:
            context.diagnostic(KubernetesDiagnosticCode.DUPLICATE_CONTAINER_NAME, values["name"][0])
            continue
        names.add(name)
        result.append(
            KubernetesContainerContext(
                path=path,
                document_index=document_index,
                api_version=api_version,
                workload_kind=workload_kind,
                workload_name=workload_name,
                namespace=namespace,
                container_kind=kind,
                container_name=name,
                container_index=index,
                workload_location=workload_location,
                container_location=context.location(container),
            )
        )
    return result


def _traverse_document(
    context: _Context, root: Node, document_index: int
) -> list[KubernetesContainerContext]:
    fields = _mapping(context, root)
    if fields is None:
        context.diagnostic(KubernetesDiagnosticCode.INVALID_DOCUMENT, root)
        return []
    api_version = _string(fields.get("apiVersion"))
    if api_version is None:
        context.diagnostic(KubernetesDiagnosticCode.MISSING_API_VERSION, root)
        return []
    kind_text = _string(fields.get("kind"))
    if kind_text is None:
        context.diagnostic(KubernetesDiagnosticCode.MISSING_KIND, root)
        return []
    try:
        kind = KubernetesWorkloadKind(kind_text)
    except ValueError:
        context.diagnostic(KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE, fields["kind"][0])
        return []
    metadata_pair = fields.get("metadata")
    metadata_node = metadata_pair[1] if metadata_pair is not None else root
    metadata = _mapping(context, metadata_node) if metadata_pair is not None else None
    if metadata is None:
        context.diagnostic(
            KubernetesDiagnosticCode.INVALID_METADATA,
            metadata_node,
        )
        return []
    workload_name = _string(metadata.get("name"))
    if workload_name is None:
        context.diagnostic(KubernetesDiagnosticCode.MISSING_WORKLOAD_NAME, metadata_node)
        return []
    namespace = _string(metadata.get("namespace")) or "default"
    assert isinstance(root, MappingNode)
    pod_spec = _pod_spec(context, root, kind)
    if pod_spec is None:
        return []
    assert isinstance(pod_spec, MappingNode)
    workload_location = context.location(fields["kind"][0])
    return [
        *_containers(
            context,
            pod_spec,
            key="containers",
            kind=KubernetesContainerKind.CONTAINER,
            path=context.source.path,
            document_index=document_index,
            api_version=api_version,
            workload_kind=kind,
            workload_name=workload_name,
            namespace=namespace,
            workload_location=workload_location,
        ),
        *_containers(
            context,
            pod_spec,
            key="initContainers",
            kind=KubernetesContainerKind.INIT_CONTAINER,
            path=context.source.path,
            document_index=document_index,
            api_version=api_version,
            workload_kind=kind,
            workload_name=workload_name,
            namespace=namespace,
            workload_location=workload_location,
        ),
    ]


def _traverse_one(
    source: KubernetesInput,
) -> tuple[list[KubernetesContainerContext], list[KubernetesDiagnostic], bool]:
    context = _Context(source, [])
    if len(source.content) > MAX_KUBERNETES_BYTES:
        context.diagnostics.append(
            KubernetesDiagnostic(
                code=KubernetesDiagnosticCode.SAFETY_LIMIT,
                severity=Severity.ERROR,
                location=SourceLocation(path=source.path, start_line=1, start_column=1),
            )
        )
        return [], context.diagnostics, True
    try:
        text = source.content.decode("utf-8-sig")
    except UnicodeDecodeError:
        location = SourceLocation(path=source.path, start_line=1, start_column=1)
        context.diagnostics.append(
            KubernetesDiagnostic(
                code=KubernetesDiagnosticCode.INVALID_ENCODING,
                severity=Severity.ERROR,
                location=location,
            )
        )
        return [], context.diagnostics, True
    try:
        aliases = sum(
            isinstance(token, AliasToken) for token in yaml.scan(text, Loader=yaml.SafeLoader)
        )
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError:
        context.diagnostics.append(
            KubernetesDiagnostic(
                code=KubernetesDiagnosticCode.INVALID_YAML,
                severity=Severity.ERROR,
                location=SourceLocation(path=source.path, start_line=1, start_column=1),
            )
        )
        return [], context.diagnostics, True
    if len(documents) > MAX_YAML_DOCUMENTS:
        context.diagnostics.append(
            KubernetesDiagnostic(
                code=KubernetesDiagnosticCode.SAFETY_LIMIT,
                severity=Severity.ERROR,
                location=SourceLocation(path=source.path, start_line=1, start_column=1),
            )
        )
        return [], context.diagnostics, True
    contexts: list[KubernetesContainerContext] = []
    document_index = 0
    for root in documents:
        if root is None or (isinstance(root, ScalarNode) and root.tag == "tag:yaml.org,2002:null"):
            continue
        document_index += 1
        if not _validate_graph(context, root, aliases):
            continue
        contexts.extend(_traverse_document(context, root, document_index))
    return (
        contexts,
        context.diagnostics,
        any(item.severity is Severity.ERROR for item in context.diagnostics),
    )


def traverse_kubernetes_workloads(
    inputs: Iterable[KubernetesInput] | KubernetesInput,
) -> KubernetesTraversalResult:
    """Traverse caller-provided manifest bytes without filesystem, process, or network access."""
    all_contexts: list[KubernetesContainerContext] = []
    all_diagnostics: list[KubernetesDiagnostic] = []
    has_loss = False
    sources = (inputs,) if isinstance(inputs, KubernetesInput) else tuple(inputs)
    for source in sorted(sources, key=lambda item: item.path.encode("utf-8")):
        contexts, source_diagnostics, loss = _traverse_one(source)
        all_contexts.extend(contexts)
        all_diagnostics.extend(source_diagnostics)
        has_loss = has_loss or loss
    diagnostics: tuple[KubernetesDiagnostic, ...] = _unique_diagnostics(all_diagnostics)
    if all_contexts:
        status = KubernetesLoadStatus.PARTIAL if has_loss else KubernetesLoadStatus.COMPLETE
    elif has_loss:
        status = KubernetesLoadStatus.FAILED
    else:
        status = KubernetesLoadStatus.COMPLETE
    return KubernetesTraversalResult(
        status=status, contexts=tuple(all_contexts), diagnostics=diagnostics
    )
