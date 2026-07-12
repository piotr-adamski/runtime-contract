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
    KubernetesEnvBinding,
    KubernetesEnvFromSource,
    KubernetesEnvFromSourceKind,
    KubernetesEnvSourceKind,
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
)

MAX_KUBERNETES_BYTES = 1024 * 1024
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 10_000
MAX_YAML_ALIASES = 256
MAX_YAML_DOCUMENTS = 256
MAX_SCALAR_BYTES = 64 * 1024
MAX_CONTAINERS = 4_096
MAX_ENV_ENTRIES = 4_096
MAX_ENV_FROM_ENTRIES = 4_096
MAX_KUBERNETES_OBJECTS = 4_096
MAX_KUBERNETES_OBJECT_KEYS = 16_384

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


def _resolve_references(
    contexts: Iterable[KubernetesContainerContext],
    objects: Iterable[KubernetesObjectPresence],
) -> tuple[KubernetesReferenceResolution, ...]:
    object_index = {item.identity(): item for item in objects}
    result: list[KubernetesReferenceResolution] = []
    for container in contexts:
        for binding in container.env:
            if binding.source_kind not in {
                KubernetesEnvSourceKind.SECRET_KEY_REF,
                KubernetesEnvSourceKind.CONFIG_MAP_KEY_REF,
            }:
                continue
            assert binding.reference_name is not None
            assert binding.reference_key is not None
            assert binding.optional is not None
            object_kind = (
                KubernetesObjectKind.SECRET
                if binding.source_kind is KubernetesEnvSourceKind.SECRET_KEY_REF
                else KubernetesObjectKind.CONFIG_MAP
            )
            reference_kind = (
                KubernetesReferenceKind.SECRET_KEY_REF
                if object_kind is KubernetesObjectKind.SECRET
                else KubernetesReferenceKind.CONFIG_MAP_KEY_REF
            )
            matched = object_index.get(
                (container.namespace, object_kind.value, binding.reference_name)
            )
            result.append(
                KubernetesReferenceResolution(
                    path=container.path,
                    document_index=container.document_index,
                    namespace=container.namespace,
                    workload_kind=container.workload_kind,
                    workload_name=container.workload_name,
                    container_name=container.container_name,
                    reference_kind=reference_kind,
                    source_index=binding.index,
                    reference_name=binding.reference_name,
                    reference_key=binding.reference_key,
                    optional=binding.optional,
                    resolved_object=matched is not None,
                    resolved_key=(
                        matched is not None
                        and binding.reference_key in {item.name for item in matched.keys}
                    ),
                    location=binding.location,
                    source_location=binding.source_location,
                )
            )
        for source in container.env_from:
            object_kind = (
                KubernetesObjectKind.SECRET
                if source.source_kind is KubernetesEnvFromSourceKind.SECRET_REF
                else KubernetesObjectKind.CONFIG_MAP
            )
            reference_kind = (
                KubernetesReferenceKind.SECRET_REF
                if object_kind is KubernetesObjectKind.SECRET
                else KubernetesReferenceKind.CONFIG_MAP_REF
            )
            matched = object_index.get(
                (container.namespace, object_kind.value, source.reference_name)
            )
            result.append(
                KubernetesReferenceResolution(
                    path=container.path,
                    document_index=container.document_index,
                    namespace=container.namespace,
                    workload_kind=container.workload_kind,
                    workload_name=container.workload_name,
                    container_name=container.container_name,
                    reference_kind=reference_kind,
                    source_index=source.index,
                    reference_name=source.reference_name,
                    optional=source.optional,
                    prefix=source.prefix,
                    resolved_object=matched is not None,
                    resolved_keys=(
                        tuple(item.name for item in matched.keys) if matched is not None else ()
                    ),
                    location=source.location,
                    source_location=source.source_location,
                )
            )
    return tuple(result)


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


def _string_allow_empty(pair: tuple[ScalarNode, Node]) -> str | None:
    node = pair[1]
    if isinstance(node, ScalarNode) and node.tag == "tag:yaml.org,2002:str":
        return str(node.value)
    return None


def _optional_bool(pair: tuple[ScalarNode, Node] | None) -> tuple[bool, bool]:
    if pair is None:
        return True, False
    node = pair[1]
    if not isinstance(node, ScalarNode) or node.tag != "tag:yaml.org,2002:bool":
        return False, False
    normalized = node.value.casefold()
    if normalized in {"true", "yes", "on"}:
        return True, True
    if normalized in {"false", "no", "off"}:
        return True, False
    return False, False


def _unexpected_fields(
    context: _Context,
    node: MappingNode,
    fields: dict[str, tuple[ScalarNode, Node]],
    allowed: frozenset[str],
    code: KubernetesDiagnosticCode,
) -> None:
    unexpected = sorted(set(fields) - allowed)
    if unexpected:
        context.diagnostic(code, node)


def _key_reference(
    context: _Context,
    source_pair: tuple[ScalarNode, Node],
    *,
    code: KubernetesDiagnosticCode,
) -> tuple[str, str, bool] | None:
    node = source_pair[1]
    fields = _mapping(context, node)
    if fields is None:
        context.diagnostic(code, node)
        return None
    assert isinstance(node, MappingNode)
    _unexpected_fields(context, node, fields, frozenset({"name", "key", "optional"}), code)
    name = _string(fields.get("name"))
    key = _string(fields.get("key"))
    valid_optional, optional = _optional_bool(fields.get("optional"))
    if name is None or key is None or not valid_optional:
        context.diagnostic(code, node)
        return None
    return name, key, optional


def _env_value_from(
    context: _Context,
    name: str,
    index: int,
    name_node: Node,
    pair: tuple[ScalarNode, Node],
) -> KubernetesEnvBinding | None:
    node = pair[1]
    fields = _mapping(context, node)
    if fields is None:
        context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_SOURCE, node)
        return None
    assert isinstance(node, MappingNode)
    supported = {
        "secretKeyRef": KubernetesEnvSourceKind.SECRET_KEY_REF,
        "configMapKeyRef": KubernetesEnvSourceKind.CONFIG_MAP_KEY_REF,
        "fieldRef": KubernetesEnvSourceKind.FIELD_REF,
        "resourceFieldRef": KubernetesEnvSourceKind.RESOURCE_FIELD_REF,
    }
    _unexpected_fields(
        context,
        node,
        fields,
        frozenset(supported),
        KubernetesDiagnosticCode.INVALID_ENV_SOURCE,
    )
    selected = [field for field in supported if field in fields]
    if len(selected) != 1:
        context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_SOURCE, node)
        return None
    field = selected[0]
    source_kind = supported[field]
    source_pair = fields[field]
    location = context.location(name_node)
    source_location = context.location(source_pair[0])
    if source_kind in {
        KubernetesEnvSourceKind.SECRET_KEY_REF,
        KubernetesEnvSourceKind.CONFIG_MAP_KEY_REF,
    }:
        reference = _key_reference(
            context,
            source_pair,
            code=KubernetesDiagnosticCode.INVALID_ENV_REFERENCE,
        )
        if reference is None:
            return None
        reference_name, reference_key, optional = reference
        return KubernetesEnvBinding(
            name=name,
            index=index,
            source_kind=source_kind,
            reference_name=reference_name,
            reference_key=reference_key,
            optional=optional,
            location=location,
            source_location=source_location,
        )
    source_node = source_pair[1]
    source_fields = _mapping(context, source_node)
    if source_fields is None:
        context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_REFERENCE, source_node)
        return None
    assert isinstance(source_node, MappingNode)
    if source_kind is KubernetesEnvSourceKind.FIELD_REF:
        _unexpected_fields(
            context,
            source_node,
            source_fields,
            frozenset({"apiVersion", "fieldPath"}),
            KubernetesDiagnosticCode.INVALID_ENV_REFERENCE,
        )
        field_path = _string(source_fields.get("fieldPath"))
        api_version_pair = source_fields.get("apiVersion")
        api_version = _string(api_version_pair) if api_version_pair is not None else None
        if field_path is None or (api_version_pair is not None and api_version is None):
            context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_REFERENCE, source_node)
            return None
        return KubernetesEnvBinding(
            name=name,
            index=index,
            source_kind=source_kind,
            field_api_version=api_version,
            field_path=field_path,
            location=location,
            source_location=source_location,
        )
    _unexpected_fields(
        context,
        source_node,
        source_fields,
        frozenset({"containerName", "resource", "divisor"}),
        KubernetesDiagnosticCode.INVALID_ENV_REFERENCE,
    )
    resource = _string(source_fields.get("resource"))
    container_pair = source_fields.get("containerName")
    divisor_pair = source_fields.get("divisor")
    resource_container = _string(container_pair) if container_pair is not None else None
    divisor = _string(divisor_pair) if divisor_pair is not None else None
    if (
        resource is None
        or (container_pair is not None and resource_container is None)
        or (divisor_pair is not None and divisor is None)
    ):
        context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_REFERENCE, source_node)
        return None
    return KubernetesEnvBinding(
        name=name,
        index=index,
        source_kind=source_kind,
        resource_container=resource_container,
        resource=resource,
        divisor=divisor,
        location=location,
        source_location=source_location,
    )


def _environment(
    context: _Context,
    fields: dict[str, tuple[ScalarNode, Node]],
) -> tuple[KubernetesEnvBinding, ...]:
    pair = fields.get("env")
    if pair is None:
        return ()
    node = pair[1]
    if not isinstance(node, SequenceNode):
        context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV, node)
        return ()
    if len(node.value) > MAX_ENV_ENTRIES:
        context.diagnostic(KubernetesDiagnosticCode.SAFETY_LIMIT, node)
        return ()
    result: list[KubernetesEnvBinding] = []
    names: set[str] = set()
    for index, entry in enumerate(node.value):
        entry_fields = _mapping(context, entry)
        if entry_fields is None:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_ENTRY, entry)
            continue
        assert isinstance(entry, MappingNode)
        _unexpected_fields(
            context,
            entry,
            entry_fields,
            frozenset({"name", "value", "valueFrom"}),
            KubernetesDiagnosticCode.INVALID_ENV_ENTRY,
        )
        name_pair = entry_fields.get("name")
        name = _string(name_pair)
        if name is None or "=" in name:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_ENTRY, entry)
            continue
        assert name_pair is not None
        if name in names:
            context.diagnostic(KubernetesDiagnosticCode.DUPLICATE_ENV_NAME, name_pair[1])
        names.add(name)
        value_pair = entry_fields.get("value")
        value_from_pair = entry_fields.get("valueFrom")
        if value_pair is not None and value_from_pair is not None:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_SOURCE, entry)
            continue
        if value_from_pair is not None:
            binding = _env_value_from(context, name, index, name_pair[1], value_from_pair)
            if binding is not None:
                result.append(binding)
            continue
        if value_pair is not None and _string_allow_empty(value_pair) is None:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_SOURCE, value_pair[1])
            continue
        source_node = value_pair[0] if value_pair is not None else name_pair[0]
        result.append(
            KubernetesEnvBinding(
                name=name,
                index=index,
                source_kind=KubernetesEnvSourceKind.VALUE,
                location=context.location(name_pair[1]),
                source_location=context.location(source_node),
            )
        )
    return tuple(result)


def _env_from_reference(
    context: _Context,
    pair: tuple[ScalarNode, Node],
) -> tuple[str, bool] | None:
    node = pair[1]
    fields = _mapping(context, node)
    if fields is None:
        context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_FROM_REFERENCE, node)
        return None
    assert isinstance(node, MappingNode)
    _unexpected_fields(
        context,
        node,
        fields,
        frozenset({"name", "optional"}),
        KubernetesDiagnosticCode.INVALID_ENV_FROM_REFERENCE,
    )
    name = _string(fields.get("name"))
    valid_optional, optional = _optional_bool(fields.get("optional"))
    if name is None or not valid_optional:
        context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_FROM_REFERENCE, node)
        return None
    return name, optional


def _environment_from(
    context: _Context,
    fields: dict[str, tuple[ScalarNode, Node]],
) -> tuple[KubernetesEnvFromSource, ...]:
    pair = fields.get("envFrom")
    if pair is None:
        return ()
    node = pair[1]
    if not isinstance(node, SequenceNode):
        context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_FROM, node)
        return ()
    if len(node.value) > MAX_ENV_FROM_ENTRIES:
        context.diagnostic(KubernetesDiagnosticCode.SAFETY_LIMIT, node)
        return ()
    result: list[KubernetesEnvFromSource] = []
    kinds = {
        "secretRef": KubernetesEnvFromSourceKind.SECRET_REF,
        "configMapRef": KubernetesEnvFromSourceKind.CONFIG_MAP_REF,
    }
    for index, entry in enumerate(node.value):
        entry_fields = _mapping(context, entry)
        if entry_fields is None:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_FROM_SOURCE, entry)
            continue
        assert isinstance(entry, MappingNode)
        _unexpected_fields(
            context,
            entry,
            entry_fields,
            frozenset({"prefix", *kinds}),
            KubernetesDiagnosticCode.INVALID_ENV_FROM_SOURCE,
        )
        selected = [field for field in kinds if field in entry_fields]
        if len(selected) != 1:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_FROM_SOURCE, entry)
            continue
        prefix_pair = entry_fields.get("prefix")
        prefix = _string_allow_empty(prefix_pair) if prefix_pair is not None else ""
        if prefix is None:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_ENV_FROM_SOURCE, entry)
            continue
        source_pair = entry_fields[selected[0]]
        reference = _env_from_reference(context, source_pair)
        if reference is None:
            continue
        reference_name, optional = reference
        result.append(
            KubernetesEnvFromSource(
                source_kind=kinds[selected[0]],
                index=index,
                reference_name=reference_name,
                optional=optional,
                prefix=prefix,
                location=context.location(entry),
                source_location=context.location(source_pair[0]),
            )
        )
    return tuple(result)


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
                env=_environment(context, values),
                env_from=_environment_from(context, values),
            )
        )
    return result


def _object_presence(
    context: _Context,
    fields: dict[str, tuple[ScalarNode, Node]],
    *,
    document_index: int,
    api_version: str,
    object_kind: KubernetesObjectKind,
    name: str,
    namespace: str,
) -> KubernetesObjectPresence | None:
    diagnostic_count = len(context.diagnostics)
    field_kinds = (
        (
            "data",
            KubernetesObjectKeyField.DATA,
        ),
        (
            "stringData",
            KubernetesObjectKeyField.STRING_DATA,
        ),
        (
            "binaryData",
            KubernetesObjectKeyField.BINARY_DATA,
        ),
    )
    allowed = (
        {"data", "binaryData"}
        if object_kind is KubernetesObjectKind.CONFIG_MAP
        else {"data", "stringData"}
    )
    keys: dict[str, KubernetesObjectKeyPresence] = {}
    limit_reported = False
    for field_name, field_kind in field_kinds:
        pair = fields.get(field_name)
        if pair is None:
            continue
        if field_name not in allowed:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_OBJECT_KEYS, pair[0])
            continue
        node = pair[1]
        values = _mapping(context, node)
        if values is None:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_OBJECT_KEYS, node)
            continue
        if len(values) > MAX_KUBERNETES_OBJECT_KEYS:
            context.diagnostic(KubernetesDiagnosticCode.SAFETY_LIMIT, node)
            continue
        for key_name, (key_node, _value_node) in values.items():
            if not key_name or "\0" in key_name or "=" in key_name:
                context.diagnostic(KubernetesDiagnosticCode.INVALID_OBJECT_KEYS, key_node)
                continue
            if key_name not in keys and len(keys) >= MAX_KUBERNETES_OBJECT_KEYS:
                if not limit_reported:
                    context.diagnostic(KubernetesDiagnosticCode.SAFETY_LIMIT, key_node)
                    limit_reported = True
                continue
            keys.setdefault(
                key_name,
                KubernetesObjectKeyPresence(
                    name=key_name,
                    field=field_kind,
                    location=context.location(key_node),
                ),
            )
    if len(context.diagnostics) != diagnostic_count:
        return None
    kind_pair = fields["kind"]
    return KubernetesObjectPresence(
        path=context.source.path,
        document_index=document_index,
        api_version=api_version,
        object_kind=object_kind,
        name=name,
        namespace=namespace,
        location=context.location(kind_pair[0]),
        keys=tuple(keys.values()),
    )


def _traverse_document(
    context: _Context,
    root: Node,
    document_index: int,
    *,
    ignore_unmarked: bool,
) -> tuple[list[KubernetesContainerContext], list[KubernetesObjectPresence]]:
    fields = _mapping(context, root)
    if fields is None:
        context.diagnostic(KubernetesDiagnosticCode.INVALID_DOCUMENT, root)
        return [], []
    if ignore_unmarked and "apiVersion" not in fields and "kind" not in fields:
        return [], []
    api_version = _string(fields.get("apiVersion"))
    if api_version is None:
        context.diagnostic(KubernetesDiagnosticCode.MISSING_API_VERSION, root)
        return [], []
    kind_text = _string(fields.get("kind"))
    if kind_text is None:
        context.diagnostic(KubernetesDiagnosticCode.MISSING_KIND, root)
        return [], []
    metadata_pair = fields.get("metadata")
    metadata_node = metadata_pair[1] if metadata_pair is not None else root
    metadata = _mapping(context, metadata_node) if metadata_pair is not None else None
    if metadata is None:
        context.diagnostic(
            KubernetesDiagnosticCode.INVALID_METADATA,
            metadata_node,
        )
        return [], []
    resource_name = _string(metadata.get("name"))
    if resource_name is None or "\0" in resource_name:
        context.diagnostic(KubernetesDiagnosticCode.MISSING_WORKLOAD_NAME, metadata_node)
        return [], []
    namespace_pair = metadata.get("namespace")
    if namespace_pair is None:
        namespace = "default"
    else:
        namespace_value = _string_allow_empty(namespace_pair)
        if namespace_value is None or "\0" in namespace_value:
            context.diagnostic(KubernetesDiagnosticCode.INVALID_METADATA, namespace_pair[1])
            return [], []
        namespace = namespace_value or "default"
    try:
        object_kind = KubernetesObjectKind(kind_text)
    except ValueError:
        object_kind = None
    if object_kind is not None:
        presence = _object_presence(
            context,
            fields,
            document_index=document_index,
            api_version=api_version,
            object_kind=object_kind,
            name=resource_name,
            namespace=namespace,
        )
        return [], [presence] if presence is not None else []
    try:
        kind = KubernetesWorkloadKind(kind_text)
    except ValueError:
        context.diagnostic(KubernetesDiagnosticCode.UNSUPPORTED_RESOURCE, fields["kind"][0])
        return [], []
    assert isinstance(root, MappingNode)
    pod_spec = _pod_spec(context, root, kind)
    if pod_spec is None:
        return [], []
    assert isinstance(pod_spec, MappingNode)
    workload_location = context.location(fields["kind"][0])
    return (
        [
            *_containers(
                context,
                pod_spec,
                key="containers",
                kind=KubernetesContainerKind.CONTAINER,
                path=context.source.path,
                document_index=document_index,
                api_version=api_version,
                workload_kind=kind,
                workload_name=resource_name,
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
                workload_name=resource_name,
                namespace=namespace,
                workload_location=workload_location,
            ),
        ],
        [],
    )


def _traverse_one(
    source: KubernetesInput,
    *,
    ignore_unmarked: bool,
) -> tuple[
    list[KubernetesContainerContext],
    list[KubernetesObjectPresence],
    list[KubernetesDiagnostic],
    bool,
]:
    context = _Context(source, [])
    if len(source.content) > MAX_KUBERNETES_BYTES:
        context.diagnostics.append(
            KubernetesDiagnostic(
                code=KubernetesDiagnosticCode.SAFETY_LIMIT,
                severity=Severity.ERROR,
                location=SourceLocation(path=source.path, start_line=1, start_column=1),
            )
        )
        return [], [], context.diagnostics, True
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
        return [], [], context.diagnostics, True
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
        return [], [], context.diagnostics, True
    if len(documents) > MAX_YAML_DOCUMENTS:
        context.diagnostics.append(
            KubernetesDiagnostic(
                code=KubernetesDiagnosticCode.SAFETY_LIMIT,
                severity=Severity.ERROR,
                location=SourceLocation(path=source.path, start_line=1, start_column=1),
            )
        )
        return [], [], context.diagnostics, True
    contexts: list[KubernetesContainerContext] = []
    objects: list[KubernetesObjectPresence] = []
    document_index = 0
    for root in documents:
        if root is None or (isinstance(root, ScalarNode) and root.tag == "tag:yaml.org,2002:null"):
            continue
        document_index += 1
        if not _validate_graph(context, root, aliases):
            continue
        document_contexts, document_objects = _traverse_document(
            context,
            root,
            document_index,
            ignore_unmarked=ignore_unmarked,
        )
        contexts.extend(document_contexts)
        objects.extend(document_objects)
        if len(objects) > MAX_KUBERNETES_OBJECTS:
            context.diagnostic(KubernetesDiagnosticCode.SAFETY_LIMIT, root)
            objects = []
            break
    return (
        contexts,
        objects,
        context.diagnostics,
        any(item.severity is Severity.ERROR for item in context.diagnostics),
    )


def traverse_kubernetes_workloads(
    inputs: Iterable[KubernetesInput] | KubernetesInput,
    *,
    ignore_unmarked: bool = False,
) -> KubernetesTraversalResult:
    """Traverse caller-provided manifest bytes without filesystem, process, or network access.

    ``ignore_unmarked`` lets extension-based discovery ignore generic YAML/JSON mappings that have
    neither Kubernetes discriminator while retaining fail-closed direct traversal by default.
    """
    all_contexts: list[KubernetesContainerContext] = []
    all_objects: list[KubernetesObjectPresence] = []
    all_diagnostics: list[KubernetesDiagnostic] = []
    loss_paths: set[str] = set()
    sources = (inputs,) if isinstance(inputs, KubernetesInput) else tuple(inputs)
    for source in sorted(sources, key=lambda item: item.path.encode("utf-8")):
        contexts, objects, source_diagnostics, loss = _traverse_one(
            source,
            ignore_unmarked=ignore_unmarked,
        )
        all_contexts.extend(contexts)
        all_objects.extend(objects)
        all_diagnostics.extend(source_diagnostics)
        if loss:
            loss_paths.add(source.path)
    if len(all_objects) > MAX_KUBERNETES_OBJECTS:
        overflow = all_objects[MAX_KUBERNETES_OBJECTS:]
        all_diagnostics.append(
            KubernetesDiagnostic(
                code=KubernetesDiagnosticCode.SAFETY_LIMIT,
                severity=Severity.ERROR,
                location=overflow[0].location,
            )
        )
        loss_paths.update(item.path for item in all_objects)
        all_objects = []
    identities: dict[tuple[str, str, str], list[KubernetesObjectPresence]] = {}
    for item in all_objects:
        identities.setdefault(item.identity(), []).append(item)
    duplicate_identities = {identity for identity, items in identities.items() if len(items) > 1}
    for identity in sorted(duplicate_identities):
        for item in identities[identity]:
            all_diagnostics.append(
                KubernetesDiagnostic(
                    code=KubernetesDiagnosticCode.DUPLICATE_OBJECT_IDENTITY,
                    severity=Severity.ERROR,
                    location=item.location,
                )
            )
            loss_paths.add(item.path)
    all_objects = [item for item in all_objects if item.identity() not in duplicate_identities]
    resolutions = _resolve_references(all_contexts, all_objects)
    diagnostics: tuple[KubernetesDiagnostic, ...] = _unique_diagnostics(all_diagnostics)
    source_statuses: list[KubernetesSourceStatus] = []
    for source in sources:
        has_facts = any(item.path == source.path for item in all_contexts) or any(
            item.path == source.path for item in all_objects
        )
        if source.path in loss_paths:
            source_status = (
                KubernetesLoadStatus.PARTIAL if has_facts else KubernetesLoadStatus.FAILED
            )
        else:
            source_status = KubernetesLoadStatus.COMPLETE
        source_statuses.append(KubernetesSourceStatus(path=source.path, status=source_status))
    if all_contexts or all_objects:
        status = KubernetesLoadStatus.PARTIAL if loss_paths else KubernetesLoadStatus.COMPLETE
    elif loss_paths:
        status = KubernetesLoadStatus.FAILED
    else:
        status = KubernetesLoadStatus.COMPLETE
    return KubernetesTraversalResult(
        status=status,
        contexts=tuple(all_contexts),
        objects=tuple(all_objects),
        resolutions=resolutions,
        sources=tuple(source_statuses),
        diagnostics=diagnostics,
    )
