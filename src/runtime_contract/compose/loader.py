"""Bounded, static Docker Compose YAML loader with redacted diagnostics."""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken

from runtime_contract.compose.models import (
    ComposeDiagnostic,
    ComposeDiagnosticCode,
    ComposeInput,
    ComposeInterpolation,
    ComposeInterpolationOperator,
    ComposeLoadResult,
    ComposeLoadStatus,
    ComposeService,
)
from runtime_contract.domain import SourceLocation

MAX_COMPOSE_BYTES = 1024 * 1024
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 10_000
MAX_ALIAS_MERGE_REFERENCES = 256
MAX_COMPOSE_SERVICES = 4_096
MAX_PROFILES_PER_SERVICE = 128
MAX_INTERPOLATIONS = 10_000
MAX_SCALAR_BYTES = 64 * 1024

_NAME = re.compile(r"[_A-Za-z][_A-Za-z0-9]*")
_SAFE_TAGS = frozenset(
    {
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:map",
        "tag:yaml.org,2002:merge",
    }
)
_OPERATORS = {
    ":-": ComposeInterpolationOperator.DEFAULT_IF_UNSET_OR_EMPTY,
    "-": ComposeInterpolationOperator.DEFAULT_IF_UNSET,
    ":?": ComposeInterpolationOperator.ERROR_IF_UNSET_OR_EMPTY,
    "?": ComposeInterpolationOperator.ERROR_IF_UNSET,
    ":+": ComposeInterpolationOperator.ALTERNATE_IF_SET_AND_NONEMPTY,
    "+": ComposeInterpolationOperator.ALTERNATE_IF_SET,
}


class _Fatal(Exception):
    def __init__(self, diagnostic: ComposeDiagnostic) -> None:
        self.diagnostic = diagnostic


@dataclass(slots=True)
class _Context:
    source: ComposeInput
    text: str
    line_starts: list[int]
    diagnostics: list[ComposeDiagnostic]
    interpolations: list[ComposeInterpolation]
    merge_references: int = 0

    def location(self, node: Node, *, absolute_index: int | None = None) -> SourceLocation:
        if absolute_index is None:
            return SourceLocation(
                path=self.source.path,
                start_line=node.start_mark.line + 1,
                start_column=node.start_mark.column + 1,
                end_line=node.end_mark.line + 1,
                end_column=node.end_mark.column + 1,
            )
        line_index = bisect.bisect_right(self.line_starts, absolute_index) - 1
        return SourceLocation(
            path=self.source.path,
            start_line=line_index + 1,
            start_column=absolute_index - self.line_starts[line_index] + 1,
        )

    def diagnostic(
        self, code: ComposeDiagnosticCode, node: Node, message: str, *, fatal: bool = False
    ) -> None:
        item = ComposeDiagnostic(code=code, location=self.location(node), message=message)
        if fatal:
            raise _Fatal(item)
        self.diagnostics.append(item)


def _sort_location(location: SourceLocation) -> tuple[int, int, int, int]:
    return (
        location.start_line or 0,
        location.start_column or 0,
        location.end_line or 0,
        location.end_column or 0,
    )


def _diagnostic_key(item: ComposeDiagnostic) -> tuple[object, ...]:
    return (*_sort_location(item.location), item.code.value, item.message)


def _interpolation_key(item: ComposeInterpolation) -> tuple[object, ...]:
    return (*_sort_location(item.location), item.name, item.operator.value, item.service or "")


def _failed(source: ComposeInput, code: ComposeDiagnosticCode, message: str) -> ComposeLoadResult:
    return ComposeLoadResult(
        status=ComposeLoadStatus.FAILED,
        diagnostics=(
            ComposeDiagnostic(
                code=code,
                location=SourceLocation(path=source.path, start_line=1, start_column=1),
                message=message,
            ),
        ),
    )


def load_compose(source: ComposeInput) -> ComposeLoadResult:
    """Load exactly one in-memory Compose document without expansion or external reads."""

    if len(source.content) > MAX_COMPOSE_BYTES:
        return _failed(
            source, ComposeDiagnosticCode.SAFETY_LIMIT, "Compose file size limit exceeded."
        )
    try:
        text = source.content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return _failed(
            source, ComposeDiagnosticCode.INVALID_ENCODING, "Compose input is not UTF-8."
        )
    line_starts = [0]
    line_starts.extend(index + 1 for index, character in enumerate(text) if character == "\n")
    context = _Context(source, text, line_starts, [], [])
    try:
        alias_count = sum(isinstance(token, AliasToken) for token in yaml.scan(text))
        if alias_count > MAX_ALIAS_MERGE_REFERENCES:
            return _failed(
                source,
                ComposeDiagnosticCode.SAFETY_LIMIT,
                "YAML alias and merge reference limit exceeded.",
            )
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError:
        return _failed(source, ComposeDiagnosticCode.INVALID_YAML, "Invalid YAML syntax.")
    if len(documents) != 1 or documents[0] is None:
        code = (
            ComposeDiagnosticCode.MULTIPLE_DOCUMENTS
            if len(documents) > 1
            else ComposeDiagnosticCode.INVALID_YAML
        )
        message = (
            "Exactly one YAML document is supported."
            if len(documents) > 1
            else "Compose document must not be empty."
        )
        return _failed(source, code, message)
    root = documents[0]
    try:
        _validate_graph(context, root, alias_count)
        if not isinstance(root, MappingNode):
            context.diagnostic(
                ComposeDiagnosticCode.INVALID_SERVICES,
                root,
                "Compose document must be a mapping.",
                fatal=True,
            )
        root_entries = _mapping_entries(context, root, fatal_duplicates={"services"})
        include_entry = root_entries.get("include")
        if include_entry is not None:
            context.diagnostic(
                ComposeDiagnosticCode.UNSUPPORTED_EXTERNAL_REFERENCE,
                include_entry[0],
                "External Compose references are not loaded.",
            )
        services_entry = root_entries.get("services")
        if services_entry is None:
            context.diagnostic(
                ComposeDiagnosticCode.MISSING_SERVICES,
                root,
                "Top-level services mapping is required.",
                fatal=True,
            )
        assert services_entry is not None
        services_node = services_entry[1]
        if not isinstance(services_node, MappingNode):
            context.diagnostic(
                ComposeDiagnosticCode.INVALID_SERVICES,
                services_node,
                "Top-level services must be a mapping.",
                fatal=True,
            )
        assert isinstance(services_node, MappingNode)
        if len(services_node.value) > MAX_COMPOSE_SERVICES:
            context.diagnostic(
                ComposeDiagnosticCode.SAFETY_LIMIT,
                services_node,
                "Compose service limit exceeded.",
                fatal=True,
            )
        services = _load_services(context, services_node)
        _scan_root_values(context, root, services_node)
        interpolations = _consolidate_interpolations(context.interpolations)
        by_service = {
            service.name: tuple(item for item in interpolations if item.service == service.name)
            for service in services
        }
        services = tuple(
            service.model_copy(update={"interpolations": by_service[service.name]})
            for service in services
        )
    except _Fatal as error:
        return ComposeLoadResult(status=ComposeLoadStatus.FAILED, diagnostics=(error.diagnostic,))
    diagnostics = _unique_sorted(context.diagnostics, _diagnostic_key)
    return ComposeLoadResult(
        status=ComposeLoadStatus.PARTIAL if diagnostics else ComposeLoadStatus.COMPLETE,
        services=services,
        interpolations=interpolations,
        diagnostics=diagnostics,
    )


_T = TypeVar("_T")


def _unique_sorted(items: list[_T], key: Callable[[_T], Any]) -> tuple[_T, ...]:
    ordered = sorted(items, key=key)
    result: list[_T] = []
    seen: set[object] = set()
    for item in ordered:
        identity = key(item)
        if identity not in seen:
            seen.add(identity)
            result.append(item)
    return tuple(result)


def _consolidate_interpolations(
    items: list[ComposeInterpolation],
) -> tuple[ComposeInterpolation, ...]:
    service_bound = {
        (*_sort_location(item.location), item.name, item.operator.value)
        for item in items
        if item.service is not None
    }
    filtered = [
        item
        for item in items
        if item.service is not None
        or (*_sort_location(item.location), item.name, item.operator.value) not in service_bound
    ]
    return _unique_sorted(filtered, _interpolation_key)


def _validate_graph(context: _Context, root: Node, aliases: int) -> None:
    seen: set[int] = set()
    stack: set[int] = set()

    def visit(node: Node, depth: int) -> None:
        if depth > MAX_YAML_DEPTH:
            context.diagnostic(
                ComposeDiagnosticCode.SAFETY_LIMIT,
                node,
                "YAML nesting depth limit exceeded.",
                fatal=True,
            )
        identity = id(node)
        if identity in stack:
            context.diagnostic(
                ComposeDiagnosticCode.CYCLIC_ALIAS,
                node,
                "Recursive YAML aliases are not supported.",
                fatal=True,
            )
        if identity in seen:
            return
        seen.add(identity)
        if len(seen) > MAX_YAML_NODES:
            context.diagnostic(
                ComposeDiagnosticCode.SAFETY_LIMIT,
                node,
                "YAML node limit exceeded.",
                fatal=True,
            )
        if node.tag not in _SAFE_TAGS:
            context.diagnostic(
                ComposeDiagnosticCode.UNSUPPORTED_CONSTRUCT,
                node,
                "Custom YAML tags are not supported.",
            )
        if isinstance(node, ScalarNode) and len(node.value.encode("utf-8")) > MAX_SCALAR_BYTES:
            context.diagnostic(
                ComposeDiagnosticCode.SAFETY_LIMIT,
                node,
                "YAML scalar size limit exceeded.",
                fatal=True,
            )
        stack.add(identity)
        if isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                visit(key_node, depth + 1)
                visit(value_node, depth + 1)
        elif isinstance(node, SequenceNode):
            for child in node.value:
                visit(child, depth + 1)
        stack.remove(identity)

    visit(root, 1)
    context.merge_references = aliases


def _mapping_entries(
    context: _Context,
    node: MappingNode,
    *,
    fatal_duplicates: set[str] | None = None,
) -> dict[str, tuple[ScalarNode, Node]]:
    fatal_duplicates = fatal_duplicates or set()
    explicit: dict[str, tuple[ScalarNode, Node]] = {}
    merges: list[MappingNode] = []
    for key_node, value_node in node.value:
        if not isinstance(key_node, ScalarNode):
            context.diagnostic(
                ComposeDiagnosticCode.UNSUPPORTED_CONSTRUCT,
                key_node,
                "Non-scalar mapping keys are not supported.",
            )
            continue
        key = key_node.value
        if key == "<<" or key_node.tag == "tag:yaml.org,2002:merge":
            context.merge_references += 1
            if context.merge_references > MAX_ALIAS_MERGE_REFERENCES:
                context.diagnostic(
                    ComposeDiagnosticCode.SAFETY_LIMIT,
                    key_node,
                    "YAML alias and merge reference limit exceeded.",
                    fatal=True,
                )
            references = (
                [value_node]
                if isinstance(value_node, MappingNode)
                else (list(value_node.value) if isinstance(value_node, SequenceNode) else [])
            )
            if not references or any(not isinstance(item, MappingNode) for item in references):
                context.diagnostic(
                    ComposeDiagnosticCode.INVALID_MERGE,
                    key_node,
                    "YAML merge value must reference mappings.",
                    fatal=True,
                )
            merges.extend(references)
            continue
        if key in explicit:
            context.diagnostic(
                ComposeDiagnosticCode.DUPLICATE_KEY,
                key_node,
                "Duplicate YAML mapping key.",
                fatal=key in fatal_duplicates,
            )
            continue
        explicit[key] = (key_node, value_node)
    inherited: dict[str, tuple[ScalarNode, Node]] = {}
    for merged in merges:
        for key, pair in _mapping_entries(context, merged).items():
            inherited.setdefault(key, pair)
    inherited.update(explicit)
    return inherited


def _load_services(context: _Context, node: MappingNode) -> tuple[ComposeService, ...]:
    services: list[ComposeService] = []
    seen: set[str] = set()
    for key_node, value_node in node.value:
        if not isinstance(key_node, ScalarNode) or key_node.tag != "tag:yaml.org,2002:str":
            context.diagnostic(
                ComposeDiagnosticCode.INVALID_SERVICE,
                key_node,
                "Service name must be a static string scalar.",
                fatal=True,
            )
        name = key_node.value
        if not name or _contains_interpolation(name):
            context.diagnostic(
                ComposeDiagnosticCode.DYNAMIC_NAME,
                key_node,
                "Service name must be non-empty and static.",
                fatal=True,
            )
        if name in seen:
            context.diagnostic(
                ComposeDiagnosticCode.DUPLICATE_KEY,
                key_node,
                "Duplicate Compose service name.",
                fatal=True,
            )
        seen.add(name)
        if not isinstance(value_node, MappingNode):
            context.diagnostic(
                ComposeDiagnosticCode.INVALID_SERVICE,
                value_node,
                "Compose service definition must be a mapping.",
                fatal=True,
            )
        entries = _mapping_entries(context, value_node)
        profiles, locations = _load_profiles(context, entries.get("profiles"))
        extends = entries.get("extends")
        if extends is not None and isinstance(extends[1], MappingNode):
            extends_entries = _mapping_entries(context, extends[1])
            file_entry = extends_entries.get("file")
            if file_entry is not None:
                context.diagnostic(
                    ComposeDiagnosticCode.UNSUPPORTED_EXTERNAL_REFERENCE,
                    file_entry[0],
                    "External Compose references are not loaded.",
                )
        _scan_value(context, value_node, name, set())
        services.append(
            ComposeService(
                name=name,
                location=context.location(key_node),
                profiles=profiles,
                profile_locations=locations,
            )
        )
    return tuple(sorted(services, key=lambda item: (item.name, *_sort_location(item.location))))


def _load_profiles(
    context: _Context, entry: tuple[ScalarNode, Node] | None
) -> tuple[tuple[str, ...], tuple[SourceLocation, ...]]:
    if entry is None:
        return (), ()
    node = entry[1]
    if not isinstance(node, SequenceNode):
        context.diagnostic(
            ComposeDiagnosticCode.INVALID_PROFILES,
            node,
            "Compose profiles must be a sequence of static names.",
        )
        return (), ()
    if len(node.value) > MAX_PROFILES_PER_SERVICE:
        context.diagnostic(
            ComposeDiagnosticCode.SAFETY_LIMIT,
            node,
            "Compose profile limit exceeded.",
            fatal=True,
        )
    pairs: list[tuple[str, SourceLocation]] = []
    seen: set[str] = set()
    for child in node.value:
        if not isinstance(child, ScalarNode) or child.tag != "tag:yaml.org,2002:str":
            context.diagnostic(
                ComposeDiagnosticCode.INVALID_PROFILES,
                child,
                "Compose profile name must be a static string scalar.",
            )
            continue
        if not child.value or _contains_interpolation(child.value):
            context.diagnostic(
                ComposeDiagnosticCode.INVALID_PROFILES,
                child,
                "Compose profile name must be non-empty and static.",
            )
            continue
        if child.value in seen:
            context.diagnostic(
                ComposeDiagnosticCode.DUPLICATE_KEY,
                child,
                "Duplicate Compose profile name.",
            )
            continue
        seen.add(child.value)
        pairs.append((child.value, context.location(child)))
    pairs.sort(key=lambda pair: (pair[0], *_sort_location(pair[1])))
    return tuple(pair[0] for pair in pairs), tuple(pair[1] for pair in pairs)


def _scan_value(context: _Context, node: Node, service: str | None, stack: set[int]) -> None:
    identity = id(node)
    stack.add(identity)
    if isinstance(node, ScalarNode):
        _scan_scalar(context, node, service)
    elif isinstance(node, SequenceNode):
        for child in node.value:
            _scan_value(context, child, service, stack)
    elif isinstance(node, MappingNode):  # pragma: no branch - PyYAML has only three node kinds
        for _, value_node in node.value:
            _scan_value(context, value_node, service, stack)
    stack.remove(identity)


def _scan_root_values(context: _Context, root: MappingNode, services: MappingNode) -> None:
    for _, value_node in root.value:
        if value_node is not services:
            _scan_value(context, value_node, None, set())


def _contains_interpolation(value: str) -> bool:
    return bool(re.search(r"(?<!\$)\$(?:\{|[_A-Za-z])", value.replace("$$", "")))


def _scan_scalar(context: _Context, node: ScalarNode, service: str | None) -> None:
    raw = context.text[node.start_mark.index : node.end_mark.index]
    _scan_interpolations(context, node, raw, node.start_mark.index, service, 0, len(raw))


def _scan_interpolations(
    context: _Context,
    node: ScalarNode,
    text: str,
    base: int,
    service: str | None,
    start: int,
    end: int,
) -> None:
    index = start
    while index < end:
        if text[index] != "$":
            index += 1
            continue
        if index + 1 < end and text[index + 1] == "$":
            index += 2
            continue
        direct = _NAME.match(text, index + 1, end)
        if direct is not None:
            _append_interpolation(
                context,
                node,
                direct.group(),
                ComposeInterpolationOperator.DIRECT,
                base + index,
                service,
            )
            index = direct.end()
            continue
        if index + 1 >= end or text[index + 1] != "{":
            index += 1
            continue
        name = _NAME.match(text, index + 2, end)
        if name is None:
            context.diagnostic(
                ComposeDiagnosticCode.UNSUPPORTED_INTERPOLATION,
                node,
                "Unsupported Compose interpolation declaration.",
            )
            index += 2
            continue
        cursor = name.end()
        operator_text = ""
        for candidate in (":-", ":?", ":+", "-", "?", "+"):
            if text.startswith(candidate, cursor):
                operator_text = candidate
                break
        body_start = cursor + len(operator_text)
        depth = 1
        close = body_start
        while close < end and depth:
            if text.startswith("${", close):
                depth += 1
                close += 2
                continue
            if text[close] == "}":
                depth -= 1
                if depth == 0:
                    break
            close += 1
        supported = close < end and (operator_text or cursor == close)
        if supported:
            _append_interpolation(
                context,
                node,
                name.group(),
                _OPERATORS.get(operator_text, ComposeInterpolationOperator.DIRECT),
                base + index,
                service,
            )
            if operator_text:
                _scan_interpolations(context, node, text, base, service, body_start, close)
            index = close + 1
            continue
        context.diagnostic(
            ComposeDiagnosticCode.UNSUPPORTED_INTERPOLATION,
            node,
            "Unsupported Compose interpolation declaration.",
        )
        index = max(index + 2, close + 1)


def _append_interpolation(
    context: _Context,
    node: ScalarNode,
    name: str,
    operator: ComposeInterpolationOperator,
    index: int,
    service: str | None,
) -> None:
    context.interpolations.append(
        ComposeInterpolation(
            name=name,
            operator=operator,
            location=context.location(node, absolute_index=index),
            service=service,
        )
    )
    if len(context.interpolations) > MAX_INTERPOLATIONS:
        context.diagnostic(
            ComposeDiagnosticCode.SAFETY_LIMIT,
            node,
            "Compose interpolation limit exceeded.",
            fatal=True,
        )


__all__ = [
    "MAX_ALIAS_MERGE_REFERENCES",
    "MAX_COMPOSE_BYTES",
    "MAX_COMPOSE_SERVICES",
    "MAX_INTERPOLATIONS",
    "MAX_PROFILES_PER_SERVICE",
    "MAX_SCALAR_BYTES",
    "MAX_YAML_DEPTH",
    "MAX_YAML_NODES",
    "load_compose",
]
