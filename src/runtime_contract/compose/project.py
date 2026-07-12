"""Pure, bounded Docker Compose project resolution with value-blind provenance."""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NoReturn

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from runtime_contract.compose.loader import load_compose
from runtime_contract.compose.models import (
    ComposeBinding,
    ComposeBindingChannel,
    ComposeBindingKind,
    ComposeDiagnostic,
    ComposeDiagnosticCode,
    ComposeEnvFile,
    ComposeInput,
    ComposeInterpolation,
    ComposeInterpolationOperator,
    ComposeInterpolationResolution,
    ComposeLoadStatus,
    ComposeProjectInput,
    ComposeProjectResult,
    ComposeProvenanceOperation,
    ComposeProvenanceOutcome,
    ComposeProvenanceStep,
    ComposeResolutionTrace,
    ComposeService,
    ComposeServiceActivation,
    ComposeSourceKind,
    ComposeUsedSource,
    ComposeVariableSourceKind,
)
from runtime_contract.domain import SourceLocation

if TYPE_CHECKING:
    from runtime_contract.analysis.models import EffectiveClassification

MAX_PROJECT_FILES = 128
MAX_PROJECT_BYTES = 8 * 1024 * 1024
MAX_PROVENANCE_STEPS = 100_000
MAX_REFERENCE_DEPTH = 32
MAX_PROJECT_REFERENCES = 1_024
MAX_ACTIVE_PROFILES = 256
MAX_SHELL_VARIABLE_NAMES = 10_000
MAX_NAME_BYTES = 512

_PROFILE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]+")
_NAME = re.compile(r"[_A-Za-z][_A-Za-z0-9]*")
_REMOTE = re.compile(r"(?:https?|git|oci)://|^git@", re.IGNORECASE)
_RESET = "!reset"
_OVERRIDE = "!override"


class _ResolverError(Exception):
    def __init__(self, diagnostic: ComposeDiagnostic) -> None:
        self.diagnostic = diagnostic


class _NullResolver:
    def classify(self, variable: str) -> EffectiveClassification:
        from runtime_contract.analysis.models import EffectiveClassification

        return EffectiveClassification()


@dataclass(slots=True)
class _Entry:
    value: object
    location: SourceLocation
    source_kind: ComposeSourceKind
    source_path: str
    source_index: int
    mode: str = "merge"


@dataclass(slots=True)
class _ServiceProjection:
    name: str
    location: SourceLocation
    source_kind: ComposeSourceKind
    source_path: str
    source_index: int
    profiles: list[_Entry] = field(default_factory=list)
    environment: list[_Entry] = field(default_factory=list)
    build_args: list[_Entry] = field(default_factory=list)
    env_files: list[_Entry] = field(default_factory=list)
    interpolation: list[ComposeInterpolation] = field(default_factory=list)
    attribute_modes: dict[str, str] = field(default_factory=dict)
    extends: tuple[str | None, str, SourceLocation] | None = None


@dataclass(slots=True)
class _State:
    source: ComposeProjectInput
    bundle: dict[str, tuple[int, ComposeInput]]
    base_dir: str
    referenced: set[str] = field(default_factory=set)
    reference_count: int = 0
    used: list[ComposeUsedSource] = field(default_factory=list)
    traces: dict[str, list[ComposeProvenanceStep]] = field(default_factory=dict)
    winners: dict[str, int | None] = field(default_factory=dict)
    global_interpolations: list[ComposeInterpolation] = field(default_factory=list)

    def reference(self, location: SourceLocation) -> None:
        self.reference_count += 1
        if self.reference_count > MAX_PROJECT_REFERENCES:
            self.fail(
                ComposeDiagnosticCode.PROVENANCE_LIMIT,
                location,
                "Compose project reference limit exceeded.",
            )

    def fail(self, code: ComposeDiagnosticCode, location: SourceLocation, message: str) -> NoReturn:
        raise _ResolverError(ComposeDiagnostic(code=code, location=location, message=message))

    def add_step(
        self,
        subject: str,
        entry: _Entry,
        operation: ComposeProvenanceOperation,
        outcome: ComposeProvenanceOutcome,
    ) -> None:
        steps = self.traces.setdefault(subject, [])
        if sum(len(items) for items in self.traces.values()) >= MAX_PROVENANCE_STEPS:
            self.fail(
                ComposeDiagnosticCode.PROVENANCE_LIMIT,
                entry.location,
                "Compose project provenance limit exceeded.",
            )
        steps.append(
            ComposeProvenanceStep(
                source_kind=entry.source_kind,
                source_path=entry.source_path,
                source_index=entry.source_index,
                location=entry.location,
                operation=operation,
                outcome=outcome,
            )
        )
        if outcome is ComposeProvenanceOutcome.EFFECTIVE:
            self.winners[subject] = len(steps) - 1

    def retire(self, subject: str, outcome: ComposeProvenanceOutcome) -> None:
        steps = self.traces.get(subject, [])
        self.traces[subject] = [
            step.model_copy(update={"outcome": outcome})
            if step.outcome is ComposeProvenanceOutcome.EFFECTIVE
            else step
            for step in steps
        ]
        self.winners[subject] = None


def resolve_compose_project(source: ComposeProjectInput) -> ComposeProjectResult:
    """Resolve an explicit in-memory Compose bundle without I/O or value expansion."""

    try:
        state = _prepare(source)
        projections = _top_level_projections(state)
        effective = _merge_project(state, projections)
        interpolations = _resolve_interpolations(state, effective)
        services = _materialize_services(state, effective, interpolations)
        traces = tuple(
            ComposeResolutionTrace(
                subject=subject,
                contributions=tuple(steps),
                winner_index=state.winners.get(subject),
            )
            for subject, steps in sorted(state.traces.items())
        )
        return ComposeProjectResult(
            status=ComposeLoadStatus.COMPLETE,
            services=services,
            interpolations=interpolations,
            resolution_traces=traces,
            used_sources=tuple(state.used),
        )
    except _ResolverError as error:
        return ComposeProjectResult(
            status=ComposeLoadStatus.FAILED,
            diagnostics=(error.diagnostic,),
        )


def _prepare(source: ComposeProjectInput) -> _State:
    first = source.files[0]
    location = SourceLocation(path=first.path, start_line=1, start_column=1)
    if len(source.files) > MAX_PROJECT_FILES:
        raise _ResolverError(
            ComposeDiagnostic(
                code=ComposeDiagnosticCode.PROJECT_SIZE_LIMIT,
                location=location,
                message="Compose project file count limit exceeded.",
            )
        )
    if sum(len(item.content) for item in source.files) > MAX_PROJECT_BYTES:
        raise _ResolverError(
            ComposeDiagnostic(
                code=ComposeDiagnosticCode.PROJECT_SIZE_LIMIT,
                location=location,
                message="Compose project byte limit exceeded.",
            )
        )
    paths: dict[str, tuple[int, ComposeInput]] = {}
    for index, item in enumerate(source.files):
        if item.path in paths:
            raise _ResolverError(
                ComposeDiagnostic(
                    code=ComposeDiagnosticCode.DUPLICATE_PROJECT_PATH,
                    location=SourceLocation(path=item.path, start_line=1, start_column=1),
                    message="Duplicate logical Compose project path.",
                )
            )
        paths[item.path] = (index, item)
    _validate_names(source.active_profiles, MAX_ACTIVE_PROFILES, True, location)
    _validate_names(source.shell_variable_names, MAX_SHELL_VARIABLE_NAMES, False, location)
    return _State(source=source, bundle=paths, base_dir=posixpath.dirname(first.path))


def _validate_names(
    names: tuple[str, ...], limit: int, profiles: bool, location: SourceLocation
) -> None:
    if len(names) > limit:
        code = (
            ComposeDiagnosticCode.INVALID_PROFILE
            if profiles
            else ComposeDiagnosticCode.INVALID_PROJECT_INPUT
        )
        raise _ResolverError(
            ComposeDiagnostic(code=code, location=location, message="Compose name limit exceeded.")
        )
    pattern = _PROFILE if profiles else _NAME
    for name in names:
        if (profiles and name == "*") or (
            pattern.fullmatch(name) and len(name.encode("utf-8")) <= MAX_NAME_BYTES
        ):
            continue
        code = (
            ComposeDiagnosticCode.INVALID_PROFILE
            if profiles
            else ComposeDiagnosticCode.INVALID_PROJECT_INPUT
        )
        raise _ResolverError(
            ComposeDiagnostic(code=code, location=location, message="Invalid Compose name.")
        )


def _top_level_projections(state: _State) -> list[_ServiceProjection]:
    parsed: list[tuple[int, ComposeInput, list[_ServiceProjection]]] = []
    for index, item in enumerate(state.source.files):
        parsed.append(
            (index, item, _parse_document(state, item.path, ComposeSourceKind.COMPOSE_FILE))
        )
    return [
        projection
        for _, item, items in parsed
        if item.path not in state.referenced
        for projection in items
    ]


def _parse_document(
    state: _State,
    path: str,
    kind: ComposeSourceKind,
    stack: tuple[str, ...] = (),
) -> list[_ServiceProjection]:
    if len(stack) >= MAX_REFERENCE_DEPTH:
        state.fail(
            ComposeDiagnosticCode.CYCLIC_REFERENCE,
            SourceLocation(path=path),
            "Compose reference depth limit exceeded.",
        )
    if path in stack:
        state.fail(
            ComposeDiagnosticCode.CYCLIC_REFERENCE,
            SourceLocation(path=path),
            "Cyclic Compose reference.",
        )
    pair = state.bundle.get(path)
    if pair is None:
        state.fail(
            ComposeDiagnosticCode.MISSING_REFERENCE,
            SourceLocation(path=stack[-1] if stack else state.source.files[0].path),
            "Referenced Compose file is missing from the bundle.",
        )
    index, source = pair
    try:
        text = source.content.decode("utf-8-sig")
        documents = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except (UnicodeDecodeError, yaml.YAMLError):
        state.fail(
            ComposeDiagnosticCode.INVALID_YAML,
            SourceLocation(path=path, start_line=1, start_column=1),
            "Invalid referenced Compose document.",
        )
    if len(documents) != 1 or not isinstance(documents[0], MappingNode):
        state.fail(
            ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
            SourceLocation(path=path, start_line=1, start_column=1),
            "Compose project document must be one mapping.",
        )
    root = documents[0]
    assert isinstance(root, MappingNode)
    entries = _entries(state, path, root)
    loaded = load_compose(source)
    state.global_interpolations.extend(
        item for item in loaded.interpolations if item.service is None
    )
    state.used.append(ComposeUsedSource(kind=kind, path=path, source_index=index))
    includes: list[_ServiceProjection] = []
    include = entries.get("include")
    if include is not None:
        for group in _include_groups(state, path, include[1]):
            group_services: list[_ServiceProjection] = []
            for reference, location in group:
                state.reference(location)
                resolved = _resolve_reference(state, path, reference, location)
                state.referenced.add(resolved)
                group_services.extend(
                    _parse_document(state, resolved, ComposeSourceKind.INCLUDE_FILE, (*stack, path))
                )
            existing = {service.name for service in includes}
            conflict = next(
                (service for service in group_services if service.name in existing), None
            )
            if conflict is not None:
                state.fail(
                    ComposeDiagnosticCode.MERGE_CONFLICT,
                    conflict.location,
                    "Included Compose resource conflicts with an existing resource.",
                )
            includes.extend(group_services)
    services_pair = entries.get("services")
    if services_pair is None or not isinstance(services_pair[1], MappingNode):
        state.fail(
            ComposeDiagnosticCode.INVALID_SERVICES,
            _location(path, root),
            "Top-level services mapping is required.",
        )
    services_node = services_pair[1]
    assert isinstance(services_node, MappingNode)
    local: list[_ServiceProjection] = []
    for key, value in _entries(state, path, services_node).values():
        if not isinstance(value, MappingNode):
            state.fail(
                ComposeDiagnosticCode.INVALID_SERVICE,
                _location(path, value),
                "Compose service must use a static name and mapping.",
            )
        local.append(_parse_service(state, path, index, kind, key, value))
    names = {service.name for service in includes}
    conflict = next((service for service in local if service.name in names), None)
    if conflict is not None:
        state.fail(
            ComposeDiagnosticCode.MERGE_CONFLICT,
            conflict.location,
            "Included Compose resource conflicts with a local resource.",
        )
    combined = [*includes, *local]
    by_name = {service.name: service for service in combined}
    return [_resolve_extends(state, service, by_name, (*stack, path)) for service in combined]


def _parse_service(
    state: _State,
    path: str,
    index: int,
    kind: ComposeSourceKind,
    key: ScalarNode,
    node: MappingNode,
) -> _ServiceProjection:
    name = key.value
    if not name or "${" in name:
        state.fail(
            ComposeDiagnosticCode.INVALID_SERVICE,
            _location(path, key),
            "Service name must be static.",
        )
    entries = _entries(state, path, node)
    projection = _ServiceProjection(name, _location(path, key), kind, path, index)
    projection.profiles = _sequence_entries(
        state, projection, entries.get("profiles"), "profiles", value_kind="profile"
    )
    projection.environment = _binding_entries(
        state, projection, entries.get("environment"), ComposeBindingKind.ENVIRONMENT
    )
    build = entries.get("build")
    if build is not None and isinstance(build[1], MappingNode):
        projection.build_args = _binding_entries(
            state,
            projection,
            _entries(state, path, build[1]).get("args"),
            ComposeBindingKind.BUILD_ARG,
        )
    projection.env_files = _sequence_entries(
        state, projection, entries.get("env_file"), "env_file", value_kind="env_file"
    )
    loaded = load_compose(ComposeInput(path=path, content=state.bundle[path][1].content))
    projection.interpolation = [item for item in loaded.interpolations if item.service == name]
    extends = entries.get("extends")
    if extends is not None:
        projection.extends = _extends_spec(state, path, extends[1])
    return projection


def _entries(state: _State, path: str, node: MappingNode) -> dict[str, tuple[ScalarNode, Node]]:
    explicit: dict[str, tuple[ScalarNode, Node]] = {}
    merges: list[MappingNode] = []
    for key, value in node.value:
        if not isinstance(key, ScalarNode):
            state.fail(
                ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
                _location(path, key),
                "Non-scalar Compose mapping key is unsupported.",
            )
        if key.value == "<<" or key.tag == "tag:yaml.org,2002:merge":
            references = (
                [value]
                if isinstance(value, MappingNode)
                else list(value.value)
                if isinstance(value, SequenceNode)
                else []
            )
            if not references or any(
                not isinstance(reference, MappingNode) for reference in references
            ):
                state.fail(
                    ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
                    _location(path, value),
                    "YAML merge must reference mappings.",
                )
            merges.extend(
                reference for reference in references if isinstance(reference, MappingNode)
            )
            continue
        if key.value in explicit:
            state.fail(
                ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
                _location(path, key),
                "Duplicate YAML mapping key.",
            )
        explicit[key.value] = (key, value)
    inherited: dict[str, tuple[ScalarNode, Node]] = {}
    for merged in merges:
        for name, pair in _entries(state, path, merged).items():
            inherited.setdefault(name, pair)
    inherited.update(explicit)
    return inherited


def _mode(state: _State, path: str, node: Node) -> str:
    if node.tag in {_RESET, _OVERRIDE}:
        return node.tag[1:]
    if node.tag.startswith("!"):
        state.fail(
            ComposeDiagnosticCode.INVALID_OVERRIDE_TAG,
            _location(path, node),
            "Unsupported Compose override tag.",
        )
    return "merge"


def _binding_entries(
    state: _State,
    service: _ServiceProjection,
    pair: tuple[ScalarNode, Node] | None,
    kind: ComposeBindingKind,
) -> list[_Entry]:
    if pair is None:
        return []
    node = pair[1]
    service.attribute_modes[
        "environment" if kind is ComposeBindingKind.ENVIRONMENT else "build_args"
    ] = _mode(state, service.source_path, node)
    if (
        service.attribute_modes[
            "environment" if kind is ComposeBindingKind.ENVIRONMENT else "build_args"
        ]
        == "reset"
    ):
        return []
    raw: list[tuple[str, ScalarNode, Node]] = []
    if isinstance(node, MappingNode):
        raw = [
            (key.value, key, value)
            for key, value in _entries(state, service.source_path, node).values()
        ]
    elif isinstance(node, SequenceNode):
        raw = [
            (child.value.split("=", 1)[0], child, child)
            for child in node.value
            if isinstance(child, ScalarNode)
        ]
    else:
        state.fail(
            ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
            _location(service.source_path, node),
            "Compose bindings must be a mapping or sequence.",
        )
    result: list[_Entry] = []
    for priority, (name, key, value) in enumerate(raw):
        if not _NAME.fullmatch(name):
            state.fail(
                ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
                _location(service.source_path, key),
                "Compose binding name must be static and valid.",
            )
        mode = _mode(state, service.source_path, value)
        binding = ComposeBinding(
            name=name,
            kind=kind,
            channel=_project_binding_channel(value),
            location=_location(service.source_path, key),
            priority=priority,
        )
        result.append(
            _Entry(
                binding,
                binding.location,
                service.source_kind,
                service.source_path,
                service.source_index,
                mode,
            )
        )
    return result


def _project_binding_channel(node: Node) -> ComposeBindingChannel:
    if isinstance(node, ScalarNode):
        if node.tag == "tag:yaml.org,2002:null":
            return ComposeBindingChannel.PASS_THROUGH
        value = node.value.split("=", 1)[1] if "=" in node.value else node.value
        if re.fullmatch(
            r"\$(?:[_A-Za-z][_A-Za-z0-9]*|\{[_A-Za-z][_A-Za-z0-9]*(?::[-?].*)?\})",
            value,
        ):
            return ComposeBindingChannel.PASS_THROUGH
    return ComposeBindingChannel.PLAIN_LITERAL


def _sequence_entries(
    state: _State,
    service: _ServiceProjection,
    pair: tuple[ScalarNode, Node] | None,
    attribute: str,
    *,
    value_kind: str,
) -> list[_Entry]:
    if pair is None:
        return []
    node = pair[1]
    service.attribute_modes[attribute] = _mode(state, service.source_path, node)
    if service.attribute_modes[attribute] == "reset":
        return []
    items = node.value if isinstance(node, SequenceNode) else [node]
    result: list[_Entry] = []
    for priority, item in enumerate(items):
        mode = _mode(state, service.source_path, item)
        location = _location(service.source_path, item)
        if value_kind == "profile":
            if not isinstance(item, ScalarNode):
                state.fail(
                    ComposeDiagnosticCode.INVALID_PROFILE,
                    location,
                    "Compose profile must be a static name.",
                )
            if not _PROFILE.fullmatch(item.value):
                state.fail(
                    ComposeDiagnosticCode.INVALID_PROFILE,
                    location,
                    "Invalid Compose profile name.",
                )
            value: object = item.value
        else:
            path_node = item
            required = True
            format_value: str | None = None
            if isinstance(item, MappingNode):
                fields = _entries(state, service.source_path, item)
                path_pair = fields.get("path")
                if path_pair is None:
                    state.fail(
                        ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
                        location,
                        "Compose env_file mapping requires path.",
                    )
                path_node = path_pair[1]
                required_pair = fields.get("required")
                if required_pair is not None and isinstance(required_pair[1], ScalarNode):
                    required = required_pair[1].value.lower() == "true"
                format_pair = fields.get("format")
                if format_pair is not None and isinstance(format_pair[1], ScalarNode):
                    format_value = format_pair[1].value
            if not isinstance(path_node, ScalarNode):
                state.fail(
                    ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
                    location,
                    "Compose env_file path must be static.",
                )
            resolved = _resolve_env_file_path(state, service, path_node.value, location)
            value = ComposeEnvFile(
                path=resolved,
                required=required,
                format=format_value,
                location=location,
                priority=priority,
            )
        result.append(
            _Entry(
                value,
                location,
                service.source_kind,
                service.source_path,
                service.source_index,
                mode,
            )
        )
    return result


def _resolve_env_file_path(
    state: _State, service: _ServiceProjection, value: str, location: SourceLocation
) -> str:
    directory = (
        posixpath.dirname(service.source_path)
        if service.source_kind in {ComposeSourceKind.INCLUDE_FILE, ComposeSourceKind.EXTENDS_FILE}
        else state.base_dir
    )
    return _safe_join(state, directory, value, location)


def _include_groups(state: _State, path: str, node: Node) -> list[list[tuple[str, SourceLocation]]]:
    items = node.value if isinstance(node, SequenceNode) else [node]
    result: list[list[tuple[str, SourceLocation]]] = []
    for item in items:
        target = item
        if isinstance(item, MappingNode):
            pair = _entries(state, path, item).get("path")
            target = pair[1] if pair else item
        targets = target.value if isinstance(target, SequenceNode) else [target]
        if not targets or any(not isinstance(candidate, ScalarNode) for candidate in targets):
            state.fail(
                ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
                _location(path, item),
                "Compose reference must be a static path.",
            )
        group: list[tuple[str, SourceLocation]] = []
        for candidate in targets:
            assert isinstance(candidate, ScalarNode)
            group.append((candidate.value, _location(path, candidate)))
        result.append(group)
    return result


def _resolve_reference(state: _State, owner: str, reference: str, location: SourceLocation) -> str:
    if _REMOTE.search(reference):
        state.fail(
            ComposeDiagnosticCode.REMOTE_REFERENCE,
            location,
            "Remote Compose references are forbidden.",
        )
    return _safe_join(state, posixpath.dirname(owner), reference, location)


def _safe_join(state: _State, directory: str, value: str, location: SourceLocation) -> str:
    if (
        not value
        or "\0" in value
        or "\\" in value
        or value.startswith("/")
        or re.match(r"^[A-Za-z]:", value)
    ):
        state.fail(
            ComposeDiagnosticCode.REMOTE_REFERENCE,
            location,
            "Unsafe local Compose reference.",
        )
    resolved = posixpath.normpath(posixpath.join(directory, value))
    if resolved in {"", ".", ".."} or resolved.startswith("../"):
        state.fail(
            ComposeDiagnosticCode.REMOTE_REFERENCE,
            location,
            "Compose reference escapes the logical root.",
        )
    return resolved


def _extends_spec(state: _State, owner: str, node: Node) -> tuple[str | None, str, SourceLocation]:
    if not isinstance(node, MappingNode):
        state.fail(
            ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
            _location(owner, node),
            "Compose extends must be a mapping.",
        )
    entries = _entries(state, owner, node)
    service_pair = entries.get("service")
    if service_pair is None or not isinstance(service_pair[1], ScalarNode):
        state.fail(
            ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
            _location(owner, node),
            "Compose extends service must be static.",
        )
    service_node = service_pair[1]
    assert isinstance(service_node, ScalarNode)
    file_pair = entries.get("file")
    file_path: str | None = None
    if file_pair is not None:
        if not isinstance(file_pair[1], ScalarNode):
            state.fail(
                ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
                _location(owner, file_pair[1]),
                "Compose extends file must be static.",
            )
        file_node = file_pair[1]
        assert isinstance(file_node, ScalarNode)
        file_path = _resolve_reference(state, owner, file_node.value, _location(owner, file_node))
    return file_path, service_node.value, _location(owner, service_node)


def _resolve_extends(
    state: _State,
    service: _ServiceProjection,
    local: dict[str, _ServiceProjection],
    stack: tuple[str, ...],
) -> _ServiceProjection:
    if service.extends is None:
        return service
    state.reference(service.extends[2])
    file_path, name, location = service.extends
    identity = f"{file_path or service.source_path}:{name}"
    if identity in stack:
        state.fail(ComposeDiagnosticCode.CYCLIC_REFERENCE, location, "Cyclic Compose extends.")
    if file_path is None:
        base = local.get(name)
    else:
        state.referenced.add(file_path)
        candidates = _parse_document(
            state, file_path, ComposeSourceKind.EXTENDS_FILE, (*stack, identity)
        )
        base = next((candidate for candidate in candidates if candidate.name == name), None)
    if base is None:
        state.fail(
            ComposeDiagnosticCode.MISSING_REFERENCE,
            location,
            "Extended Compose service is missing from the bundle.",
        )
    assert base is not None
    base = _resolve_extends(state, base, local, (*stack, identity))
    return _inherit(base, service)


def _inherit(base: _ServiceProjection, child: _ServiceProjection) -> _ServiceProjection:
    result = _ServiceProjection(
        child.name,
        child.location,
        child.source_kind,
        child.source_path,
        child.source_index,
        profiles=[*base.profiles, *child.profiles],
        environment=[*base.environment, *child.environment],
        build_args=[*base.build_args, *child.build_args],
        env_files=[*base.env_files, *child.env_files],
        interpolation=[*base.interpolation, *child.interpolation],
        attribute_modes=child.attribute_modes,
    )
    return result


def _merge_project(
    state: _State, projections: list[_ServiceProjection]
) -> dict[str, _ServiceProjection]:
    result: dict[str, _ServiceProjection] = {}
    for service in projections:
        current = result.get(service.name)
        if current is None:
            current = _ServiceProjection(
                service.name,
                service.location,
                service.source_kind,
                service.source_path,
                service.source_index,
            )
            result[service.name] = current
        else:
            current.location = service.location
            current.source_kind = service.source_kind
            current.source_path = service.source_path
            current.source_index = service.source_index
        current.profiles = _merge_sequence(
            state,
            f"/services/{service.name}/profiles",
            current.profiles,
            service.profiles,
            service.attribute_modes.get("profiles"),
            deduplicate=True,
            reset_entry=_service_entry(service),
        )
        current.environment = _merge_mapping(
            state,
            f"/services/{service.name}/environment",
            current.environment,
            service.environment,
            service.attribute_modes.get("environment"),
            _service_entry(service),
        )
        current.build_args = _merge_mapping(
            state,
            f"/services/{service.name}/build/args",
            current.build_args,
            service.build_args,
            service.attribute_modes.get("build_args"),
            _service_entry(service),
        )
        current.env_files = _merge_sequence(
            state,
            f"/services/{service.name}/env_file",
            current.env_files,
            service.env_files,
            service.attribute_modes.get("env_file"),
            deduplicate=False,
            reset_entry=_service_entry(service),
        )
        current.interpolation.extend(service.interpolation)
    return result


def _merge_mapping(
    state: _State,
    prefix: str,
    old: list[_Entry],
    new: list[_Entry],
    attribute_mode: str | None,
    reset_entry: _Entry,
) -> list[_Entry]:
    current = {item.value.name: item for item in old if isinstance(item.value, ComposeBinding)}
    if attribute_mode in {"reset", "override"}:
        for name in list(current):
            subject = f"{prefix}/{name}"
            state.retire(
                subject,
                ComposeProvenanceOutcome.REMOVED
                if attribute_mode == "reset"
                else ComposeProvenanceOutcome.SUPERSEDED,
            )
            state.add_step(
                subject,
                reset_entry,
                ComposeProvenanceOperation.RESET
                if attribute_mode == "reset"
                else ComposeProvenanceOperation.SUPERSEDED,
                ComposeProvenanceOutcome.REMOVED
                if attribute_mode == "reset"
                else ComposeProvenanceOutcome.SUPERSEDED,
            )
        current.clear()
    for entry in new:
        assert isinstance(entry.value, ComposeBinding)
        name = entry.value.name
        subject = f"{prefix}/{name}"
        if entry.mode == "reset":
            state.retire(subject, ComposeProvenanceOutcome.REMOVED)
            state.add_step(
                subject,
                entry,
                ComposeProvenanceOperation.RESET,
                ComposeProvenanceOutcome.REMOVED,
            )
            current.pop(name, None)
            continue
        if name in current:
            state.retire(subject, ComposeProvenanceOutcome.SUPERSEDED)
            operation = ComposeProvenanceOperation.REPLACED
        else:
            operation = (
                ComposeProvenanceOperation.REPLACED
                if attribute_mode == "override"
                else ComposeProvenanceOperation.INTRODUCED
            )
        current[name] = entry
        state.add_step(subject, entry, operation, ComposeProvenanceOutcome.EFFECTIVE)
    return list(current.values())


def _merge_sequence(
    state: _State,
    prefix: str,
    old: list[_Entry],
    new: list[_Entry],
    attribute_mode: str | None,
    *,
    deduplicate: bool,
    reset_entry: _Entry,
) -> list[_Entry]:
    current = list(old)
    if attribute_mode in {"reset", "override"}:
        outcome = (
            ComposeProvenanceOutcome.REMOVED
            if attribute_mode == "reset"
            else ComposeProvenanceOutcome.SUPERSEDED
        )
        for position, item in enumerate(current):
            suffix = item.value if deduplicate and isinstance(item.value, str) else position
            subject = f"{prefix}/{suffix}"
            state.retire(subject, outcome)
            state.add_step(
                subject,
                reset_entry,
                ComposeProvenanceOperation.RESET
                if attribute_mode == "reset"
                else ComposeProvenanceOperation.SUPERSEDED,
                outcome,
            )
        current.clear()
    for entry in new:
        identity = entry.value if isinstance(entry.value, str) else None
        if deduplicate and any(item.value == identity for item in current):
            subject = f"{prefix}/{identity}"
            state.add_step(
                subject,
                entry,
                ComposeProvenanceOperation.RETAINED,
                ComposeProvenanceOutcome.SUPERSEDED,
            )
            continue
        current.append(entry)
        suffix = identity if identity is not None else str(len(current) - 1)
        state.add_step(
            f"{prefix}/{suffix}",
            entry,
            ComposeProvenanceOperation.INTRODUCED
            if len(current) == 1
            else ComposeProvenanceOperation.MERGED,
            ComposeProvenanceOutcome.EFFECTIVE,
        )
    return current


def _resolve_interpolations(
    state: _State, services: dict[str, _ServiceProjection]
) -> tuple[ComposeInterpolation, ...]:
    available: dict[str, tuple[ComposeSourceKind, str | None]] = {}
    for index, name in enumerate(state.source.shell_variable_names):
        available[name] = (ComposeSourceKind.EXPLICIT_SHELL_NAME, None)
        state.used.append(
            ComposeUsedSource(
                kind=ComposeSourceKind.EXPLICIT_SHELL_NAME,
                path=None,
                source_index=index,
            )
        )
    cli = [
        (index, item)
        for index, item in enumerate(state.source.interpolation_sources)
        if item.kind is ComposeVariableSourceKind.CLI_ENV_FILE
    ]
    selected = cli or [
        (index, item)
        for index, item in enumerate(state.source.interpolation_sources)
        if item.kind is ComposeVariableSourceKind.PROJECT_DOTENV
    ]
    for index, variable_source in selected:
        kind = (
            ComposeSourceKind.CLI_ENV_FILE
            if variable_source.kind is ComposeVariableSourceKind.CLI_ENV_FILE
            else ComposeSourceKind.PROJECT_DOTENV
        )
        state.used.append(
            ComposeUsedSource(kind=kind, path=variable_source.path, source_index=index)
        )
        for name in _dotenv_names(variable_source.path, variable_source.content):
            if name not in state.source.shell_variable_names:
                available[name] = (kind, variable_source.path)
    items: list[ComposeInterpolation] = []
    all_interpolations = [*state.global_interpolations]
    for service in services.values():
        all_interpolations.extend(service.interpolation)
    seen: set[tuple[object, ...]] = set()
    for interpolation in all_interpolations:
        identity = (
            interpolation.location.path,
            interpolation.location.start_line,
            interpolation.location.start_column,
            interpolation.name,
            interpolation.service,
        )
        if identity in seen:
            continue
        seen.add(identity)
        resolved = available.get(interpolation.name)
        fallback = interpolation.operator in {
            ComposeInterpolationOperator.DEFAULT_IF_UNSET_OR_EMPTY,
            ComposeInterpolationOperator.DEFAULT_IF_UNSET,
            ComposeInterpolationOperator.ALTERNATE_IF_SET_AND_NONEMPTY,
            ComposeInterpolationOperator.ALTERNATE_IF_SET,
        }
        items.append(
            interpolation.model_copy(
                update={
                    "resolved_source_kind": resolved[0] if resolved else None,
                    "resolved_source_path": resolved[1] if resolved else None,
                    "resolution": (
                        ComposeInterpolationResolution.RESOLVED
                        if resolved
                        else ComposeInterpolationResolution.FALLBACK
                        if fallback
                        else ComposeInterpolationResolution.UNRESOLVED
                    ),
                }
            )
        )
        source_pair = state.bundle.get(interpolation.location.path)
        source_index = source_pair[0] if source_pair is not None else 0
        source_kind = next(
            (
                item.kind
                for item in reversed(state.used)
                if item.path == interpolation.location.path
                and item.kind
                in {
                    ComposeSourceKind.COMPOSE_FILE,
                    ComposeSourceKind.INCLUDE_FILE,
                    ComposeSourceKind.EXTENDS_FILE,
                }
            ),
            ComposeSourceKind.COMPOSE_FILE,
        )
        subject = (
            f"/interpolations/{interpolation.service or 'global'}/{interpolation.name}/"
            f"{interpolation.location.start_line or 0}:{interpolation.location.start_column or 0}"
        )
        state.add_step(
            subject,
            _Entry(
                interpolation,
                interpolation.location,
                source_kind,
                interpolation.location.path,
                source_index,
            ),
            ComposeProvenanceOperation.INTRODUCED,
            ComposeProvenanceOutcome.EFFECTIVE,
        )
    return tuple(
        sorted(
            items,
            key=lambda item: (
                item.location.path,
                item.location.start_line or 0,
                item.location.start_column or 0,
                item.name,
            ),
        )
    )


def _dotenv_names(path: str, content: bytes) -> tuple[str, ...]:
    from runtime_contract.analysis.dotenv import DotenvAnalyzer
    from runtime_contract.analysis.models import FactKind
    from runtime_contract.analysis.protocols import AnalyzerInput
    from runtime_contract.discovery import CandidateKind
    from runtime_contract.domain import ConfigKey, Profile

    result = DotenvAnalyzer().analyze(
        AnalyzerInput(
            path=path,
            kind=CandidateKind.ENV_EXAMPLE,
            content=content,
            component="compose-project",
            root=".",
            profile=Profile.DEFAULT,
            resolver=_NullResolver(),
        )
    )
    if result.completeness.value == "failed":
        raise _ResolverError(
            ComposeDiagnostic(
                code=ComposeDiagnosticCode.INVALID_PROJECT_INPUT,
                location=SourceLocation(path=path),
                message="Invalid dotenv interpolation source.",
            )
        )
    return tuple(
        observation.fact.name
        for observation in result.observations
        if observation.fact_kind is FactKind.CONFIG_KEY and isinstance(observation.fact, ConfigKey)
    )


def _materialize_services(
    state: _State,
    projections: dict[str, _ServiceProjection],
    interpolations: tuple[ComposeInterpolation, ...],
) -> tuple[ComposeService, ...]:
    active = set(state.source.active_profiles)
    result: list[ComposeService] = []
    for projection in projections.values():
        profiles = tuple(str(item.value) for item in projection.profiles)
        if not profiles:
            activation = ComposeServiceActivation.ALWAYS_ENABLED
        elif "*" in active or active.intersection(profiles):
            activation = ComposeServiceActivation.PROFILE_ENABLED
        else:
            activation = ComposeServiceActivation.PROFILE_DISABLED
        service_interpolations = tuple(
            item for item in interpolations if item.service == projection.name
        )
        result.append(
            ComposeService(
                name=projection.name,
                location=projection.location,
                profiles=profiles,
                profile_locations=tuple(item.location for item in projection.profiles),
                interpolations=service_interpolations,
                bindings=tuple(
                    item.value
                    for item in [*projection.environment, *projection.build_args]
                    if isinstance(item.value, ComposeBinding)
                ),
                env_files=tuple(
                    item.value
                    for item in projection.env_files
                    if isinstance(item.value, ComposeEnvFile)
                ),
                activation=activation,
            )
        )
    return tuple(result)


def _location(path: str, node: Node) -> SourceLocation:
    return SourceLocation(
        path=path,
        start_line=node.start_mark.line + 1,
        start_column=node.start_mark.column + 1,
        end_line=node.end_mark.line + 1,
        end_column=node.end_mark.column + 1,
    )


def _service_entry(service: _ServiceProjection) -> _Entry:
    return _Entry(
        None,
        service.location,
        service.source_kind,
        service.source_path,
        service.source_index,
    )


__all__ = [
    "MAX_ACTIVE_PROFILES",
    "MAX_NAME_BYTES",
    "MAX_PROJECT_BYTES",
    "MAX_PROJECT_FILES",
    "MAX_PROJECT_REFERENCES",
    "MAX_PROVENANCE_STEPS",
    "MAX_REFERENCE_DEPTH",
    "MAX_SHELL_VARIABLE_NAMES",
    "resolve_compose_project",
]
