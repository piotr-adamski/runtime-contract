"""Static JavaScript and TypeScript ``process.env`` analysis using Tree-sitter."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from runtime_contract.analysis.models import (
    AnalysisCompleteness,
    AnalysisDiagnostic,
    AnalysisResult,
    Confidence,
    DiagnosticCode,
    FactKind,
    FactObservation,
)
from runtime_contract.analysis.protocols import AnalyzerInput
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    ConsumerAccessKind,
    Phase,
    RequirementSource,
    Severity,
    SourceLocation,
)
from runtime_contract.sensitivity import classify_sensitivity

_TS_SUFFIXES = frozenset({".ts", ".mts", ".cts"})
_TSX_SUFFIXES = frozenset({".tsx"})
_WRAPPERS = frozenset(
    {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "type_assertion",
        "non_null_expression",
    }
)
_SCOPE_TYPES = frozenset(
    {
        "program",
        "statement_block",
        "function_declaration",
        "function_expression",
        "arrow_function",
        "generator_function_declaration",
        "generator_function",
        "class_declaration",
        "class",
        "catch_clause",
    }
)
_FUNCTION_TYPES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "generator_function_declaration",
        "generator_function",
    }
)
_VITE_BUILTINS = frozenset({"MODE", "BASE_URL", "PROD", "DEV", "SSR"})


class JavaScriptTypeScriptAnalyzer:
    """Find statically named Node.js environment reads without executing source."""

    analyzer_id = "javascript-typescript-tree-sitter"
    supported_kinds = frozenset({CandidateKind.JAVASCRIPT})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        try:
            input.content.decode("utf-8")
        except UnicodeDecodeError:
            return _failed(input.path, DiagnosticCode.INVALID_ENCODING)
        try:
            parser = Parser(_language(input.path))
            tree = parser.parse(input.content)
        except (ValueError, TypeError, OverflowError):
            return _failed(input.path, DiagnosticCode.SYNTAX_ERROR)
        visitor = _Visitor(input, tree.root_node)
        visitor.walk(tree.root_node)
        return visitor.result()


class _Visitor:
    def __init__(self, input: AnalyzerInput, root: Node) -> None:
        self.input = input
        self.root = root
        self.bindings = _process_binding_scopes(root, input.content)
        self.observations: dict[str, FactObservation] = {}
        self.diagnostics: dict[str, AnalysisDiagnostic] = {}
        self._syntax_ranges: set[tuple[int, int]] = set()

    def walk(self, node: Node) -> None:
        if node.type in {"ERROR", "MISSING"} or node.is_missing:
            key = (node.start_byte, node.end_byte)
            if key not in self._syntax_ranges:
                self._syntax_ranges.add(key)
                self.add_diagnostic(DiagnosticCode.PARTIAL_ANALYSIS, _location(self.input, node))
        if node.type == "member_expression":
            self._member(node)
        elif node.type == "subscript_expression":
            self._subscript(node)
        elif node.type == "variable_declarator":
            self._destructuring(node)
        for child in node.children:
            self.walk(child)

    def result(self) -> AnalysisResult:
        completeness = (
            AnalysisCompleteness.PARTIAL if self.diagnostics else AnalysisCompleteness.COMPLETE
        )
        return AnalysisResult(
            completeness=completeness,
            observations=tuple(self.observations.values()),
            diagnostics=tuple(self.diagnostics.values()),
        )

    def _member(self, node: Node) -> None:
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj is None or prop is None or prop.type not in {"property_identifier", "identifier"}:
            return
        if _direct_process_env(obj, self.input.content) and not self._shadowed(obj):
            self._record(_text(prop, self.input.content), node)
        elif _direct_import_meta_env(obj, self.input.content):
            self._record(
                _text(prop, self.input.content),
                node,
                access_kind=ConsumerAccessKind.VITE_IMPORT_META_ENV,
                phase=Phase.BUILD,
            )

    def _subscript(self, node: Node) -> None:
        obj = node.child_by_field_name("object")
        index = node.child_by_field_name("index")
        if obj is None or index is None:
            return
        process_env = _direct_process_env(obj, self.input.content)
        import_meta_env = _direct_import_meta_env(obj, self.input.content)
        if not process_env and not import_meta_env:
            return
        if process_env and self._shadowed(obj):
            return
        name = _string_literal(index, self.input.content)
        if name is None:
            self.add_diagnostic(DiagnosticCode.DYNAMIC_NAME, _location(self.input, node))
        else:
            self._record(
                name,
                node,
                access_kind=(
                    ConsumerAccessKind.VITE_IMPORT_META_ENV
                    if import_meta_env
                    else ConsumerAccessKind.NODE_PROCESS_ENV
                ),
                phase=Phase.BUILD if import_meta_env else Phase.RUNTIME,
            )

    def _destructuring(self, node: Node) -> None:
        pattern = node.child_by_field_name("name")
        value = node.child_by_field_name("value")
        if (
            pattern is None
            or pattern.type != "object_pattern"
            or value is None
            or not (
                _direct_process_env(value, self.input.content)
                or _direct_import_meta_env(value, self.input.content)
            )
            or (_direct_process_env(value, self.input.content) and self._shadowed(value))
        ):
            return
        for child in pattern.named_children:
            if child.type in {"shorthand_property_identifier_pattern", "object_assignment_pattern"}:
                name_node = child.child_by_field_name("left") or child
                self._record_env_kind(_text(name_node, self.input.content), child, value)
            elif child.type == "pair_pattern":
                key = child.child_by_field_name("key")
                if key is None or key.type == "computed_property_name":
                    self.add_diagnostic(DiagnosticCode.DYNAMIC_NAME, _location(self.input, child))
                else:
                    name = _property_name(key, self.input.content)
                    if name is None:
                        self.add_diagnostic(
                            DiagnosticCode.DYNAMIC_NAME, _location(self.input, child)
                        )
                    else:
                        self._record_env_kind(name, child, value)
            else:
                self.add_diagnostic(DiagnosticCode.DYNAMIC_NAME, _location(self.input, child))

    def _shadowed(self, node: Node) -> bool:
        scope = _nearest_scope(node)
        while scope is not None:
            if scope.id in self.bindings:
                return True
            scope = _nearest_scope(scope.parent) if scope.parent is not None else None
        return False

    def _record_env_kind(self, name: str, node: Node, env: Node) -> None:
        is_import_meta = _direct_import_meta_env(env, self.input.content)
        self._record(
            name,
            node,
            access_kind=(
                ConsumerAccessKind.VITE_IMPORT_META_ENV
                if is_import_meta
                else ConsumerAccessKind.NODE_PROCESS_ENV
            ),
            phase=Phase.BUILD if is_import_meta else Phase.RUNTIME,
        )

    def _record(
        self,
        name: str,
        node: Node,
        *,
        access_kind: ConsumerAccessKind = ConsumerAccessKind.NODE_PROCESS_ENV,
        phase: Phase = Phase.RUNTIME,
    ) -> None:
        if access_kind is ConsumerAccessKind.VITE_IMPORT_META_ENV and name in _VITE_BUILTINS:
            return
        resolved = self.input.resolver.classify(name)
        if resolved.ignored:
            return
        sensitivity = classify_sensitivity(name, override=resolved.secret)
        allow_literal = (
            resolved.allow_literal
            if resolved.allow_literal is not None
            else not sensitivity.sensitive
        )
        key = ConfigKey(
            name=name,
            component=self.input.component,
            secret=sensitivity.sensitive,
            secret_source=sensitivity.source,
            sensitivity_reason=sensitivity.reason,
            sensitivity_confidence=sensitivity.confidence,
            allow_literal=allow_literal,
        )
        required = resolved.required if resolved.required is not None else True
        requirement_source = (
            RequirementSource.CONFIG_OVERRIDE
            if resolved.required is not None
            else RequirementSource.DETECTED_DEFAULT
        )
        consumer = Consumer(
            config_key_id=key.id,
            component=self.input.component,
            phase=phase,
            required=required,
            requirement_source=requirement_source,
            access_kind=access_kind,
            location=_location(self.input, node),
            has_literal_fallback=False,
        )
        self.observations.setdefault(
            key.id,
            FactObservation(fact_kind=FactKind.CONFIG_KEY, confidence=Confidence.EXACT, fact=key),
        )
        self.observations[consumer.id] = FactObservation(
            fact_kind=FactKind.CONSUMER, confidence=Confidence.EXACT, fact=consumer
        )

    def add_diagnostic(self, code: DiagnosticCode, location: SourceLocation) -> None:
        diagnostic = AnalysisDiagnostic(
            code=code,
            severity=Severity.WARNING,
            primary_location=location,
            parameters=(("access_kind", ConsumerAccessKind.NODE_PROCESS_ENV.value),),
        )
        self.diagnostics[diagnostic.id] = diagnostic


def _language(path: str) -> Language:
    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    factory: Callable[[], object]
    if suffix in _TSX_SUFFIXES:
        factory = tree_sitter_typescript.language_tsx
    elif suffix in _TS_SUFFIXES:
        factory = tree_sitter_typescript.language_typescript
    else:
        factory = tree_sitter_javascript.language
    return Language(factory())


def _unwrap(node: Node) -> Node:
    current = node
    while current.type in _WRAPPERS:
        expression = current.child_by_field_name("expression")
        if expression is None:
            expression = (
                current.named_children[-1]
                if current.type == "type_assertion" and current.named_children
                else current.named_children[0]
                if current.named_children
                else None
            )
        if expression is None or expression == current:
            break
        current = expression
    return current


def _direct_process_env(node: Node, source: bytes) -> bool:
    current = _unwrap(node)
    if current.type != "member_expression":
        return False
    obj = current.child_by_field_name("object")
    prop = current.child_by_field_name("property")
    return (
        obj is not None
        and prop is not None
        and _unwrap(obj).type == "identifier"
        and _text(_unwrap(obj), source) == "process"
        and _text(prop, source) == "env"
    )


def _direct_import_meta_env(node: Node, source: bytes) -> bool:
    current = _unwrap(node)
    if current.type != "member_expression":
        return False
    obj = current.child_by_field_name("object")
    prop = current.child_by_field_name("property")
    if obj is None or prop is None or _text(prop, source) != "env":
        return False
    meta = _unwrap(obj)
    return meta.type == "meta_property" and _text(meta, source) == "import.meta"


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _string_literal(node: Node, source: bytes) -> str | None:
    if node.type != "string":
        return None
    raw = _text(node, source)
    if len(raw) < 2 or raw[0] not in {'"', "'"} or raw[-1] != raw[0]:
        return None
    body = raw[1:-1]
    try:
        return bytes(body, "utf-8").decode("unicode_escape") if "\\" in body else body
    except UnicodeDecodeError:
        return None


def _property_name(node: Node, source: bytes) -> str | None:
    if node.type in {"property_identifier", "identifier", "shorthand_property_identifier_pattern"}:
        return _text(node, source)
    return _string_literal(node, source)


def _nearest_scope(node: Node | None) -> Node | None:
    current = node
    while current is not None and current.type not in _SCOPE_TYPES:
        current = current.parent
    return current


def _process_binding_scopes(root: Node, source: bytes) -> set[int]:
    scopes: set[int] = set()
    for node in _nodes(root):
        targets: list[Node] = []
        if node.type in {
            "import_clause",
            "namespace_import",
            "named_imports",
            "required_parameter",
            "optional_parameter",
        }:
            targets = list(node.named_children)
        elif node.type in {"variable_declarator", "formal_parameters", "catch_clause"}:
            target = node.child_by_field_name("name") or node.child_by_field_name("parameter")
            targets = [target] if target is not None else list(node.named_children[:1])
        elif node.type in {
            "function_declaration",
            "generator_function_declaration",
            "class_declaration",
        }:
            target = node.child_by_field_name("name")
            targets = [target] if target is not None else []
        if not any(_binding_names(target, source) for target in targets):
            continue
        scope = _binding_scope(node)
        if scope is not None:
            scopes.add(scope.id)
    return scopes


def _binding_names(node: Node, source: bytes) -> bool:
    if node.type in {"identifier", "type_identifier", "shorthand_property_identifier_pattern"}:
        return _text(node, source) == "process"
    if node.type == "import_specifier":
        binding = node.child_by_field_name("alias") or node.child_by_field_name("name")
        return binding is not None and _binding_names(binding, source)
    if node.type == "pair_pattern":
        binding = node.child_by_field_name("value")
        return binding is not None and _binding_names(binding, source)
    if node.type == "assignment_pattern":
        binding = node.child_by_field_name("left")
        return binding is not None and _binding_names(binding, source)
    return any(_binding_names(child, source) for child in node.named_children)


def _binding_scope(node: Node) -> Node | None:
    if node.type in {"formal_parameters", "required_parameter", "optional_parameter"}:
        current = node.parent
        while current is not None and current.type not in _FUNCTION_TYPES:
            current = current.parent
        return current
    if node.type == "catch_clause":
        return node
    declaration = node
    while declaration.parent is not None and declaration.type not in {
        "lexical_declaration",
        "variable_declaration",
    }:
        if declaration.type in _FUNCTION_TYPES or declaration.type in {
            "catch_clause",
            "import_statement",
            "class_declaration",
        }:
            break
        declaration = declaration.parent
    if declaration.type == "variable_declaration":
        current = declaration.parent
        while current is not None and current.type not in _FUNCTION_TYPES | {"program"}:
            current = current.parent
        return current
    return _nearest_scope(declaration.parent)


def _nodes(node: Node) -> Iterator[Node]:
    yield node
    for child in node.named_children:
        yield from _nodes(child)


def _location(input: AnalyzerInput, node: Node) -> SourceLocation:
    start_row, start_byte_column = node.start_point
    end_row, end_byte_column = node.end_point
    start_line_byte = input.content.rfind(b"\n", 0, node.start_byte) + 1
    end_line_byte = input.content.rfind(b"\n", 0, node.end_byte) + 1
    start_column = (
        len(input.content[start_line_byte : start_line_byte + start_byte_column].decode("utf-8"))
        + 1
    )
    end_column = (
        len(input.content[end_line_byte : end_line_byte + end_byte_column].decode("utf-8")) + 1
    )
    return SourceLocation(
        path=input.path,
        start_line=start_row + 1,
        start_column=start_column,
        end_line=end_row + 1,
        end_column=end_column,
    )


def _failed(path: str, code: DiagnosticCode) -> AnalysisResult:
    diagnostic = AnalysisDiagnostic(
        code=code,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path=path),
    )
    return AnalysisResult(completeness=AnalysisCompleteness.FAILED, diagnostics=(diagnostic,))
