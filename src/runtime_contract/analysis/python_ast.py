"""Static Python environment-variable analysis without executing source code."""

from __future__ import annotations

import ast
import io
import tokenize
from dataclasses import dataclass

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

_OS_MODULE = "os-module"
_GETENV = "os-getenv"
_ENVIRON = "os-environ"
_SHADOWED = "shadowed"


class PythonAstAnalyzer:
    """Find statically named ``os`` environment accesses in Python source bytes."""

    analyzer_id = "python-ast"
    supported_kinds = frozenset({CandidateKind.PYTHON})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        try:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(input.content).readline)
            source = input.content.decode(encoding)
        except (SyntaxError, UnicodeDecodeError, LookupError):
            return _failed(input.path, DiagnosticCode.INVALID_ENCODING)

        try:
            tree = ast.parse(source, filename=input.path)
        except SyntaxError as error:
            location = _syntax_location(input.path, error)
            return _failed(input.path, DiagnosticCode.SYNTAX_ERROR, location)

        visitor = _Visitor(input)
        try:
            visitor.visit(tree)
        except RecursionError:
            visitor.add_diagnostic(DiagnosticCode.PARTIAL_ANALYSIS, SourceLocation(path=input.path))
        return visitor.result()


@dataclass(frozen=True, slots=True)
class _Access:
    kind: ConsumerAccessKind
    node: ast.Call | ast.Subscript
    key: ast.expr
    fallback: ast.expr | None = None
    has_fallback: bool = False


class _Visitor(ast.NodeVisitor):
    def __init__(self, input: AnalyzerInput) -> None:
        self.input = input
        self.scopes: list[dict[str, str]] = [{}]
        self.observations: dict[str, FactObservation] = {}
        self.diagnostics: dict[str, AnalysisDiagnostic] = {}

    def result(self) -> AnalysisResult:
        completeness = (
            AnalysisCompleteness.PARTIAL if self.diagnostics else AnalysisCompleteness.COMPLETE
        )
        return AnalysisResult(
            completeness=completeness,
            observations=tuple(self.observations.values()),
            diagnostics=tuple(self.diagnostics.values()),
        )

    def add_diagnostic(
        self,
        code: DiagnosticCode,
        location: SourceLocation,
        access_kind: ConsumerAccessKind | None = None,
    ) -> None:
        diagnostic = AnalysisDiagnostic(
            code=code,
            severity=Severity.WARNING,
            primary_location=location,
            parameters=((("access_kind", access_kind.value),) if access_kind is not None else ()),
        )
        self.diagnostics[diagnostic.id] = diagnostic

    def bind(self, name: str, binding: str = _SHADOWED) -> None:
        self.scopes[-1][name] = binding

    def resolve(self, name: str) -> str | None:
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".", 1)[0]
            self.bind(bound, _OS_MODULE if alias.name == "os" else _SHADOWED)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                if node.module == "os":
                    self.add_diagnostic(
                        DiagnosticCode.UNSUPPORTED_CONSTRUCT, _location(self.input.path, node)
                    )
                continue
            bound = alias.asname or alias.name
            binding = _SHADOWED
            if node.module == "os" and node.level == 0:
                if alias.name == "getenv":
                    binding = _GETENV
                elif alias.name == "environ":
                    binding = _ENVIRON
            self.bind(bound, binding)

    def visit_Call(self, node: ast.Call) -> None:
        access = self._call_access(node)
        if access is not None:
            if not self._valid_call(node, access.kind):
                self.add_diagnostic(
                    DiagnosticCode.UNSUPPORTED_CONSTRUCT,
                    _location(self.input.path, node),
                    access.kind,
                )
            else:
                self._record(access)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._is_environ(node.value):
            self._record(_Access(ConsumerAccessKind.PYTHON_OS_ENVIRON, node, node.slice))
        self.generic_visit(node)

    def _call_access(self, node: ast.Call) -> _Access | None:
        func = node.func
        kind: ConsumerAccessKind | None = None
        if (isinstance(func, ast.Name) and self.resolve(func.id) == _GETENV) or (
            isinstance(func, ast.Attribute) and func.attr == "getenv" and self._is_os(func.value)
        ):
            kind = ConsumerAccessKind.PYTHON_OS_GETENV
        elif (
            isinstance(func, ast.Attribute) and func.attr == "get" and self._is_environ(func.value)
        ):
            kind = ConsumerAccessKind.PYTHON_OS_ENVIRON_GET
        if kind is None:
            return None
        key = node.args[0] if node.args else ast.Constant(value=None)
        fallback: ast.expr | None = node.args[1] if len(node.args) == 2 else None
        keyword_default = next(
            (item.value for item in node.keywords if item.arg == "default"), None
        )
        if fallback is None:
            fallback = keyword_default
        return _Access(kind, node, key, fallback, fallback is not None)

    def _valid_call(self, node: ast.Call, kind: ConsumerAccessKind) -> bool:
        del kind
        if not 1 <= len(node.args) <= 2 or any(isinstance(arg, ast.Starred) for arg in node.args):
            return False
        if any(keyword.arg != "default" for keyword in node.keywords):
            return False
        defaults = sum(keyword.arg == "default" for keyword in node.keywords)
        return defaults <= 1 and not (len(node.args) == 2 and defaults)

    def _is_os(self, node: ast.expr) -> bool:
        return isinstance(node, ast.Name) and self.resolve(node.id) == _OS_MODULE

    def _is_environ(self, node: ast.expr) -> bool:
        return (isinstance(node, ast.Name) and self.resolve(node.id) == _ENVIRON) or (
            isinstance(node, ast.Attribute) and node.attr == "environ" and self._is_os(node.value)
        )

    def _record(self, access: _Access) -> None:
        location = _location(self.input.path, access.node)
        if not isinstance(access.key, ast.Constant) or type(access.key.value) is not str:
            self.add_diagnostic(DiagnosticCode.DYNAMIC_NAME, location, access.kind)
            return
        name = access.key.value
        has_literal = False
        fallback_unknown = False
        if access.has_fallback:
            try:
                value = ast.literal_eval(access.fallback)  # type: ignore[arg-type]
                has_literal = value is not None
            except (ValueError, TypeError, MemoryError, RecursionError):
                fallback_unknown = True
                self.add_diagnostic(DiagnosticCode.UNSUPPORTED_CONSTRUCT, location, access.kind)

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
        required = not has_literal
        requirement_source = (
            RequirementSource.LITERAL_FALLBACK
            if has_literal
            else RequirementSource.DETECTED_DEFAULT
        )
        if resolved.required is not None:
            required = resolved.required
            requirement_source = RequirementSource.CONFIG_OVERRIDE
        consumer = Consumer(
            config_key_id=key.id,
            component=self.input.component,
            phase=Phase.RUNTIME,
            required=required,
            requirement_source=requirement_source,
            access_kind=access.kind,
            location=location,
            has_literal_fallback=has_literal and not fallback_unknown,
        )
        key_observation = FactObservation(
            fact_kind=FactKind.CONFIG_KEY, confidence=Confidence.EXACT, fact=key
        )
        consumer_observation = FactObservation(
            fact_kind=FactKind.CONSUMER, confidence=Confidence.EXACT, fact=consumer
        )
        self.observations.setdefault(key.id, key_observation)
        self.observations[consumer.id] = consumer_observation

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for item in (*node.decorator_list, *node.args.defaults, *node.args.kw_defaults):
            if item is not None:
                self.visit(item)
        if node.returns is not None:
            self.visit(node.returns)
        self.bind(node.name)
        self.scopes.append({})
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ):
            self.bind(argument.arg)
        if node.args.vararg is not None:
            self.bind(node.args.vararg.arg)
        if node.args.kwarg is not None:
            self.bind(node.args.kwarg.arg)
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for item in (*node.args.defaults, *node.args.kw_defaults):
            if item is not None:
                self.visit(item)
        self.scopes.append({})
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self.bind(argument.arg)
        if node.args.vararg is not None:
            self.bind(node.args.vararg.arg)
        if node.args.kwarg is not None:
            self.bind(node.args.kwarg.arg)
        self.visit(node.body)
        self.scopes.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for item in (*node.decorator_list, *node.bases):
            self.visit(item)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self.bind(node.name)
        self.scopes.append({})
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self._shadow_target(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
        self._shadow_target(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._shadow_target(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._shadow_target(node.target)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._shadow_target(node.target)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)  # type: ignore[arg-type]

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._shadow_target(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)  # type: ignore[arg-type]

    def _shadow_target(self, target: ast.expr) -> None:
        if isinstance(target, ast.Name):
            self.bind(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._shadow_target(item)


def _location(path: str, node: ast.AST) -> SourceLocation:
    return SourceLocation(
        path=path,
        start_line=getattr(node, "lineno", None),
        start_column=(
            value + 1 if (value := getattr(node, "col_offset", None)) is not None else None
        ),
        end_line=getattr(node, "end_lineno", None),
        end_column=(
            value + 1 if (value := getattr(node, "end_col_offset", None)) is not None else None
        ),
    )


def _syntax_location(path: str, error: SyntaxError) -> SourceLocation:
    start_line = error.lineno
    start_column = error.offset if error.offset and error.offset > 0 else None
    end_line = error.end_lineno
    end_column = error.end_offset if error.end_offset and error.end_offset > 0 else None
    if (
        start_line is None
        or end_line is None
        or (
            end_line,
            end_column or 1,
        )
        < (start_line, start_column or 1)
    ):
        end_line = None
        end_column = None
    return SourceLocation(
        path=path,
        start_line=start_line,
        start_column=start_column,
        end_line=end_line,
        end_column=end_column,
    )


def _failed(
    path: str,
    code: DiagnosticCode,
    location: SourceLocation | None = None,
) -> AnalysisResult:
    diagnostic = AnalysisDiagnostic(
        code=code,
        severity=Severity.ERROR,
        primary_location=location or SourceLocation(path=path),
    )
    return AnalysisResult(
        completeness=AnalysisCompleteness.FAILED,
        diagnostics=(diagnostic,),
    )
