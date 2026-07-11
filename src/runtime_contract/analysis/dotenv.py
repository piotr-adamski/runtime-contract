"""Static ``.env.example`` declaration analysis without retaining values."""

from __future__ import annotations

import re

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
    EvidenceKind,
    Phase,
    Provider,
    ProviderMechanism,
    ProviderRole,
    SecretSource,
    Severity,
    SourceLocation,
)

MAX_DOTENV_BYTES = 1_048_576
MAX_LOGICAL_DECLARATION = 262_144
MAX_DECLARATIONS = 10_000
MAX_INTERPOLATION_REFERENCES = 10_000

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SECRET_NAME = re.compile(r"(?:^|_)(?:TOKEN|PASSWORD|SECRET|PRIVATE_KEY)$")


class DotenvAnalyzer:
    """Inventory declarations from the exact ``.env.example`` candidate kind."""

    analyzer_id = "dotenv-example"
    supported_kinds = frozenset({CandidateKind.ENV_EXAMPLE})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        if len(input.content) > MAX_DOTENV_BYTES:
            return _limit(input.path, "file_size")
        try:
            source = input.content.decode("utf-8-sig")
        except UnicodeDecodeError:
            return _failed(input.path, DiagnosticCode.INVALID_ENCODING)
        parser = _Parser(input, source)
        return parser.parse()


class _Parser:
    def __init__(self, input: AnalyzerInput, source: str) -> None:
        self.input = input
        self.source = source
        self.length = len(source)
        self.index = 0
        self.line = 1
        self.column = 1
        self.declarations = 0
        self.references = 0
        self.key_observations: dict[str, FactObservation] = {}
        self.provider_observations: list[FactObservation] = []
        self.diagnostics: list[AnalysisDiagnostic] = []

    def parse(self) -> AnalysisResult:
        while self.index < self.length:
            self._horizontal_space()
            if self._at_newline():
                self._newline()
                continue
            if self._peek() == "#":
                self._to_newline()
                continue
            if not self._declaration():
                break
        if any(item.code is DiagnosticCode.SAFETY_LIMIT for item in self.diagnostics):
            return AnalysisResult(
                completeness=AnalysisCompleteness.FAILED,
                diagnostics=tuple(self.diagnostics),
            )
        completeness = (
            AnalysisCompleteness.PARTIAL if self.diagnostics else AnalysisCompleteness.COMPLETE
        )
        return AnalysisResult(
            completeness=completeness,
            observations=(*self.key_observations.values(), *self.provider_observations),
            diagnostics=tuple(self.diagnostics),
        )

    def _declaration(self) -> bool:
        start_index = self.index
        start_line = self.line
        start_column = self.column
        if self.source.startswith("export", self.index):
            boundary = self.index + 6
            if boundary == self.length or self.source[boundary] in " \t\r\n":
                self._advance(6)
                self._horizontal_space()
                if self._at_newline() or self.index == self.length or self._peek() == "#":
                    self._syntax("export_without_declaration", start_line, start_column)
                    self._to_newline()
                    return True
                start_index = self.index
                start_line = self.line
                start_column = self.column
        match = _NAME.match(self.source, self.index)
        if match is None:
            kind = "empty_name" if self._peek() == "=" else "invalid_name"
            self._syntax(kind, start_line, start_column)
            self._to_newline()
            return True
        name = match.group()
        self._advance(len(name))
        self._horizontal_space()
        if self._peek() != "=":
            self._syntax("missing_separator", self.line, self.column)
            self._to_newline()
            return True
        self._advance()
        self._horizontal_space()
        current = self._peek()
        quote = current if current and current in "'\"`" else None
        if quote is None:
            if not self._unquoted_value():
                return False
        elif not self._quoted_value(quote):
            self._syntax("unterminated_quote", start_line, start_column)
            return False
        if self.index - start_index > MAX_LOGICAL_DECLARATION:
            self._safety_limit("logical_declaration", start_line, start_column)
            return False
        self.declarations += 1
        if self.declarations > MAX_DECLARATIONS:
            self._safety_limit("declarations", start_line, start_column)
            return False
        self._record(name, start_line, start_column)
        if self._at_newline():
            self._newline()
        return True

    def _quoted_value(self, quote: str) -> bool:
        interpolate = quote == '"'
        self._advance()
        while self.index < self.length:
            char = self._peek()
            if char == "\\" and self.index + 1 < self.length:
                self._advance(2)
                continue
            if char == quote:
                self._advance()
                self._horizontal_space()
                if self._peek() == "#":
                    self._to_newline()
                    return True
                if self._at_newline() or self.index == self.length:
                    return True
                self._syntax("trailing_garbage", self.line, self.column)
                self._to_newline()
                return True
            if interpolate and char == "$" and not self._interpolation():
                return False
            if interpolate and char == "$":
                continue
            if self._at_newline():
                self._newline()
            else:
                self._advance()
        return False

    def _unquoted_value(self) -> bool:
        previous_space = False
        while self.index < self.length and not self._at_newline():
            char = self._peek()
            if char == "#" and previous_space:
                self._to_newline()
                return True
            if char == "\\" and self.index + 1 < self.length:
                self._advance(2)
                previous_space = False
                continue
            if char == "$" and not self._interpolation():
                return False
            if char == "$":
                previous_space = False
                continue
            previous_space = char in " \t"
            self._advance()
        return True

    def _interpolation(self) -> bool:
        line, column = self.line, self.column
        if self.index + 1 >= self.length:
            self._advance()
            return True
        if self.source[self.index + 1] == "(":
            self._opaque_command()
            return True
        if self.source[self.index + 1] == "{":
            end = self.source.find("}", self.index + 2)
            if end < 0:
                self._syntax("unterminated_interpolation", line, column)
                self.index = self.length
                return False
            body_start = self.index + 2
            match = _NAME.match(self.source, body_start)
            if match is not None:
                suffix = self.source[match.end() : end]
                supported = suffix == "" or suffix.startswith((":-", "-", ":+", "+"))
                if supported and not self._reference(line, column):
                    return False
            self._advance(end + 1 - self.index)
            return True
        match = _NAME.match(self.source, self.index + 1)
        if match is not None:
            if not self._reference(line, column):
                return False
            self._advance(match.end() - self.index)
            return True
        self._advance()
        return True

    def _opaque_command(self) -> None:
        depth = 0
        while self.index < self.length:
            char = self._peek()
            if char == "\\" and self.index + 1 < self.length:
                self._advance(2)
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                self._advance()
                if depth == 0:
                    return
                continue
            if self._at_newline():
                self._newline()
            else:
                self._advance()

    def _reference(self, line: int, column: int) -> bool:
        self.references += 1
        if self.references > MAX_INTERPOLATION_REFERENCES:
            self._safety_limit("interpolation_references", line, column)
            return False
        return True

    def _record(self, name: str, line: int, column: int) -> None:
        resolved = self.input.resolver.classify(name)
        heuristic_secret = bool(_SECRET_NAME.search(name))
        secret = resolved.secret if resolved.secret is not None else heuristic_secret
        secret_source = (
            SecretSource.CONFIG_OVERRIDE
            if resolved.secret is not None
            else SecretSource.HEURISTIC
            if heuristic_secret
            else SecretSource.NOT_SECRET
        )
        allow_literal = resolved.allow_literal if resolved.allow_literal is not None else not secret
        key = ConfigKey(
            name=name,
            component=self.input.component,
            secret=secret,
            secret_source=secret_source,
            allow_literal=allow_literal,
        )
        location = SourceLocation(path=self.input.path, start_line=line, start_column=column)
        provider = Provider(
            config_key_id=key.id,
            component=self.input.component,
            role=ProviderRole.DECLARATION,
            phase=Phase.NOT_APPLICABLE,
            mechanism=ProviderMechanism.ENV_EXAMPLE,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=location,
        )
        self.key_observations.setdefault(
            key.id,
            FactObservation(fact_kind=FactKind.CONFIG_KEY, confidence=Confidence.EXACT, fact=key),
        )
        self.provider_observations.append(
            FactObservation(fact_kind=FactKind.PROVIDER, confidence=Confidence.EXACT, fact=provider)
        )

    def _syntax(self, kind: str, line: int, column: int) -> None:
        self.diagnostics.append(
            AnalysisDiagnostic(
                code=DiagnosticCode.SYNTAX_ERROR,
                severity=Severity.ERROR,
                primary_location=SourceLocation(
                    path=self.input.path, start_line=line, start_column=column
                ),
                parameters=(("syntax_kind", kind),),
            )
        )

    def _safety_limit(self, kind: str, line: int, column: int) -> None:
        self.diagnostics.append(
            AnalysisDiagnostic(
                code=DiagnosticCode.SAFETY_LIMIT,
                severity=Severity.ERROR,
                primary_location=SourceLocation(
                    path=self.input.path, start_line=line, start_column=column
                ),
                parameters=(("limit_kind", kind),),
            )
        )

    def _peek(self) -> str:
        return self.source[self.index] if self.index < self.length else ""

    def _at_newline(self) -> bool:
        return bool(self._peek()) and self._peek() in "\r\n"

    def _horizontal_space(self) -> None:
        while self._peek() and self._peek() in " \t":
            self._advance()

    def _to_newline(self) -> None:
        while self.index < self.length and not self._at_newline():
            self._advance()

    def _newline(self) -> None:
        if self._peek() == "\r":
            self.index += 1
            if self._peek() == "\n":
                self.index += 1
        else:
            self.index += 1
        self.line += 1
        self.column = 1

    def _advance(self, count: int = 1) -> None:
        self.index += count
        self.column += count


def _failed(path: str, code: DiagnosticCode) -> AnalysisResult:
    diagnostic = AnalysisDiagnostic(
        code=code,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path=path),
    )
    return AnalysisResult(completeness=AnalysisCompleteness.FAILED, diagnostics=(diagnostic,))


def _limit(path: str, kind: str) -> AnalysisResult:
    diagnostic = AnalysisDiagnostic(
        code=DiagnosticCode.SAFETY_LIMIT,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path=path, start_line=1, start_column=1),
        parameters=(("limit_kind", kind),),
    )
    return AnalysisResult(completeness=AnalysisCompleteness.FAILED, diagnostics=(diagnostic,))
