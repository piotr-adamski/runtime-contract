"""Static Dockerfile delivery analysis without value retention or execution."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

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
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Provider,
    ProviderMechanism,
    ProviderRole,
    Severity,
    SourceLocation,
)
from runtime_contract.sensitivity import classify_sensitivity

MAX_DOCKERFILE_BYTES = 1_048_576
MAX_LOGICAL_INSTRUCTION = 262_144
MAX_INSTRUCTIONS = 10_000
MAX_STAGES = 1_000
MAX_DECLARATIONS = 5_000
MAX_VALUE_TOKENS = 10_000
MAX_SUBSTITUTIONS = 10_000
MAX_HEREDOC_LINES = 100_000

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_INSTRUCTION = re.compile(r"([A-Za-z]+)(?:[ \t]+(.*))?\Z", re.DOTALL)
_SUBSTITUTION = re.compile(
    r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*(?:(?::-|:\+|-|\+)[^}]*)?\})"
)
_HEREDOC = re.compile(r"<<-?[ \t]*(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z0-9_.-]+))")


@dataclass(frozen=True, slots=True)
class _LogicalInstruction:
    text: str
    positions: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class _Stage:
    number: int
    alias: str | None
    base_stage: int | None
    from_location: SourceLocation
    visible_args: frozenset[str]
    visible_env: frozenset[str]
    arg_locations: tuple[tuple[str, SourceLocation], ...]
    env_locations: tuple[tuple[str, SourceLocation], ...]


class DockerfileAnalyzer:
    """Inventory explicit ``ARG`` and ``ENV`` delivery facts from Dockerfiles."""

    analyzer_id = "dockerfile"
    supported_kinds = frozenset({CandidateKind.DOCKERFILE})

    def analyze(self, input: AnalyzerInput, /) -> AnalysisResult:
        if input.kind is not CandidateKind.DOCKERFILE:
            raise ValueError("DockerfileAnalyzer requires CandidateKind.DOCKERFILE")
        if len(input.content) > MAX_DOCKERFILE_BYTES:
            return _failed_limit(input.path, "file_size")
        try:
            source = input.content.decode("utf-8-sig")
        except UnicodeDecodeError:
            return _failed(input.path, DiagnosticCode.INVALID_ENCODING)
        return _Parser(input, source).parse()


class _Parser:
    def __init__(self, input: AnalyzerInput, source: str) -> None:
        self.input = input
        self.source = source
        self.escape = "\\"
        self.instructions = 0
        self.declarations = 0
        self.tokens = 0
        self.substitutions = 0
        self.global_args: set[str] = set()
        self.stages: list[_Stage] = []
        self.aliases: dict[str, int] = {}
        self.unresolved_bases: list[tuple[str, tuple[int, int]]] = []
        self.current_stage: int | None = None
        self.keys: dict[str, FactObservation] = {}
        self.providers: list[FactObservation] = []
        self.environment: FactObservation | None = None
        self.diagnostics: list[AnalysisDiagnostic] = []

    def parse(self) -> AnalysisResult:
        logical = self._logical_instructions()
        if logical is None:
            return AnalysisResult(
                completeness=AnalysisCompleteness.FAILED,
                diagnostics=tuple(self.diagnostics),
            )
        for instruction in logical:
            self.instructions += 1
            if self.instructions > MAX_INSTRUCTIONS:
                self._limit("instructions", instruction.positions[0])
                break
            if len(instruction.text) > MAX_LOGICAL_INSTRUCTION:
                self._limit("logical_instruction", instruction.positions[0])
                break
            match = _INSTRUCTION.fullmatch(instruction.text.strip())
            if match is None:
                self._syntax("instruction_boundary", instruction.positions[0])
                continue
            keyword = match.group(1).upper()
            payload = match.group(2) or ""
            payload_offset = instruction.text.find(payload) if payload else len(instruction.text)
            if keyword == "FROM":
                self._from(payload, instruction, payload_offset)
            elif keyword == "ARG":
                self._arg(payload, instruction, payload_offset)
            elif keyword == "ENV":
                self._env(payload, instruction, payload_offset)
        if any(item.code is DiagnosticCode.SAFETY_LIMIT for item in self.diagnostics):
            return AnalysisResult(
                completeness=AnalysisCompleteness.FAILED,
                diagnostics=tuple(self.diagnostics),
            )
        completeness = (
            AnalysisCompleteness.PARTIAL if self.diagnostics else AnalysisCompleteness.COMPLETE
        )
        observations: tuple[FactObservation, ...] = (
            *self.keys.values(),
            *((self.environment,) if self.environment is not None else ()),
            *self.providers,
        )
        return AnalysisResult(
            completeness=completeness,
            observations=observations,
            diagnostics=tuple(self.diagnostics),
        )

    def _logical_instructions(self) -> list[_LogicalInstruction] | None:
        physical = self.source.splitlines(keepends=True)
        result: list[_LogicalInstruction] = []
        parts: list[str] = []
        positions: list[tuple[int, int]] = []
        directive_phase = True
        line_index = 0
        while line_index < len(physical):
            raw = physical[line_index]
            body = raw.rstrip("\r\n")
            line_number = line_index + 1
            stripped = body.lstrip(" \t")
            if not parts and directive_phase and stripped.startswith("#"):
                directive = stripped[1:].strip()
                if directive.lower().startswith("escape="):
                    candidate = directive.split("=", 1)[1].strip()
                    if candidate in ("\\", "`"):
                        self.escape = candidate
                line_index += 1
                continue
            if not parts and (not stripped or stripped.startswith("#")):
                line_index += 1
                continue
            directive_phase = False
            continuation = body.endswith(self.escape)
            segment = body[:-1] if continuation else body
            if parts:
                parts.append(" ")
                positions.append((line_number, 1))
            parts.append(segment)
            positions.extend((line_number, column) for column in range(1, len(segment) + 1))
            line_index += 1
            if continuation:
                if line_index == len(physical):
                    self._syntax("unterminated_continuation", (line_number, len(body) or 1))
                    parts.clear()
                    positions.clear()
                continue
            text = "".join(parts)
            result.append(_LogicalInstruction(text=text, positions=tuple(positions)))
            parts.clear()
            positions.clear()
            heredocs = [
                next(group for group in match.groups() if group is not None)
                for match in _HEREDOC.finditer(text)
            ]
            for terminator in heredocs:
                consumed = 0
                while line_index < len(physical):
                    candidate = physical[line_index].rstrip("\r\n")
                    line_index += 1
                    consumed += 1
                    if consumed > MAX_HEREDOC_LINES:
                        self._limit("heredoc_lines", (line_number, 1))
                        return None
                    if candidate.lstrip("\t") == terminator:
                        break
                else:
                    self._unsupported("unterminated_heredoc", (line_number, 1))
        return result

    def _from(self, payload: str, instruction: _LogicalInstruction, offset: int) -> None:
        self.current_stage = None
        tokens = self._shell_tokens(payload, instruction, offset)
        if tokens is None or not tokens:
            self._syntax("malformed_from", self._position(instruction, offset))
            return
        index = 0
        while index < len(tokens) and tokens[index][0].startswith("--"):
            if not tokens[index][0].lower().startswith("--platform="):
                self._syntax("malformed_from", tokens[index][1])
                return
            index += 1
        if index >= len(tokens):
            self._syntax("malformed_from", self._position(instruction, offset))
            return
        base, base_position = tokens[index]
        index += 1
        alias: str | None = None
        if index < len(tokens):
            if index + 2 != len(tokens) or tokens[index][0].upper() != "AS":
                self._syntax("malformed_from", tokens[index][1])
                return
            alias_candidate, alias_position = tokens[index + 1]
            if not _NAME.fullmatch(alias_candidate):
                self._syntax("invalid_stage_alias", alias_position)
                return
            alias = alias_candidate
        alias_key = alias.casefold() if alias is not None else None
        if alias_key is not None and alias_key in self.aliases:
            self._syntax("duplicate_stage_alias", base_position)
            return
        if alias_key is not None:
            for unresolved, unresolved_position in self.unresolved_bases:
                if unresolved == alias_key:
                    self._syntax("future_stage_reference", unresolved_position)
        base_stage = self.aliases.get(base.casefold())
        if "$" in base and base_stage is None:
            self._count_substitutions(base, base_position)
            self._unsupported("dynamic_from", base_position)
        elif base_stage is None:
            self.unresolved_bases.append((base.casefold(), base_position))
        inherited_args: frozenset[str] = frozenset()
        inherited_env: frozenset[str] = frozenset()
        inherited_arg_locations: tuple[tuple[str, SourceLocation], ...] = ()
        inherited_env_locations: tuple[tuple[str, SourceLocation], ...] = ()
        if base_stage is not None:
            parent = self.stages[base_stage - 1]
            inherited_args = parent.visible_args
            inherited_env = parent.visible_env
            inherited_arg_locations = parent.arg_locations
            inherited_env_locations = parent.env_locations
        number = len(self.stages) + 1
        if number > MAX_STAGES:
            self._limit("stages", base_position)
            return
        stage = _Stage(
            number=number,
            alias=alias,
            base_stage=base_stage,
            from_location=self._location(base_position),
            visible_args=inherited_args,
            visible_env=inherited_env,
            arg_locations=inherited_arg_locations,
            env_locations=inherited_env_locations,
        )
        self.stages.append(stage)
        self.current_stage = number
        if alias_key is not None:
            self.aliases[alias_key] = number

    def _arg(self, payload: str, instruction: _LogicalInstruction, offset: int) -> None:
        stripped = payload.strip()
        name_text = stripped.split("=", 1)[0].strip()
        name_offset = offset + payload.find(name_text) if name_text else offset
        position = self._position(instruction, name_offset)
        if "=" not in stripped and any(char.isspace() for char in stripped):
            self._syntax("malformed_arg", position)
            return
        if not _NAME.fullmatch(name_text):
            self._syntax("invalid_arg_name", position)
            return
        if "=" in stripped:
            self._count_substitutions(stripped.split("=", 1)[1], position)
        self._declaration(name_text, position, Phase.BUILD, ProviderMechanism.DOCKERFILE_ARG)
        location = self._location(position)
        if self.current_stage is None:
            self.global_args.add(name_text)
            return
        stage = self.stages[self.current_stage - 1]
        self.stages[self.current_stage - 1] = replace(
            stage,
            visible_args=stage.visible_args | {name_text},
            arg_locations=(*stage.arg_locations, (name_text, location)),
        )

    def _env(self, payload: str, instruction: _LogicalInstruction, offset: int) -> None:
        if self.current_stage is None:
            self._syntax("env_before_from", self._position(instruction, offset))
            return
        tokens = self._shell_tokens(payload, instruction, offset)
        if tokens is None or not tokens:
            self._syntax("malformed_env", self._position(instruction, offset))
            return
        pairs: list[tuple[str, tuple[int, int]]] = []
        if "=" not in tokens[0][0]:
            name, position = tokens[0]
            if len(tokens) < 2 or not _NAME.fullmatch(name):
                self._syntax("malformed_env", position)
                return
            pairs.append((name, position))
            self._count_substitutions(payload[payload.find(tokens[1][0]) :], tokens[1][1])
        else:
            for token, position in tokens:
                if "=" not in token:
                    self._syntax("malformed_env", position)
                    return
                name, value = token.split("=", 1)
                if not _NAME.fullmatch(name):
                    self._syntax("invalid_env_name", position)
                    return
                pairs.append((name, position))
                self._count_substitutions(value, position)
        stage = self.stages[self.current_stage - 1]
        for name, position in pairs:
            self._declaration(name, position, Phase.RUNTIME, ProviderMechanism.DOCKERFILE_ENV)
            location = self._location(position)
            stage = replace(
                stage,
                visible_env=stage.visible_env | {name},
                env_locations=(*stage.env_locations, (name, location)),
            )
        self.stages[self.current_stage - 1] = stage

    def _shell_tokens(
        self, payload: str, instruction: _LogicalInstruction, offset: int
    ) -> list[tuple[str, tuple[int, int]]] | None:
        tokens: list[tuple[str, tuple[int, int]]] = []
        index = 0
        while True:
            while index < len(payload) and payload[index].isspace():
                index += 1
            if index >= len(payload):
                return tokens
            start = index
            rendered: list[str] = []
            quote: str | None = None
            while index < len(payload):
                char = payload[index]
                if quote is None and char.isspace():
                    break
                if char in "'\"" and (quote is None or quote == char):
                    quote = None if quote == char else char
                    index += 1
                    continue
                if char == self.escape and index + 1 < len(payload):
                    index += 1
                    char = payload[index]
                rendered.append(char)
                index += 1
            if quote is not None:
                self._syntax("unterminated_quote", self._position(instruction, offset + start))
                return None
            self.tokens += 1
            if self.tokens > MAX_VALUE_TOKENS:
                self._limit("value_tokens", self._position(instruction, offset + start))
                return None
            tokens.append(("".join(rendered), self._position(instruction, offset + start)))

    def _declaration(
        self,
        name: str,
        position: tuple[int, int],
        phase: Phase,
        mechanism: ProviderMechanism,
    ) -> None:
        self.declarations += 1
        if self.declarations > MAX_DECLARATIONS:
            self._limit("declarations", position)
            return
        resolved = self.input.resolver.classify(name)
        sensitivity = classify_sensitivity(name, override=resolved.secret)
        key = ConfigKey(
            name=name,
            component=self.input.component,
            secret=sensitivity.sensitive,
            secret_source=sensitivity.source,
            sensitivity_reason=sensitivity.reason,
            sensitivity_confidence=sensitivity.confidence,
            allow_literal=(
                resolved.allow_literal
                if resolved.allow_literal is not None
                else not sensitivity.sensitive
            ),
        )
        environment = Environment(
            component=self.input.component,
            target=self.input.root,
            kind=EnvironmentKind.IMPLICIT,
            profile=self.input.profile,
        )
        provider = Provider(
            config_key_id=key.id,
            component=self.input.component,
            environment_id=environment.id,
            role=ProviderRole.DELIVERY,
            phase=phase,
            mechanism=mechanism,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=self._location(position),
        )
        self.keys.setdefault(
            key.id,
            FactObservation(fact_kind=FactKind.CONFIG_KEY, confidence=Confidence.EXACT, fact=key),
        )
        if self.environment is None:
            self.environment = FactObservation(
                fact_kind=FactKind.ENVIRONMENT,
                confidence=Confidence.EXACT,
                fact=environment,
            )
        self.providers.append(
            FactObservation(fact_kind=FactKind.PROVIDER, confidence=Confidence.EXACT, fact=provider)
        )

    def _count_substitutions(self, value: str, position: tuple[int, int]) -> None:
        self.substitutions += len(_SUBSTITUTION.findall(value))
        if self.substitutions > MAX_SUBSTITUTIONS:
            self._limit("substitutions", position)

    def _syntax(self, kind: str, position: tuple[int, int]) -> None:
        self.diagnostics.append(
            self._diagnostic(DiagnosticCode.SYNTAX_ERROR, "syntax_kind", kind, position)
        )

    def _unsupported(self, kind: str, position: tuple[int, int]) -> None:
        self.diagnostics.append(
            self._diagnostic(DiagnosticCode.UNSUPPORTED_CONSTRUCT, "construct_kind", kind, position)
        )

    def _limit(self, kind: str, position: tuple[int, int]) -> None:
        self.diagnostics.append(
            self._diagnostic(DiagnosticCode.SAFETY_LIMIT, "limit_kind", kind, position)
        )

    def _diagnostic(
        self,
        code: DiagnosticCode,
        parameter: str,
        kind: str,
        position: tuple[int, int],
    ) -> AnalysisDiagnostic:
        return AnalysisDiagnostic(
            code=code,
            severity=Severity.ERROR
            if code is not DiagnosticCode.UNSUPPORTED_CONSTRUCT
            else Severity.WARNING,
            primary_location=self._location(position),
            parameters=((parameter, kind),),
        )

    def _position(self, instruction: _LogicalInstruction, offset: int) -> tuple[int, int]:
        return instruction.positions[min(max(offset, 0), len(instruction.positions) - 1)]

    def _location(self, position: tuple[int, int]) -> SourceLocation:
        return SourceLocation(
            path=self.input.path,
            start_line=position[0],
            start_column=position[1],
        )


def _failed(path: str, code: DiagnosticCode) -> AnalysisResult:
    return AnalysisResult(
        completeness=AnalysisCompleteness.FAILED,
        diagnostics=(
            AnalysisDiagnostic(
                code=code,
                severity=Severity.ERROR,
                primary_location=SourceLocation(path=path),
            ),
        ),
    )


def _failed_limit(path: str, kind: str) -> AnalysisResult:
    return AnalysisResult(
        completeness=AnalysisCompleteness.FAILED,
        diagnostics=(
            AnalysisDiagnostic(
                code=DiagnosticCode.SAFETY_LIMIT,
                severity=Severity.ERROR,
                primary_location=SourceLocation(path=path, start_line=1, start_column=1),
                parameters=(("limit_kind", kind),),
            ),
        ),
    )
