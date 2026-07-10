"""Strict semantic models for ``runtime-contract.yaml`` version 1."""

from __future__ import annotations

import fnmatch
import posixpath
import re
from datetime import date
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    StrictBool,
    StrictStr,
    field_validator,
    model_validator,
)

from runtime_contract.rules import RuleId

ROOT_NAME_PATTERN = r"^[A-Za-z][A-Za-z0-9_-]{0,63}$"
VARIABLE_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"
SUPPRESSION_ID_PATTERN = r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$"
RootName = Annotated[StrictStr, Field(pattern=ROOT_NAME_PATTERN)]
VariableName = Annotated[StrictStr, Field(pattern=VARIABLE_NAME_PATTERN)]
RelativePath = Annotated[str, Field(min_length=1)]
GlobPattern = Annotated[str, Field(min_length=1)]


class ConfigModel(BaseModel):
    """Common strict model policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)


def _validate_relative(value: str) -> str:
    if "\\" in value or "\0" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ValueError("must be a relative POSIX path")
    normalized = posixpath.normpath(value)
    if normalized == ".." or normalized.startswith("../"):
        raise ValueError("must not escape its root")
    return normalized


def _validate_glob(value: str) -> str:
    if not value.strip() or "\0" in value or "\\" in value or value.startswith("!"):
        raise ValueError("must be a non-empty supported glob")
    if ".." in PurePosixPath(value.lstrip("/")).parts or value.startswith("//"):
        raise ValueError("must not escape its root")
    re.compile(fnmatch.translate(value))
    return value


def _validate_optional_relative(value: str | None) -> str | None:
    return None if value is None else _validate_relative(value)


def _validate_optional_glob(value: str | None) -> str | None:
    return None if value is None else _validate_glob(value)


def _validate_globs(value: list[str]) -> list[str]:
    return [_validate_glob(item) for item in value]


class RootTarget(ConfigModel):
    """A named scan target relative to the logical project root."""

    path: RelativePath
    include: list[GlobPattern] = Field(default_factory=list)
    exclude: list[GlobPattern] = Field(default_factory=list)

    _path = field_validator("path")(_validate_relative)
    _include = field_validator("include")(_validate_globs)
    _exclude = field_validator("exclude")(_validate_globs)


class Roots(RootModel[dict[RootName, RootTarget]]):
    """Named targets accepting a string shorthand or expanded object."""

    model_config = ConfigDict(frozen=True)

    @model_validator(mode="before")
    @classmethod
    def expand_shorthand(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        return {
            key: {"path": item} if isinstance(item, str) else item for key, item in value.items()
        }


class SourceType(StrEnum):
    AUTO = "auto"
    COMPOSE = "compose"
    KUBERNETES = "kubernetes"


class Source(ConfigModel):
    root: RootName
    type: SourceType
    path: RelativePath
    provides: list[VariableName] = Field(default_factory=list)

    _path = field_validator("path")(_validate_relative)

    @field_validator("provides")
    @classmethod
    def unique_provides(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("must not contain duplicates")
        return value


class EnvironmentProfile(ConfigModel):
    roots: list[RootName] = Field(min_length=1)
    sources: list[Source] = Field(default_factory=list)

    @field_validator("roots")
    @classmethod
    def unique_roots(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("must not contain duplicates")
        return value


class ScopedRule(ConfigModel):
    secret: StrictBool | None = None
    required: StrictBool | None = None
    roots: list[RootName] = Field(default_factory=list)
    environments: list[RootName] = Field(default_factory=list)

    @field_validator("roots", "environments")
    @classmethod
    def unique_selectors(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("must not contain duplicates")
        return value


class VariableRule(ScopedRule):
    allow_literal: StrictBool | None = None
    reason: str | None = None

    @model_validator(mode="after")
    def reason_for_literal(self) -> Self:
        if self.allow_literal is True and (self.reason is None or not self.reason.strip()):
            raise ValueError("allow_literal true requires a non-empty reason")
        return self


class VariableRuleList(RootModel[list[VariableRule]]):
    model_config = ConfigDict(frozen=True)

    @model_validator(mode="after")
    def nonempty_unique_scopes(self) -> Self:
        if not self.root:
            raise ValueError("rule list must not be empty")
        scopes = [(tuple(rule.roots), tuple(rule.environments)) for rule in self.root]
        if len(set(scopes)) != len(scopes):
            raise ValueError("rules for one variable must have distinct selector sets")
        return self


class PatternRule(ScopedRule):
    pattern: GlobPattern
    _pattern = field_validator("pattern")(_validate_glob)


class Classifications(ConfigModel):
    variables: dict[VariableName, VariableRule | VariableRuleList] = Field(default_factory=dict)
    patterns: list[PatternRule] = Field(default_factory=list)


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class SeverityOverride(ScopedRule):
    rule: RuleId
    severity: Severity


class Suppression(ConfigModel):
    id: Annotated[str, Field(pattern=SUPPRESSION_ID_PATTERN)]
    rule: RuleId
    reason: Annotated[str, Field(min_length=1)]
    variable: VariableName | None = None
    path: GlobPattern | None = None
    roots: list[RootName] = Field(default_factory=list)
    environments: list[RootName] = Field(default_factory=list)
    expires: date | None = None

    _path = field_validator("path")(_validate_optional_glob)

    @model_validator(mode="after")
    def has_selector(self) -> Self:
        if self.variable is None and self.path is None and not self.roots and not self.environments:
            raise ValueError("suppression requires at least one selector")
        if not self.reason.strip():
            raise ValueError("reason must not be blank")
        return self


class OutputFormat(StrEnum):
    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


class FailOn(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    NEVER = "never"


class Execution(ConfigModel):
    environment: RootName | None = None
    format: OutputFormat = OutputFormat.TEXT
    fail_on: FailOn = FailOn.ERROR
    report: RelativePath | None = None

    _report = field_validator("report")(_validate_optional_relative)


class RuntimeContractConfig(ConfigModel):
    """Semantic source of truth for ``runtime-contract.yaml`` version 1."""

    version: Literal[1]
    include: list[GlobPattern] = Field(default_factory=list)
    exclude: list[GlobPattern] = Field(default_factory=list)
    roots: Roots | None = None
    environments: dict[RootName, EnvironmentProfile] = Field(default_factory=dict)
    classifications: Classifications = Field(default_factory=Classifications)
    severity_overrides: list[SeverityOverride] = Field(default_factory=list)
    suppressions: list[Suppression] = Field(default_factory=list)
    execution: Execution = Field(default_factory=Execution)

    _include = field_validator("include")(_validate_globs)
    _exclude = field_validator("exclude")(_validate_globs)

    @field_validator("version", mode="before")
    @classmethod
    def exact_version(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("must be the integer 1")
        return value

    def effective_roots(self) -> dict[str, RootTarget]:
        if self.roots is None:
            return {"default": RootTarget(path=".")}
        return self.roots.root

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        roots = self.effective_roots()
        root_names = set(roots)
        environment_names = set(self.environments)
        if "default" in roots and roots["default"].path != ".":
            raise ValueError("root name 'default' is reserved for path '.'")
        for name, environment in self.environments.items():
            unknown = set(environment.roots) - root_names
            if unknown:
                raise ValueError(f"environment {name!r} references unknown roots")
            for source in environment.sources:
                if source.root not in environment.roots:
                    raise ValueError(f"source root {source.root!r} is outside environment {name!r}")
        rules: list[ScopedRule] = [*self.severity_overrides]
        rules.extend(self.classifications.patterns)
        for value in self.classifications.variables.values():
            rules.extend(value.root if isinstance(value, VariableRuleList) else [value])
        for suppression in self.suppressions:
            rules.append(suppression)  # type: ignore[arg-type]
        for rule in rules:
            if set(rule.roots) - root_names:
                raise ValueError("rule references unknown roots")
            if set(rule.environments) - environment_names:
                raise ValueError("rule references unknown environments")
        ids = [item.id for item in self.suppressions]
        if len(set(ids)) != len(ids):
            raise ValueError("suppression ids must be unique")
        if (
            self.execution.environment is not None
            and self.execution.environment not in self.environments
        ):
            raise ValueError("execution references an unknown environment")
        return self
