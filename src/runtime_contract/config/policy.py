"""Ordered classification, severity, and suppression policy resolution."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from datetime import date

from runtime_contract.config.loader import ConfigDocument
from runtime_contract.config.models import (
    ClassificationDecision,
    PatternRule,
    Severity,
    VariableRuleList,
)
from runtime_contract.rules import RuleId


@dataclass(frozen=True, slots=True)
class AppliedRule:
    pointer: str
    order: int
    scope: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    secret: bool | None
    required: bool | None
    allow_literal: bool | None
    reason: str | None
    applied: tuple[AppliedRule, ...]
    ignored: bool = False


@dataclass(frozen=True, slots=True)
class UnusedClassificationRule:
    pointer: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class SuppressionResult:
    suppressed: bool
    id: str | None = None
    reason: str | None = None
    expired: bool = False
    pointer: str | None = None


@dataclass(frozen=True, slots=True)
class SuppressionExpiryWarning:
    id: str
    reason: str
    pointer: str
    severity: str = "warning"


def _matches(
    roots: list[str], environments: list[str], root: str | None, environment: str | None
) -> bool:
    return (not roots or root in roots) and (not environments or environment in environments)


class ConfigPolicy:
    """Resolve ordered policies while retaining YAML provenance."""

    def __init__(self, document: ConfigDocument) -> None:
        self.document = document
        self._used_classification_pointers: set[str] = set()

    def _applied(self, pointer: str, order: int, scope: str) -> AppliedRule:
        line, column = self.document.locations.get(pointer, (1, 1))
        return AppliedRule(pointer, order, scope, line, column)

    def classify(
        self, variable: str, *, root: str | None = None, environment: str | None = None
    ) -> ClassificationResult:
        values: dict[str, bool | str | None] = {
            "secret": None,
            "required": None,
            "allow_literal": None,
            "reason": None,
        }
        ignored = False
        applied: list[AppliedRule] = []
        for index, rule in enumerate(self.document.config.classifications.patterns):
            if _pattern_matches(rule, variable) and _matches(
                rule.roots, rule.environments, root, environment
            ):
                ignored = _apply_decision(rule.classification, values, ignored)
                if rule.secret is not None:
                    ignored = False
                for field in ("secret", "required", "reason"):
                    value = getattr(rule, field)
                    if value is not None:
                        values[field] = value
                pointer = f"/classifications/patterns/{index}"
                applied.append(self._applied(pointer, index, "pattern"))
        exact = self.document.config.classifications.variables.get(variable)
        if exact is not None:
            rules = exact.root if isinstance(exact, VariableRuleList) else [exact]
            for index, exact_rule in enumerate(rules):
                if _matches(exact_rule.roots, exact_rule.environments, root, environment):
                    ignored = _apply_decision(exact_rule.classification, values, ignored)
                    if exact_rule.secret is not None:
                        ignored = False
                    for field in ("secret", "required", "allow_literal", "reason"):
                        value = getattr(exact_rule, field)
                        if value is not None:
                            values[field] = value
                    suffix = f"/{index}" if isinstance(exact, VariableRuleList) else ""
                    pointer = f"/classifications/variables/{variable}{suffix}"
                    applied.append(self._applied(pointer, index, "exact"))
        self._used_classification_pointers.update(item.pointer for item in applied)
        return ClassificationResult(
            secret=values["secret"] if isinstance(values["secret"], bool) else None,
            ignored=ignored,
            required=values["required"] if isinstance(values["required"], bool) else None,
            allow_literal=(
                values["allow_literal"] if isinstance(values["allow_literal"], bool) else None
            ),
            reason=values["reason"] if isinstance(values["reason"], str) else None,
            applied=tuple(applied),
        )

    def unused_classification_rules(
        self, contexts: tuple[tuple[str, str | None, str | None], ...] = ()
    ) -> tuple[UnusedClassificationRule, ...]:
        """Return explicit classification declarations unused by observed key contexts."""
        applied = self._used_classification_pointers | {
            item.pointer
            for variable, root, environment in contexts
            for item in self.classify(variable, root=root, environment=environment).applied
        }
        declared: list[str] = [
            f"/classifications/patterns/{index}"
            for index, _ in enumerate(self.document.config.classifications.patterns)
        ]
        for variable, value in self.document.config.classifications.variables.items():
            if isinstance(value, VariableRuleList):
                declared.extend(
                    f"/classifications/variables/{variable}/{index}"
                    for index, _ in enumerate(value.root)
                )
            else:
                declared.append(f"/classifications/variables/{variable}")
        return tuple(
            UnusedClassificationRule(pointer, *self.document.locations.get(pointer, (1, 1)))
            for pointer in declared
            if pointer not in applied
        )

    def severity(
        self,
        rule_id: RuleId,
        default: Severity,
        *,
        root: str | None = None,
        environment: str | None = None,
    ) -> tuple[Severity, AppliedRule | None]:
        value = default
        applied = None
        for index, override in enumerate(self.document.config.severity_overrides):
            if override.rule is rule_id and _matches(
                override.roots, override.environments, root, environment
            ):
                value = override.severity
                applied = self._applied(f"/severity_overrides/{index}", index, "severity")
        return value, applied

    def suppression(
        self,
        rule_id: RuleId,
        *,
        variable: str | None = None,
        path: str | None = None,
        root: str | None = None,
        environment: str | None = None,
        on_date: date,
    ) -> SuppressionResult:
        for index, item in enumerate(self.document.config.suppressions):
            if item.rule is not rule_id:
                continue
            if item.variable is not None and item.variable != variable:
                continue
            if item.path is not None and (path is None or not fnmatch.fnmatchcase(path, item.path)):
                continue
            if not _matches(item.roots, item.environments, root, environment):
                continue
            expired = item.expires is not None and item.expires < on_date
            return SuppressionResult(
                not expired,
                item.id,
                item.reason,
                expired,
                f"/suppressions/{index}",
            )
        return SuppressionResult(False)

    def expired_suppression_warnings(
        self, *, on_date: date
    ) -> tuple[SuppressionExpiryWarning, ...]:
        """Return deterministic warnings for expired declarations."""

        return tuple(
            SuppressionExpiryWarning(item.id, item.reason, f"/suppressions/{index}")
            for index, item in enumerate(self.document.config.suppressions)
            if item.expires is not None and item.expires < on_date
        )


def _pattern_matches(rule: PatternRule, variable: str) -> bool:
    if rule.pattern is not None:
        return fnmatch.fnmatchcase(variable, rule.pattern)
    assert rule.regex is not None
    return re.fullmatch(rule.regex, variable, flags=re.ASCII) is not None


def _apply_decision(
    decision: ClassificationDecision | None,
    values: dict[str, bool | str | None],
    ignored: bool,
) -> bool:
    if decision is ClassificationDecision.SENSITIVE:
        values["secret"] = True
        return False
    if decision is ClassificationDecision.PUBLIC:
        values["secret"] = False
        return False
    if decision is ClassificationDecision.IGNORE:
        values.update(secret=None, required=None, allow_literal=None)
        return True
    return ignored
