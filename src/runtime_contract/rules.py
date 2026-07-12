"""Stable, value-safe public catalog of finding rules."""

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Literal


class RuleId(StrEnum):
    """Identifiers shared by findings, configuration, and JSON Schema."""

    RTC001 = "RTC001"
    RTC002 = "RTC002"
    RTC003 = "RTC003"
    RTC004 = "RTC004"
    RTC005 = "RTC005"
    RTC006 = "RTC006"
    RTC007 = "RTC007"
    RTC008 = "RTC008"
    RTC009 = "RTC009"
    RTC010 = "RTC010"
    RTC011 = "RTC011"
    RTC012 = "RTC012"


RuleSeverity = Literal["error", "warning", "info"]


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Human-facing metadata for one stable finding identifier."""

    id: RuleId
    name: str
    title: str
    default_severity: RuleSeverity
    rationale: str
    remediation: str


_RULES = (
    RuleDefinition(
        RuleId.RTC001,
        "REQUIRED_NOT_PROVIDED",
        "Required variable not provided",
        "error",
        "A required variable is not delivered to the selected target in the required phase.",
        "Provide the variable to every selected target in the required phase, or explicitly make the requirement optional.",
    ),
    RuleDefinition(
        RuleId.RTC002,
        "SECRET_LITERAL",
        "Secret has a literal value",
        "error",
        "A non-placeholder literal for a sensitive variable can expose a secret in source configuration.",
        "Replace the literal with an empty or approved placeholder, pass-through reference, or secret-backed delivery.",
    ),
    RuleDefinition(
        RuleId.RTC003,
        "PRIVATE_KEY_CONTENT",
        "Private-key content detected",
        "error",
        "Private-key material in a scanned source is always sensitive regardless of the variable name.",
        "Remove the private-key content from the repository and rotate the affected key outside runtime-contract.",
    ),
    RuleDefinition(
        RuleId.RTC004,
        "UNDOCUMENTED_VARIABLE",
        "Variable is not documented",
        "warning",
        "A variable consumed by code is absent from the component's documenting source.",
        "Declare the variable in the component's documentation source without adding a real secret value.",
    ),
    RuleDefinition(
        RuleId.RTC005,
        "UNUSED_DECLARATION",
        "Declaration has no consumer",
        "warning",
        "A documented variable has no statically detected consumer in the selected component.",
        "Remove the stale declaration or confirm and document the unsupported consumption pattern.",
    ),
    RuleDefinition(
        RuleId.RTC006,
        "DYNAMIC_REFERENCE",
        "Variable reference is dynamic",
        "warning",
        "The variable name is computed dynamically and cannot be resolved safely by static analysis.",
        "Use a statically named access or document the limitation; runtime-contract will not execute code or guess the name.",
    ),
    RuleDefinition(
        RuleId.RTC007,
        "CONFLICTING_DEFAULT",
        "Static defaults conflict",
        "warning",
        "Static sources describe incompatible fallback or default behavior for one variable.",
        "Choose one intended default contract and align every static declaration and consumer.",
    ),
    RuleDefinition(
        RuleId.RTC008,
        "OPTIONAL_NOT_PROVIDED",
        "Optional variable not provided",
        "info",
        "An optional variable has no delivery for the selected target and phase.",
        "No action is required when omission is intentional; otherwise add the matching delivery.",
    ),
    RuleDefinition(
        RuleId.RTC009,
        "DELIVERY_UNVERIFIABLE",
        "Bulk delivery cannot be verified",
        "error",
        "A bulk provider may deliver variables, but it cannot prove this required key for the selected target.",
        "Add a statically verifiable key or an explicit valueless provides declaration for the target.",
    ),
    RuleDefinition(
        RuleId.RTC010,
        "PHASE_MISMATCH",
        "Delivery phase does not match",
        "error",
        "The variable is delivered only in a phase different from the consumer requirement.",
        "Move or duplicate delivery into the required build or runtime phase.",
    ),
    RuleDefinition(
        RuleId.RTC011,
        "CUSTOM_SETTINGS_SOURCE",
        "Custom Settings source is dynamic",
        "warning",
        "A dynamic Pydantic Settings source cannot be resolved without executing project code.",
        "Expose a static field alias or prefix, or document the custom source as an intentional analysis limitation.",
    ),
    RuleDefinition(
        RuleId.RTC012,
        "UNSUPPORTED_K8S_RESOURCE",
        "Kubernetes resource is unsupported",
        "info",
        "The Kubernetes resource is outside the supported v0.1 workload and key-source set.",
        "Use a supported plain manifest for analysis or assess the unsupported resource with its native tooling.",
    ),
)

RULE_CATALOG = MappingProxyType({item.id: item for item in _RULES})


def get_rule(rule_id: RuleId | str, /) -> RuleDefinition:
    """Return one definition or raise ``ValueError`` for an unknown public ID."""

    try:
        normalized = rule_id if isinstance(rule_id, RuleId) else RuleId(rule_id)
    except ValueError:
        raise ValueError("unknown runtime-contract rule identifier") from None
    return RULE_CATALOG[normalized]


__all__ = ["RULE_CATALOG", "RuleDefinition", "RuleId", "RuleSeverity", "get_rule"]
