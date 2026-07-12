"""Catalog for technical analyzer diagnostics, separate from RTC findings."""

from dataclasses import dataclass
from types import MappingProxyType

from runtime_contract.analysis.models import DIAGNOSTIC_SEVERITY, DiagnosticCode


@dataclass(frozen=True, slots=True)
class DiagnosticDefinition:
    code: DiagnosticCode
    title: str
    rationale: str
    remediation: str


_TITLES = {
    DiagnosticCode.INVALID_ENCODING: "Invalid source encoding",
    DiagnosticCode.SYNTAX_ERROR: "Source syntax error",
    DiagnosticCode.DYNAMIC_NAME: "Dynamic variable name",
    DiagnosticCode.UNSUPPORTED_CONSTRUCT: "Unsupported static construct",
    DiagnosticCode.PARTIAL_ANALYSIS: "Partial source analysis",
    DiagnosticCode.ANALYZER_NOT_REGISTERED: "Analyzer not registered",
    DiagnosticCode.ANALYZER_CONTRACT: "Analyzer contract failure",
    DiagnosticCode.FILESYSTEM_MUTATION: "Filesystem changed during scan",
    DiagnosticCode.NORMALIZATION_ERROR: "Fact normalization failed",
    DiagnosticCode.READ_ERROR: "Source read failed",
    DiagnosticCode.SAFETY_LIMIT: "Safety limit exceeded",
    DiagnosticCode.UNSUPPORTED_K8S_RESOURCE: "Unsupported Kubernetes resource",
    DiagnosticCode.UNUSED_CLASSIFICATION_RULE: "Unused classification rule",
    DiagnosticCode.CUSTOM_SETTINGS_SOURCE: "Dynamic Pydantic Settings source",
}


DIAGNOSTIC_CATALOG = MappingProxyType(
    {
        code: DiagnosticDefinition(
            code=code,
            title=_TITLES[code],
            rationale="The analyzer could not produce complete, reliable static evidence for this input condition.",
            remediation="Review the referenced source location and replace the construct with supported, statically resolvable input when complete analysis is required.",
        )
        for code in DiagnosticCode
    }
)


def diagnostic_severity(code: DiagnosticCode) -> str:
    return DIAGNOSTIC_SEVERITY[code].value


__all__ = ["DIAGNOSTIC_CATALOG", "DiagnosticDefinition", "diagnostic_severity"]
