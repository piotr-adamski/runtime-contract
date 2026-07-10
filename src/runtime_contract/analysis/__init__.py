"""Public, language-independent analyzer extension contract."""

from runtime_contract.analysis.models import (
    AnalysisCompleteness,
    AnalysisDiagnostic,
    AnalysisResult,
    AnalysisResultSchemaId,
    Confidence,
    DecisionSource,
    DiagnosticCode,
    DiagnosticParameter,
    EffectiveClassification,
    FactKind,
    FactObservation,
)
from runtime_contract.analysis.protocols import Analyzer, AnalyzerInput, ClassificationResolver
from runtime_contract.analysis.registry import (
    AnalyzerExecutionError,
    AnalyzerNotRegisteredError,
    AnalyzerRegistry,
    AnalyzerRegistryError,
    CandidateKindConflictError,
    DuplicateAnalyzerIdError,
    InvalidAnalyzerCallableError,
    InvalidAnalyzerIdError,
    InvalidSupportedKindsError,
)
from runtime_contract.analysis.resolver import ConfigPolicyClassificationResolver

__all__ = [
    "AnalysisCompleteness",
    "AnalysisDiagnostic",
    "AnalysisResult",
    "AnalysisResultSchemaId",
    "Analyzer",
    "AnalyzerExecutionError",
    "AnalyzerInput",
    "AnalyzerNotRegisteredError",
    "AnalyzerRegistry",
    "AnalyzerRegistryError",
    "CandidateKindConflictError",
    "ClassificationResolver",
    "Confidence",
    "ConfigPolicyClassificationResolver",
    "DecisionSource",
    "DiagnosticCode",
    "DiagnosticParameter",
    "DuplicateAnalyzerIdError",
    "EffectiveClassification",
    "FactKind",
    "FactObservation",
    "InvalidAnalyzerCallableError",
    "InvalidAnalyzerIdError",
    "InvalidSupportedKindsError",
]
