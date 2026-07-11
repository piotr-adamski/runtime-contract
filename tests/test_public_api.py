"""Readable snapshots for the supported public import surface."""

from importlib import import_module

PUBLIC_EXPORTS = {
    "runtime_contract": (
        "CandidateKind",
        "DiscoveryError",
        "DiscoveryErrorCode",
        "DiscoveryItem",
        "DiscoveryResult",
        "DiscoveryStats",
        "FileIdentity",
        "discover",
    ),
    "runtime_contract.analysis": (
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
        "DockerfileAnalyzer",
        "DotenvAnalyzer",
        "DuplicateAnalyzerIdError",
        "EffectiveClassification",
        "FactKind",
        "FactObservation",
        "InvalidAnalyzerCallableError",
        "InvalidAnalyzerIdError",
        "InvalidSupportedKindsError",
        "JavaScriptTypeScriptAnalyzer",
        "PythonAstAnalyzer",
    ),
    "runtime_contract.domain": (
        "ConfigKey",
        "Consumer",
        "ConsumerAccessKind",
        "Contract",
        "ContractSchemaId",
        "Environment",
        "EnvironmentKind",
        "EvidenceKind",
        "Finding",
        "FindingParameter",
        "Phase",
        "Profile",
        "Provider",
        "ProviderMechanism",
        "ProviderRole",
        "RequirementSource",
        "RuleId",
        "SafeIdentifier",
        "SecretSource",
        "Severity",
        "SourceLocation",
    ),
    "runtime_contract.normalization": (
        "NormalizationError",
        "NormalizationErrorCode",
        "normalize_observations",
    ),
    "runtime_contract.scan": (
        "ReportInputs",
        "ReportMetadata",
        "ScanFile",
        "ScanRequest",
        "ScanResult",
        "ScanRun",
        "ScanStatus",
        "ScanSummary",
        "parse_json_report",
        "render",
        "run_scan",
        "schema_bytes",
        "write_atomic",
    ),
}


def test_public_exports_match_reviewable_snapshot() -> None:
    for module_name, expected in PUBLIC_EXPORTS.items():
        module = import_module(module_name)
        assert tuple(module.__all__) == expected
        assert all(getattr(module, name) is not None for name in expected)


def test_documented_import_paths_are_supported() -> None:
    from runtime_contract.analysis import AnalysisResult, AnalyzerInput, AnalyzerRegistry
    from runtime_contract.discovery import CandidateKind
    from runtime_contract.domain import (
        ConfigKey,
        Consumer,
        Contract,
        Environment,
        Finding,
        Provider,
        SourceLocation,
    )
    from runtime_contract.normalization import normalize_observations
    from runtime_contract.scan import ScanResult, parse_json_report, render, run_scan, write_atomic

    assert all(
        item is not None
        for item in (
            AnalysisResult,
            AnalyzerInput,
            AnalyzerRegistry,
            CandidateKind,
            ConfigKey,
            Consumer,
            Contract,
            Environment,
            Finding,
            Provider,
            SourceLocation,
            normalize_observations,
            ScanResult,
            parse_json_report,
            render,
            run_scan,
            write_atomic,
        )
    )
