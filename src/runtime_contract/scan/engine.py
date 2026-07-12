"""End-to-end scan orchestration independent from Typer."""

from __future__ import annotations

import os
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from runtime_contract.analysis import (
    AnalysisDiagnostic,
    AnalyzerExecutionError,
    AnalyzerInput,
    AnalyzerRegistry,
    ComposeAnalyzer,
    ConfigPolicyClassificationResolver,
    DiagnosticCode,
    DockerfileAnalyzer,
    DotenvAnalyzer,
    FactObservation,
    JavaScriptTypeScriptAnalyzer,
    KubernetesAnalyzer,
    PythonAstAnalyzer,
)
from runtime_contract.analysis.dockerfile import MAX_DOCKERFILE_BYTES
from runtime_contract.analysis.dotenv import MAX_DOTENV_BYTES
from runtime_contract.config.execution import EffectiveExecution, resolve_execution
from runtime_contract.config.loader import ConfigDocument, load_config
from runtime_contract.config.models import RuntimeContractConfig
from runtime_contract.config.policy import ConfigPolicy
from runtime_contract.discovery import CandidateKind, DiscoveryError, discover
from runtime_contract.domain import Contract, Profile, Severity, SourceLocation
from runtime_contract.errors import PublicError
from runtime_contract.flow import build_flow_graph
from runtime_contract.kubernetes import MAX_KUBERNETES_BYTES
from runtime_contract.normalization import NormalizationError, normalize_observations
from runtime_contract.precedence import analyze_precedence
from runtime_contract.scan.models import (
    ReportInputs,
    ReportMetadata,
    ScanFile,
    ScanResult,
    ScanStatus,
    ScanSummary,
)
from runtime_contract.scan.renderers import render


@dataclass(frozen=True, slots=True)
class ScanRequest:
    path: Path = Path(".")
    config: Path | None = None
    roots: tuple[str, ...] = ()
    environment: str | None = None
    include: tuple[str, ...] | None = None
    exclude: tuple[str, ...] | None = None
    output_format: str | None = None
    output: Path | None = None
    report: Path | None = None
    fail_on: str | None = None
    verbosity: int = 0


@dataclass(frozen=True, slots=True)
class ScanRun:
    result: ScanResult
    rendered: str
    output_path: Path | None
    exit_code: int


def _unique(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _document(root: Path, requested: Path | None) -> tuple[ConfigDocument, bool]:
    if requested is not None and (requested.is_absolute() or ".." in requested.parts):
        raise PublicError("configuration path must remain relative to the project root")
    document = load_config(root, require=requested is not None, config_path=requested)
    if document is not None:
        return document, True
    config = RuntimeContractConfig(version=1)
    return ConfigDocument(config, root / "runtime-contract.yaml", {}), False


def _selected_roots(document: ConfigDocument, request: ScanRequest) -> tuple[str, ...]:
    available = document.config.effective_roots()
    if request.roots:
        selected = _unique(request.roots)
    elif request.environment is not None:
        selected = tuple(document.config.environments[request.environment].roots)
    else:
        selected = tuple(available)
    unknown = [name for name in selected if name not in available]
    if unknown:
        raise PublicError(f"unknown root: {unknown[0]}; available roots: {', '.join(available)}")
    return selected


def _profile(environment: str | None) -> Profile:
    if environment is None:
        return Profile.DEFAULT
    try:
        return Profile(environment)
    except ValueError:
        return Profile.DEFAULT


def _technical_diagnostic(code: DiagnosticCode, path: str) -> AnalysisDiagnostic:
    return AnalysisDiagnostic(
        code=code,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path=path),
    )


def _file_size_diagnostic(path: str) -> AnalysisDiagnostic:
    return AnalysisDiagnostic(
        code=DiagnosticCode.SAFETY_LIMIT,
        severity=Severity.ERROR,
        primary_location=SourceLocation(path=path, start_line=1, start_column=1),
        parameters=(("limit_kind", "file_size"),),
    )


def run_scan(request: ScanRequest) -> ScanRun:
    try:
        root = request.path.resolve(strict=True)
    except OSError:
        raise PublicError("project path is inaccessible") from None
    if not root.is_dir():
        raise PublicError("project path must be a readable directory")
    document, has_config = _document(root, request.config)
    execution: EffectiveExecution = resolve_execution(
        document.config,
        environment=request.environment,
        output_format=request.output_format,
        fail_on=request.fail_on,
        report=request.report,
    )
    selected = _selected_roots(document, request)
    include = tuple(dict.fromkeys(request.include)) if request.include is not None else None
    exclude = tuple(dict.fromkeys(request.exclude)) if request.exclude is not None else None
    discovery = discover(
        root,
        environment=execution.value.environment,
        config_path=request.config,
        selected_roots=selected,
        include=include,
        exclude=exclude,
        config_document=document if has_config else None,
    )
    kubernetes_analyzer = KubernetesAnalyzer()
    registry = AnalyzerRegistry(
        (
            PythonAstAnalyzer(),
            JavaScriptTypeScriptAnalyzer(),
            DotenvAnalyzer(),
            DockerfileAnalyzer(),
            ComposeAnalyzer(),
            kubernetes_analyzer,
        )
    )
    policy = ConfigPolicy(document)
    observations: list[FactObservation] = []
    diagnostics: list[AnalysisDiagnostic] = []
    files: list[ScanFile] = []
    counts = {"complete": 0, "partial": 0, "failed": 0, "analyzed": 0, "skipped": 0}
    kubernetes_projects: dict[str, list[AnalyzerInput]] = {}
    supported = {
        CandidateKind.PYTHON,
        CandidateKind.JAVASCRIPT,
        CandidateKind.ENV_EXAMPLE,
        CandidateKind.DOCKERFILE,
        CandidateKind.COMPOSE,
        CandidateKind.KUBERNETES,
    }
    for item in discovery.candidates:
        if item.kind not in supported:
            counts["skipped"] += 1
            files.append(
                ScanFile(
                    path=item.path,
                    kind=item.kind.value,
                    status="skipped",
                    reason="no_registered_analyzer",
                )
            )
            continue
        counts["analyzed"] += 1
        try:
            resolved = item.revalidate(discovery.canonical_root)
        except DiscoveryError:
            counts["failed"] += 1
            diagnostics.append(_technical_diagnostic(DiagnosticCode.FILESYSTEM_MUTATION, item.path))
            files.append(ScanFile(path=item.path, kind=item.kind.value, status="failed"))
            continue
        size_limit = {
            CandidateKind.ENV_EXAMPLE: MAX_DOTENV_BYTES,
            CandidateKind.DOCKERFILE: MAX_DOCKERFILE_BYTES,
            CandidateKind.KUBERNETES: MAX_KUBERNETES_BYTES,
        }.get(item.kind)
        if size_limit is not None:
            try:
                oversized = resolved.stat().st_size > size_limit
            except OSError:
                counts["failed"] += 1
                diagnostics.append(_technical_diagnostic(DiagnosticCode.READ_ERROR, item.path))
                files.append(ScanFile(path=item.path, kind=item.kind.value, status="failed"))
                continue
            if oversized:
                counts["failed"] += 1
                diagnostics.append(_file_size_diagnostic(item.path))
                files.append(ScanFile(path=item.path, kind=item.kind.value, status="failed"))
                continue
        try:
            content = resolved.read_bytes()
        except OSError:
            counts["failed"] += 1
            diagnostics.append(_technical_diagnostic(DiagnosticCode.READ_ERROR, item.path))
            files.append(ScanFile(path=item.path, kind=item.kind.value, status="failed"))
            continue
        resolver = ConfigPolicyClassificationResolver(
            policy, item.root_name, execution.value.environment
        )
        analyzer_input = AnalyzerInput(
            path=item.path,
            kind=item.kind,
            content=content,
            component=item.root_name,
            root=item.root_name,
            profile=_profile(execution.value.environment),
            resolver=resolver,
        )
        if item.kind is CandidateKind.KUBERNETES:
            kubernetes_projects.setdefault(item.root_name, []).append(analyzer_input)
            continue
        try:
            result = registry.analyze(analyzer_input)
        except AnalyzerExecutionError:
            counts["failed"] += 1
            diagnostics.append(_technical_diagnostic(DiagnosticCode.ANALYZER_CONTRACT, item.path))
            files.append(ScanFile(path=item.path, kind=item.kind.value, status="failed"))
            continue
        counts[result.completeness.value] += 1
        files.append(
            ScanFile(path=item.path, kind=item.kind.value, status=result.completeness.value)
        )
        observations.extend(result.observations)
        diagnostics.extend(result.diagnostics)
    for project_inputs in kubernetes_projects.values():
        try:
            project = kubernetes_analyzer.analyze_project(project_inputs)
        except Exception:
            for project_input in project_inputs:
                counts["failed"] += 1
                diagnostics.append(
                    _technical_diagnostic(DiagnosticCode.ANALYZER_CONTRACT, project_input.path)
                )
                files.append(
                    ScanFile(
                        path=project_input.path,
                        kind=project_input.kind.value,
                        status="failed",
                    )
                )
            continue
        status_by_path = dict(project.file_completeness)
        for project_input in project_inputs:
            completeness = status_by_path[project_input.path]
            counts[completeness.value] += 1
            files.append(
                ScanFile(
                    path=project_input.path,
                    kind=project_input.kind.value,
                    status=completeness.value,
                )
            )
        observations.extend(project.result.observations)
        diagnostics.extend(project.result.diagnostics)
    try:
        contract = normalize_observations(observations)
    except NormalizationError:
        counts["failed"] += 1
        diagnostics.append(
            _technical_diagnostic(DiagnosticCode.NORMALIZATION_ERROR, "runtime-contract.yaml")
        )
        contract = Contract()
    for unused in policy.unused_classification_rules():
        diagnostics.append(
            AnalysisDiagnostic(
                code=DiagnosticCode.UNUSED_CLASSIFICATION_RULE,
                severity=Severity.WARNING,
                primary_location=SourceLocation(
                    path=document.path.relative_to(root).as_posix(),
                    start_line=unused.line,
                    start_column=unused.column,
                ),
                parameters=(("pointer", unused.pointer),),
            )
        )
    flow_graph = build_flow_graph(contract)
    precedence = analyze_precedence(contract)
    status = (
        ScanStatus.FAILED
        if counts["failed"]
        else ScanStatus.PARTIAL
        if counts["partial"]
        else ScanStatus.COMPLETE
    )
    diagnostics_tuple = tuple(sorted(diagnostics, key=lambda item: item.id))
    candidate_kinds = {
        kind.value: sum(1 for item in discovery.candidates if item.kind is kind)
        for kind in CandidateKind
        if any(item.kind is kind for item in discovery.candidates)
    }
    summary = ScanSummary(
        candidates=len(discovery.candidates),
        analyzed=counts["analyzed"],
        skipped=counts["skipped"],
        complete_files=counts["complete"],
        partial_files=counts["partial"],
        failed_files=counts["failed"],
        config_keys=len(contract.config_keys),
        consumers=len(contract.consumers),
        providers=len(contract.providers),
        flow_nodes=len(flow_graph.nodes),
        flow_edges=len(flow_graph.edges),
        precedence_providers=len(precedence.providers),
        precedence_conflicts=len(precedence.conflicts),
        diagnostics=len(diagnostics_tuple),
        candidate_kinds=candidate_kinds,
        skipped_reasons=(
            {"no_registered_analyzer": counts["skipped"]} if counts["skipped"] else {}
        ),
    )
    config_label = document.path.relative_to(root).as_posix() if has_config else None
    try:
        tool_version = version("runtime-contract")
    except PackageNotFoundError:
        tool_version = None
    scan_result = ScanResult(
        schema_id="runtime-contract/v1",
        schema_version=1,
        metadata=ReportMetadata(tool_version=tool_version),
        inputs=ReportInputs(
            config=config_label,
            environment=execution.value.environment,
            selected_roots=selected,
            include=tuple(document.config.include) if include is None else include,
            exclude=tuple(document.config.exclude) if exclude is None else exclude,
            fail_on=execution.value.fail_on.value,
        ),
        status=status,
        summary=summary,
        contract=contract,
        flow_graph=flow_graph,
        precedence=precedence,
        diagnostics=diagnostics_tuple,
        findings=(),
        files=tuple(sorted(files, key=lambda item: item.path.encode("utf-8"))),
    )
    output_format = execution.value.format.value
    rendered = render(scan_result, output_format, request.verbosity)
    output = request.output
    if output is None and execution.value.report is not None:
        output = Path(execution.value.report)
    return ScanRun(scan_result, rendered, output, 0 if status is ScanStatus.COMPLETE else 2)


def write_atomic(root: Path, output: Path, content: str) -> None:
    target = root / output
    parent = target.parent
    if not parent.is_dir():
        raise OSError("output parent must already exist")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


__all__ = ["ScanRequest", "ScanRun", "run_scan", "write_atomic"]
