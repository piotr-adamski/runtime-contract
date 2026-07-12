"""Kubernetes analyzer semantics, wiring facts, and capability boundaries."""

from __future__ import annotations

import builtins
import os
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

from runtime_contract.analysis import (
    AnalysisCompleteness,
    AnalysisResult,
    AnalyzerInput,
    DiagnosticCode,
    KubernetesAnalyzer,
)
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    ConfigKey,
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
    RuleId,
    SecretSource,
    SensitivityConfidence,
    SensitivityReason,
    Severity,
)
from runtime_contract.kubernetes import loader as kubernetes_loader
from runtime_contract.normalization import normalize_observations
from tests.analysis.doubles import StaticResolver

FIXTURE = Path(__file__).parents[1] / "kubernetes" / "fixtures" / "env-envfrom.yaml"
CANARY = "kubernetes-analyzer-value-canary-Q7Z9"


def analyze(source: str | bytes) -> AnalysisResult:
    content = source.encode() if isinstance(source, str) else source
    return KubernetesAnalyzer().analyze(
        AnalyzerInput(
            path="manifests/workload.yaml",
            kind=CandidateKind.KUBERNETES,
            content=content,
            component="api",
            root="api",
            profile=Profile.STAGING,
            resolver=StaticResolver(),
        )
    )


def analyze_project(*sources: tuple[str, str]) -> AnalysisResult:
    return (
        KubernetesAnalyzer()
        .analyze_project(
            tuple(
                AnalyzerInput(
                    path=path,
                    kind=CandidateKind.KUBERNETES,
                    content=content.encode(),
                    component="api",
                    root="api",
                    profile=Profile.STAGING,
                    resolver=StaticResolver(),
                )
                for path, content in sources
            )
        )
        .result
    )


def facts(result: AnalysisResult, kind: type[Any]) -> list[Any]:
    return [item.fact for item in result.observations if isinstance(item.fact, kind)]


def test_analyzer_maps_one_workload_environment_explicit_env_and_bulk_env_from() -> None:
    result = analyze(FIXTURE.read_bytes())

    assert result.completeness is AnalysisCompleteness.COMPLETE
    environments = facts(result, Environment)
    assert [(item.target, item.kind, item.profile) for item in environments] == [
        ("tenant-a/Deployment/api", EnvironmentKind.KUBERNETES_WORKLOAD, Profile.STAGING)
    ]
    keys = facts(result, ConfigKey)
    assert sorted(item.name for item in keys) == [
        "CONFIG_VALUE",
        "CPU_LIMIT",
        "EMPTY_DEFAULT",
        "INIT_READY",
        "LITERAL_VALUE",
        "POD_NAME",
        "SECRET_TOKEN",
    ]
    assert next(item for item in keys if item.name == "SECRET_TOKEN").secret is True
    providers = facts(result, Provider)
    explicit = [item for item in providers if item.mechanism is ProviderMechanism.KUBERNETES_ENV]
    bulk = [item for item in providers if item.mechanism is ProviderMechanism.KUBERNETES_ENV_FROM]
    assert len(explicit) == 7
    assert len(bulk) == 2
    assert all(item.evidence_kind is EvidenceKind.EXPLICIT_KEY for item in explicit)
    assert all(item.evidence_kind is EvidenceKind.UNRESOLVED_BULK for item in bulk)
    assert all(item.config_key_id is None for item in bulk)
    assert all(item.phase is Phase.RUNTIME for item in providers)
    assert all(item.environment_id == environments[0].id for item in providers)
    normalize_observations(result.observations)
    rendered = repr(result) + result.model_dump_json()
    for forbidden in (
        "kubernetes-literal-value-canary-Q7Z9",
        "kubernetes-init-value-canary-Q7Z9",
        "missing-secret-bulk",
    ):
        assert forbidden not in rendered


def test_unsupported_resource_is_complete_rtc012_info() -> None:
    result = analyze("apiVersion: v1\nkind: Service\nmetadata: {name: api}\n")
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert result.observations == ()
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code is DiagnosticCode.UNSUPPORTED_K8S_RESOURCE
    assert diagnostic.rule_id is RuleId.RTC012
    assert diagnostic.severity is Severity.INFO


def test_invalid_env_is_partial_and_preserves_safe_workload_facts() -> None:
    result = analyze(
        f"""apiVersion: v1
kind: Pod
metadata: {{name: api}}
spec:
  containers:
    - name: safe
      env: [{{name: SAFE, value: {CANARY}}}]
    - name: broken
      env: invalid
"""
    )
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert [item.name for item in facts(result, ConfigKey)] == ["SAFE"]
    assert len(facts(result, Environment)) == 1
    assert result.diagnostics[0].code is DiagnosticCode.SYNTAX_ERROR
    assert CANARY not in repr(result) + result.model_dump_json()


@pytest.mark.parametrize(
    ("source", "code"),
    [
        (b"\xff", DiagnosticCode.INVALID_ENCODING),
        (b"apiVersion: v1\nkind: [\n", DiagnosticCode.SYNTAX_ERROR),
    ],
)
def test_fatal_manifest_errors_fail_without_facts(source: bytes, code: DiagnosticCode) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.FAILED
    assert result.observations == ()
    assert result.diagnostics[0].code is code


def test_generic_mapping_is_complete_without_kubernetes_facts() -> None:
    result = analyze('{"fixture":"expected-facts","values":[1,2]}')
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert result.observations == ()
    assert result.diagnostics == ()


def test_recoverable_safety_limit_maps_to_partial_loss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kubernetes_loader, "MAX_ENV_ENTRIES", 0)
    result = analyze(
        """apiVersion: v1
kind: Pod
metadata: {name: api}
spec:
  containers:
    - name: app
      env: [{name: KEY}]
"""
    )
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert result.diagnostics[0].code is DiagnosticCode.SAFETY_LIMIT


def test_no_filesystem_environment_subprocess_eval_exec_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ForbiddenEnvironment(dict[str, str]):
        def __getitem__(self, key: str) -> str:
            raise AssertionError(f"ambient environment read: {key}")

        def get(self, key: str, default: Any = None) -> Any:
            raise AssertionError(f"ambient environment read: {key}, {default}")

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"forbidden capability used: {args!r}, {kwargs!r}")

    source = f"""apiVersion: v1
kind: Pod
metadata: {{name: api}}
spec:
  containers:
    - name: app
      env: [{{name: TOKEN, value: {CANARY}}}]
"""
    with monkeypatch.context() as scoped:
        scoped.setattr(os, "environ", ForbiddenEnvironment())
        scoped.setattr(os, "getenv", forbidden)
        scoped.setattr(subprocess, "run", forbidden)
        scoped.setattr(subprocess, "Popen", forbidden)
        scoped.setattr(socket, "socket", forbidden)
        scoped.setattr(builtins, "open", forbidden)
        scoped.setattr(builtins, "eval", forbidden)
        scoped.setattr(builtins, "exec", forbidden)
        for name in ("read_bytes", "read_text", "exists", "stat", "resolve"):
            scoped.setattr(Path, name, forbidden)
        result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert CANARY not in repr(result) + result.model_dump_json()


def test_wrong_kind_is_rejected_and_input_repr_is_redacted() -> None:
    input = AnalyzerInput(
        path="workload.yaml",
        kind=CandidateKind.PYTHON,
        content=CANARY.encode(),
        component="api",
        root="api",
        profile=Profile.DEFAULT,
        resolver=StaticResolver(),
    )
    assert CANARY not in repr(input)
    with pytest.raises(ValueError, match=r"CandidateKind\.KUBERNETES"):
        KubernetesAnalyzer().analyze(input)


def test_project_resolves_local_env_from_keys_across_files_in_same_namespace() -> None:
    result = analyze_project(
        (
            "manifests/workload.yaml",
            """apiVersion: v1
kind: Deployment
metadata: {name: api, namespace: tenant-a}
spec:
  template:
    spec:
      containers:
        - name: app
          envFrom:
            - prefix: CM_
              configMapRef: {name: app-config}
            - prefix: SEC_
              secretRef: {name: app-secret}
            - configMapRef: {name: external-config, optional: true}
""",
        ),
        (
            "manifests/config.yaml",
            """apiVersion: v1
kind: ConfigMap
metadata: {name: app-config, namespace: tenant-a}
data: {LOG_LEVEL: hidden, SHARED: hidden}
binaryData: {CERT: aGlkZGVu}
""",
        ),
        (
            "manifests/secret.yaml",
            """apiVersion: v1
kind: Secret
metadata: {name: app-secret, namespace: tenant-a}
data: {TOKEN: aGlkZGVu}
stringData: {PASSWORD: hidden}
""",
        ),
    )

    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert sorted(item.name for item in facts(result, ConfigKey)) == [
        "CM_CERT",
        "CM_LOG_LEVEL",
        "CM_SHARED",
        "SEC_PASSWORD",
        "SEC_TOKEN",
    ]
    secret_keys = {
        item.name: item for item in facts(result, ConfigKey) if item.name.startswith("SEC_")
    }
    assert set(secret_keys) == {"SEC_PASSWORD", "SEC_TOKEN"}
    assert all(item.secret for item in secret_keys.values())
    assert all(item.secret_source is SecretSource.HEURISTIC for item in secret_keys.values())
    assert all(
        item.sensitivity_reason is SensitivityReason.SECRET_METADATA
        for item in secret_keys.values()
    )
    assert all(
        item.sensitivity_confidence is SensitivityConfidence.CERTAIN
        for item in secret_keys.values()
    )
    providers = facts(result, Provider)
    resolved = [item for item in providers if item.evidence_kind is EvidenceKind.RESOLVED_BULK]
    unresolved = [item for item in providers if item.evidence_kind is EvidenceKind.UNRESOLVED_BULK]
    assert len(resolved) == 5
    assert len(unresolved) == 1
    assert unresolved[0].config_key_id is None
    assert all(item.mechanism is ProviderMechanism.KUBERNETES_ENV_FROM for item in providers)
    normalize_observations(result.observations)
    public = repr(result) + result.model_dump_json()
    assert "aGlkZGVu" not in public
    assert "hidden" not in public


def test_project_never_resolves_across_namespace_or_object_kind() -> None:
    result = analyze_project(
        (
            "workload.yaml",
            """apiVersion: v1
kind: Pod
metadata: {name: api, namespace: tenant-a}
spec:
  containers:
    - name: app
      envFrom:
        - configMapRef: {name: shared}
        - secretRef: {name: shared}
""",
        ),
        (
            "other-namespace.yaml",
            """apiVersion: v1
kind: ConfigMap
metadata: {name: shared, namespace: tenant-b}
data: {WRONG_NAMESPACE: hidden}
""",
        ),
        (
            "wrong-kind.yaml",
            """apiVersion: v1
kind: ConfigMap
metadata: {name: shared, namespace: tenant-a}
data: {RIGHT_CONFIG: hidden}
""",
        ),
    )

    assert sorted(item.name for item in facts(result, ConfigKey)) == ["RIGHT_CONFIG"]
    providers = facts(result, Provider)
    assert sum(item.evidence_kind is EvidenceKind.RESOLVED_BULK for item in providers) == 1
    assert sum(item.evidence_kind is EvidenceKind.UNRESOLVED_BULK for item in providers) == 1


def test_malformed_presence_never_suppresses_unresolved_bulk_evidence() -> None:
    result = analyze_project(
        (
            "workload.yaml",
            """apiVersion: v1
kind: Pod
metadata: {name: api}
spec:
  containers:
    - name: app
      envFrom: [{secretRef: {name: app-secret}}]
""",
        ),
        (
            "secret.yaml",
            """apiVersion: v1
kind: Secret
metadata: {name: app-secret}
stringData: invalid-secret-map-canary-Q7Z9
""",
        ),
    )

    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert facts(result, ConfigKey) == []
    providers = facts(result, Provider)
    assert len(providers) == 1
    assert providers[0].evidence_kind is EvidenceKind.UNRESOLVED_BULK
    assert "invalid-secret-map-canary-Q7Z9" not in repr(result) + result.model_dump_json()


def test_project_requires_one_component_root_and_profile() -> None:
    with pytest.raises(ValueError, match="at least one input"):
        KubernetesAnalyzer().analyze_project(())

    first = AnalyzerInput(
        path="a.yaml",
        kind=CandidateKind.KUBERNETES,
        content=b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n",
        component="api",
        root="api",
        profile=Profile.DEFAULT,
        resolver=StaticResolver(),
    )
    second = AnalyzerInput(
        path="b.yaml",
        kind=CandidateKind.KUBERNETES,
        content=b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: b}\n",
        component="worker",
        root="worker",
        profile=Profile.DEFAULT,
        resolver=StaticResolver(),
    )

    with pytest.raises(ValueError, match="share component, root, and profile"):
        KubernetesAnalyzer().analyze_project((first, second))
