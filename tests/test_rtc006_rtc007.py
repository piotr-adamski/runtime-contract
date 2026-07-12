"""D3.05 grouped conflict, duplicate, override and dynamic findings."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from runtime_contract.cli import app
from runtime_contract.domain import (
    ConfigKey,
    Contract,
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
    ProviderRole,
    SecretSource,
    SourceLocation,
)
from runtime_contract.evaluation import evaluate_ambiguities
from runtime_contract.precedence import analyze_precedence

runner = CliRunner()


def write(root: Path, path: str, content: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def scan(root: Path, output_format: str = "json"):  # type: ignore[no-untyped-def]
    return runner.invoke(app, ["scan", str(root), "--format", output_format])


def test_dynamic_references_are_grouped_by_component_and_phase(tmp_path: Path) -> None:
    write(
        tmp_path,
        "settings.py",
        "import os\nfirst = 'A'\nsecond = 'B'\nos.getenv(first)\nos.environ[second]\n",
    )
    result = scan(tmp_path)
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    findings = [item for item in payload["findings"] if item["rule_id"] == "RTC006"]
    assert len(findings) == 1
    assert findings[0]["phase"] == "runtime"
    assert len(findings[0]["evidence_locations"]) == 2
    assert dict(findings[0]["parameters"])["location_count"] == "2"


def test_duplicate_kubernetes_declarations_are_one_info_finding(tmp_path: Path) -> None:
    write(
        tmp_path,
        "pod.yaml",
        """apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
    - name: app
      image: example
      env:
        - {name: PORT, value: one}
        - {name: PORT, value: two}
""",
    )
    result = scan(tmp_path)
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    findings = [item for item in payload["findings"] if item["rule_id"] == "RTC007"]
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert dict(findings[0]["parameters"])["issue"] == "duplicate_declaration"


def test_incomparable_competing_sources_are_grouped_without_values() -> None:
    key = ConfigKey(
        name="PORT",
        component="app",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=True,
    )
    environment = Environment(
        component="app",
        target="app",
        kind=EnvironmentKind.IMPLICIT,
        profile=Profile.DEFAULT,
    )
    providers = (
        Provider(
            config_key_id=key.id,
            component="app",
            environment_id=environment.id,
            role=ProviderRole.DELIVERY,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=SourceLocation(path="compose.yaml", start_line=4),
        ),
        Provider(
            config_key_id=key.id,
            component="app",
            environment_id=environment.id,
            role=ProviderRole.DELIVERY,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.DOCKERFILE_ENV,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=SourceLocation(path="Dockerfile", start_line=2),
        ),
    )
    contract = Contract(config_keys=(key,), environments=(environment,), providers=providers)
    findings = evaluate_ambiguities(contract, analyze_precedence(contract), (), {})
    assert len(findings) == 1
    assert findings[0].rule_id.value == "RTC007"
    assert findings[0].severity.value == "warning"
    assert len(findings[0].evidence_locations) == 2
    assert dict(findings[0].parameters)["issue"] == "competing_sources"


def test_independent_targets_and_resolved_override_do_not_duplicate_rtc007() -> None:
    key = ConfigKey(
        name="PORT",
        component="app",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=True,
    )
    environments = tuple(
        Environment(
            component="app",
            target=target,
            kind=EnvironmentKind.COMPOSE_SERVICE,
            profile=Profile.DEFAULT,
        )
        for target in ("one", "two")
    )
    independent = tuple(
        Provider(
            config_key_id=key.id,
            component="app",
            environment_id=environment.id,
            role=ProviderRole.DELIVERY,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=SourceLocation(path=f"{environment.target}.yaml", start_line=1),
        )
        for environment in environments
    )
    contract = Contract(config_keys=(key,), environments=environments, providers=independent)
    assert evaluate_ambiguities(contract, analyze_precedence(contract), (), {}) == ()

    same_path = tuple(
        item.model_copy(
            update={
                "environment_id": environments[0].id,
                "location": SourceLocation(path="compose.yaml", start_line=line),
                "id": "",
            }
        )
        for item, line in zip(independent, (4, 5), strict=True)
    )
    overridden = Contract(config_keys=(key,), environments=environments, providers=same_path)
    assert evaluate_ambiguities(overridden, analyze_precedence(overridden), (), {}) == ()


def test_text_and_sarif_render_grouped_dynamic_rule(tmp_path: Path) -> None:
    write(tmp_path, "settings.py", "import os\nname = 'A'\nos.getenv(name)\n")
    text = scan(tmp_path, "text")
    assert "RTC006 Variable reference is dynamic" in text.stdout
    sarif = scan(tmp_path, "sarif")
    results = json.loads(sarif.stdout)["runs"][0]["results"]
    assert any(item["ruleId"] == "RTC006" for item in results)
