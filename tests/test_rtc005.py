"""D3.03 RTC005 unused-provider evaluation."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from runtime_contract.cli import app
from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    ConsumerAccessKind,
    Contract,
    Environment,
    EnvironmentKind,
    EvidenceKind,
    Phase,
    Profile,
    Provider,
    ProviderMechanism,
    ProviderRole,
    RequirementSource,
    SecretSource,
    SourceLocation,
)
from runtime_contract.evaluation import evaluate_unused_providers
from runtime_contract.precedence import analyze_precedence

runner = CliRunner()


def write(root: Path, path: str, content: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def scan(root: Path, output_format: str = "json"):  # type: ignore[no-untyped-def]
    return runner.invoke(app, ["scan", str(root), "--format", output_format])


def test_unused_declaration_emits_value_safe_warning(tmp_path: Path) -> None:
    write(tmp_path, ".env.example", "UNUSED=placeholder\n")
    payload = json.loads(scan(tmp_path).stdout)
    finding = payload["findings"][0]
    assert finding["rule_id"] == "RTC005"
    assert finding["severity"] == "warning"
    assert finding["phase"] == "not_applicable"
    assert dict(finding["parameters"]) == {
        "context": "unassigned",
        "mechanism": "env_example",
        "provider_role": "declaration",
    }
    assert finding["evidence_locations"] == [finding["primary_location"]]
    assert "placeholder" not in json.dumps(finding)


def test_used_declaration_does_not_emit_rtc005(tmp_path: Path) -> None:
    write(tmp_path, ".env.example", "USED=placeholder\n")
    write(tmp_path, "settings.py", 'import os\nos.getenv("USED", "safe")\n')
    payload = json.loads(scan(tmp_path).stdout)
    assert all(item["rule_id"] != "RTC005" for item in payload["findings"])


def test_overridden_delivery_is_reported_as_shadowed() -> None:
    key = ConfigKey(
        name="TOKEN",
        component="app",
        secret=False,
        secret_source=SecretSource.NOT_SECRET,
        allow_literal=False,
    )
    environment = Environment(
        component="app",
        target="app",
        kind=EnvironmentKind.COMPOSE_SERVICE,
        profile=Profile.DEFAULT,
    )
    consumer = Consumer(
        config_key_id=key.id,
        component="app",
        phase=Phase.RUNTIME,
        required=False,
        requirement_source=RequirementSource.DETECTED_DEFAULT,
        access_kind=ConsumerAccessKind.PYTHON_OS_GETENV,
        location=SourceLocation(path="settings.py", start_line=1),
        has_literal_fallback=True,
    )
    providers = tuple(
        Provider(
            config_key_id=key.id,
            component="app",
            environment_id=environment.id,
            role=ProviderRole.DELIVERY,
            phase=Phase.RUNTIME,
            mechanism=ProviderMechanism.COMPOSE_ENVIRONMENT,
            evidence_kind=EvidenceKind.EXPLICIT_KEY,
            location=SourceLocation(path="compose.yaml", start_line=line),
        )
        for line in (4, 5)
    )
    contract = Contract(
        config_keys=(key,),
        environments=(environment,),
        consumers=(consumer,),
        providers=providers,
    )
    findings = evaluate_unused_providers(contract, analyze_precedence(contract))
    assert len(findings) == 1
    assert dict(findings[0].parameters)["context"] == "shadowed"
    assert dict(findings[0].parameters)["mechanism"] == "compose_environment"


def test_delivery_for_component_without_consumers_is_unassigned(tmp_path: Path) -> None:
    write(tmp_path, "compose.yaml", "services:\n  worker:\n    environment:\n      EXTRA: value\n")
    payload = json.loads(scan(tmp_path).stdout)
    finding = next(item for item in payload["findings"] if item["rule_id"] == "RTC005")
    assert dict(finding["parameters"])["context"] == "unassigned"
    assert dict(finding["parameters"])["provider_role"] == "delivery"


def test_dynamic_reference_suppresses_unused_guess(tmp_path: Path) -> None:
    write(tmp_path, ".env.example", "MAYBE_USED=placeholder\n")
    write(tmp_path, "settings.py", "import os\nname = 'MAYBE_USED'\nos.getenv(name)\n")
    result = scan(tmp_path)
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "partial"
    assert all(item["rule_id"] != "RTC005" for item in payload["findings"])


def test_text_and_sarif_explain_without_provider_values(tmp_path: Path) -> None:
    write(tmp_path, ".env.example", "ORPHAN=do-not-render\n")
    text = scan(tmp_path, "text")
    assert "RTC005 Declaration has no consumer" in text.stdout
    assert "do-not-render" not in text.stdout
    sarif = scan(tmp_path, "sarif")
    result = json.loads(sarif.stdout)["runs"][0]["results"][0]
    assert result["ruleId"] == "RTC005"
    assert "do-not-render" not in sarif.stdout
