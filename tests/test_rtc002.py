"""D3.04 RTC002 unsafe secret-source evaluation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from runtime_contract.cli import app

runner = CliRunner()


def write(root: Path, path: str, content: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def scan(root: Path, output_format: str = "json"):  # type: ignore[no-untyped-def]
    return runner.invoke(app, ["scan", str(root), "--format", output_format])


def rtc002(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in payload["findings"] if item["rule_id"] == "RTC002"]


def test_compose_secret_literal_is_value_safe_error(tmp_path: Path) -> None:
    write(tmp_path, "settings.py", 'import os\nos.getenv("API_TOKEN", "safe")\n')
    write(
        tmp_path,
        "compose.yaml",
        "services:\n  app:\n    environment:\n      API_TOKEN: literal-canary-never-render\n",
    )
    result = scan(tmp_path)
    payload = json.loads(result.stdout)
    finding = rtc002(payload)[0]
    assert finding["severity"] == "error"
    assert dict(finding["parameters"]) == {
        "channel": "plain_literal",
        "classification": "token",
        "confidence": "high",
        "recommended_source": "secret_reference",
    }
    assert "literal-canary-never-render" not in result.stdout
    assert runner.invoke(app, ["check", str(tmp_path), "--format", "json"]).exit_code == 1


@pytest.mark.parametrize("value", ["${API_TOKEN}", ""])
def test_compose_pass_through_is_allowed(tmp_path: Path, value: str) -> None:
    write(tmp_path, "settings.py", 'import os\nos.getenv("API_TOKEN", "safe")\n')
    write(
        tmp_path, "compose.yaml", f"services:\n  app:\n    environment:\n      API_TOKEN: {value}\n"
    )
    assert rtc002(json.loads(scan(tmp_path).stdout)) == []


def test_dockerfile_env_secret_literal_is_unsafe_but_arg_pass_through_is_safe(
    tmp_path: Path,
) -> None:
    write(tmp_path, "Dockerfile", "FROM scratch\nARG BUILD_TOKEN\nENV API_TOKEN=hidden\n")
    payload = json.loads(scan(tmp_path).stdout)
    findings = rtc002(payload)
    assert len(findings) == 1
    assert findings[0]["phase"] == "runtime"
    assert "hidden" not in json.dumps(findings)


def test_kubernetes_plain_and_configmap_are_unsafe_secretref_is_safe(tmp_path: Path) -> None:
    write(
        tmp_path,
        "deployment.yaml",
        """apiVersion: apps/v1
kind: Deployment
metadata: {name: app}
spec:
  selector: {matchLabels: {app: app}}
  template:
    metadata: {labels: {app: app}}
    spec:
      containers:
        - name: app
          image: example
          env:
            - {name: PLAIN_TOKEN, value: never-render}
            - name: MAP_TOKEN
              valueFrom: {configMapKeyRef: {name: cfg, key: MAP_TOKEN}}
            - name: SAFE_TOKEN
              valueFrom: {secretKeyRef: {name: sec, key: SAFE_TOKEN}}
""",
    )
    payload = json.loads(scan(tmp_path).stdout)
    findings = rtc002(payload)
    assert {dict(item["parameters"])["channel"] for item in findings} == {
        "plain_literal",
        "config_map_reference",
    }
    assert "never-render" not in json.dumps(payload)


def test_local_configmap_bulk_is_unsafe_and_secret_bulk_is_safe(tmp_path: Path) -> None:
    write(
        tmp_path,
        "objects.yaml",
        """apiVersion: v1
kind: ConfigMap
metadata: {name: cfg}
data: {API_TOKEN: never-render}
---
apiVersion: v1
kind: Secret
metadata: {name: sec}
data: {SAFE_TOKEN: bmV2ZXItcmVuZGVy}
---
apiVersion: v1
kind: Pod
metadata: {name: app}
spec:
  containers:
    - name: app
      image: example
      envFrom:
        - {configMapRef: {name: cfg}}
        - {secretRef: {name: sec}}
""",
    )
    findings = rtc002(json.loads(scan(tmp_path).stdout))
    assert len(findings) == 1
    assert dict(findings[0]["parameters"])["channel"] == "config_map_bulk"
    assert "never-render" not in json.dumps(findings)


def test_explicit_allow_literal_reason_suppresses_rtc002(tmp_path: Path) -> None:
    write(
        tmp_path,
        "runtime-contract.yaml",
        """version: 1
classifications:
  variables:
    API_TOKEN: {secret: true, allow_literal: true, reason: approved test fixture}
""",
    )
    write(tmp_path, "settings.py", 'import os\nos.getenv("API_TOKEN", "safe")\n')
    write(
        tmp_path, "compose.yaml", "services:\n  app:\n    environment:\n      API_TOKEN: approved\n"
    )
    assert rtc002(json.loads(scan(tmp_path).stdout)) == []


def test_text_and_sarif_expose_channel_not_value(tmp_path: Path) -> None:
    write(tmp_path, "Dockerfile", "FROM scratch\nENV API_TOKEN=redacted-canary\n")
    text = scan(tmp_path, "text")
    assert "RTC002 Secret has a literal value" in text.stdout
    assert "redacted-canary" not in text.stdout
    sarif = scan(tmp_path, "sarif")
    assert json.loads(sarif.stdout)["runs"][0]["results"][0]["ruleId"] == "RTC002"
    assert "redacted-canary" not in sarif.stdout
