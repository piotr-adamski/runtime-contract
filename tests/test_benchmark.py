"""Bounded acquisition, annotation accounting and runner E2E on trusted fixtures."""

from __future__ import annotations

import importlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from jsonschema import ValidationError

BASE = Path(__file__).parents[1] / "benchmarks/public-corpus"


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch) -> dict[str, ModuleType]:
    monkeypatch.syspath_prepend(str(BASE / "scripts"))
    return {
        name: importlib.import_module(name)
        for name in ("acquire", "common", "run", "validate_annotations")
    }


def archive(files: dict[str, str], prefix: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as output:
        for name, content in files.items():
            item = tarfile.TarInfo(prefix + "/" + name)
            item.size = len(content.encode())
            output.addfile(item, io.BytesIO(content.encode()))
    return buffer.getvalue()


def test_acquire_never_extracts_dotenv_builds_or_keys(
    tmp_path: Path, harness: dict[str, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    sha = "a" * 40
    raw = archive(
        {
            "app.py": "raise RuntimeError('MUST_NOT_EXECUTE')",
            ".env": "SECRET",
            ".env.production": "SECRET",
            ".env.example": "KEY=",
            "x.key": "SECRET",
            "node_modules/x.js": "throw Error()",
            ".next/cache": "private",
        },
        "fixture-" + sha,
    )
    monkeypatch.setattr(
        harness["acquire"].urllib.request, "urlopen", lambda *a, **k: io.BytesIO(raw)
    )
    result = harness["acquire"].acquire(
        {"repository": "owner/fixture", "sha": sha}, tmp_path / "tree"
    )
    assert result["files"] == 2 and result["excluded"]["private_or_generated"] == 5
    assert (tmp_path / "tree/app.py").exists()
    assert not (tmp_path / "tree/.env").exists()


@pytest.mark.parametrize(
    "name,prefix", [("../../escape", "fixture-" + "a" * 40), ("app.py", "wrong-sha")]
)
def test_acquisition_identity_and_containment_fail_closed(
    tmp_path: Path,
    harness: dict[str, ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    prefix: str,
) -> None:
    raw = archive({name: "content"}, prefix)
    monkeypatch.setattr(
        harness["acquire"].urllib.request, "urlopen", lambda *a, **k: io.BytesIO(raw)
    )
    with pytest.raises(ValueError, match="identity or containment"):
        harness["acquire"].acquire(
            {"repository": "owner/fixture", "sha": "a" * 40}, tmp_path / "tree"
        )
    assert not (tmp_path / "escape").exists()


def test_corpus_schema_rejects_moving_refs_and_duplicate_repos(
    tmp_path: Path, harness: dict[str, ModuleType]
) -> None:
    document = json.loads((BASE / "corpus.yaml").read_text())
    document["repositories"][0]["sha"] = "main"
    path = tmp_path / "corpus.yaml"
    path.write_text(json.dumps(document))
    with pytest.raises(ValidationError):
        harness["common"].corpus(path)
    document["repositories"][0]["sha"] = "a" * 40
    document["repositories"].append(document["repositories"][0])
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="duplicate"):
        harness["common"].corpus(path)


def annotation() -> dict[str, Any]:
    return {
        "repository": "owner/fixture",
        "sha": "a" * 40,
        "mode": "configured",
        "finding_id": "finding-id",
        "rule_id": "RTC001",
        "severity": "error",
        "component": "app",
        "phase": "runtime",
        "location": "app.py:1",
        "key": "KEY",
        "verdict": "cannot_determine",
        "confidence": "low",
        "reason": "Runtime delivery cannot be established from the static repository alone.",
        "reviewer": "technical reviewer",
        "reviewed_on": "2026-10-18",
        "second_review": "pending",
        "security_withheld": False,
    }


def test_annotations_require_exact_coverage_and_security_redaction(
    tmp_path: Path, harness: dict[str, ModuleType]
) -> None:
    row = annotation()
    raw: dict[str, Any] = {
        "contract": {"config_keys": [{"id": "key-id", "name": "KEY"}]},
        "findings": [
            {
                "id": "finding-id",
                "rule_id": "RTC001",
                "severity": "error",
                "component": "app",
                "phase": "runtime",
                "config_key_id": "key-id",
                "primary_location": {"path": "app.py", "start_line": 1},
            }
        ],
    }
    (tmp_path / "owner--fixture.configured.json").write_text(json.dumps(raw))
    runs = [
        {"repository": "owner/fixture", "mode": "configured", "status": "complete", "sha": "a" * 40}
    ]
    validate = harness["validate_annotations"].validate
    validate([row], runs, tmp_path)
    with pytest.raises(ValueError, match="every finding"):
        validate([], runs, tmp_path)
    with pytest.raises(ValueError, match="duplicate"):
        validate([row, row], runs, tmp_path)
    with pytest.raises(ValidationError):
        validate([{**row, "verdict": "guessed"}], runs, tmp_path)
    with pytest.raises(ValueError, match="metadata"):
        validate([{**row, "rule_id": "RTC002"}], runs, tmp_path)
    for field, value in {
        "sha": "b" * 40,
        "severity": "warning",
        "location": "other.py:1",
        "key": "OTHER",
        "component": "other",
        "phase": "build",
    }.items():
        with pytest.raises(ValueError, match=r"metadata|references"):
            validate([{**row, field: value}], runs, tmp_path)
    raw["findings"][0]["rule_id"] = "RTC002"
    (tmp_path / "owner--fixture.configured.json").write_text(json.dumps(raw))
    # A raw sensitive finding cannot be relabeled as an ordinary finding.
    with pytest.raises(ValueError, match="metadata"):
        validate([row], runs, tmp_path)
    with pytest.raises(ValueError, match="withheld"):
        validate([{**row, "rule_id": "RTC002"}], runs, tmp_path)
    with pytest.raises(ValueError, match="exposes"):
        validate([{**row, "rule_id": "RTC002", "security_withheld": True}], runs, tmp_path)


def test_public_export_requires_fresh_destination(
    tmp_path: Path, harness: dict[str, ModuleType]
) -> None:
    exporter = importlib.import_module("build_report")
    destination = tmp_path / "public"
    exporter.fresh_output(destination)
    stale = destination / "old-sensitive.json"
    stale.write_text("must be preserved, never published")
    with pytest.raises(ValueError, match="fresh or empty"):
        exporter.fresh_output(destination)
    assert stale.read_text() == "must be preserved, never published"


@pytest.mark.skipif(
    sys.platform != "linux", reason="Pilot runner requires Linux resource limits and GNU time"
)
def test_runner_warmup_measurements_and_source_integrity_e2e(
    tmp_path: Path, harness: dict[str, ModuleType], monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = json.loads((BASE / "corpus.yaml").read_text())
    manifest["repositories"] = manifest["repositories"][:1]
    item = manifest["repositories"][0]
    name = harness["common"].slug(item)
    source = tmp_path / "sources" / name
    source.mkdir(parents=True)
    (source / "app.py").write_text("raise RuntimeError('SUBJECT_CODE_MUST_NOT_RUN')")
    (tmp_path / "receipts").mkdir()
    (tmp_path / "receipts" / f"{name}.json").write_text(
        json.dumps({"sha": item["sha"], "tree_sha256": harness["common"].tree_digest(source)})
    )
    (tmp_path / "corpus.yaml").write_text(json.dumps(manifest))
    fixture = tmp_path / "fixture"
    (fixture / "configs").mkdir(parents=True)
    (fixture / "configs" / f"{name}.yaml").write_text("version: 1\n")
    monkeypatch.setattr(harness["run"], "BASE", fixture)
    cli = tmp_path / "bin" / "runtime-contract"
    cli.parent.mkdir()
    cli.write_text(
        f'#!{sys.executable}\nimport sys\nprint(\'runtime-contract 0.1.2\' if \'--version\' in sys.argv else \'{{"status":"complete","summary":{{"findings":0}}}}\')\n'
    )
    cli.chmod(0o755)
    os.symlink(sys.executable, cli.parent / "python")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run.py",
            "--corpus",
            str(tmp_path / "corpus.yaml"),
            "--workspace",
            str(tmp_path),
            "--cli",
            str(cli),
        ],
    )
    harness["run"].main()
    result = json.loads((tmp_path / "raw/measurements.json").read_text())
    assert len(result) == 2
    assert all(
        len(run["samples"]) == 3 and run["deterministic"] and run["source_unchanged"]
        for run in result
    )
    assert all(run["median_seconds"] > 0 and run["peak_rss_kib"] > 0 for run in result)
