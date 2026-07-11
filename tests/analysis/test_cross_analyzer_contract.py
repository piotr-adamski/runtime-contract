"""D1.14 cross-analyzer contract and end-to-end regression tests."""

from __future__ import annotations

import ast
import codecs
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from typer.testing import CliRunner

from runtime_contract.analysis import (
    AnalysisCompleteness,
    AnalysisResult,
    AnalyzerInput,
    AnalyzerRegistry,
    DiagnosticCode,
    EffectiveClassification,
    FactKind,
    FactObservation,
    JavaScriptTypeScriptAnalyzer,
    PythonAstAnalyzer,
    python_ast,
)
from runtime_contract.cli import app
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import ConfigKey, Consumer, ConsumerAccessKind, Contract, Profile
from runtime_contract.normalization import normalize_observations
from runtime_contract.scan import ScanRequest, ScanResult, run_scan

FIXTURES = Path(__file__).parent / "fixtures" / "cross"
GOLDENS = Path(__file__).parent / "golden"
CANARIES = (
    "D1_14_CANARY_VALUE_9f31",
    "-----BEGIN D1_14 TEST PRIVATE KEY-----",
)
runner = CliRunner()


@dataclass(frozen=True)
class Resolver:
    def classify(self, variable: str) -> EffectiveClassification:
        del variable
        return EffectiveClassification()


@dataclass(frozen=True)
class LanguageCase:
    analyzer: PythonAstAnalyzer | JavaScriptTypeScriptAnalyzer
    extension: str
    content: bytes
    component: str
    fact_kinds: frozenset[FactKind]
    names: tuple[str, ...]
    access_kinds: frozenset[ConsumerAccessKind]
    completeness: AnalysisCompleteness
    diagnostics: tuple[DiagnosticCode, ...]
    golden: str


def _case(language: str, extension: str) -> LanguageCase:
    python = language == "python"
    return LanguageCase(
        analyzer=PythonAstAnalyzer() if python else JavaScriptTypeScriptAnalyzer(),
        extension=extension,
        content=FIXTURES.joinpath(language, f"settings.{extension}").read_bytes(),
        component=f"{language}-app",
        fact_kinds=frozenset({FactKind.CONFIG_KEY, FactKind.CONSUMER}),
        names=("API_TOKEN", "API_URL", "WORKERS"),
        access_kinds=(
            frozenset(
                {
                    ConsumerAccessKind.PYTHON_OS_GETENV,
                    ConsumerAccessKind.PYTHON_OS_ENVIRON,
                    ConsumerAccessKind.PYTHON_OS_ENVIRON_GET,
                }
            )
            if python
            else frozenset({ConsumerAccessKind.NODE_PROCESS_ENV})
        ),
        completeness=AnalysisCompleteness.COMPLETE,
        diagnostics=(),
        golden=f"{language}-analysis.json",
    )


LANGUAGE_CASES = (
    pytest.param(_case("python", "py"), id="python-py"),
    pytest.param(_case("javascript", "js"), id="javascript-js"),
    pytest.param(replace(_case("javascript", "js"), extension="jsx"), id="javascript-jsx"),
    pytest.param(replace(_case("javascript", "js"), extension="mjs"), id="javascript-mjs"),
    pytest.param(replace(_case("javascript", "js"), extension="cjs"), id="javascript-cjs"),
    pytest.param(_case("typescript", "ts"), id="typescript-ts"),
    pytest.param(replace(_case("typescript", "ts"), extension="tsx"), id="typescript-tsx"),
    pytest.param(replace(_case("typescript", "ts"), extension="mts"), id="typescript-mts"),
    pytest.param(replace(_case("typescript", "ts"), extension="cts"), id="typescript-cts"),
)


def _input(case: LanguageCase, *, content: bytes | None = None) -> AnalyzerInput:
    kind = CandidateKind.PYTHON if case.extension == "py" else CandidateKind.JAVASCRIPT
    return AnalyzerInput(
        path=f"src/settings.{case.extension}",
        kind=kind,
        content=case.content if content is None else content,
        component=case.component,
        root=case.component,
        profile=Profile.PROD,
        resolver=Resolver(),
    )


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _golden_payload(case: LanguageCase) -> dict[str, Any]:
    result = AnalyzerRegistry((case.analyzer,)).analyze(_input(case))
    contract = normalize_observations(result.observations)
    return {
        "analysis": result.model_dump(mode="json"),
        "normalized_contract": contract.model_dump(mode="json"),
    }


def _facts(result: Any, expected: type[ConfigKey] | type[Consumer]) -> list[Any]:
    return [item.fact for item in result.observations if isinstance(item.fact, expected)]


@pytest.mark.parametrize("case", LANGUAGE_CASES)
def test_language_matrix_matches_static_golden_and_normalization(case: LanguageCase) -> None:
    payload = _golden_payload(case)
    result = payload["analysis"]
    contract = payload["normalized_contract"]
    assert result["completeness"] == case.completeness.value
    assert {item["fact_kind"] for item in result["observations"]} == {
        item.value for item in case.fact_kinds
    }
    assert tuple(sorted(item["name"] for item in contract["config_keys"])) == case.names
    assert {item["access_kind"] for item in contract["consumers"]} == {
        item.value for item in case.access_kinds
    }
    assert len(contract["config_keys"]) == 3
    assert len(contract["consumers"]) == 4
    assert result["diagnostics"] == list(case.diagnostics)
    golden = GOLDENS.joinpath(case.golden).read_text(encoding="utf-8")
    assert golden.endswith("\n")
    if case.extension in {"py", "js", "ts"}:
        assert _canonical(payload) == golden
    serialized = repr(payload) + golden
    assert not any(canary in serialized for canary in CANARIES)
    assert not any(item["location"]["path"].startswith("/") for item in contract["consumers"])


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        pytest.param(b'import os\nos.getenv("A")\n', AnalysisCompleteness.COMPLETE, id="utf8"),
        pytest.param(
            codecs.BOM_UTF8 + b'import os\nos.getenv("A")\n',
            AnalysisCompleteness.COMPLETE,
            id="utf8-bom",
        ),
        pytest.param(
            '# -*- coding: latin-1 -*-\nimport os\nos.getenv("CAFÉ")\n'.encode("latin-1"),
            AnalysisCompleteness.COMPLETE,
            id="pep263-latin1",
        ),
        pytest.param(
            codecs.BOM_UTF8 + b"# coding: latin-1\npass\n",
            AnalysisCompleteness.FAILED,
            id="bom-cookie-conflict",
        ),
        pytest.param(
            b"# coding: unknown-codec\npass\n", AnalysisCompleteness.FAILED, id="unknown-codec"
        ),
        pytest.param(
            b'# coding: ascii\nname="\xff"\n',
            AnalysisCompleteness.FAILED,
            id="invalid-declared-bytes",
        ),
    ],
)
def test_python_encoding_contract(content: bytes, expected: AnalysisCompleteness) -> None:
    case = _case("python", "py")
    result = case.analyzer.analyze(_input(case, content=content))
    assert result.completeness is expected
    if expected is AnalysisCompleteness.FAILED:
        assert not result.observations
        assert [item.code for item in result.diagnostics] == [DiagnosticCode.INVALID_ENCODING]
        assert not any(canary in repr(result) for canary in CANARIES)
    else:
        assert not result.diagnostics


@pytest.mark.parametrize("language", ["javascript", "typescript"])
@pytest.mark.parametrize(
    ("content", "expected"),
    [
        pytest.param(b"process.env.A\n", AnalysisCompleteness.COMPLETE, id="utf8"),
        pytest.param(
            codecs.BOM_UTF8 + b"process.env.A\n", AnalysisCompleteness.COMPLETE, id="utf8-bom"
        ),
        pytest.param(
            "// żółć\nprocess.env.A\n".encode(), AnalysisCompleteness.COMPLETE, id="utf8-nonascii"
        ),
        pytest.param(b"process.env.A\xff", AnalysisCompleteness.FAILED, id="invalid-utf8"),
        pytest.param(
            "// café\nprocess.env.A\n".encode("latin-1"), AnalysisCompleteness.FAILED, id="latin1"
        ),
    ],
)
def test_javascript_typescript_utf8_only(
    language: str, content: bytes, expected: AnalysisCompleteness
) -> None:
    case = _case(language, "js" if language == "javascript" else "ts")
    result = case.analyzer.analyze(_input(case, content=content))
    assert result.completeness is expected
    if expected is AnalysisCompleteness.FAILED:
        assert not result.observations
        assert [item.code for item in result.diagnostics] == [DiagnosticCode.INVALID_ENCODING]


@pytest.mark.parametrize(
    ("source", "position"),
    [
        pytest.param(
            'if True print("D1_14_CANARY_VALUE_9f31")\nimport os\nos.getenv("A")',
            "before",
            id="before-read",
        ),
        pytest.param(
            'import os\nos.getenv("A")\nif True print("D1_14_CANARY_VALUE_9f31")',
            "after",
            id="after-read",
        ),
    ],
)
def test_python_syntax_failure_is_redacted_and_discards_observations(
    source: str, position: str
) -> None:
    case = _case("python", "py")
    first = case.analyzer.analyze(_input(case, content=source.encode()))
    second = case.analyzer.analyze(_input(case, content=source.encode()))
    assert first == second
    assert first.completeness is AnalysisCompleteness.FAILED
    assert not first.observations
    assert [item.code for item in first.diagnostics] == [DiagnosticCode.SYNTAX_ERROR]
    assert first.diagnostics[0].primary_location.start_line == (1 if position == "before" else 3)
    assert CANARIES[0] not in repr(first)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("process.env.BEFORE; const broken = ; process.env.AFTER", id="error"),
        pytest.param("process.env.BEFORE; const broken =", id="missing"),
    ],
)
def test_tree_sitter_recovery_preserves_safe_static_and_dynamic_reads(source: str) -> None:
    case = _case("typescript", "ts")
    content = f"{source}; process.env[key]".encode()
    first = case.analyzer.analyze(_input(case, content=content))
    second = case.analyzer.analyze(_input(case, content=content))
    assert first == second
    assert first.completeness is AnalysisCompleteness.PARTIAL
    assert "BEFORE" in {item.name for item in _facts(first, ConfigKey)}
    codes = [item.code for item in first.diagnostics]
    assert DiagnosticCode.PARTIAL_ANALYSIS in codes
    assert DiagnosticCode.DYNAMIC_NAME in codes
    assert len(first.diagnostics) == len({item.id for item in first.diagnostics})
    assert not any(canary in repr(first) for canary in CANARIES)


@pytest.mark.parametrize("language", ["python", "javascript", "typescript"])
def test_flat_megabyte_files_are_complete_and_deterministic(language: str) -> None:
    python = language == "python"
    extension = "py" if python else "js" if language == "javascript" else "ts"
    case = _case(language, extension)
    access: Callable[[str], str] = (
        (lambda name: f'import os\nos.getenv("{name}")\n')
        if python
        else (lambda name: f"process.env.{name};\n")
    )
    neutral = "value = 1\n" if python else "const value = 1;\n"
    lines = [access("BEGIN")]
    size = len(lines[0])
    while size < 524_288:
        lines.append(neutral)
        size += len(neutral)
    lines.append(access("MIDDLE"))
    size += len(lines[-1])
    while size < 1_048_576:
        lines.append(neutral)
        size += len(neutral)
    lines.extend([neutral] * 5)
    lines.append(access("END"))
    content = "".join(lines).encode()
    assert len(content) >= 1_048_576
    first = case.analyzer.analyze(_input(case, content=content))
    second = case.analyzer.analyze(_input(case, content=content))
    assert first == second
    assert first.completeness is AnalysisCompleteness.COMPLETE
    assert {item.name for item in _facts(first, ConfigKey)} == {"BEGIN", "MIDDLE", "END"}
    consumers = _facts(first, Consumer)
    assert len(consumers) == 3
    assert consumers[-1].location.start_line is not None
    assert consumers[-1].location.start_line >= content.count(b"\n") - 9
    assert not first.diagnostics


def test_controlled_python_recursion_is_partial_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = python_ast._Visitor.visit
    calls = 0

    def fail_after_first(self: Any, node: ast.AST) -> Any:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RecursionError(CANARIES[0])
        return original(self, node)

    monkeypatch.setattr(python_ast._Visitor, "visit", fail_after_first)
    case = _case("python", "py")
    result = case.analyzer.analyze(_input(case, content=b"pass\n"))
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert [item.code for item in result.diagnostics] == [DiagnosticCode.PARTIAL_ANALYSIS]
    assert CANARIES[0] not in repr(result)


def _write_project(root: Path) -> None:
    root.joinpath("runtime-contract.yaml").write_text(
        """version: 1
roots:
  api: api
  web: web
  worker: worker
environments:
  prod:
    roots: [api, web, worker]
""",
        encoding="utf-8",
    )
    for name in ("api", "web", "worker"):
        root.joinpath(name).mkdir()
    root.joinpath("api/settings.py").write_text(
        f'import os\nos.getenv("SHARED")\nos.getenv("API_ONLY", "{CANARIES[0]}")\n',
        encoding="utf-8",
    )
    root.joinpath("web/settings.js").write_text(
        f'const canary="{CANARIES[1]}"; process.env.SHARED; process.env.WEB_ONLY;\n',
        encoding="utf-8",
    )
    root.joinpath("worker/settings.ts").write_text(
        "process.env.SHARED; process.env.WORKER_ONLY;\n", encoding="utf-8"
    )


@pytest.mark.parametrize("output_format", ["text", "json", "sarif"])
def test_multi_root_cli_and_run_scan_are_deterministic_safe_and_valid(
    tmp_path: Path, output_format: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_project(tmp_path)
    analyzed_kinds: list[CandidateKind] = []
    observations: list[FactObservation] = []
    original_analyze = AnalyzerRegistry.analyze

    def record_analysis(registry: AnalyzerRegistry, input: AnalyzerInput) -> AnalysisResult:
        analyzed_kinds.append(input.kind)
        result = original_analyze(registry, input)
        observations.extend(result.observations)
        return result

    monkeypatch.setattr(AnalyzerRegistry, "analyze", record_analysis)
    args = ["scan", str(tmp_path), "--environment", "prod", "--format", output_format]
    first = runner.invoke(app, args)
    second = runner.invoke(app, args)
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == ""
    direct = run_scan(ScanRequest(path=tmp_path, environment="prod", output_format=output_format))
    assert direct.exit_code == 0
    assert direct.rendered == first.stdout
    assert isinstance(direct.result, ScanResult)
    assert isinstance(direct.result.contract, Contract)
    assert set(analyzed_kinds) == {CandidateKind.PYTHON, CandidateKind.JAVASCRIPT}
    assert observations and all(type(item) is FactObservation for item in observations)
    for canary in (*CANARIES, str(tmp_path)):
        assert canary not in repr(direct.result)
        assert canary not in first.stdout + first.stderr
    assert direct.result.inputs.selected_roots == ("api", "web", "worker")
    assert {
        item.component for item in direct.result.contract.config_keys if item.name == "SHARED"
    } == {
        "api",
        "web",
        "worker",
    }
    assert {item.path.rsplit("/", 1)[-1] for item in direct.result.files} == {
        "settings.py",
        "settings.js",
        "settings.ts",
    }
    target = tmp_path / f"report-{output_format}.out"
    written = runner.invoke(app, [*args, "--output", target.name])
    assert written.exit_code == 0
    assert written.stdout == written.stderr == ""
    assert target.read_bytes() == first.stdout.encode("utf-8")
    if output_format == "json":
        schema = json.loads(Path("schemas/runtime-contract-scan-result-v1.schema.json").read_text())
        jsonschema.Draft202012Validator(schema).validate(json.loads(first.stdout))
    elif output_format == "sarif":
        schema = json.loads(Path("tests/fixtures/sarif/sarif-schema-2.1.0.json").read_text())
        jsonschema.Draft4Validator(schema).validate(json.loads(first.stdout))


def test_duplicate_roots_observations_and_output_redaction(tmp_path: Path) -> None:
    _write_project(tmp_path)
    args = [
        "scan",
        str(tmp_path),
        "--root",
        "api",
        "--root",
        "api",
        "--format",
        "json",
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["inputs"]["selected_roots"] == ["api"]
    assert payload["summary"]["analyzed"] == 1
    assert {item["component"] for item in payload["contract"]["config_keys"]} == {"api"}
    direct_case = _case("python", "py")
    analysis = direct_case.analyzer.analyze(_input(direct_case))
    once = normalize_observations(analysis.observations)
    repeated = normalize_observations(analysis.observations * 3)
    assert repeated == once
    target = Path("report.json")
    written = runner.invoke(app, [*args, "--output", str(target)])
    assert written.exit_code == 0
    assert written.stdout == written.stderr == ""
    report = tmp_path / target
    assert report.read_text(encoding="utf-8") == result.stdout
    assert not any(canary in report.read_text(encoding="utf-8") for canary in CANARIES)


def test_same_key_across_files_and_access_kinds_deduplicates_only_identity() -> None:
    case = _case("python", "py")
    first_input = replace(_input(case), path="src/first.py", content=b'import os\nos.getenv("A")\n')
    second_input = replace(
        _input(case), path="src/second.py", content=b'import os\nos.environ["A"]\n'
    )
    first = case.analyzer.analyze(first_input)
    second = case.analyzer.analyze(second_input)
    contract = normalize_observations(first.observations + second.observations)
    assert len(contract.config_keys) == 1
    assert len(contract.consumers) == 2
    assert {item.location.path for item in contract.consumers} == {
        "src/first.py",
        "src/second.py",
    }
    assert {item.access_kind for item in contract.consumers} == {
        ConsumerAccessKind.PYTHON_OS_GETENV,
        ConsumerAccessKind.PYTHON_OS_ENVIRON,
    }


def test_overlapping_named_roots_analyze_physical_file_once(tmp_path: Path) -> None:
    tmp_path.joinpath("nested").mkdir()
    tmp_path.joinpath("nested/settings.py").write_text(
        'import os\nos.getenv("SHARED")\n', encoding="utf-8"
    )
    tmp_path.joinpath("runtime-contract.yaml").write_text(
        "version: 1\nroots:\n  all: .\n  nested: nested\n", encoding="utf-8"
    )
    run = run_scan(ScanRequest(path=tmp_path, roots=("all", "nested"), output_format="json"))
    assert run.exit_code == 0
    assert run.result.inputs.selected_roots == ("all", "nested")
    assert run.result.summary.analyzed == 1
    assert len(run.result.files) == 1
    assert [(item.name, item.component) for item in run.result.contract.config_keys] == [
        ("SHARED", "all")
    ]


@pytest.mark.parametrize("language", ["python", "javascript", "typescript"])
def test_analyzed_source_is_never_executed_or_imported(tmp_path: Path, language: str) -> None:
    marker = tmp_path / "executed"
    if language == "python":
        case = _case("python", "py")
        source = f'from pathlib import Path\nPath({str(marker)!r}).write_text("bad")\nimport os\nos.getenv("A")\n'
    else:
        extension = "js" if language == "javascript" else "ts"
        case = _case(language, extension)
        source = f'require("fs").writeFileSync({json.dumps(str(marker))}, "bad"); process.env.A;\n'
    result = case.analyzer.analyze(_input(case, content=source.encode()))
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert {item.name for item in _facts(result, ConfigKey)} == {"A"}
    assert not marker.exists()


def test_golden_hashes_are_stable_and_reviewable() -> None:
    hashes = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(GOLDENS.glob("*-analysis.json"))
    }
    assert set(hashes) == {
        "python-analysis.json",
        "javascript-analysis.json",
        "typescript-analysis.json",
    }
    assert all(len(value) == 64 for value in hashes.values())
