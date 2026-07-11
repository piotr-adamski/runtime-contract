"""D1.10 JavaScript and TypeScript analyzer behavior and safety tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest
from tree_sitter import Parser

from runtime_contract.analysis import (
    AnalysisCompleteness,
    AnalyzerInput,
    AnalyzerRegistry,
    DecisionSource,
    DiagnosticCode,
    EffectiveClassification,
    JavaScriptTypeScriptAnalyzer,
    javascript_typescript,
)
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    ConsumerAccessKind,
    Profile,
    RequirementSource,
    SecretSource,
)


@dataclass(frozen=True)
class Resolver:
    result: EffectiveClassification = field(default_factory=EffectiveClassification)

    def classify(self, variable: str) -> EffectiveClassification:
        del variable
        return self.result


def analyze(source: bytes | str, path: str = "src/settings.ts", resolver: Resolver | None = None):  # type: ignore[no-untyped-def]
    content = source.encode() if isinstance(source, str) else source
    return JavaScriptTypeScriptAnalyzer().analyze(
        AnalyzerInput(
            path=path,
            kind=CandidateKind.JAVASCRIPT,
            content=content,
            component="api",
            root="project",
            profile=Profile.PROD,
            resolver=resolver or Resolver(),
        )
    )


def facts(result, kind: type[ConfigKey] | type[Consumer]):  # type: ignore[no-untyped-def]
    return [item.fact for item in result.observations if isinstance(item.fact, kind)]


@pytest.mark.parametrize(
    ("path", "source", "names"),
    [
        ("a.js", "process.env.API_URL", {"API_URL"}),
        ("a.mjs", 'process.env["API_URL"]', {"API_URL"}),
        ("a.cjs", "process.env['API_URL']", {"API_URL"}),
        ("a.jsx", "const x=<div>{process.env.JSX}</div>", {"JSX"}),
        ("a.ts", "process.env.API_URL.valueOf()", {"API_URL"}),
        ("a.mts", "process?.env.API_URL", {"API_URL"}),
        ("a.cts", "process.env?.API_URL", {"API_URL"}),
        ("a.tsx", "const x=<div data-x={process?.env?.API_URL}/>", {"API_URL"}),
        ("a.ts", 'process?.env?.["API_URL"]', {"API_URL"}),
    ],
)
def test_supported_languages_and_access_forms(path: str, source: str, names: set[str]) -> None:
    result = analyze(source, path)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert {item.name for item in facts(result, ConfigKey)} == names
    assert all(
        item.access_kind is ConsumerAccessKind.NODE_PROCESS_ENV for item in facts(result, Consumer)
    )


@pytest.mark.parametrize(
    "source",
    [
        "const { API_URL } = process.env",
        "let { API_URL: url } = process.env",
        "var { API_URL = fallback } = process.env",
        "const { API_URL: url = fallback } = process.env",
    ],
)
def test_destructuring_forms(source: str) -> None:
    assert {item.name for item in facts(analyze(source), ConfigKey)} == {"API_URL"}


def test_multiple_destructured_and_duplicate_reads() -> None:
    result = analyze("const { A, B: b }=process.env; process.env.A; process.env.A")
    assert {item.name for item in facts(result, ConfigKey)} == {"A", "B"}
    assert len(facts(result, Consumer)) == 4


@pytest.mark.parametrize(
    "source",
    [
        "process.env[key]",
        'process.env[prefix + "_TOKEN"]',
        "process?.env?.[getName()]",
        "const { [key]: value } = process.env",
        "const { ...environment } = process.env",
    ],
)
def test_dynamic_names_are_partial_warnings(source: str) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert not result.observations
    assert result.diagnostics[0].code is DiagnosticCode.DYNAMIC_NAME
    assert result.diagnostics[0].severity.value == "warning"
    assert result.diagnostics[0].primary_location.start_line == 1


@pytest.mark.parametrize(
    "source",
    [
        '// process.env.COMMENT\n"process.env.STRING"',
        "`process.env.TEMPLATE`",
        "/process\\.env\\.REGEX/",
        "something.process.env.KEY",
        "obj.env.KEY",
        "import.meta.env.KEY",
        'Deno.env.get("KEY")',
        "Bun.env.KEY",
        "const env=process.env; env.KEY",
        "const p=process; p.env.KEY",
    ],
)
def test_false_positives_and_aliases_are_ignored(source: str) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert not result.observations
    assert not result.diagnostics


def test_template_expression_is_code_but_jsx_text_and_attributes_are_not() -> None:
    result = analyze(
        '<div title="process.env.ATTRIBUTE">process.env.TEXT{`x${process.env.CODE}`}</div>',
        "a.jsx",
    )
    assert {item.name for item in facts(result, ConfigKey)} == {"CODE"}


@pytest.mark.parametrize(
    "source",
    [
        "function f(process){ process.env.NO } process.env.YES",
        "const f=(process)=>process.env.NO; process.env.YES",
        "try{}catch(process){process.env.NO} process.env.YES",
        "import process from 'node:process'; process.env.NO",
        "import {x as process} from 'x'; process.env.NO",
        "const process={env:{}}; process.env.NO",
        "function process(){} process.env.NO",
        "class process{} process.env.NO",
        "const {process}=value; process.env.NO",
    ],
)
def test_lexical_process_shadowing(source: str) -> None:
    names = {item.name for item in facts(analyze(source), ConfigKey)}
    assert names <= {"YES"}
    assert ("YES" in source) == (names == {"YES"})


def test_block_shadowing_does_not_hide_sibling_global_process() -> None:
    result = analyze("process.env.BEFORE; { let process; process.env.NO } process.env.AFTER")
    assert {item.name for item in facts(result, ConfigKey)} == {"BEFORE", "AFTER"}


@pytest.mark.parametrize(
    "source",
    [
        "import {process as p} from 'x'; process.env.YES",
        "const {process: p}=value; process.env.YES",
    ],
)
def test_property_names_that_bind_an_alias_do_not_shadow_process(source: str) -> None:
    assert {item.name for item in facts(analyze(source), ConfigKey)} == {"YES"}


def test_destructuring_alias_named_process_does_shadow() -> None:
    assert not facts(analyze("const {x: process}=value; process.env.NO"), ConfigKey)


@pytest.mark.parametrize(
    "source",
    [
        "(process.env as Record<string,string>).AS",
        "(process.env satisfies Record<string,string>).SAT",
        "process.env!.NON_NULL",
        "(<Record<string,string>>process.env).ASSERT",
        "(((process.env))).PAREN",
    ],
)
def test_typescript_wrappers(source: str) -> None:
    assert len(facts(analyze(source), ConfigKey)) == 1


@pytest.mark.parametrize(
    "source",
    [
        "const broken = ; process.env.AFTER",
        "process.env.BEFORE; const broken =",
        "process.env.BEFORE; function broken( { process.env.AFTER",
    ],
)
def test_error_and_missing_nodes_preserve_unambiguous_reads(source: str) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert result.diagnostics
    assert all(item.code is DiagnosticCode.PARTIAL_ANALYSIS for item in result.diagnostics)
    assert facts(result, ConfigKey)


def test_unicode_character_columns_and_crlf_are_stable() -> None:
    result = analyze('const żółć="✓"; process.env.ŻÓŁĆ\r\nprocess.env.AFTER')
    consumers = sorted(facts(result, Consumer), key=lambda item: item.location.start_line or 0)
    assert consumers[0].location.start_column == 17
    assert consumers[0].location.end_column == 33
    assert consumers[1].location.start_line == 2
    assert consumers[1].location.start_column == 1


@pytest.mark.parametrize("source", ["", "const value=1"])
def test_empty_and_no_observation_files(source: str) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert not result.observations


def test_invalid_utf8_is_failed() -> None:
    result = analyze(b"process.env.A\xff")
    assert result.completeness is AnalysisCompleteness.FAILED
    assert result.diagnostics[0].code is DiagnosticCode.INVALID_ENCODING


def test_resolver_overrides_classification() -> None:
    resolver = Resolver(
        EffectiveClassification(
            secret=True,
            secret_source=DecisionSource.CONFIG_OVERRIDE,
            required=False,
            required_source=DecisionSource.CONFIG_OVERRIDE,
            allow_literal=True,
            allow_literal_source=DecisionSource.CONFIG_OVERRIDE,
        )
    )
    result = analyze("process.env.PLAIN", resolver=resolver)
    key = facts(result, ConfigKey)[0]
    consumer = facts(result, Consumer)[0]
    assert (key.secret, key.secret_source, key.allow_literal) == (
        True,
        SecretSource.CONFIG_OVERRIDE,
        True,
    )
    assert (consumer.required, consumer.requirement_source) == (
        False,
        RequirementSource.CONFIG_OVERRIDE,
    )


def test_secret_heuristic_and_plain_defaults() -> None:
    result = analyze("process.env.API_TOKEN; process.env.HOST")
    keys = {item.name: item for item in facts(result, ConfigKey)}
    assert (keys["API_TOKEN"].secret, keys["API_TOKEN"].allow_literal) == (True, False)
    assert (keys["HOST"].secret, keys["HOST"].allow_literal) == (False, True)


def test_output_is_byte_deterministic_relative_and_registry_compatible() -> None:
    source = "process.env.A; process.env.B"
    first = analyze(source)
    second = analyze(source)
    assert first.model_dump_json() == second.model_dump_json()
    assert json.loads(first.model_dump_json())["schema_id"] == "runtime-contract/analysis-result/v1"
    assert "/home/" not in first.model_dump_json()
    registry = AnalyzerRegistry((JavaScriptTypeScriptAnalyzer(),))
    assert (
        registry.resolve(CandidateKind.JAVASCRIPT).analyzer_id
        == "javascript-typescript-tree-sitter"
    )


def test_source_is_never_executed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    marker = tmp_path / "executed"
    source = f'require("fs").writeFileSync({json.dumps(str(marker))}, "bad"); process.env.SAFE'
    assert {item.name for item in facts(analyze(source), ConfigKey)} == {"SAFE"}
    assert not marker.exists()


def test_parser_construction_failure_is_typed_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenParser:
        def __init__(self, language) -> None:  # type: ignore[no-untyped-def]
            del language
            raise ValueError("unusable parser")

    monkeypatch.setattr(javascript_typescript, "Parser", BrokenParser)
    result = analyze("process.env.A")
    assert result.completeness is AnalysisCompleteness.FAILED
    assert result.diagnostics[0].code is DiagnosticCode.SYNTAX_ERROR


@pytest.mark.parametrize(
    "source",
    [
        "process.env",
        'function f(process){process.env["NO"]}',
        "const x=value",
        "const {A}=other.env",
        "function f(process){const {A}=process.env}",
        "const {1: value}=process.env",
        'process.env["A\\x"]',
        "function f(){ { var process }; process.env.NO } process.env.YES",
        "function f(process?: object){process.env.NO} process.env.YES",
        "function f(process: object){process.env.NO} process.env.YES",
    ],
)
def test_other_defensive_and_binding_paths(source: str) -> None:
    result = analyze(source)
    assert result.completeness in {AnalysisCompleteness.COMPLETE, AnalysisCompleteness.PARTIAL}


def test_javascript_default_for_extensionless_path() -> None:
    assert {item.name for item in facts(analyze("process.env.A", "script"), ConfigKey)} == {"A"}


def test_internal_recovery_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    input = AnalyzerInput(
        path="a.js",
        kind=CandidateKind.JAVASCRIPT,
        content=b"const process=1",
        component="api",
        root="project",
        profile=Profile.PROD,
        resolver=Resolver(),
    )
    tree = Parser(javascript_typescript._language("a.js")).parse(input.content)
    visitor = javascript_typescript._Visitor(input, tree.root_node)
    visitor._member(tree.root_node)
    visitor._subscript(tree.root_node)

    class EmptyWrapper:
        type = "parenthesized_expression"
        named_children: tuple[object, ...] = ()

        def child_by_field_name(self, name: str):  # type: ignore[no-untyped-def]
            del name
            return None

    assert javascript_typescript._unwrap(EmptyWrapper()).type == "parenthesized_expression"  # type: ignore[arg-type]

    class SelfWrapper(EmptyWrapper):
        def child_by_field_name(self, name: str):  # type: ignore[no-untyped-def]
            del name
            return self

    assert javascript_typescript._unwrap(SelfWrapper()).type == "parenthesized_expression"  # type: ignore[arg-type]

    class MalformedString:
        type = "string"
        start_byte = 0
        end_byte = 1

    assert javascript_typescript._string_literal(MalformedString(), b"x") is None  # type: ignore[arg-type]

    monkeypatch.setattr(javascript_typescript, "_binding_scope", lambda node: None)
    assert not javascript_typescript._process_binding_scopes(tree.root_node, input.content)


def test_invalid_rest_order_still_reports_each_recoverable_construct() -> None:
    result = analyze("const {...rest, ...other}=process.env")
    assert result.completeness is AnalysisCompleteness.PARTIAL
