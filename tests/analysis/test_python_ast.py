"""D1.09 Python AST analyzer behavior and safety tests."""

from __future__ import annotations

import ast
import codecs
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import jsonschema
import pytest

from runtime_contract.analysis import (
    AnalysisCompleteness,
    AnalyzerInput,
    AnalyzerRegistry,
    DecisionSource,
    DiagnosticCode,
    EffectiveClassification,
    PythonAstAnalyzer,
    python_ast,
)
from runtime_contract.analysis.schema import schema_bytes
from runtime_contract.discovery import CandidateKind
from runtime_contract.domain import (
    ConfigKey,
    Consumer,
    ConsumerAccessKind,
    Phase,
    Profile,
    RequirementSource,
    SecretSource,
)

FIXTURES = Path(__file__).parent / "fixtures" / "python"


@dataclass(frozen=True)
class Resolver:
    result: EffectiveClassification = field(default_factory=EffectiveClassification)

    def classify(self, variable: str) -> EffectiveClassification:
        del variable
        return self.result


def analyze(source: bytes | str, resolver: Resolver | None = None):  # type: ignore[no-untyped-def]
    content = source.encode() if isinstance(source, str) else source
    return PythonAstAnalyzer().analyze(
        AnalyzerInput(
            path="src/settings.py",
            kind=CandidateKind.PYTHON,
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
    ("source", "access_kind", "required", "literal"),
    [
        ('import os\nos.getenv("A")', ConsumerAccessKind.PYTHON_OS_GETENV, True, False),
        ('import os\nos.getenv("A", "x")', ConsumerAccessKind.PYTHON_OS_GETENV, False, True),
        ('import os\nos.getenv("A", None)', ConsumerAccessKind.PYTHON_OS_GETENV, True, False),
        (
            'import os\nos.environ.get("A")',
            ConsumerAccessKind.PYTHON_OS_ENVIRON_GET,
            True,
            False,
        ),
        (
            'import os\nos.environ.get("A", default={"x": 1})',
            ConsumerAccessKind.PYTHON_OS_ENVIRON_GET,
            False,
            True,
        ),
        (
            'import os\nos.environ["A"]',
            ConsumerAccessKind.PYTHON_OS_ENVIRON,
            True,
            False,
        ),
        (
            'import os as operating_system\noperating_system.getenv("A")',
            ConsumerAccessKind.PYTHON_OS_GETENV,
            True,
            False,
        ),
        (
            'from os import getenv\ngetenv("A")',
            ConsumerAccessKind.PYTHON_OS_GETENV,
            True,
            False,
        ),
        (
            'from os import getenv as read_env\nread_env("A")',
            ConsumerAccessKind.PYTHON_OS_GETENV,
            True,
            False,
        ),
        (
            'from os import environ\nenviron.get("A")',
            ConsumerAccessKind.PYTHON_OS_ENVIRON_GET,
            True,
            False,
        ),
        (
            'from os import environ as env\nenv["A"]',
            ConsumerAccessKind.PYTHON_OS_ENVIRON,
            True,
            False,
        ),
    ],
)
def test_supported_accesses(
    source: str, access_kind: ConsumerAccessKind, required: bool, literal: bool
) -> None:
    result = analyze(source)
    consumers = facts(result, Consumer)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert len(facts(result, ConfigKey)) == len(consumers) == 1
    assert consumers[0].access_kind is access_kind
    assert consumers[0].required is required
    assert consumers[0].has_literal_fallback is literal
    assert consumers[0].requirement_source is (
        RequirementSource.LITERAL_FALLBACK if literal else RequirementSource.DETECTED_DEFAULT
    )


def test_multiple_and_repeated_keys_deduplicate_only_config_key() -> None:
    result = analyze(FIXTURES.joinpath("accesses.py").read_bytes())
    assert len(facts(result, ConfigKey)) == 4
    assert len(facts(result, Consumer)) == 4
    repeated = analyze('import os\nos.getenv("A")\nos.environ["A"]')
    assert len(facts(repeated, ConfigKey)) == 1
    assert len(facts(repeated, Consumer)) == 2


def test_resolver_overrides_all_classification_fields() -> None:
    resolver = Resolver(
        EffectiveClassification(
            required=False,
            required_source=DecisionSource.CONFIG_OVERRIDE,
            secret=True,
            secret_source=DecisionSource.CONFIG_OVERRIDE,
            allow_literal=True,
            allow_literal_source=DecisionSource.CONFIG_OVERRIDE,
        )
    )
    result = analyze('import os\nos.getenv("PLAIN")', resolver)
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


@pytest.mark.parametrize("name", ["API_TOKEN", "PASSWORD", "SIGNING_PRIVATE_KEY", "CLIENT_SECRET"])
def test_secret_heuristic_and_default_literal_policy(name: str) -> None:
    key = facts(analyze(f'import os\nos.getenv("{name}")'), ConfigKey)[0]
    assert key.secret is True
    assert key.secret_source is SecretSource.HEURISTIC
    assert key.allow_literal is False


def test_non_secret_defaults_to_allow_literal() -> None:
    key = facts(analyze('import os\nos.getenv("HOST")'), ConfigKey)[0]
    assert (key.secret, key.secret_source, key.allow_literal) == (
        False,
        SecretSource.NOT_SECRET,
        True,
    )


@pytest.mark.parametrize(
    "source",
    [
        'def getenv(name): return name\ngetenv("A")',
        'class Obj: pass\nos = Obj()\nos.getenv("A")',
        'import other\nother.getenv("A")',
        'import os\nos = object()\nos.getenv("A")',
        'import os as env\ndef f(env):\n    return env.getenv("A")',
        'import os\nreader = os.getenv\nreader("A")',
        '# os.getenv("A")\nTEXT = \'os.getenv("A")\'',
        'import os\nos.environ.setdefault("A", "x")',
        'import os\nos.environ.pop("A")\nos.environ.update(A="x")',
        'import os.path as path\npath.getenv("A")',
    ],
)
def test_unrelated_or_out_of_scope_constructs_are_ignored(source: str) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE
    assert not result.observations
    assert not result.diagnostics


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("import os\nos.getenv(NAME)", DiagnosticCode.DYNAMIC_NAME),
        ('import os\nos.environ[f"{NAME}_URL"]', DiagnosticCode.DYNAMIC_NAME),
        ('import os\nos.getenv("A", make_default())', DiagnosticCode.UNSUPPORTED_CONSTRUCT),
        ("import os\nos.getenv()", DiagnosticCode.UNSUPPORTED_CONSTRUCT),
        ('import os\nos.getenv("A", "x", "y")', DiagnosticCode.UNSUPPORTED_CONSTRUCT),
        ('import os\nos.getenv("A", fallback="x")', DiagnosticCode.UNSUPPORTED_CONSTRUCT),
        ("import os\nos.getenv(*args)", DiagnosticCode.UNSUPPORTED_CONSTRUCT),
        ('import os\nos.getenv("A", **kwargs)', DiagnosticCode.UNSUPPORTED_CONSTRUCT),
        ('import os\nos.getenv("A", "x", default="y")', DiagnosticCode.UNSUPPORTED_CONSTRUCT),
        ("from os import *", DiagnosticCode.UNSUPPORTED_CONSTRUCT),
    ],
)
def test_loss_constructs_are_partial(source: str, code: DiagnosticCode) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert result.diagnostics[0].code is code
    if code is DiagnosticCode.DYNAMIC_NAME:
        assert result.diagnostics[0].parameters[0][0] == "access_kind"
        assert not result.observations


def test_dynamic_fallback_preserves_exact_key_and_required_default() -> None:
    result = analyze('import os\nos.getenv("A", make_default())')
    assert len(facts(result, ConfigKey)) == len(facts(result, Consumer)) == 1
    consumer = facts(result, Consumer)[0]
    assert consumer.required is True
    assert consumer.has_literal_fallback is False


def test_multiline_and_utf8_byte_columns_use_ast_locations() -> None:
    result = analyze('import os\nlabel = "żółć"; os.getenv(\n    "A",\n    "x",\n)')
    location = facts(result, Consumer)[0].location
    assert location.start_line == 2
    # AST columns are UTF-8 byte offsets: the four non-ASCII characters add two bytes each.
    assert location.start_column == 21
    assert location.end_line == 5


@pytest.mark.parametrize(
    "content",
    [
        codecs.BOM_UTF8 + b'import os\nos.getenv("A")',
        '# coding: latin-1\nimport os\nos.getenv("CAFÉ")'.encode("latin-1"),
    ],
)
def test_bom_and_coding_cookie(content: bytes) -> None:
    assert len(facts(analyze(content), Consumer)) == 1


@pytest.mark.parametrize(
    "content",
    [b"# coding: unknown-codec\npass\n", b"# coding: ascii\nname = '\xff'\n"],
)
def test_invalid_encoding_is_failed_without_observations(content: bytes) -> None:
    result = analyze(content)
    assert result.completeness is AnalysisCompleteness.FAILED
    assert result.diagnostics[0].code is DiagnosticCode.INVALID_ENCODING
    assert not result.observations


def test_syntax_error_is_failed_stable_and_does_not_leak_source() -> None:
    source = "import os\nos.getenv(SECRET_VALUE"
    first = analyze(source)
    second = analyze(source)
    assert first == second
    assert first.completeness is AnalysisCompleteness.FAILED
    assert first.diagnostics[0].code is DiagnosticCode.SYNTAX_ERROR
    assert first.diagnostics[0].primary_location.path == "src/settings.py"
    assert "SECRET_VALUE" not in first.model_dump_json()


@pytest.mark.parametrize("source", ["", "value = 1", "(" * 150 + "0" + ")" * 150])
def test_empty_plain_and_deep_valid_files_are_safe(source: str) -> None:
    result = analyze(source)
    assert result.completeness is AnalysisCompleteness.COMPLETE


def test_scope_kinds_and_sequential_shadowing() -> None:
    source = """
import os
os.getenv("MODULE")
async def a():
    import os as local
    local.getenv("ASYNC")
def f():
    from os import getenv
    getenv("FUNCTION")
    getenv = lambda name: name
    getenv("SHADOWED")
class C:
    from os import environ as env
    env["CLASS"]
value = (lambda os: os.getenv("LAMBDA"))(object())
"""
    result = analyze(source)
    assert {key.name for key in facts(result, ConfigKey)} == {
        "MODULE",
        "ASYNC",
        "FUNCTION",
        "CLASS",
    }


def test_other_import_shadows_prior_binding() -> None:
    result = analyze('from os import getenv\nfrom other import getenv\ngetenv("A")')
    assert not result.observations


def test_registry_returns_failed_result_for_broken_python() -> None:
    input = AnalyzerInput(
        path="broken.py",
        kind=CandidateKind.PYTHON,
        content=b"def broken(",
        component="api",
        root="project",
        profile=Profile.PROD,
        resolver=Resolver(),
    )
    registry = AnalyzerRegistry((PythonAstAnalyzer(),))
    assert registry.resolve(CandidateKind.PYTHON).analyzer_id == "python-ast"
    assert registry.analyze(input).completeness is AnalysisCompleteness.FAILED


def test_output_is_deterministic_relative_and_schema_valid() -> None:
    source = 'import os\nos.getenv("A")\nos.environ["B"]'
    first = analyze(source)
    second = analyze(source)
    assert first.model_dump_json() == second.model_dump_json()
    payload = json.loads(first.model_dump_json())
    jsonschema.validate(payload, json.loads(schema_bytes()))
    serialized = first.model_dump_json()
    assert "/home/" not in serialized
    assert "project" not in serialized
    assert all(
        not observation.fact.location.path.startswith("/")
        for observation in first.observations
        if isinstance(observation.fact, Consumer)
    )


def test_extended_scope_and_assignment_visitors() -> None:
    source = """
import os
from other import *
from .os import getenv as relative_getenv
from os import path
x = [1]
x[0]

def deco(value): return value

@deco
def function(pos=os.getenv("DEFAULT"), /, *args, required, named=os.getenv("KWDEFAULT"), **kwargs) -> str:
    annotated: str
    assigned: str = os.getenv("ANNASSIGN")
    os_name = os
    os_name += object()
    (left, [right]) = (1, [2])
    object().attribute = 1
    if (named_value := os.getenv("NAMED")):
        pass
    for os_name in [object()]:
        pass
    else:
        os.getenv("FOR_ELSE")
    with open(__file__) as os_name, open(__file__):
        os.getenv("WITH")
    return "value"

async def asynchronous():
    async for os_name in iterator():
        os.getenv("ASYNC_FOR")
    async with manager() as os_name:
        os.getenv("ASYNC_WITH")

lambda_value = lambda pos=os.getenv("LAMBDA_DEFAULT"), *args, required, named=1, **kwargs: os.getenv("LAMBDA")

@deco
class Child(object, metaclass=type):
    os.getenv("CLASS_BODY")
"""
    names = {key.name for key in facts(analyze(source), ConfigKey)}
    assert names == {
        "DEFAULT",
        "KWDEFAULT",
        "ANNASSIGN",
        "NAMED",
        "FOR_ELSE",
        "WITH",
        "ASYNC_FOR",
        "ASYNC_WITH",
        "LAMBDA_DEFAULT",
        "LAMBDA",
        "CLASS_BODY",
    }


def test_pydantic_v1_and_v2_settings_fields_aliases_and_prefixes() -> None:
    source = """
from pydantic import BaseSettings as V1Settings, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Legacy(V1Settings):
    token: str = Field(..., alias="LEGACY_TOKEN")
    class Config:
        env_prefix = "APP_"

class Current(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SERVICE_")
    endpoint: str
    region: str = "eu"
    credential: str = Field(validation_alias="SERVICE_CREDENTIAL")
"""
    result = analyze(source)
    keys = {item.name for item in facts(result, ConfigKey)}
    consumers = facts(result, Consumer)
    assert keys == {
        "LEGACY_TOKEN",
        "SERVICE_ENDPOINT",
        "SERVICE_REGION",
        "SERVICE_CREDENTIAL",
    }
    assert all(item.access_kind is ConsumerAccessKind.PYDANTIC_SETTINGS for item in consumers)
    assert all(item.phase is Phase.RUNTIME for item in consumers)
    assert {item.required for item in consumers} == {False, True}


def test_pydantic_custom_sources_are_reported_without_execution() -> None:
    result = analyze(
        """
from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    value: str
    @classmethod
    def settings_customise_sources(cls, *sources):
        raise RuntimeError("must never execute")
"""
    )
    assert DiagnosticCode.CUSTOM_SETTINGS_SOURCE in {item.code for item in result.diagnostics}
    assert result.completeness is AnalysisCompleteness.PARTIAL


def test_pydantic_settings_honor_ignore_and_required_overrides() -> None:
    source = "from pydantic_settings import BaseSettings\nclass Settings(BaseSettings):\n    value: str = 'x'\n"
    ignored = analyze(
        source,
        Resolver(
            EffectiveClassification(
                ignored=True,
            )
        ),
    )
    assert not ignored.observations
    required = analyze(
        source,
        Resolver(
            EffectiveClassification(
                required=True,
                required_source=DecisionSource.CONFIG_OVERRIDE,
            )
        ),
    )
    assert facts(required, Consumer)[0].required is True


def test_pydantic_helper_edge_cases_are_deterministic() -> None:
    module = ast.parse(
        "pass\nConfig = object()\nmodel_config = {'env_prefix': 'DICT_', 'other': 1}\n"
        "other = Factory(env_prefix='NOPE_')\nvalue = Other(alias='IGNORED')\n"
    )
    assert python_ast._literal_assignment(module.body[:2], "missing") is None
    dictionary = cast(ast.Assign, module.body[2]).value
    assert python_ast._settings_prefix(dictionary, set()) == "DICT_"
    assert python_ast._settings_prefix(ast.Dict(keys=[], values=[]), set()) is None
    wrong_config = cast(ast.Assign, module.body[3]).value
    assert python_ast._settings_prefix(wrong_config, {"SettingsConfigDict"}) is None
    wrong_field = cast(ast.Assign, module.body[4]).value
    assert python_ast._field_alias(wrong_field, {"Field"}) is None
    assert (
        python_ast._field_alias(
            ast.Call(func=ast.Name(id="Field"), args=[], keywords=[]), {"Field"}
        )
        is None
    )
    assert python_ast._field_alias(ast.Constant(value="plain"), {"Field"}) is None


def test_partial_analysis_on_ast_recursion(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_visit(self, node):  # type: ignore[no-untyped-def]
        del self, node
        raise RecursionError

    monkeypatch.setattr(python_ast._Visitor, "visit", fail_visit)
    result = analyze("pass")
    assert result.completeness is AnalysisCompleteness.PARTIAL
    assert result.diagnostics[0].code is DiagnosticCode.PARTIAL_ANALYSIS


def test_location_helpers_tolerate_missing_and_incomplete_positions() -> None:
    assert python_ast._location("a.py", ast.Module(body=[], type_ignores=[])).start_line is None
    missing = SyntaxError()
    assert python_ast._syntax_location("a.py", missing).start_line is None
    complete = SyntaxError()
    complete.lineno = 2
    complete.offset = 3
    complete.end_lineno = 2
    complete.end_offset = 4
    assert python_ast._syntax_location("a.py", complete).end_column == 4
