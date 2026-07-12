"""Public behavior tests for runtime-contract.yaml version 1."""

from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError
from typer.testing import CliRunner

from runtime_contract.cli import app
from runtime_contract.config import loader as config_loader
from runtime_contract.config.execution import resolve_execution
from runtime_contract.config.loader import ConfigValidationError, load_config, parse_strict_yaml
from runtime_contract.config.models import OutputFormat, Roots, Severity
from runtime_contract.config.policy import ConfigPolicy
from runtime_contract.config.schema import generate_schema_bytes, schema_bytes
from runtime_contract.discovery import DiscoveryError, DiscoveryErrorCode, discover
from runtime_contract.rules import RuleId

runner = CliRunner()
REPO = Path(__file__).parents[1]


def write_config(root: Path, text: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "runtime-contract.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def error_for(root: Path, text: str) -> ConfigValidationError:
    write_config(root, text)
    with pytest.raises(ConfigValidationError) as caught:
        load_config(root, require=True)
    return caught.value


def test_minimal_and_full_examples_validate_at_runtime_and_against_schema() -> None:
    schema = json.loads(generate_schema_bytes())
    validator = Draft202012Validator(schema)
    for name in ("minimal", "full"):
        document = load_config(REPO / "examples" / name, require=True)
        assert document is not None
        normalized = document.config.model_dump(mode="json", exclude_defaults=False)
        validator.validate(normalized)


@pytest.mark.parametrize("value", [None, '"1"', "1.0", "2", "true"])
def test_version_is_required_and_exact(tmp_path: Path, value: str | None) -> None:
    text = "roots: {}\n" if value is None else f"version: {value}\n"
    error = error_for(tmp_path, text)
    assert any(item.code == "invalid_version" for item in error.errors)


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\ntyop: true\n",
        "version: 1\nroots:\n  api:\n    path: .\n    typo: true\n",
        "version: 1\nenvironments:\n  prod:\n    roots: [default]\n    typo: true\n",
        "version: 1\nclassifications:\n  typo: true\n",
        "version: 1\nclassifications:\n  patterns:\n    - pattern: X*\n      typo: true\n",
        "version: 1\nexecution:\n  typo: true\n",
    ],
)
def test_unknown_fields_are_rejected_at_every_level(tmp_path: Path, text: str) -> None:
    assert any(item.code == "unknown_field" for item in error_for(tmp_path, text).errors)


@pytest.mark.parametrize(
    ("text", "code"),
    [
        ("version: 1\nversion: 1\n", "yaml_duplicate_key"),
        ("version: !!int 1\n", "yaml_tag"),
        ("base: &base {}\nversion: 1\n", "yaml_anchor"),
        ("version: 1\nvalue: *base\n", "yaml_alias"),
        ("version: 1\n<<: {}\n", "yaml_merge_key"),
        ("version: 1\n---\nversion: 1\n", "yaml_multiple_documents"),
    ],
)
def test_unsupported_yaml_features_are_rejected(text: str, code: str) -> None:
    with pytest.raises(ConfigValidationError) as caught:
        parse_strict_yaml(text)
    assert caught.value.errors[0].code == code


def test_syntax_error_is_single_diagnostic() -> None:
    with pytest.raises(ConfigValidationError) as caught:
        parse_strict_yaml("version: [1\n")
    assert len(caught.value.errors) == 1
    assert caught.value.errors[0].code == "yaml_syntax"


def test_explicit_two_document_markers_are_rejected() -> None:
    with pytest.raises(ConfigValidationError) as caught:
        parse_strict_yaml("---\nversion: 1\n---\nversion: 1\n")
    assert caught.value.errors[0].code == "yaml_multiple_documents"


def test_syntax_error_without_parser_mark_uses_origin() -> None:
    error = config_loader._syntax_error(ValueError("test"))
    assert (error.errors[0].line, error.errors[0].column) == (1, 1)


def test_string_and_expanded_roots_normalize_identically(tmp_path: Path) -> None:
    (tmp_path / "apps" / "api").mkdir(parents=True)
    write_config(tmp_path, "version: 1\nroots:\n  api: apps/api\n")
    short = load_config(tmp_path, require=True)
    write_config(tmp_path, "version: 1\nroots:\n  api:\n    path: apps/api\n")
    expanded = load_config(tmp_path, require=True)
    assert short is not None and expanded is not None
    assert short.config == expanded.config


def test_roots_reject_non_mapping_input() -> None:
    with pytest.raises(ValidationError):
        Roots.model_validate(["api"])


def test_missing_roots_creates_implicit_default(tmp_path: Path) -> None:
    write_config(tmp_path, "version: 1\n")
    document = load_config(tmp_path, require=True)
    assert document is not None
    assert document.config.effective_roots()["default"].path == "."


def test_missing_config_is_optional_or_a_stable_required_error(tmp_path: Path) -> None:
    assert load_config(tmp_path) is None
    with pytest.raises(ConfigValidationError) as caught:
        load_config(tmp_path, require=True)
    assert caught.value.errors[0].code == "config_missing"


def test_config_must_be_a_regular_file(tmp_path: Path) -> None:
    (tmp_path / "runtime-contract.yaml").mkdir()
    with pytest.raises(ConfigValidationError) as caught:
        load_config(tmp_path, require=True)
    assert caught.value.errors[0].code == "config_unsafe"


@pytest.mark.parametrize("path", ["/tmp", "../outside", "C:/outside"])
def test_unsafe_root_paths_are_rejected(tmp_path: Path, path: str) -> None:
    error = error_for(tmp_path, f"version: 1\nroots:\n  api: {path}\n")
    assert error.errors


def test_root_symlink_escape_and_canonical_alias_are_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
    assert (
        error_for(tmp_path, "version: 1\nroots:\n  api: escape\n").errors[0].code == "root_unsafe"
    )
    (tmp_path / "real").mkdir()
    (tmp_path / "alias").symlink_to(tmp_path / "real", target_is_directory=True)
    error = error_for(tmp_path, "version: 1\nroots:\n  a: real\n  b: alias\n")
    assert any(item.code == "root_alias" for item in error.errors)


def test_inaccessible_root_is_reported(tmp_path: Path) -> None:
    error = error_for(tmp_path, "version: 1\nroots:\n  missing: not-created\n")
    assert error.errors[0].code == "root_inaccessible"


def test_named_root_discovery_applies_global_then_root_filters(tmp_path: Path) -> None:
    for path in ("apps/api/src/keep.py", "apps/api/src/drop.py", "apps/api/tests/no.py"):
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("", encoding="utf-8")
    write_config(
        tmp_path,
        """version: 1
include: ["apps/**/*.py"]
exclude: ["**/drop.py"]
roots:
  api:
    path: apps/api
    include: ["src/**"]
    exclude: ["tests/**"]
""",
    )
    assert [item.path for item in discover(tmp_path).candidates] == ["apps/api/src/keep.py"]


def test_named_root_cannot_restore_hard_boundaries(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / ".env").write_text("SECRET=value", encoding="utf-8")
    (tmp_path / "app" / ".git").mkdir()
    (tmp_path / "app" / ".git" / "config.py").write_text("", encoding="utf-8")
    write_config(tmp_path, 'version: 1\nroots:\n  app:\n    path: app\n    include: ["**"]\n')
    with pytest.raises(DiscoveryError) as caught:
        discover(tmp_path)
    assert caught.value.code is DiscoveryErrorCode.ALL_INCLUDED_REJECTED


def test_global_and_root_includes_are_an_intersection(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "global.py").write_text("", encoding="utf-8")
    (tmp_path / "app" / "root.py").write_text("", encoding="utf-8")
    write_config(
        tmp_path,
        """version: 1
include: ["app/global.py"]
roots:
  app:
    path: app
    include: ["root.py"]
""",
    )
    assert discover(tmp_path).candidates == ()


def test_environment_references_and_sources_are_validated(tmp_path: Path) -> None:
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "compose.yaml").write_text("services: {}", encoding="utf-8")
    valid = """version: 1
roots: {api: api}
environments:
  production:
    roots: [api]
    sources:
      - {root: api, type: compose, path: compose.yaml, provides: [DATABASE_URL]}
"""
    write_config(tmp_path, valid)
    assert load_config(tmp_path, require=True) is not None
    assert error_for(tmp_path, valid.replace("roots: [api]", "roots: [missing]")).errors
    assert error_for(tmp_path, valid.replace("root: api, type", "root: missing, type")).errors


def test_sources_must_exist_be_files_and_support_auto(tmp_path: Path) -> None:
    (tmp_path / "api").mkdir()
    template = """version: 1
roots: {api: api}
environments:
  production:
    roots: [api]
    sources:
      - {root: api, type: %s, path: %s}
"""
    missing = error_for(tmp_path, template % ("compose", "missing.yaml"))
    assert missing.errors[0].code == "source_inaccessible"
    (tmp_path / "api" / "directory.yaml").mkdir()
    unsafe = error_for(tmp_path, template % ("compose", "directory.yaml"))
    assert unsafe.errors[0].code == "source_unsafe"
    (tmp_path / "api" / "unsupported.txt").write_text("", encoding="utf-8")
    unsupported = error_for(tmp_path, template % ("auto", "unsupported.txt"))
    assert unsupported.errors[0].code == "source_type"
    wrong_compose = error_for(tmp_path, template % ("compose", "unsupported.txt"))
    assert wrong_compose.errors[0].code == "source_type"
    (tmp_path / "api" / "manifest.json").write_text("{}", encoding="utf-8")
    write_config(tmp_path, template % ("kubernetes", "manifest.json"))
    assert load_config(tmp_path, require=True) is not None


def test_named_yaml_can_be_explicitly_classified_as_compose(tmp_path: Path) -> None:
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "deployment.yml").write_text("services: {}\n", encoding="utf-8")
    write_config(
        tmp_path,
        """version: 1
roots: {api: api}
environments:
  prod:
    roots: [api]
    sources:
      - {root: api, type: compose, path: deployment.yml}
""",
    )
    result = discover(tmp_path)
    assert [(item.path, item.kind.value) for item in result.candidates] == [
        ("api/deployment.yml", "compose")
    ]


@pytest.mark.parametrize(
    "provides",
    ["{DATABASE_URL: value}", "[DATABASE_URL, DATABASE_URL]", "[NOT-VALID]"],
)
def test_provides_accepts_names_only_without_duplicates(tmp_path: Path, provides: str) -> None:
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "compose.yaml").write_text("services: {}", encoding="utf-8")
    error = error_for(
        tmp_path,
        f"""version: 1
roots: {{api: api}}
environments:
  production:
    roots: [api]
    sources:
      - {{root: api, type: compose, path: compose.yaml, provides: {provides}}}
""",
    )
    assert error.errors


def test_ordered_classification_exact_precedence_and_scope(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        """version: 1
environments:
  development: {roots: [default]}
classifications:
  variables:
    OPTIONAL_DB_CREDENTIAL:
      - {secret: false, environments: [development]}
      - {required: true, roots: [default], environments: [development]}
  patterns:
    - {pattern: "*_CREDENTIAL", secret: true, required: true}
    - {pattern: "OPTIONAL_*_CREDENTIAL", required: false}
""",
    )
    document = load_config(tmp_path, require=True)
    assert document is not None
    policy = ConfigPolicy(document)
    pattern = policy.classify("optional_DB_CREDENTIAL", root="default", environment="development")
    assert pattern.secret is True and pattern.required is True
    result = policy.classify("OPTIONAL_DB_CREDENTIAL", root="default", environment="development")
    assert result.secret is False and result.required is True
    assert [item.scope for item in result.applied] == ["pattern", "pattern", "exact", "exact"]


def test_explicit_classification_glob_regex_scope_and_audit(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        """version: 1
environments:
  prod: {roots: [default]}
classifications:
  variables:
    FALSE_POSITIVE: {classification: public, reason: documented exception}
    INTERNAL_HANDLE: {classification: sensitive}
    UNUSED_KEY: {classification: ignore, reason: generated upstream}
  patterns:
    - {pattern: "INTERNAL_*", classification: ignore, reason: broad generated family}
    - {pattern: "*_TOKEN", classification: sensitive, environments: [prod]}
    - {regex: "^PUBLIC_[A-Z0-9_]+$", classification: public, reason: public contract}
""",
    )
    document = load_config(tmp_path, require=True)
    assert document is not None
    policy = ConfigPolicy(document)
    assert policy.classify("CUSTOM_TOKEN", environment="prod").secret is True
    public = policy.classify("PUBLIC_ENDPOINT")
    assert public.secret is False and public.reason == "public contract"
    false_positive = policy.classify("FALSE_POSITIVE")
    assert false_positive.secret is False and false_positive.reason == "documented exception"
    internal = policy.classify("INTERNAL_HANDLE")
    assert internal.secret is True and internal.ignored is False
    ignored = policy.classify("UNUSED_KEY")
    assert ignored.ignored is True and ignored.secret is None
    unused = ConfigPolicy(document).unused_classification_rules(
        (
            ("CUSTOM_TOKEN", "default", "prod"),
            ("PUBLIC_ENDPOINT", "default", None),
            ("FALSE_POSITIVE", "default", None),
            ("INTERNAL_HANDLE", "default", None),
        )
    )
    assert [item.pointer for item in unused] == ["/classifications/variables/UNUSED_KEY"]


@pytest.mark.parametrize(
    "rule",
    [
        "{classification: public}",
        "{classification: ignore}",
        "{classification: sensitive, secret: false}",
        "{classification: public, secret: true, reason: conflict}",
        "{classification: ignore, required: false, reason: conflict}",
        "{classification: ignore, allow_literal: false, reason: conflict}",
    ],
)
def test_explicit_exact_classification_conflicts_and_reasons_fail_closed(
    tmp_path: Path, rule: str
) -> None:
    assert error_for(
        tmp_path, f"version: 1\nclassifications:\n  variables:\n    KEY: {rule}\n"
    ).errors


@pytest.mark.parametrize(
    "rule",
    [
        "{pattern: X, regex: X, classification: sensitive}",
        "{classification: sensitive}",
        "{regex: '(?=X)X', classification: sensitive}",
        "{regex: '^(X+)+$', classification: sensitive}",
        "{regex: 'X++', classification: sensitive}",
        "{regex: '^X$', classification: public}",
        "{pattern: X, classification: sensitive}\n    - {pattern: X, classification: public, reason: conflict}",
    ],
)
def test_pattern_selector_and_regex_safety_fail_closed(tmp_path: Path, rule: str) -> None:
    assert error_for(tmp_path, f"version: 1\nclassifications:\n  patterns:\n    - {rule}\n").errors


def test_explicit_null_regex_is_accepted_and_unused_rule_lists_are_precise(
    tmp_path: Path,
) -> None:
    write_config(
        tmp_path,
        """version: 1
environments:
  prod: {roots: [default]}
  dev: {roots: [default]}
classifications:
  variables:
    SCOPED:
      - {classification: sensitive, environments: [prod]}
      - {classification: public, reason: development fixture, environments: [dev]}
  patterns:
    - {pattern: "GLOB_*", regex: null, classification: sensitive}
""",
    )
    document = load_config(tmp_path, require=True)
    assert document is not None
    unused = ConfigPolicy(document).unused_classification_rules(
        (("SCOPED", "default", "prod"), ("GLOB_KEY", "default", None))
    )
    assert [item.pointer for item in unused] == ["/classifications/variables/SCOPED/1"]


@pytest.mark.parametrize(
    "body",
    [
        "variables:\n    X: []",
        "variables:\n    X: {allow_literal: true}",
        "patterns:\n    - {pattern: X, allow_literal: true}",
        "patterns:\n    - {pattern: '', secret: true}",
    ],
)
def test_invalid_classification_rules(tmp_path: Path, body: str) -> None:
    assert error_for(tmp_path, f"version: 1\nclassifications:\n  {body}\n").errors


def test_blank_whitespace_suppression_reason_is_rejected(tmp_path: Path) -> None:
    error = error_for(
        tmp_path,
        "version: 1\nsuppressions:\n  - {id: one, rule: RTC001, reason: ' ', variable: X}\n",
    )
    assert error.errors


@pytest.mark.parametrize(
    "text",
    [
        "version: 1\nroots: {default: elsewhere}\n",
        "version: 1\nroots: {api: .}\nenvironments:\n  prod: {roots: [api, api]}\n",
        "version: 1\nclassifications:\n  patterns:\n    - {pattern: X, roots: [default, default]}\n",
        "version: 1\nclassifications:\n  patterns:\n    - {pattern: X, roots: [missing]}\n",
        "version: 1\nclassifications:\n  patterns:\n    - {pattern: X, environments: [missing]}\n",
        "version: 1\nexecution: {environment: missing}\n",
        "version: 1\nclassifications:\n  variables:\n    X:\n      - {secret: true}\n      - {required: true}\n",
    ],
)
def test_cross_section_and_duplicate_selector_errors(tmp_path: Path, text: str) -> None:
    assert error_for(tmp_path, text).errors


def test_rule_registry_drives_override_and_schema_enum(tmp_path: Path) -> None:
    error = error_for(
        tmp_path,
        "version: 1\nseverity_overrides:\n  - {rule: UNKNOWN, severity: error}\n",
    )
    assert error.errors
    schema_text = generate_schema_bytes().decode()
    for rule in RuleId:
        assert f'"{rule.value}"' in schema_text


def test_severity_override_is_last_matching_and_has_location(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        """version: 1
severity_overrides:
  - {rule: RTC001, severity: warning}
  - {rule: RTC001, severity: info}
""",
    )
    document = load_config(tmp_path, require=True)
    assert document is not None
    severity, applied = ConfigPolicy(document).severity(RuleId.RTC001, Severity.ERROR)
    assert severity is Severity.INFO
    assert applied is not None and applied.pointer == "/severity_overrides/1"


def test_scoped_exact_and_severity_rules_can_be_non_matching(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        """version: 1
environments:
  prod: {roots: [default]}
classifications:
  variables:
    TOKEN: {secret: true, environments: [prod]}
severity_overrides:
  - {rule: RTC002, severity: warning}
  - {rule: RTC001, severity: info, environments: [prod]}
""",
    )
    document = load_config(tmp_path, require=True)
    assert document is not None
    policy = ConfigPolicy(document)
    assert policy.classify("TOKEN", environment=None).secret is None
    severity, applied = policy.severity(RuleId.RTC001, Severity.ERROR, environment=None)
    assert severity is Severity.ERROR and applied is None


def test_suppressions_require_scope_unique_ids_and_reason(tmp_path: Path) -> None:
    for suppression in (
        "{id: one, rule: RTC001, reason: why}",
        "{id: one, rule: RTC001, reason: '', variable: X}",
    ):
        assert error_for(tmp_path, f"version: 1\nsuppressions:\n  - {suppression}\n").errors
    duplicate = """version: 1
suppressions:
  - {id: one, rule: RTC001, reason: why, variable: X}
  - {id: one, rule: RTC002, reason: why, variable: Y}
"""
    assert error_for(tmp_path, duplicate).errors


def test_suppression_matching_checks_every_selector(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        """version: 1
environments:
  prod: {roots: [default]}
suppressions:
  - {id: other-rule, rule: RTC002, reason: why, variable: TOKEN}
  - {id: other-variable, rule: RTC001, reason: why, variable: OTHER}
  - {id: other-path, rule: RTC001, reason: why, path: "src/**"}
  - {id: other-scope, rule: RTC001, reason: why, roots: [default], environments: [prod]}
  - {id: match, rule: RTC001, reason: why, path: "deploy/**"}
""",
    )
    document = load_config(tmp_path, require=True)
    assert document is not None
    policy = ConfigPolicy(document)
    result = policy.suppression(
        RuleId.RTC001,
        variable="TOKEN",
        path="deploy/app.yaml",
        root="different",
        environment=None,
        on_date=date(2026, 7, 10),
    )
    assert result.id == "match" and result.suppressed is True
    none = policy.suppression(RuleId.RTC012, on_date=date(2026, 7, 10))
    assert none.suppressed is False and none.id is None


def test_expired_suppression_does_not_hide_finding(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        """version: 1
suppressions:
  - {id: old, rule: RTC001, reason: temporary, variable: TOKEN, expires: 2026-01-01}
""",
    )
    document = load_config(tmp_path, require=True)
    assert document is not None
    result = ConfigPolicy(document).suppression(
        RuleId.RTC001, variable="TOKEN", on_date=date(2026, 7, 10)
    )
    assert result.expired is True and result.suppressed is False
    warnings = ConfigPolicy(document).expired_suppression_warnings(on_date=date(2026, 7, 10))
    assert warnings[0].id == "old" and warnings[0].severity == "warning"


def test_execution_defaults_and_precedence(tmp_path: Path) -> None:
    write_config(tmp_path, "version: 1\nexecution: {format: json, fail_on: warning}\n")
    document = load_config(tmp_path, require=True)
    assert document is not None
    result = resolve_execution(
        document.config,
        output_format="text",
        environ={"RUNTIME_CONTRACT_FORMAT": "sarif", "UNRELATED": "ignored"},
    )
    assert result.value.format is OutputFormat.TEXT
    assert result.sources["format"] == "CLI argument"
    assert result.value.fail_on.value == "warning"
    assert result.sources["report"] == "default"


def test_execution_rejects_invalid_value_and_unknown_environment(tmp_path: Path) -> None:
    write_config(tmp_path, "version: 1\nenvironments:\n  prod: {roots: [default]}\n")
    document = load_config(tmp_path, require=True)
    assert document is not None
    with pytest.raises(ValueError, match="invalid execution"):
        resolve_execution(document.config, environ={"RUNTIME_CONTRACT_FORMAT": "xml"})
    with pytest.raises(ValueError, match="unknown environment"):
        resolve_execution(document.config, environment="missing", environ={})


def test_errors_have_stable_location_pointer_and_sorting(tmp_path: Path) -> None:
    error = error_for(tmp_path, "version: 1\nzeta: true\nalpha: true\n")
    assert [item.pointer for item in error.errors] == ["/alpha", "/zeta"]
    assert all(item.line > 0 and item.column > 0 and item.code for item in error.errors)


def test_config_validate_cli_exit_codes_json_and_sarif(tmp_path: Path) -> None:
    write_config(tmp_path, "version: 1\n")
    valid = runner.invoke(app, ["config", "validate", str(tmp_path), "--format", "json"])
    assert valid.exit_code == 0
    assert json.loads(valid.stdout)["valid"] is True
    write_config(tmp_path, "version: '1'\n")
    invalid = runner.invoke(app, ["config", "validate", str(tmp_path), "--format", "json"])
    assert invalid.exit_code == 2
    assert json.loads(invalid.stderr)["valid"] is False
    sarif = runner.invoke(app, ["config", "validate", str(tmp_path), "--format", "sarif"])
    assert sarif.exit_code == 2 and "SARIF" in sarif.stderr


def test_config_validate_cli_text_env_sarif_and_invalid_formats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_config(tmp_path, "version: 1\n")
    text = runner.invoke(app, ["config", "validate", str(tmp_path)])
    assert text.exit_code == 0 and "Configuration valid" in text.stdout
    invalid = runner.invoke(app, ["config", "validate", str(tmp_path), "--format", "xml"])
    assert invalid.exit_code == 2 and "text or json" in invalid.stderr
    monkeypatch.setenv("RUNTIME_CONTRACT_FORMAT", "sarif")
    env_sarif = runner.invoke(app, ["config", "validate", str(tmp_path)])
    assert env_sarif.exit_code == 2 and "SARIF" in env_sarif.stderr
    monkeypatch.setenv("RUNTIME_CONTRACT_FORMAT", "xml")
    env_invalid = runner.invoke(app, ["config", "validate", str(tmp_path)])
    assert env_invalid.exit_code == 2 and "invalid execution" in env_invalid.stderr


def test_every_analysis_command_validates_configuration_first(tmp_path: Path) -> None:
    write_config(tmp_path, "version: '1'\n")
    for arguments in (
        ["scan", str(tmp_path)],
        ["check", str(tmp_path)],
        ["explain", "RTC001", str(tmp_path)],
    ):
        result = runner.invoke(app, arguments)
        assert result.exit_code == 2
        assert "invalid_version" in result.stderr
    diff = runner.invoke(app, ["diff", str(tmp_path), str(tmp_path)])
    assert diff.exit_code == 2 and "invalid_version" in diff.stderr


def test_check_execution_overrides_reject_unknown_values(tmp_path: Path) -> None:
    write_config(tmp_path, "version: 1\nenvironments:\n  prod: {roots: [default]}\n")
    unknown = runner.invoke(app, ["check", str(tmp_path), "--environment", "missing"])
    assert unknown.exit_code == 2 and "unknown environment" in unknown.stderr
    bad_format = runner.invoke(app, ["scan", str(tmp_path), "--format", "xml"])
    assert bad_format.exit_code == 2 and "invalid execution" in bad_format.stderr


def test_schema_generation_is_deterministic_and_bundled_resource_matches() -> None:
    tracked = (REPO / "schemas" / "runtime-contract.schema.json").read_bytes()
    assert generate_schema_bytes() == tracked == schema_bytes()
    schema = json.loads(tracked)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"].startswith("https://")
    Draft202012Validator.check_schema(schema)


def test_config_explain_reports_order_scope_and_yaml_location(tmp_path: Path) -> None:
    shutil.copytree(REPO / "examples" / "full", tmp_path, dirs_exist_ok=True)
    result = runner.invoke(
        app,
        [
            "config",
            "explain",
            "LOCAL_TEST_TOKEN",
            "--path",
            str(tmp_path),
            "--root",
            "test_app",
            "--environment",
            "development",
        ],
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["allow_literal"] is True
    assert payload["applied"][-1]["line"] > 0


def test_config_explain_rejects_invalid_config_root_and_environment(tmp_path: Path) -> None:
    write_config(tmp_path, "version: '1'\n")
    invalid = runner.invoke(app, ["config", "explain", "X", "--path", str(tmp_path)])
    assert invalid.exit_code == 2 and "invalid_version" in invalid.stderr
    write_config(tmp_path, "version: 1\n")
    root = runner.invoke(
        app, ["config", "explain", "X", "--path", str(tmp_path), "--root", "missing"]
    )
    assert root.exit_code == 2 and "unknown root" in root.stderr
    environment = runner.invoke(
        app,
        ["config", "explain", "X", "--path", str(tmp_path), "--environment", "missing"],
    )
    assert environment.exit_code == 2 and "unknown environment" in environment.stderr


def test_discovery_environment_selects_profile_roots_and_rejects_unknown(tmp_path: Path) -> None:
    for name in ("api", "worker"):
        (tmp_path / name).mkdir()
        (tmp_path / name / f"{name}.py").write_text("", encoding="utf-8")
    write_config(
        tmp_path,
        """version: 1
roots: {api: api, worker: worker}
environments:
  prod: {roots: [api]}
""",
    )
    assert [item.path for item in discover(tmp_path, environment="prod").candidates] == [
        "api/api.py"
    ]
    with pytest.raises(DiscoveryError, match="unknown environment"):
        discover(tmp_path, environment="missing")
