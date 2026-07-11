"""End-to-end D1.12 scan flow tests."""

import importlib.metadata
import json
import os
import re
from pathlib import Path
from typing import cast

import jsonschema
import pytest
from typer.testing import CliRunner

from runtime_contract.analysis import AnalyzerExecutionError, AnalyzerRegistry
from runtime_contract.analysis.dotenv import MAX_DOTENV_BYTES
from runtime_contract.cli import app
from runtime_contract.config.loader import ConfigDocument
from runtime_contract.config.loader import load_config as actual_load_config
from runtime_contract.discovery import (
    CandidateKind,
    DiscoveryError,
    DiscoveryErrorCode,
    DiscoveryItem,
    discover,
)
from runtime_contract.normalization import NormalizationError, NormalizationErrorCode
from runtime_contract.scan import ScanRequest
from runtime_contract.scan import engine as scan_engine
from runtime_contract.scan.schema import generate_schema_bytes

runner = CliRunner()


def write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    write(
        tmp_path / "runtime-contract.yaml",
        """version: 1
roots:
  api: apps/api
  web: apps/web
classifications:
  variables:
    DATABASE_URL:
      secret: true
      required: true
""",
    )
    write(
        tmp_path / "apps/api/settings.py",
        'import os\na = os.getenv("DATABASE_URL")\nb = os.environ["DATABASE_URL"]\n',
    )
    write(tmp_path / "apps/web/config.ts", "const value = process.env.API_URL;\n")
    write(tmp_path / "Dockerfile", "FROM scratch\n")
    return tmp_path


def test_scan_help_exposes_d1_12_options() -> None:
    result = runner.invoke(app, ["scan", "--help"], terminal_width=200, color=False)
    assert result.exit_code == 0
    help_text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", result.stdout)
    for option in (
        "--config",
        "--root",
        "--include",
        "--exclude",
        "--format",
        "--output",
        "--fail-on",
        "--quiet",
        "--verbose",
    ):
        assert option in help_text
    assert "--report" not in help_text


@pytest.mark.parametrize(
    "arguments",
    [
        ["--quiet", "-v"],
        ["-vvv"],
        ["--output", "a", "--report", "b"],
    ],
)
def test_invalid_cli_combinations_exit_two(project: Path, arguments: list[str]) -> None:
    result = runner.invoke(app, ["scan", str(project), *arguments])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Error:" in result.stderr


def test_happy_path_json_is_normalized_schema_valid_and_deterministic(project: Path) -> None:
    arguments = ["scan", str(project), "--format", "json"]
    first = runner.invoke(app, arguments)
    second = runner.invoke(app, arguments)
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    payload = json.loads(first.stdout)
    schema = json.loads(Path("schemas/runtime-contract-scan-result-v1.schema.json").read_text())
    jsonschema.validate(payload, schema)
    assert payload["status"] == "complete"
    assert payload["inputs"]["selected_roots"] == ["api", "web"]
    assert payload["summary"]["consumers"] == 3
    assert payload["summary"]["config_keys"] == 2
    assert payload["summary"]["providers"] == 0
    assert {item["component"] for item in payload["contract"]["consumers"]} == {"api", "web"}
    assert "/home/" not in first.stdout


def test_root_selection_deduplicates_and_unknown_lists_available(project: Path) -> None:
    selected = runner.invoke(
        app, ["scan", str(project), "--root", "api", "--root", "api", "--format", "json"]
    )
    assert selected.exit_code == 0
    payload = json.loads(selected.stdout)
    assert payload["inputs"]["selected_roots"] == ["api"]
    assert {item["component"] for item in payload["contract"]["consumers"]} == {"api"}
    unknown = runner.invoke(app, ["scan", str(project), "--root", "missing"])
    assert unknown.exit_code == 2
    assert "available roots: api, web" in unknown.stderr


def test_partial_preserves_observations_and_exits_zero(tmp_path: Path) -> None:
    write(tmp_path / "app.py", 'import os\nos.getenv("KNOWN")\nos.getenv(name)\n')
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "partial"
    assert payload["summary"]["consumers"] == 1
    assert payload["summary"]["partial_files"] == 1


@pytest.mark.parametrize("name", ["app.py", "app.js"])
def test_invalid_encoding_is_failed_exit_two_with_safe_json(tmp_path: Path, name: str) -> None:
    write(tmp_path / name, b"\xff\xfeSECRET_VALUE")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "failed"
    assert "SECRET_VALUE" not in result.stdout + result.stderr
    assert str(tmp_path) not in result.stdout + result.stderr


def test_only_unsupported_candidates_are_skipped_without_diagnostic(tmp_path: Path) -> None:
    write(tmp_path / "Dockerfile", "FROM scratch\n")
    write(tmp_path / "compose.yaml", "services: {}\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "complete"
    assert payload["summary"]["skipped"] == 2
    assert payload["diagnostics"] == []


def test_dotenv_example_is_analyzed_and_forbidden_env_files_are_never_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sentinel = "forbidden-fixture-secret-Q7Z9"
    write(tmp_path / ".env.example", "PUBLIC_KEY=example\nINCLUDE=.env\n")
    for name in (".env", ".env.local", ".env.production", ".env.development", ".env.test"):
        write(tmp_path / name, f"SECRET={sentinel}\n")
    original = Path.read_bytes
    opened: list[str] = []

    def guarded_read(path: Path) -> bytes:
        opened.append(path.name)
        if path.name != ".env.example" and path.name.startswith(".env"):
            raise AssertionError("a forbidden dotenv file was opened")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["providers"] == 2
    assert payload["summary"]["candidate_kinds"] == {"env_example": 1}
    assert opened == [".env.example"]
    assert sentinel not in result.stdout + result.stderr


def test_outside_root_dotenv_example_symlink_is_rejected_without_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / ".env.example"
    write(outside, "SECRET=outside-sentinel-X8\n")
    (root / ".env.example").symlink_to(outside)

    def forbidden_read(path: Path) -> bytes:
        raise AssertionError(f"unexpected read: {path.name}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read)
    result = runner.invoke(app, ["scan", str(root), "--format", "json"])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "outside-sentinel-X8" not in result.stderr


def test_oversized_dotenv_example_is_rejected_before_content_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / ".env.example"
    target.write_bytes(b"X" * (MAX_DOTENV_BYTES + 1))

    def forbidden_read(path: Path) -> bytes:
        raise AssertionError(f"oversized candidate was read: {path.name}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read)
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["diagnostics"][0]["code"] == "safety_limit"
    assert payload["diagnostics"][0]["parameters"] == [["limit_kind", "file_size"]]


def test_dotenv_metadata_read_failure_is_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path / ".env.example", "KEY=value\n")

    class FailedMetadata:
        def stat(self) -> os.stat_result:
            raise OSError

    def failed_metadata(item: DiscoveryItem, root: Path) -> Path:
        del item, root
        return cast(Path, FailedMetadata())

    monkeypatch.setattr(DiscoveryItem, "revalidate", failed_metadata)
    run = scan_engine.run_scan(ScanRequest(path=tmp_path, output_format="json"))
    assert run.exit_code == 2
    assert run.result.diagnostics[0].code.value == "read_error"


def test_atomic_output_leaves_stdout_empty_and_matches_stdout(
    project: Path, tmp_path: Path
) -> None:
    expected = runner.invoke(app, ["scan", str(project), "--format", "json"])
    target = tmp_path / "scan.json"
    written = runner.invoke(
        app, ["scan", str(project), "--format", "json", "--output", str(target)]
    )
    assert written.exit_code == 0
    assert written.stdout == ""
    assert target.read_text(encoding="utf-8") == expected.stdout
    assert target.read_bytes().endswith(b"\n")


def test_json_and_sarif_ignore_verbosity(project: Path) -> None:
    for output_format in ("json", "sarif"):
        plain = runner.invoke(app, ["scan", str(project), "--format", output_format])
        verbose = runner.invoke(app, ["scan", str(project), "--format", output_format, "-vv"])
        assert plain.exit_code == verbose.exit_code == 0
        assert plain.stdout == verbose.stdout
        assert json.loads(plain.stdout)


def test_missing_default_config_is_allowed_but_explicit_missing_is_error(tmp_path: Path) -> None:
    allowed = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert allowed.exit_code == 0
    missing = runner.invoke(app, ["scan", str(tmp_path), "--config", "missing.yaml"])
    assert missing.exit_code == 2
    assert "config_missing" in missing.stderr


def test_explicit_config_and_escape_rules(tmp_path: Path) -> None:
    write(tmp_path / "configs/custom.yaml", "version: 1\n")
    write(tmp_path / "app.py", 'import os\nos.getenv("KEY")\n')
    valid = runner.invoke(
        app,
        ["scan", str(tmp_path), "--config", "configs/custom.yaml", "--format", "json"],
    )
    assert valid.exit_code == 0
    assert json.loads(valid.stdout)["inputs"]["config"] == "configs/custom.yaml"
    escaped = runner.invoke(app, ["scan", str(tmp_path), "--config", "../outside.yaml"])
    assert escaped.exit_code == 2
    assert "relative to the project root" in escaped.stderr
    outside = tmp_path.parent / "outside.yaml"
    write(outside, "version: 1\n")
    (tmp_path / "linked.yaml").symlink_to(outside)
    linked = runner.invoke(app, ["scan", str(tmp_path), "--config", "linked.yaml"])
    assert linked.exit_code == 2
    assert "config_unsafe" in linked.stderr


def test_cli_include_and_exclude_replace_global_filters(tmp_path: Path) -> None:
    write(
        tmp_path / "runtime-contract.yaml",
        'version: 1\ninclude: ["src/**/*.py"]\nexclude: ["**/ignored.py"]\n',
    )
    write(tmp_path / "src/main.py", 'import os\nos.getenv("SRC")\n')
    write(tmp_path / "web/main.ts", "const value = process.env.WEB;\n")
    write(tmp_path / "web/ignored.ts", "const value = process.env.IGNORED;\n")
    default = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert default.exit_code == 0
    assert json.loads(default.stdout)["summary"]["consumers"] == 1
    overridden = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--include",
            "web/**/*.ts",
            "--exclude",
            "**/ignored.ts",
            "--format",
            "json",
        ],
    )
    assert overridden.exit_code == 0
    payload = json.loads(overridden.stdout)
    assert [key["name"] for key in payload["contract"]["config_keys"]] == ["WEB"]


def test_output_errors_are_redacted_and_do_not_create_target(project: Path, tmp_path: Path) -> None:
    target = tmp_path / "missing" / "scan.json"
    result = runner.invoke(app, ["scan", str(project), "--format", "json", "--output", str(target)])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr == "Error: could not write report.\n"
    assert not target.exists()


def test_text_modes_cover_empty_partial_failed_and_quiet(tmp_path: Path) -> None:
    empty = runner.invoke(app, ["scan", str(tmp_path)])
    assert empty.exit_code == 0
    assert "No supported consumers found." in empty.stdout
    quiet = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
    assert quiet.stdout == "Result: complete — 0 consumers, 0 config keys\n"
    write(tmp_path / "partial.py", 'import os\nos.getenv("KNOWN")\nos.getenv(name)\n')
    partial = runner.invoke(app, ["scan", str(tmp_path)])
    assert partial.exit_code == 0
    assert "DYNAMIC_NAME" in partial.stdout
    assert "partial coverage" in partial.stdout
    write(tmp_path / "failed.py", b"\xff")
    failed = runner.invoke(app, ["scan", str(tmp_path)])
    assert failed.exit_code == 2
    assert "INVALID_ENCODING" in failed.stdout
    assert "reliable complete result" in failed.stdout


def test_text_verbose_levels_add_file_and_effective_scope_details(project: Path) -> None:
    write(project / "apps/api/Dockerfile", "FROM scratch\n")
    default = runner.invoke(app, ["scan", str(project)])
    one = runner.invoke(app, ["scan", str(project), "-v"])
    two = runner.invoke(app, ["scan", str(project), "-vv"])
    assert default.exit_code == one.exit_code == two.exit_code == 0
    assert "\nFiles\n" not in default.stdout
    assert "\nFiles\n" in one.stdout
    assert "complete  python  apps/api/settings.py" in one.stdout
    assert "Effective scope" not in one.stdout
    assert "Effective scope" in two.stdout
    assert "Named roots: api, web" in two.stdout
    assert "no_registered_analyzer=1" in two.stdout
    assert default.stdout != one.stdout != two.stdout


def test_sarif_diagnostic_region_and_metadata_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path / "app.py", "import os\nos.getenv(name)\n")
    normal = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
    payload = json.loads(normal.stdout)
    sarif_schema = json.loads(
        Path("tests/fixtures/sarif/sarif-schema-2.1.0.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft4Validator(sarif_schema).validate(payload)
    physical = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["region"] == {"startColumn": 1, "startLine": 2}
    assert payload["runs"][0]["tool"]["driver"]["semanticVersion"] == "0.1.0-dev.0"

    def missing(_: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr("runtime_contract.scan.renderers.importlib.metadata.version", missing)
    fallback = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
    assert json.loads(fallback.stdout)["runs"][0]["tool"]["driver"]["semanticVersion"] == (
        "0.0.0-unknown"
    )


def test_environment_selects_roots_and_profile(project: Path) -> None:
    config = project / "runtime-contract.yaml"
    config.write_text(
        config.read_text(encoding="utf-8") + "environments:\n  prod:\n    roots: [api]\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", str(project), "--environment", "prod", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["inputs"]["environment"] == "prod"
    assert payload["inputs"]["selected_roots"] == ["api"]

    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "  prod:\n    roots: [api]\n", "  custom:\n    roots: [api]\n"
        ),
        encoding="utf-8",
    )
    custom = runner.invoke(
        app, ["scan", str(project), "--environment", "custom", "--format", "json"]
    )
    assert custom.exit_code == 0
    assert json.loads(custom.stdout)["inputs"]["environment"] == "custom"


def test_project_path_and_read_errors_are_safely_mapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = runner.invoke(app, ["scan", str(tmp_path / "missing")])
    assert missing.exit_code == 2
    assert str(tmp_path) not in missing.stderr
    file_root = tmp_path / "file"
    write(file_root, "x")
    not_directory = runner.invoke(app, ["scan", str(file_root)])
    assert not_directory.exit_code == 2
    write(tmp_path / "app.py", "import os\n")
    original = Path.read_bytes

    def fail_read(path: Path) -> bytes:
        if path.name == "app.py":
            raise OSError
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", fail_read)
    unreadable = runner.invoke(app, ["scan", str(tmp_path)])
    assert unreadable.exit_code == 2
    assert unreadable.stderr == ""
    assert "READ_ERROR" in unreadable.stdout


def test_atomic_replace_failure_preserves_target_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "scan.json"
    target.write_text("old", encoding="utf-8")

    def fail_replace(source: str, destination: Path) -> None:
        raise OSError

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError):
        scan_engine.write_atomic(tmp_path, Path("scan.json"), "new\n")
    assert target.read_text(encoding="utf-8") == "old"
    assert list(tmp_path.iterdir()) == [target]


def test_scan_schema_generator_matches_committed_artifact() -> None:
    assert (
        generate_schema_bytes()
        == Path("schemas/runtime-contract-scan-result-v1.schema.json").read_bytes()
    )


def test_discovery_override_validation_branches(project: Path, tmp_path: Path) -> None:
    with pytest.raises(DiscoveryError, match="available roots"):
        discover(project, selected_roots=("missing",))
    with pytest.raises(DiscoveryError, match="not found"):
        discover(tmp_path, config_path=Path("missing.yaml"))


def test_yaml_report_maps_to_atomic_output(tmp_path: Path) -> None:
    write(
        tmp_path / "runtime-contract.yaml",
        "version: 1\nexecution:\n  format: json\n  report: reports/scan.json\n",
    )
    write(tmp_path / "app.py", 'import os\nos.getenv("KEY")\n')
    (tmp_path / "reports").mkdir()
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert result.stdout == ""
    assert json.loads((tmp_path / "reports/scan.json").read_text())["status"] == "complete"


def test_engine_failures_return_failed_reports_and_continue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path / "a.py", 'import os\nos.getenv("A")\n')
    write(tmp_path / "b.py", 'import os\nos.getenv("B")\n')
    original_revalidate = DiscoveryItem.revalidate

    def mutate_one(item: DiscoveryItem, root: Path) -> Path:
        if item.path == "a.py":
            raise DiscoveryError(DiscoveryErrorCode.FILESYSTEM_MUTATION, "changed")
        return original_revalidate(item, root)

    monkeypatch.setattr(DiscoveryItem, "revalidate", mutate_one)
    mutation = scan_engine.run_scan(ScanRequest(path=tmp_path, output_format="json"))
    assert mutation.exit_code == 2
    assert mutation.result.summary.failed_files == 1
    assert mutation.result.summary.consumers == 1
    assert mutation.result.diagnostics[0].code.value == "filesystem_mutation"
    monkeypatch.setattr(DiscoveryItem, "revalidate", original_revalidate)

    def analyzer_contract(*args: object, **kwargs: object) -> None:
        raise AnalyzerExecutionError("test", CandidateKind.PYTHON, TypeError())

    monkeypatch.setattr(AnalyzerRegistry, "analyze", analyzer_contract)
    analyzer = scan_engine.run_scan(ScanRequest(path=tmp_path, output_format="json"))
    assert analyzer.exit_code == 2
    assert {item.code.value for item in analyzer.result.diagnostics} == {"analyzer_contract"}


def test_normalization_failure_returns_safe_failed_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path / "app.py", 'import os\nos.getenv("KEY")\n')

    def conflict(observations: object) -> None:
        raise NormalizationError(NormalizationErrorCode.CONFLICTING_FACT, "unsafe detail")

    monkeypatch.setattr(scan_engine, "normalize_observations", conflict)
    result = scan_engine.run_scan(ScanRequest(path=tmp_path, output_format="json"))
    assert result.exit_code == 2
    assert result.result.status.value == "failed"
    assert result.result.contract.consumers == ()
    assert result.result.diagnostics[0].code.value == "normalization_error"
    assert "unsafe detail" not in result.rendered


def test_configuration_is_loaded_exactly_once(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    def counted(
        logical_root: Path, *, require: bool = False, config_path: Path | None = None
    ) -> ConfigDocument | None:
        nonlocal calls
        calls += 1
        return actual_load_config(logical_root, require=require, config_path=config_path)

    monkeypatch.setattr("runtime_contract.scan.engine.load_config", counted)
    result = scan_engine.run_scan(ScanRequest(path=project, output_format="json"))
    assert result.exit_code == 0
    assert calls == 1
