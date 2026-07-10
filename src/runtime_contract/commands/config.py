"""Configuration validation commands."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer

from runtime_contract.config.execution import resolve_execution
from runtime_contract.config.loader import ConfigValidationError, errors_json, load_config
from runtime_contract.config.policy import ConfigPolicy

app = typer.Typer(help="Inspect and validate runtime-contract.yaml.", no_args_is_help=True)


def _render_errors(error: ConfigValidationError, output_format: str) -> None:
    if output_format == "json":
        typer.echo(errors_json(error), err=True)
        return
    for item in error.errors:
        typer.echo(
            f"Error [{item.code}] {item.pointer} ({item.line}:{item.column}): {item.message}",
            err=True,
        )


def validate_for_analysis(
    path: Path,
    *,
    environment: str | None = None,
    output_format: str | None = None,
    fail_on: str | None = None,
    report: Path | None = None,
) -> None:
    """Validate configuration and explicit execution overrides before analysis."""

    try:
        document = load_config(path)
        if document is None:
            return
        resolve_execution(
            document.config,
            environment=environment,
            output_format=output_format,
            fail_on=fail_on,
            report=report,
        )
    except ConfigValidationError as error:
        _render_errors(error, "text")
        raise typer.Exit(code=2) from None
    except ValueError as error:
        typer.echo(f"Error: {error}.", err=True)
        raise typer.Exit(code=2) from None


@app.command("validate")
def validate(
    path: Annotated[Path, typer.Argument(help="Project directory to validate.")] = Path("."),
    output_format: Annotated[
        str | None,
        typer.Option("--format", help="Validation output: text or json."),
    ] = None,
) -> None:
    """Validate configuration without scanning project files."""

    requested = output_format or "text"
    if requested == "sarif":
        typer.echo("Error: SARIF is not supported for config validation.", err=True)
        raise typer.Exit(code=2)
    if requested not in {"text", "json"}:
        typer.echo("Error: config validation format must be text or json.", err=True)
        raise typer.Exit(code=2)
    try:
        document = load_config(path, require=True)
        assert document is not None
        effective = resolve_execution(document.config, output_format=output_format)
    except ConfigValidationError as error:
        _render_errors(error, requested)
        raise typer.Exit(code=2) from None
    except (OSError, RuntimeError, ValueError):
        typer.echo("Error: invalid execution configuration.", err=True)
        raise typer.Exit(code=2) from None
    if effective.value.format.value == "sarif":
        typer.echo("Error: SARIF is not supported for config validation.", err=True)
        raise typer.Exit(code=2)
    if effective.value.format.value == "json":
        typer.echo(
            json.dumps(
                {
                    "valid": True,
                    "version": document.config.version,
                    "roots": sorted(document.config.effective_roots()),
                    "execution": {
                        key: {
                            "value": value.value
                            if hasattr(value, "value")
                            else str(value)
                            if value is not None
                            else None,
                            "source": effective.sources[key],
                        }
                        for key, value in effective.value.model_dump(mode="python").items()
                    },
                },
                sort_keys=True,
            )
        )
    else:
        typer.echo("Configuration valid (version 1).")


@app.command("explain")
def explain(
    variable: Annotated[str, typer.Argument(help="Exact variable name to classify.")],
    path: Annotated[Path, typer.Option("--path", help="Project directory.")] = Path("."),
    root: Annotated[str | None, typer.Option(help="Root selector context.")] = None,
    environment: Annotated[str | None, typer.Option(help="Environment selector context.")] = None,
) -> None:
    """Explain ordered classification rules and YAML locations."""

    try:
        document = load_config(path, require=True)
        assert document is not None
        if root is not None and root not in document.config.effective_roots():
            raise ValueError("unknown root")
        if environment is not None and environment not in document.config.environments:
            raise ValueError("unknown environment")
    except ConfigValidationError as error:
        _render_errors(error, "text")
        raise typer.Exit(code=2) from None
    except ValueError as error:
        typer.echo(f"Error: {error}.", err=True)
        raise typer.Exit(code=2) from None
    result = ConfigPolicy(document).classify(variable, root=root, environment=environment)
    typer.echo(json.dumps(asdict(result), sort_keys=True))
