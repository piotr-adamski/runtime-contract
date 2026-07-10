"""The check command."""

from pathlib import Path
from typing import Annotated

import typer

from runtime_contract.commands.config import validate_for_analysis


def check(
    path: Annotated[
        Path,
        typer.Argument(help="Project directory to check."),
    ] = Path("."),
    environment: Annotated[str | None, typer.Option(help="Select an environment profile.")] = None,
    output_format: Annotated[
        str | None, typer.Option("--format", help="Output format override.")
    ] = None,
    fail_on: Annotated[str | None, typer.Option(help="Failure threshold override.")] = None,
    report: Annotated[Path | None, typer.Option(help="Relative report path override.")] = None,
) -> None:
    """Check a project against the runtime contract."""
    validate_for_analysis(
        path,
        environment=environment,
        output_format=output_format,
        fail_on=fail_on,
        report=report,
    )
    typer.echo("Error: check command is not implemented yet.", err=True)
    raise typer.Exit(code=2)
