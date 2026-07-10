"""The scan command."""

from pathlib import Path
from typing import Annotated

import typer


def scan(
    path: Annotated[
        Path,
        typer.Argument(help="Project directory to scan."),
    ] = Path("."),
) -> None:
    """Inspect a project for runtime-contract findings."""
    del path
    typer.echo("Error: scan command is not implemented yet.", err=True)
    raise typer.Exit(code=2)
