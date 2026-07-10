"""The check command."""

from pathlib import Path
from typing import Annotated

import typer


def check(
    path: Annotated[
        Path,
        typer.Argument(help="Project directory to check."),
    ] = Path("."),
) -> None:
    """Check a project against the runtime contract."""
    del path
    typer.echo("Error: check command is not implemented yet.", err=True)
    raise typer.Exit(code=2)
