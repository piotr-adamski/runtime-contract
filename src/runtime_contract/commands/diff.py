"""The diff command."""

from pathlib import Path
from typing import Annotated

import typer


def diff(
    left: Annotated[
        Path,
        typer.Argument(help="Left project directory or saved JSON report."),
    ],
    right: Annotated[
        Path,
        typer.Argument(help="Right project directory or saved JSON report."),
    ],
) -> None:
    """Compare two projects or saved reports without invoking Git."""
    del left, right
    typer.echo("Error: diff command is not implemented yet.", err=True)
    raise typer.Exit(code=2)
