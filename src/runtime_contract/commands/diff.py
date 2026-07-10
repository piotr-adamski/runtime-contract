"""The diff command."""

from pathlib import Path
from typing import Annotated

import typer

from runtime_contract.commands.config import _render_errors
from runtime_contract.config.loader import ConfigValidationError, load_config


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
    for path in (left, right):
        if path.is_dir():
            try:
                load_config(path)
            except ConfigValidationError as error:
                _render_errors(error, "text")
                raise typer.Exit(code=2) from None
    typer.echo("Error: diff command is not implemented yet.", err=True)
    raise typer.Exit(code=2)
