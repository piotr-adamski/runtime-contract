"""The explain command."""

from pathlib import Path
from typing import Annotated

import typer

from runtime_contract.commands.config import _render_errors
from runtime_contract.config.loader import ConfigValidationError, load_config


def explain(
    rule_or_finding_id: Annotated[
        str,
        typer.Argument(help="Rule ID or finding ID to explain."),
    ],
    path: Annotated[
        Path | None,
        typer.Argument(help="Optional project directory for finding lookup."),
    ] = None,
) -> None:
    """Explain a rule or finding without changing project files."""
    del rule_or_finding_id
    if path is not None:
        try:
            load_config(path)
        except ConfigValidationError as error:
            _render_errors(error, "text")
            raise typer.Exit(code=2) from None
    typer.echo("Error: explain command is not implemented yet.", err=True)
    raise typer.Exit(code=2)
