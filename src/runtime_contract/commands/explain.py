"""The explain command."""

from pathlib import Path
from typing import Annotated

import typer


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
    del rule_or_finding_id, path
    typer.echo("Error: explain command is not implemented yet.", err=True)
    raise typer.Exit(code=2)
