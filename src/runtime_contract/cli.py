"""Command-line interface for runtime-contract."""

import importlib.metadata
from typing import Annotated

import typer

from runtime_contract.commands import check, config, diff, explain, scan

app = typer.Typer(
    help="Check environment-variable delivery contracts without running project code.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    """Print the installed distribution version and exit."""
    if not value:
        return

    try:
        package_version = importlib.metadata.version("runtime-contract")
    except importlib.metadata.PackageNotFoundError:
        typer.echo(
            "Error: distribution metadata for 'runtime-contract' is unavailable.",
            err=True,
        )
        raise typer.Exit(code=2) from None

    typer.echo(f"runtime-contract {package_version}")
    raise typer.Exit()


@app.callback()
def cli(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the installed version and exit.",
        ),
    ] = False,
) -> None:
    """Check environment-variable delivery contracts without running project code."""


app.command()(scan.scan)
app.command()(check.check)
app.command()(explain.explain)
app.command()(diff.diff)
app.add_typer(config.app, name="config")


def main() -> None:
    """Run the runtime-contract CLI."""
    app()
