"""Command-line interface for runtime-contract."""

import importlib.metadata
from typing import Annotated

import typer

from runtime_contract.commands import check, config, diff, explain, scan

app = typer.Typer(
    help="Check environment-variable delivery contracts without running project code.",
    no_args_is_help=True,
    epilog=(
        "Quick start: runtime-contract scan .\n\n"
        "Configuration: commands discover runtime-contract.yaml in PATH. "
        "Execution settings resolve in this order: built-in defaults < YAML < "
        "RUNTIME_CONTRACT_* environment variables < explicit CLI options."
    ),
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


app.command(
    epilog=(
        "Examples:\n\n"
        "  runtime-contract scan .\n\n"
        "  runtime-contract scan ./service --format json --output scan.json\n\n"
        "  runtime-contract scan . --environment production --root api --root worker"
    )
)(scan.scan)
app.command(
    epilog=(
        "Examples:\n\n"
        "  runtime-contract check .\n\n"
        "  runtime-contract check . --fail-on warning\n\n"
        "  runtime-contract check . --format sarif --output runtime-contract.sarif"
    )
)(check.check)
app.command(
    epilog=(
        "Examples:\n\n"
        "  runtime-contract explain RTC001\n\n"
        "  runtime-contract explain RTC001 ./service --format json\n\n"
        "  runtime-contract explain RTC001-<fingerprint> scan.json"
    )
)(explain.explain)
app.command(
    epilog=(
        "Examples:\n\n"
        "  runtime-contract diff ./before ./after\n\n"
        "  runtime-contract diff before.json after.json --format json"
    )
)(diff.diff)
app.add_typer(config.app, name="config")


def main() -> None:
    """Run the runtime-contract CLI."""
    app()
