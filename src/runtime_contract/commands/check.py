"""The check command backed by the same scan engine."""

from pathlib import Path
from typing import Annotated

import typer

from runtime_contract.config.loader import ConfigValidationError
from runtime_contract.discovery import DiscoveryError
from runtime_contract.normalization import NormalizationError
from runtime_contract.scan import ScanRequest, run_scan, write_atomic
from runtime_contract.security import redact_exception


def _fail(message: str) -> None:
    typer.echo(f"Error: {message}.", err=True)
    raise typer.Exit(code=2) from None


def check(
    path: Annotated[Path, typer.Argument(help="Project directory to check.")] = Path("."),
    config: Annotated[
        Path | None, typer.Option("--config", help="Configuration path relative to PATH.")
    ] = None,
    environment: Annotated[str | None, typer.Option(help="Select an environment profile.")] = None,
    output_format: Annotated[
        str | None, typer.Option("--format", help="Output format override.")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", help="Write the report atomically to this path.")
    ] = None,
    fail_on: Annotated[str | None, typer.Option(help="Failure threshold override.")] = None,
    report: Annotated[Path | None, typer.Option(help="Relative report path override.")] = None,
) -> None:
    """Check a project and exit one when a reliable result has error findings."""

    if output is not None and report is not None:
        _fail("--output and --report cannot be used together")
    try:
        run = run_scan(
            ScanRequest(
                path=path,
                config=config,
                environment=environment,
                output_format=output_format,
                output=output,
                report=report,
                fail_on=fail_on,
                command="check",
            )
        )
        if run.output_path is not None:
            try:
                write_atomic(path.resolve(strict=True), run.output_path, run.rendered)
            except OSError:
                _fail("could not write report")
        else:
            typer.echo(run.rendered, nl=False)
    except ConfigValidationError as error:
        item = error.errors[0]
        _fail(
            f"configuration file is invalid [{item.code}] at {item.pointer} "
            f"({item.line}:{item.column})"
        )
    except typer.Exit:
        raise
    except (DiscoveryError, NormalizationError, RuntimeError, ValueError) as error:
        _fail(redact_exception(error).message)
    if run.exit_code:
        raise typer.Exit(code=run.exit_code)
