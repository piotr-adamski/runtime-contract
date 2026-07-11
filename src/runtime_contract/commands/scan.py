"""The scan command and its thin Typer adapter."""

from pathlib import Path
from typing import Annotated

import typer

from runtime_contract.config.loader import ConfigValidationError
from runtime_contract.discovery import DiscoveryError
from runtime_contract.normalization import NormalizationError
from runtime_contract.scan import ScanRequest, run_scan, write_atomic


def _fail(message: str) -> None:
    typer.echo(f"Error: {message}.", err=True)
    raise typer.Exit(code=2)


def scan(
    path: Annotated[Path, typer.Argument(help="Project directory to scan.")] = Path("."),
    config: Annotated[
        Path | None, typer.Option("--config", help="Configuration path relative to PATH.")
    ] = None,
    roots: Annotated[
        list[str] | None, typer.Option("--root", help="Named root to scan; repeatable.")
    ] = None,
    environment: Annotated[str | None, typer.Option(help="Select an environment profile.")] = None,
    include: Annotated[
        list[str] | None,
        typer.Option("--include", help="Replace global include filters; repeatable."),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option("--exclude", help="Replace global exclude filters; repeatable."),
    ] = None,
    output_format: Annotated[
        str | None, typer.Option("--format", help="Output format: text, json, or sarif.")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", help="Write the report atomically to this path.")
    ] = None,
    report: Annotated[Path | None, typer.Option("--report", hidden=True)] = None,
    fail_on: Annotated[
        str | None, typer.Option(help="Effective finding threshold (scan remains non-blocking).")
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Print only the final text status.")
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase text detail (maximum: -vv)."),
    ] = 0,
) -> None:
    """Statically inspect supported environment-variable consumers."""
    if output is not None and report is not None:
        _fail("--output and --report cannot be used together")
    if quiet and verbose:
        _fail("--quiet and --verbose cannot be used together")
    if verbose > 2:
        _fail("--verbose may be specified at most twice")
    request = ScanRequest(
        path=path,
        config=config,
        roots=tuple(roots or ()),
        environment=environment,
        include=tuple(include) if include is not None else None,
        exclude=tuple(exclude) if exclude is not None else None,
        output_format=output_format,
        output=output,
        report=report,
        fail_on=fail_on,
        verbosity=-1 if quiet else verbose,
    )
    try:
        run = run_scan(request)
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
        message = str(error) or "scan failed"
        _fail(message)
    if run.exit_code:
        raise typer.Exit(code=run.exit_code)
