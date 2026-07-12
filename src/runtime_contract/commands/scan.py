"""The scan command and its thin Typer adapter."""

import os
import shutil
import sys
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
        str | None,
        typer.Option(
            "--format",
            help="Output format: text, json, or sarif (default: text; overrides env/YAML).",
        ),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", help="Write the report atomically to this path.")
    ] = None,
    report: Annotated[Path | None, typer.Option("--report", hidden=True)] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            help=(
                "Finding threshold: error, warning, info, or never "
                "(default: error; scan remains non-blocking)."
            )
        ),
    ] = None,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Print only the final text status.")
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase text detail (maximum: -vv)."),
    ] = 0,
    color: Annotated[str, typer.Option(help="Terminal color: auto, always, or never.")] = "auto",
    no_emoji: Annotated[bool, typer.Option("--no-emoji", help="Disable terminal symbols.")] = False,
    width: Annotated[
        int | None, typer.Option(help="Terminal width override (40-240 columns).")
    ] = None,
) -> None:
    """Statically inspect supported environment-variable consumers."""
    if output is not None and report is not None:
        _fail("--output and --report cannot be used together")
    if quiet and verbose:
        _fail("--quiet and --verbose cannot be used together")
    if verbose > 2:
        _fail("--verbose may be specified at most twice")
    if color not in {"auto", "always", "never"}:
        _fail("--color must be auto, always, or never")
    if width is not None and not 40 <= width <= 240:
        _fail("--width must be between 40 and 240")
    is_tty = sys.stdout.isatty() and output is None and report is None
    terminal_color = color == "always" or (
        color == "auto" and is_tty and "NO_COLOR" not in os.environ
    )
    terminal_width = max(
        40, min(240, width or shutil.get_terminal_size(fallback=(100, 24)).columns)
    )
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
        terminal_color=terminal_color,
        terminal_emoji=is_tty and not no_emoji,
        terminal_width=terminal_width,
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
        _fail(redact_exception(error).message)
    if run.exit_code:
        raise typer.Exit(code=run.exit_code)
