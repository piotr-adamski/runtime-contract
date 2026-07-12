"""Explicit execution-setting precedence without automatic environment mapping."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from runtime_contract.config.models import Execution, FailOn, OutputFormat, RuntimeContractConfig
from runtime_contract.errors import PublicError

ENVIRONMENT_KEYS = {
    "environment": "RUNTIME_CONTRACT_ENVIRONMENT",
    "format": "RUNTIME_CONTRACT_FORMAT",
    "fail_on": "RUNTIME_CONTRACT_FAIL_ON",
    "report": "RUNTIME_CONTRACT_REPORT",
}


@dataclass(frozen=True, slots=True)
class EffectiveExecution:
    value: Execution
    sources: dict[str, str]


def resolve_execution(
    config: RuntimeContractConfig,
    *,
    environment: str | None = None,
    output_format: str | None = None,
    fail_on: str | None = None,
    report: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> EffectiveExecution:
    """Resolve defaults < YAML < four named variables < explicit CLI arguments."""

    env = os.environ if environ is None else environ
    defaults = Execution()
    values = defaults.model_dump(mode="python")
    sources = {key: "default" for key in values}
    yaml_values = config.execution.model_dump(mode="python")
    fields_set = config.execution.model_fields_set
    for key in fields_set:
        values[key] = yaml_values[key]
        sources[key] = "yaml"
    for key, variable in ENVIRONMENT_KEYS.items():
        if variable in env:
            values[key] = env[variable]
            sources[key] = "environment variable"
    cli = {
        "environment": environment,
        "format": output_format,
        "fail_on": fail_on,
        "report": str(report) if report is not None else None,
    }
    for key, value in cli.items():
        if value is not None:
            values[key] = value
            sources[key] = "CLI argument"
    try:
        effective = Execution.model_validate(values)
    except ValidationError as error:
        del error
        raise PublicError("invalid execution setting") from None
    if effective.environment is not None and effective.environment not in config.environments:
        raise PublicError("unknown environment")
    return EffectiveExecution(effective, sources)


__all__ = ["EffectiveExecution", "FailOn", "OutputFormat", "resolve_execution"]
