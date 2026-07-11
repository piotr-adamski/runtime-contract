"""Public static Docker Compose loading API."""

from runtime_contract.compose.loader import (
    MAX_ALIAS_MERGE_REFERENCES,
    MAX_COMPOSE_BYTES,
    MAX_COMPOSE_SERVICES,
    MAX_INTERPOLATIONS,
    MAX_PROFILES_PER_SERVICE,
    MAX_SCALAR_BYTES,
    MAX_YAML_DEPTH,
    MAX_YAML_NODES,
    load_compose,
)
from runtime_contract.compose.models import (
    ComposeDiagnostic,
    ComposeDiagnosticCode,
    ComposeInput,
    ComposeInterpolation,
    ComposeInterpolationOperator,
    ComposeLoadResult,
    ComposeLoadStatus,
    ComposeService,
)

__all__ = [
    "MAX_ALIAS_MERGE_REFERENCES",
    "MAX_COMPOSE_BYTES",
    "MAX_COMPOSE_SERVICES",
    "MAX_INTERPOLATIONS",
    "MAX_PROFILES_PER_SERVICE",
    "MAX_SCALAR_BYTES",
    "MAX_YAML_DEPTH",
    "MAX_YAML_NODES",
    "ComposeDiagnostic",
    "ComposeDiagnosticCode",
    "ComposeInput",
    "ComposeInterpolation",
    "ComposeInterpolationOperator",
    "ComposeLoadResult",
    "ComposeLoadStatus",
    "ComposeService",
    "load_compose",
]
