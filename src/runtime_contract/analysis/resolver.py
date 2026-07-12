"""Adapter from configuration policy to analyzer-safe effective decisions."""

from __future__ import annotations

from dataclasses import dataclass

from runtime_contract.analysis.models import DecisionSource, EffectiveClassification
from runtime_contract.config.policy import ConfigPolicy


@dataclass(frozen=True, slots=True)
class ConfigPolicyClassificationResolver:
    """Bind ConfigPolicy to one logical root and environment without exposing its rules."""

    _policy: ConfigPolicy
    _root: str
    _environment: str | None

    def classify(self, variable: str) -> EffectiveClassification:
        result = self._policy.classify(variable, root=self._root, environment=self._environment)
        source = DecisionSource.CONFIG_OVERRIDE
        return EffectiveClassification(
            ignored=result.ignored,
            secret=result.secret,
            secret_source=source if result.secret is not None else None,
            required=result.required,
            required_source=source if result.required is not None else None,
            allow_literal=result.allow_literal,
            allow_literal_source=source if result.allow_literal is not None else None,
        )
