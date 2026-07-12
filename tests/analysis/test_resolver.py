"""ConfigPolicy adapter boundary tests."""

from __future__ import annotations

from dataclasses import dataclass

from runtime_contract.analysis import ConfigPolicyClassificationResolver, DecisionSource
from runtime_contract.config.policy import ClassificationResult


@dataclass
class PolicyDouble:
    result: ClassificationResult
    call: tuple[str, str | None, str | None] | None = None

    def classify(
        self, variable: str, *, root: str | None = None, environment: str | None = None
    ) -> ClassificationResult:
        self.call = (variable, root, environment)
        return self.result


def test_resolver_binds_scope_maps_sources_and_exposes_no_rules() -> None:
    policy = PolicyDouble(ClassificationResult(True, False, True, "private", ()))
    resolver = ConfigPolicyClassificationResolver(policy, "api", "prod")  # type: ignore[arg-type]
    result = resolver.classify("API_KEY")
    assert policy.call == ("API_KEY", "api", "prod")
    assert result.model_dump(mode="json") == {
        "ignored": False,
        "secret": True,
        "secret_source": "config_override",
        "required": False,
        "required_source": "config_override",
        "allow_literal": True,
        "allow_literal_source": "config_override",
    }
    assert result.required_source is DecisionSource.CONFIG_OVERRIDE
    assert not hasattr(result, "reason") and not hasattr(result, "applied")


def test_resolver_preserves_null_decisions_and_is_deterministic() -> None:
    policy = PolicyDouble(ClassificationResult(None, None, None, None, ()))
    resolver = ConfigPolicyClassificationResolver(policy, "api", None)  # type: ignore[arg-type]
    assert resolver.classify("KEY") == resolver.classify("KEY")
    assert set(resolver.classify("KEY").model_dump().values()) == {None, False}


def test_resolver_exposes_ignore_decision_without_policy_details() -> None:
    policy = PolicyDouble(ClassificationResult(None, None, None, "generated", (), True))
    result = ConfigPolicyClassificationResolver(policy, "api", "prod").classify("GENERATED")  # type: ignore[arg-type]
    assert result.ignored is True
    assert result.secret is None
