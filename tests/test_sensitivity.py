"""D2.11 sensitivity classification catalogue."""

import pytest

from runtime_contract.domain import SecretSource
from runtime_contract.sensitivity import (
    SensitivityConfidence,
    SensitivityReason,
    classify_sensitivity,
)


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("ACCESS_TOKEN", SensitivityReason.TOKEN),
        ("access-token", SensitivityReason.TOKEN),
        ("accessToken", SensitivityReason.TOKEN),
        ("DB_PASSWORD", SensitivityReason.PASSWORD),
        ("db.passwd", SensitivityReason.PASSWORD),
        ("CLIENT_SECRET", SensitivityReason.SECRET),
        ("SSH_PRIVATE_KEY", SensitivityReason.PRIVATE_KEY),
        ("service/private-key", SensitivityReason.PRIVATE_KEY),
        ("OPENAI_API_KEY", SensitivityReason.API_KEY),
        ("openaiApiKey", SensitivityReason.API_KEY),
        ("SERVICE_APIKEY", SensitivityReason.API_KEY),
        ("SERVICE_CREDENTIAL", SensitivityReason.CREDENTIAL),
        ("aws.credentials", SensitivityReason.CREDENTIAL),
    ],
)
def test_positive_name_catalogue(name: str, reason: SensitivityReason) -> None:
    result = classify_sensitivity(name)
    assert result.sensitive is True
    assert result.reason is reason
    assert result.confidence is SensitivityConfidence.HIGH
    assert result.source is SecretSource.HEURISTIC


@pytest.mark.parametrize(
    "name",
    [
        "MONKEY",
        "HOCKEY",
        "TOKEN_COUNT",
        "TOKEN_LIMIT",
        "TOKEN_TTL",
        "TOKEN_TYPE",
        "PASSWORD_POLICY",
        "PASSWORD_MIN_LENGTH",
        "SECRET_NAME",
        "SECRET_NAMESPACE",
        "CREDENTIAL_TYPE",
        "API_KEY_ROTATION_DAYS",
        "PUBLIC_KEY",
        "USERNAME",
    ],
)
def test_negative_false_positive_catalogue(name: str) -> None:
    result = classify_sensitivity(name)
    assert result.sensitive is False
    assert result.reason is SensitivityReason.NO_MATCH
    assert result.confidence is SensitivityConfidence.NONE
    assert result.source is SecretSource.NOT_SECRET


def test_override_and_secret_metadata_are_explicit_and_value_blind() -> None:
    forced_public = classify_sensitivity("ACCESS_TOKEN", override=False)
    assert forced_public.model_dump() == {
        "sensitive": False,
        "source": SecretSource.CONFIG_OVERRIDE,
        "reason": SensitivityReason.CONFIG_OVERRIDE,
        "confidence": SensitivityConfidence.CERTAIN,
    }
    metadata = classify_sensitivity("CONFIG", secret_metadata=True)
    assert metadata.sensitive is True
    assert metadata.reason is SensitivityReason.SECRET_METADATA
    assert "value" not in metadata.model_dump_json().casefold()
