import os

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict  # type: ignore[import-not-found]

database_url = os.environ["DATABASE_URL"]
service_token = os.getenv("SERVICE_TOKEN")
optional_mode = os.getenv("OPTIONAL_MODE", "safe-default")
missing_runtime = os.getenv("MISSING_RUNTIME")


class ApplicationSettings(BaseSettings):  # type: ignore[misc]
    model_config = SettingsConfigDict(env_prefix="APP_")

    endpoint: str = Field(validation_alias="PUBLIC_URL")
    service_token: str = Field(validation_alias="SERVICE_TOKEN")
