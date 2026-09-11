"""Environment-backed application settings."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration shared by local and AWS execution modes."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    environment: str = Field(default="local", alias="SENTINEL_ENV")
    log_level: str = Field(default="INFO", alias="SENTINEL_LOG_LEVEL")
    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")
    bedrock_model_id: str | None = Field(default=None, alias="BEDROCK_MODEL_ID")
    table_name: str | None = Field(default=None, alias="SENTINEL_TABLE_NAME")
    bucket_name: str | None = Field(default=None, alias="SENTINEL_BUCKET_NAME")
    state_machine_arn: str | None = Field(default=None, alias="SENTINEL_STATE_MACHINE_ARN")
    fixture_version: str = Field(default="v1", alias="SENTINEL_FIXTURE_VERSION")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide immutable-by-convention settings object."""

    return Settings()
