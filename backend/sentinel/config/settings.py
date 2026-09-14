"""Environment-backed application settings."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration shared by local and AWS execution modes.

    Model provider selection is provider-agnostic. ``SENTINEL_MODEL_PROVIDER``
    selects the Strands model provider used by the guarded agent:

    - ``local`` (default): deterministic ``ProcurementPlannerModel``. No
      credentials or network access required. Used by tests and the offline demo.
    - ``bedrock``: Amazon Bedrock (``strands.models.BedrockModel``).
    - ``anthropic``: Anthropic Claude directly (``strands.models.AnthropicModel``).
    - ``openai``: OpenAI (``strands.models.OpenAIModel``).
    - ``openrouter``: OpenRouter's OpenAI-compatible API.
    - ``openai_compatible``: any OpenAI-compatible endpoint via ``base_url``.
    - ``litellm``: LiteLLM, which fronts 100+ providers.
    - ``ollama``: local Ollama server.
    - ``gemini``: Google Gemini.
    - ``mistral``: Mistral AI.

    ``SENTINEL_MODE`` is retained for backwards compatibility. Setting
    ``SENTINEL_MODE=bedrock`` without an explicit provider selects Bedrock.

    Override via environment variables or a ``.env`` file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    environment: str = Field(default="local", alias="SENTINEL_ENV")
    mode: str = Field(default="local", alias="SENTINEL_MODE")
    log_level: str = Field(default="INFO", alias="SENTINEL_LOG_LEVEL")

    # Model provider selection (provider-agnostic).
    model_provider: str = Field(default="local", alias="SENTINEL_MODEL_PROVIDER")
    model_id: str | None = Field(default=None, alias="SENTINEL_MODEL_ID")
    model_api_key: str | None = Field(default=None, alias="SENTINEL_MODEL_API_KEY")
    model_base_url: str | None = Field(default=None, alias="SENTINEL_MODEL_BASE_URL")

    # AWS configuration.
    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")
    bedrock_model_id: str | None = Field(default=None, alias="BEDROCK_MODEL_ID")
    table_name: str | None = Field(default=None, alias="SENTINEL_TABLE_NAME")
    bucket_name: str | None = Field(default=None, alias="SENTINEL_BUCKET_NAME")
    state_machine_arn: str | None = Field(default=None, alias="SENTINEL_STATE_MACHINE_ARN")
    fixture_version: str = Field(default="v1", alias="SENTINEL_FIXTURE_VERSION")

    # HTTP server / API configuration.
    host: str = Field(default="0.0.0.0", alias="SENTINEL_HOST")
    port: int = Field(default=8080, alias="SENTINEL_PORT")
    cors_origin: str = Field(default="*", alias="SENTINEL_CORS_ORIGIN")
    serve_frontend: bool = Field(default=False, alias="SENTINEL_SERVE_FRONTEND")
    frontend_dist: str | None = Field(default=None, alias="SENTINEL_FRONTEND_DIST")

    @property
    def resolved_provider(self) -> str:
        """The effective model provider, honouring the legacy ``SENTINEL_MODE`` flag."""
        provider = (self.model_provider or "local").strip().lower()
        if provider == "local" and self.mode.lower() == "bedrock":
            return "bedrock"
        return provider

    @property
    def use_bedrock(self) -> bool:
        return self.resolved_provider == "bedrock"

    @property
    def use_local_model(self) -> bool:
        return self.resolved_provider == "local"

    @property
    def use_durable_persistence(self) -> bool:
        return bool(self.table_name)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide immutable-by-convention settings object."""

    return Settings()
