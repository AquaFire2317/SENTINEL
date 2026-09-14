"""Provider-agnostic model factory for the SENTINEL-guarded Strands agent.

SENTINEL secures *any* Strands agent regardless of which model provider drives
it. This module resolves ``SENTINEL_MODEL_PROVIDER`` (and the matching
credentials) into a concrete Strands ``Model`` instance. The security guarantee
does not depend on the provider: every tool call is gated by the PolicyEngine
before it can execute, so a hosted model from OpenRouter is contained exactly
like a Bedrock or local-planning one.

Supported providers
-------------------
``local``
    Deterministic ``ProcurementPlannerModel``. Offline, credential-free.
``bedrock``
    Amazon Bedrock (``strands.models.BedrockModel``).
``anthropic``
    Anthropic Claude (``anthropic`` SDK).
``openai``
    OpenAI (``openai`` SDK).
``openrouter``
    OpenRouter's OpenAI-compatible API (``openai`` SDK).
``openai_compatible``
    Any OpenAI-compatible endpoint via an explicit ``base_url``.
``litellm``
    LiteLLM, which fronts 100+ providers behind one interface.
``ollama``
    A local Ollama server.
``gemini``
    Google Gemini (``google-genai`` SDK).
``mistral``
    Mistral AI (``mistralai`` SDK).

Providers whose SDK is not installed are reported by :func:`list_providers` and
raise an actionable :class:`ProviderNotInstalled` from :func:`build_model`.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentinel.config.settings import get_settings


class ProviderError(RuntimeError):
    """Base class for model-provider configuration failures."""


class UnknownProviderError(ProviderError):
    """Raised when an unrecognised provider id is requested."""


class ProviderNotConfiguredError(ProviderError):
    """Raised when a provider is missing required configuration (model id/key)."""


class ProviderNotInstalledError(ProviderError):
    """Raised when a provider's optional SDK is not installed."""


@dataclass(frozen=True)
class ProviderSpec:
    """Static metadata plus a builder for one model provider."""

    id: str
    name: str
    description: str
    sdk_module: str | None
    default_model: str | None = None
    suggested_models: tuple[str, ...] = ()
    requires_api_key: bool = False
    supports_base_url: bool = False
    default_base_url: str | None = None
    docs_url: str | None = None
    builder: Callable[..., Any] | None = field(default=None, repr=False)


def _resolve_api_key(explicit: str | None) -> str | None:
    return explicit or get_settings().model_api_key


def _build_bedrock(*, model_id: str, api_key: str | None, base_url: str | None, params: dict | None) -> Any:
    from strands.models import BedrockModel

    settings = get_settings()
    resolved_id = model_id or settings.bedrock_model_id
    if not resolved_id:
        raise ProviderNotConfiguredError(
            "Bedrock requires a model id. Set SENTINEL_MODEL_ID (or BEDROCK_MODEL_ID)."
        )
    kwargs: dict[str, Any] = {
        "model_id": resolved_id,
        "region_name": settings.aws_region,
    }
    if base_url:
        kwargs["endpoint_url"] = base_url
    if params:
        kwargs.update(params)
    return BedrockModel(**kwargs)


def _build_anthropic(*, model_id: str, api_key: str | None, base_url: str | None, params: dict | None) -> Any:
    from strands.models.anthropic import AnthropicModel

    client_args: dict[str, Any] = {}
    if api_key:
        client_args["api_key"] = api_key
    if base_url:
        client_args["base_url"] = base_url
    return AnthropicModel(model_id=model_id, client_args=client_args or None, params=params)


def _build_openai(*, model_id: str, api_key: str | None, base_url: str | None, params: dict | None) -> Any:
    from strands.models.openai import OpenAIModel

    client_args: dict[str, Any] = {}
    if api_key:
        client_args["api_key"] = api_key
    if base_url:
        client_args["base_url"] = base_url
    return OpenAIModel(model_id=model_id, client_args=client_args or None, params=params)


def _build_litellm(*, model_id: str, api_key: str | None, base_url: str | None, params: dict | None) -> Any:
    from strands.models.litellm import LiteLLMModel

    client_args: dict[str, Any] = {}
    if api_key:
        client_args["api_key"] = api_key
    if base_url:
        client_args["api_base"] = base_url
    return LiteLLMModel(model_id=model_id, client_args=client_args or None, params=params)


def _build_ollama(*, model_id: str, api_key: str | None, base_url: str | None, params: dict | None) -> Any:
    from strands.models.ollama import OllamaModel

    settings = get_settings()
    host = base_url or settings.model_base_url or "http://localhost:11434"
    return OllamaModel(host=host, model_id=model_id, params=params)


def _build_gemini(*, model_id: str, api_key: str | None, base_url: str | None, params: dict | None) -> Any:
    from strands.models.gemini import GeminiModel

    client_args: dict[str, Any] = {}
    if api_key:
        client_args["api_key"] = api_key
    return GeminiModel(model_id=model_id, client_args=client_args or None, params=params)


def _build_mistral(*, model_id: str, api_key: str | None, base_url: str | None, params: dict | None) -> Any:
    from strands.models.mistral import MistralModel

    return MistralModel(api_key=api_key, model_id=model_id, params=params)


def _build_local(*, vulnerable: bool = False, **_: Any) -> Any:
    from sentinel.integrations.strands_models import ProcurementPlannerModel

    return ProcurementPlannerModel(vulnerable=vulnerable)


PROVIDER_SPECS: dict[str, ProviderSpec] = {
    "local": ProviderSpec(
        id="local",
        name="Local deterministic planner",
        description="Offline, credential-free planner. Reproducible for CI and demos.",
        sdk_module=None,
        default_model="sentinel-procurement-planner",
        suggested_models=("sentinel-procurement-planner",),
        builder=_build_local,
    ),
    "bedrock": ProviderSpec(
        id="bedrock",
        name="AWS Bedrock",
        description="Amazon Bedrock models via the Strands BedrockModel provider.",
        sdk_module="boto3",
        default_model=None,
        suggested_models=(
            "us.anthropic.claude-sonnet-4-20250514-v1:0",
            "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
        ),
        builder=_build_bedrock,
        docs_url="https://docs.aws.amazon.com/bedrock/",
    ),
    "anthropic": ProviderSpec(
        id="anthropic",
        name="Anthropic Claude",
        description="Anthropic's hosted Claude models.",
        sdk_module="anthropic",
        default_model="claude-3-7-sonnet-latest",
        suggested_models=(
            "claude-3-7-sonnet-latest",
            "claude-3-5-haiku-latest",
            "claude-3-opus-latest",
        ),
        requires_api_key=True,
        supports_base_url=True,
        builder=_build_anthropic,
        docs_url="https://docs.anthropic.com/",
    ),
    "openai": ProviderSpec(
        id="openai",
        name="OpenAI",
        description="OpenAI's hosted models.",
        sdk_module="openai",
        default_model="gpt-4o-mini",
        suggested_models=("gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o3-mini"),
        requires_api_key=True,
        supports_base_url=True,
        builder=_build_openai,
        docs_url="https://platform.openai.com/docs/models",
    ),
    "openrouter": ProviderSpec(
        id="openrouter",
        name="OpenRouter",
        description="OpenRouter's OpenAI-compatible gateway to many models.",
        sdk_module="openai",
        default_model="openai/gpt-4o-mini",
        suggested_models=(
            "openai/gpt-4o-mini",
            "anthropic/claude-3.7-sonnet",
            "google/gemini-2.0-flash-001",
            "meta-llama/llama-3.3-70b-instruct",
            "deepseek/deepseek-chat",
        ),
        requires_api_key=True,
        supports_base_url=True,
        default_base_url="https://openrouter.ai/api/v1",
        builder=_build_openai,
        docs_url="https://openrouter.ai/docs",
    ),
    "openai_compatible": ProviderSpec(
        id="openai_compatible",
        name="OpenAI-compatible endpoint",
        description="Any server exposing the OpenAI chat-completions API.",
        sdk_module="openai",
        default_model=None,
        suggested_models=(),
        requires_api_key=False,
        supports_base_url=True,
        builder=_build_openai,
        docs_url="https://platform.openai.com/docs/api-reference/chat",
    ),
    "litellm": ProviderSpec(
        id="litellm",
        name="LiteLLM (100+ providers)",
        description="Unified interface to providers such as Azure, Vertex, Groq, and more.",
        sdk_module="litellm",
        default_model="openai/gpt-4o-mini",
        suggested_models=(
            "openai/gpt-4o-mini",
            "anthropic/claude-3-7-sonnet-latest",
            "groq/llama-3.3-70b-versatile",
        ),
        requires_api_key=True,
        supports_base_url=True,
        builder=_build_litellm,
        docs_url="https://docs.litellm.ai/docs/providers",
    ),
    "ollama": ProviderSpec(
        id="ollama",
        name="Ollama (local)",
        description="Locally hosted open models served by Ollama.",
        sdk_module="ollama",
        default_model="llama3.2",
        suggested_models=("llama3.2", "qwen2.5", "mistral"),
        requires_api_key=False,
        supports_base_url=True,
        default_base_url="http://localhost:11434",
        builder=_build_ollama,
        docs_url="https://ollama.com/",
    ),
    "gemini": ProviderSpec(
        id="gemini",
        name="Google Gemini",
        description="Google's Gemini models via the google-genai SDK.",
        sdk_module="google.genai",
        default_model="gemini-2.0-flash",
        suggested_models=("gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"),
        requires_api_key=True,
        builder=_build_gemini,
        docs_url="https://ai.google.dev/gemini-api/docs/models",
    ),
    "mistral": ProviderSpec(
        id="mistral",
        name="Mistral AI",
        description="Mistral's hosted models.",
        sdk_module="mistralai",
        default_model="mistral-large-latest",
        suggested_models=("mistral-large-latest", "mistral-medium-latest", "mistral-small-latest"),
        requires_api_key=True,
        builder=_build_mistral,
        docs_url="https://docs.mistral.ai/",
    ),
}


def provider_ids() -> list[str]:
    """Return the ordered list of supported provider ids."""
    return list(PROVIDER_SPECS)


def get_spec(provider: str) -> ProviderSpec:
    spec = PROVIDER_SPECS.get(provider.strip().lower())
    if spec is None:
        raise UnknownProviderError(
            f"Unknown provider '{provider}'. Supported: {', '.join(provider_ids())}"
        )
    return spec


def sdk_installed(module: str | None) -> bool:
    """Return True when an optional SDK module can be imported."""
    if module is None:
        return True
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def list_providers() -> list[dict[str, Any]]:
    """Describe every provider for the API/dashboard (never exposes secrets)."""
    settings = get_settings()
    configured_provider = settings.resolved_provider
    result: list[dict[str, Any]] = []
    for spec in PROVIDER_SPECS.values():
        installed = sdk_installed(spec.sdk_module)
        result.append(
            {
                "id": spec.id,
                "name": spec.name,
                "description": spec.description,
                "sdk": spec.sdk_module,
                "sdk_installed": installed,
                "requires_api_key": spec.requires_api_key,
                "supports_base_url": spec.supports_base_url,
                "default_model": spec.default_model,
                "models": list(spec.suggested_models),
                "active": spec.id == configured_provider,
                "configured": installed and _is_configured(spec, settings),
                "docs_url": spec.docs_url,
            }
        )
    return result


def _is_configured(spec: ProviderSpec, settings: Any) -> bool:
    if spec.id == "local":
        return True
    if spec.requires_api_key and not (settings.model_api_key):
        if spec.id == "bedrock":
            return bool(settings.bedrock_model_id or settings.model_id)
        return False
    if spec.id == "bedrock":
        return bool(settings.bedrock_model_id or settings.model_id)
    if spec.id == "openai_compatible":
        return bool(settings.model_base_url)
    return True


def build_model(
    provider: str | None = None,
    *,
    model_id: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    params: dict[str, Any] | None = None,
    vulnerable: bool = False,
) -> Any:
    """Build a Strands model provider from configuration.

    Args:
        provider: Provider id. Defaults to ``SENTINEL_MODEL_PROVIDER``.
        model_id: Model id. Defaults to the provider default or settings.
        api_key: API key. Defaults to ``SENTINEL_MODEL_API_KEY``.
        base_url: Base URL for OpenAI-compatible providers.
        params: Extra model parameters passed through to the provider.
        vulnerable: Only meaningful for the ``local`` provider.

    Raises:
        UnknownProviderError: The provider id is not recognised.
        ProviderNotInstalledError: The provider's optional SDK is missing.
        ProviderNotConfiguredError: Required model id/key/base URL is missing.
    """
    settings = get_settings()
    resolved = (provider or settings.resolved_provider).strip().lower()
    spec = get_spec(resolved)

    if resolved == "local":
        return _build_local(vulnerable=vulnerable)

    if not sdk_installed(spec.sdk_module):
        extra = spec.id.replace("_", "-")
        raise ProviderNotInstalledError(
            f"Provider '{spec.id}' requires the '{spec.sdk_module}' package. Install it with "
            f"`pip install strands-agents[{extra}]` or `pip install {spec.sdk_module}`."
        )

    resolved_model = model_id or settings.model_id or spec.default_model
    if not resolved_model:
        raise ProviderNotConfiguredError(
            f"Provider '{spec.id}' requires a model id. Set SENTINEL_MODEL_ID."
        )

    resolved_key = _resolve_api_key(api_key)
    if spec.requires_api_key and not resolved_key:
        raise ProviderNotConfiguredError(
            f"Provider '{spec.id}' requires an API key. Set SENTINEL_MODEL_API_KEY."
        )

    resolved_base_url = base_url or settings.model_base_url or spec.default_base_url

    if spec.id == "openai_compatible" and not resolved_base_url:
        raise ProviderNotConfiguredError(
            "Provider 'openai_compatible' requires SENTINEL_MODEL_BASE_URL."
        )

    assert spec.builder is not None
    return spec.builder(
        model_id=resolved_model,
        api_key=resolved_key,
        base_url=resolved_base_url,
        params=params,
    )


def describe_active_model() -> dict[str, Any]:
    """Return the effective provider/model without instantiating an SDK client."""
    settings = get_settings()
    provider = settings.resolved_provider
    spec = PROVIDER_SPECS.get(provider)
    return {
        "provider": provider,
        "provider_name": spec.name if spec else provider,
        "model_id": settings.model_id
        or (settings.bedrock_model_id if provider == "bedrock" else None)
        or (spec.default_model if spec else None),
        "sdk_installed": sdk_installed(spec.sdk_module) if spec else False,
        "requires_api_key": spec.requires_api_key if spec else False,
        "api_key_set": bool(settings.model_api_key),
        "base_url": settings.model_base_url
        or (spec.default_base_url if spec else None),
        "mode": settings.mode,
        "environment": settings.environment,
    }
