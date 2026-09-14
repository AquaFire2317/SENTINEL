"""Tests for the provider-agnostic model factory."""

from types import SimpleNamespace

import pytest
from sentinel.integrations import providers
from sentinel.integrations.providers import (
    ProviderNotConfiguredError,
    ProviderNotInstalledError,
    UnknownProviderError,
    build_model,
    describe_active_model,
    list_providers,
)
from sentinel.integrations.strands_models import ProcurementPlannerModel


def test_core_providers_are_registered():
    ids = [p["id"] for p in list_providers()]
    for expected in (
        "local",
        "bedrock",
        "anthropic",
        "openai",
        "openrouter",
        "openai_compatible",
        "litellm",
        "ollama",
        "gemini",
        "mistral",
    ):
        assert expected in ids


def test_build_local_model_is_deterministic_planner():
    model = build_model("local")
    assert isinstance(model, ProcurementPlannerModel)


def test_build_local_vulnerable_flag():
    model = build_model("local", vulnerable=True)
    assert isinstance(model, ProcurementPlannerModel)
    assert model.vulnerable is True


def test_unknown_provider_raises():
    with pytest.raises(UnknownProviderError):
        build_model("not-a-provider")


def test_missing_sdk_raises_actionable_error(monkeypatch):
    monkeypatch.setattr(providers, "sdk_installed", lambda module: False)
    with pytest.raises(ProviderNotInstalledError):
        build_model("anthropic")


def test_hosted_provider_requires_api_key(monkeypatch):
    monkeypatch.setattr(providers, "sdk_installed", lambda module: True)
    settings = SimpleNamespace(
        resolved_provider="openrouter",
        model_api_key=None,
        model_id=None,
        model_base_url=None,
        bedrock_model_id=None,
        aws_region="us-east-1",
    )
    monkeypatch.setattr(providers, "get_settings", lambda: settings)
    with pytest.raises(ProviderNotConfiguredError):
        build_model("openrouter")


def test_openai_compatible_requires_base_url(monkeypatch):
    monkeypatch.setattr(providers, "sdk_installed", lambda module: True)
    settings = SimpleNamespace(
        resolved_provider="openai_compatible",
        model_api_key="key",
        model_id="some-model",
        model_base_url=None,
        bedrock_model_id=None,
        aws_region="us-east-1",
    )
    monkeypatch.setattr(providers, "get_settings", lambda: settings)
    with pytest.raises(ProviderNotConfiguredError):
        build_model("openai_compatible")


def test_describe_active_model_defaults_to_local(monkeypatch):
    settings = SimpleNamespace(
        resolved_provider="local",
        model_api_key=None,
        model_id=None,
        model_base_url=None,
        bedrock_model_id=None,
        aws_region="us-east-1",
        mode="local",
        environment="local",
    )
    monkeypatch.setattr(providers, "get_settings", lambda: settings)
    described = describe_active_model()
    assert described["provider"] == "local"
    assert described["sdk_installed"] is True
