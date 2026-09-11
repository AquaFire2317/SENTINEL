from sentinel import __version__
from sentinel.config.settings import Settings, get_settings
from sentinel.errors import ConfigurationError, SentinelError


def test_package_has_version():
    assert __version__ == "0.1.0"


def test_settings_have_safe_local_defaults():
    settings = Settings()

    assert settings.environment == "local"
    assert settings.aws_region == "us-east-1"
    assert settings.fixture_version == "v1"
    assert settings.bedrock_model_id is None


def test_settings_accept_environment_aliases(monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")

    settings = Settings()

    assert settings.environment == "test"
    assert settings.aws_region == "eu-west-1"


def test_settings_are_cached_for_application_use():
    get_settings.cache_clear()

    assert get_settings() is get_settings()


def test_expected_errors_have_stable_codes():
    error = ConfigurationError("missing setting")

    assert isinstance(error, SentinelError)
    assert error.code == "CONFIGURATION_ERROR"
    assert error.message == "missing setting"
