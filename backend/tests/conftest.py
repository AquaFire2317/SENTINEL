"""Shared test configuration."""

import pytest


@pytest.fixture
def local_settings():
    from sentinel.config.settings import Settings

    return Settings()
