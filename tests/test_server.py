"""Tests for server app creation and health endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secretgate.config import Config
from secretgate.server import create_app


@pytest.fixture
def app():
    """Create a minimal app for testing."""
    config = Config(
        enable_known_values=False,
        forward_proxy_port=None,
    )
    return create_app(config)


@pytest.fixture
def client(app):
    """Test client for the app."""
    return TestClient(app)


class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_health_includes_version(self, client):
        from secretgate import __version__

        resp = client.get("/health")
        data = resp.json()
        assert data["version"] == __version__


class TestAppCreation:
    """Tests for app factory."""

    def test_default_providers_registered(self):
        """Default providers (openai, anthropic, ollama) are registered."""
        from secretgate.config import DEFAULT_PROVIDERS, ProviderConfig

        config = Config(
            enable_known_values=False,
            providers={
                name: ProviderConfig(name=name, base_url=url)
                for name, url in DEFAULT_PROVIDERS.items()
            },
        )
        app = create_app(config)
        route_paths = [r.path for r in app.routes]
        assert any("/openai" in r for r in route_paths)
        assert any("/anthropic" in r for r in route_paths)

    def test_custom_providers(self):
        """Custom provider config is respected."""
        from secretgate.config import ProviderConfig

        config = Config(
            enable_known_values=False,
            providers={
                "custom": ProviderConfig(name="custom", base_url="http://localhost:9999")
            },
        )
        app = create_app(config)
        routes = [r.path for r in app.routes]
        assert any("/custom" in r for r in routes)
