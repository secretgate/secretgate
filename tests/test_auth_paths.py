"""Tests for auth path detection — ensures OAuth/token endpoints skip scanning."""

from __future__ import annotations

import pytest

from secretgate.forward import _AUTH_PATH_PATTERNS, _ConnectionHandler


class TestAuthPathPattern:
    """Verify that auth/token endpoints are correctly identified for scan skipping."""

    @pytest.mark.parametrize(
        "path",
        [
            "/oauth/token",
            "/oauth",
            "/auth/callback",
            "/auth",
            "/token",
            "/token/refresh",
            "/token?grant_type=refresh",
            "/authorize",
            "/authorize?client_id=abc",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/login",
            "/v1/oauth/token",
            "/api/auth/login",
            "/OAUTH/TOKEN",  # case insensitive
        ],
    )
    def test_auth_paths_detected(self, path):
        """Known auth paths should be detected."""
        assert _AUTH_PATH_PATTERNS.search(path), f"Expected {path!r} to match auth pattern"

    @pytest.mark.parametrize(
        "path",
        [
            "/v1/chat/completions",
            "/v1/messages",
            "/api/generate",
            "/health",
            "/status",
            "/v1/embeddings",
            "/authorization-header-test",  # doesn't match /authorize boundary
        ],
    )
    def test_non_auth_paths_not_detected(self, path):
        """Normal API paths should NOT match auth patterns."""
        assert not _AUTH_PATH_PATTERNS.search(path), f"Did not expect {path!r} to match"

    def test_is_auth_path_method(self):
        """_ConnectionHandler._is_auth_path static method works correctly."""
        assert _ConnectionHandler._is_auth_path("/oauth/token") is True
        assert _ConnectionHandler._is_auth_path("/v1/chat/completions") is False
