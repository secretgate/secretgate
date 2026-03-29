"""Tests for the shared patterns module and expanded scanner coverage."""

from __future__ import annotations

from secretgate.patterns import is_auth_path


class TestIsAuthPath:
    """Ensure auth endpoints are correctly identified and non-auth paths pass through."""

    def test_oauth_path(self):
        assert is_auth_path("/oauth/token") is True

    def test_oauth_trailing(self):
        assert is_auth_path("/v1/oauth") is True

    def test_auth_path(self):
        assert is_auth_path("/auth/callback") is True

    def test_token_path(self):
        assert is_auth_path("/token") is True

    def test_token_with_query(self):
        assert is_auth_path("/token?grant_type=refresh") is True

    def test_authorize_path(self):
        assert is_auth_path("/authorize") is True

    def test_well_known(self):
        assert is_auth_path("/.well-known/openid-configuration") is True

    def test_login_path(self):
        assert is_auth_path("/login") is True

    def test_api_messages_not_auth(self):
        assert is_auth_path("/v1/messages") is False

    def test_chat_completions_not_auth(self):
        assert is_auth_path("/v1/chat/completions") is False

    def test_health_not_auth(self):
        assert is_auth_path("/health") is False

    def test_root_not_auth(self):
        assert is_auth_path("/") is False

    def test_empty_not_auth(self):
        assert is_auth_path("") is False

    def test_case_insensitive(self):
        assert is_auth_path("/OAuth/Token") is True
        assert is_auth_path("/AUTH/callback") is True
