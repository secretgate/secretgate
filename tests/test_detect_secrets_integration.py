"""Tests for optional detect-secrets integration."""

import pytest

from secretgate.secrets.scanner import SecretScanner


@pytest.fixture
def scanner():
    return SecretScanner(use_detect_secrets=True)


def test_detect_secrets_available():
    """detect-secrets should be installed in dev environment."""
    from secretgate.secrets.detect_secrets_adapter import is_available

    assert is_available()


def test_catches_aws_key_via_detect_secrets(scanner):
    """detect-secrets should catch AWS keys (may duplicate our own scanner)."""
    matches = scanner.scan("my key AKIAIOSFODNN7EXAMPLE here")
    assert any("AWS" in m.pattern_name or "AWS" in m.service for m in matches)


def test_catches_sendgrid_key(scanner):
    """detect-secrets catches SendGrid keys via its SendGridDetector."""
    # Fake key with correct format: SG. + 22 chars + . + 43 chars
    fake_key = "SG." + "a" * 22 + "." + "b" * 43
    matches = scanner.scan(f"SENDGRID_KEY={fake_key}")
    types = [(m.service, m.pattern_name) for m in matches]
    assert any("SendGrid" in svc or "SendGrid" in name for svc, name in types)


def test_no_false_positives_on_normal_code(scanner):
    """With entropy detectors disabled, normal code should not trigger."""
    normals = [
        "import os",
        "DEBUG=true",
        "const x = 42",
        "Hello, World!",
        "def my_function():",
    ]
    for text in normals:
        matches = scanner.scan(text)
        ds_matches = [m for m in matches if m.service == "detect-secrets"]
        assert not ds_matches, f"False positive on: {text!r} -> {ds_matches}"


def test_detect_secrets_supplements_builtin():
    """With detect-secrets enabled, we should get at least as many matches."""
    text = "AKIAIOSFODNN7EXAMPLE"
    builtin_only = SecretScanner(use_detect_secrets=False)
    with_ds = SecretScanner(use_detect_secrets=True)

    builtin_matches = builtin_only.scan(text)
    combined_matches = with_ds.scan(text)

    assert len(combined_matches) >= len(builtin_matches)


def test_deduplication(scanner):
    """Same secret shouldn't appear twice even if both scanners find it."""
    text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    matches = scanner.scan(text)
    values = [m.value for m in matches]
    assert len(values) == len(set(values)), f"Duplicate matches: {values}"


def test_import_error_without_package():
    """Should raise ImportError with helpful message if not installed."""
    from unittest.mock import patch

    with patch("secretgate.secrets.detect_secrets_adapter.is_available", return_value=False):
        with pytest.raises(ImportError, match="detect-secrets is not installed"):
            SecretScanner(use_detect_secrets=True)
