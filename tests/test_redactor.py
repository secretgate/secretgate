"""Tests for secret redaction and unredaction."""

from secretgate.secrets.scanner import SecretScanner
from secretgate.secrets.redactor import SecretRedactor


def test_redact_and_unredact():
    scanner = SecretScanner()
    redactor = SecretRedactor(scanner)

    original = "Use this key: AKIAIOSFODNN7EXAMPLE to authenticate."
    redacted = redactor.redact(original)

    # Secret should be replaced
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "REDACTED<" in redacted

    # Should be reversible
    restored = redactor.unredact(redacted)
    assert restored == original


def test_redact_preserves_non_secret_text():
    scanner = SecretScanner()
    redactor = SecretRedactor(scanner)

    text = "This has no secrets at all."
    assert redactor.redact(text) == text
    assert redactor.count == 0


def test_redact_multiple_secrets():
    scanner = SecretScanner()
    redactor = SecretRedactor(scanner)

    text = (
        "aws_key=AKIAIOSFODNN7EXAMPLE\n"
        "github_token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"
    )
    redacted = redactor.redact(text)

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ghp_" not in redacted
    assert redactor.count >= 2

    # Full round-trip
    restored = redactor.unredact(redacted)
    assert restored == text


def test_clear_wipes_secrets():
    scanner = SecretScanner()
    redactor = SecretRedactor(scanner)

    redactor.redact("key=AKIAIOSFODNN7EXAMPLE")
    assert redactor.count == 1

    redactor.clear()
    assert redactor.count == 0
