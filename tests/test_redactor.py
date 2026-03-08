"""Tests for secret redaction and unredaction."""

from secretgate.secrets.scanner import SecretScanner
from secretgate.secrets.redactor import SecretRedactor, _slugify


def test_redact_and_unredact():
    scanner = SecretScanner()
    redactor = SecretRedactor(scanner)

    original = "Use this key: AKIAIOSFODNN7EXAMPLE to authenticate."
    redacted = redactor.redact(original)

    # Secret should be replaced with a self-documenting placeholder
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "REDACTED<aws-access-key:" in redacted

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

    text = "aws_key=AKIAIOSFODNN7EXAMPLE\ngithub_token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n"
    redacted = redactor.redact(text)

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "ghp_" not in redacted
    assert redactor.count >= 2

    # Full round-trip
    restored = redactor.unredact(redacted)
    assert restored == text


def test_same_secret_gets_same_placeholder():
    scanner = SecretScanner()
    redactor = SecretRedactor(scanner)

    text = "first=AKIAIOSFODNN7EXAMPLE\nsecond=AKIAIOSFODNN7EXAMPLE\n"
    redacted = redactor.redact(text)
    lines = redacted.strip().splitlines()

    # Both lines should use the same placeholder
    placeholder_1 = lines[0].split("=", 1)[1]
    placeholder_2 = lines[1].split("=", 1)[1]
    assert placeholder_1 == placeholder_2
    assert "REDACTED<" in placeholder_1

    # Only one entry in the store
    assert redactor.count == 1

    # Round-trip still works
    assert redactor.unredact(redacted) == text


def test_placeholder_format_is_self_documenting():
    scanner = SecretScanner()
    redactor = SecretRedactor(scanner)

    redacted = redactor.redact("key=AKIAIOSFODNN7EXAMPLE")
    # Should contain the pattern type and a hash
    assert "REDACTED<aws-access-key:" in redacted
    # Hash should be 12 hex chars
    import re

    assert re.search(r"REDACTED<aws-access-key:[0-9a-f]{12}>", redacted)


def test_placeholder_is_deterministic():
    scanner = SecretScanner()
    r1 = SecretRedactor(scanner)
    r2 = SecretRedactor(scanner)

    text = "key=AKIAIOSFODNN7EXAMPLE"
    # Two separate redactor instances produce the same placeholder
    assert r1.redact(text) == r2.redact(text)


def test_slugify():
    assert _slugify("AWS Access Key") == "aws-access-key"
    assert _slugify("Personal Access Token") == "personal-access-token"
    assert _slugify("high-entropy value (SECRET_KEY)") == "high-entropy-value-secret-key"
    assert _slugify("  Private Key  ") == "private-key"


def test_clear_wipes_secrets():
    scanner = SecretScanner()
    redactor = SecretRedactor(scanner)

    redactor.redact("key=AKIAIOSFODNN7EXAMPLE")
    assert redactor.count == 1

    redactor.clear()
    assert redactor.count == 0
