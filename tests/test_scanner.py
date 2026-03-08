"""Tests for secret scanning."""

from secretgate.secrets.scanner import SecretScanner


def test_detects_aws_access_key():
    scanner = SecretScanner()
    matches = scanner.scan("my key is AKIAIOSFODNN7EXAMPLE ok")
    assert len(matches) >= 1
    assert any(m.service == "Amazon" for m in matches)


def test_detects_github_pat():
    scanner = SecretScanner()
    text = "export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijij"
    matches = scanner.scan(text)
    assert any(m.service == "GitHub" for m in matches)


def test_detects_private_key():
    scanner = SecretScanner()
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
    matches = scanner.scan(text)
    assert any(m.pattern_name == "Private Key" for m in matches)


def test_detects_high_entropy():
    scanner = SecretScanner()
    text = 'SECRET_KEY=aB3$xZ9!kL7@mN5&pQ2*rT8^wV4(yU6)'
    matches = scanner.scan(text)
    assert any(m.service == "entropy" for m in matches)


def test_ignores_normal_text():
    scanner = SecretScanner()
    matches = scanner.scan("Hello, this is a normal code comment with no secrets.")
    assert len(matches) == 0


def test_ignores_low_entropy_values():
    scanner = SecretScanner()
    matches = scanner.scan("DEBUG=true\nHOST=localhost\nPORT=8080")
    # These are all low-entropy, non-secret values
    assert not any(m.service == "entropy" for m in matches)


def test_multiple_secrets_same_line():
    scanner = SecretScanner()
    text = "AKIAIOSFODNN7EXAMPLE ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    matches = scanner.scan(text)
    assert len(matches) >= 2
