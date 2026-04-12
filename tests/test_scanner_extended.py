"""Extended tests for SecretScanner — covers more secret types, edge cases,
deduplication, entropy detection, and multi-line scanning.
"""

from __future__ import annotations

import pytest

from secretgate.secrets.scanner import SecretScanner


@pytest.fixture
def scanner():
    """Scanner with default settings (entropy enabled, known-values disabled)."""
    return SecretScanner(enable_known_values=False)


@pytest.fixture
def scanner_no_entropy():
    """Scanner with entropy detection disabled."""
    return SecretScanner(enable_entropy=False, enable_known_values=False)


# ---------------------------------------------------------------------------
# Regex pattern detection
# ---------------------------------------------------------------------------

class TestRegexDetection:
    """Test that various secret formats are detected by regex patterns."""

    def test_aws_access_key(self, scanner):
        matches = scanner.scan("AKIAIOSFODNN7EXAMPLE")
        assert any(m.service == "Amazon" for m in matches)

    def test_aws_secret_key(self, scanner):
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        matches = scanner.scan(text)
        assert any("Amazon" in m.service for m in matches)

    def test_github_pat_classic(self, scanner):
        # Pattern requires exactly 36 alphanumeric chars after ghp_
        token = "ghp_" + "A" * 36
        matches = scanner.scan(token)
        assert any(m.service == "GitHub" for m in matches)

    def test_github_fine_grained_token(self, scanner):
        token = "github_pat_" + "A" * 22 + "_" + "B" * 59
        matches = scanner.scan(token)
        assert any(m.service == "GitHub" for m in matches)

    def test_gitlab_pat(self, scanner):
        matches = scanner.scan("glpat-ABCDEFGHIJKLMNOPqrst")
        assert any("GitLab" in m.service for m in matches)

    def test_slack_bot_token(self, scanner):
        # Pattern: xoxb-{11 digits}-{11 digits}-{24 alphanum}
        token = "xoxb-12345678901-12345678901-" + "A" * 24
        matches = scanner.scan(token)
        assert any("Slack" in m.service for m in matches)

    def test_slack_webhook(self, scanner):
        # Build webhook URL dynamically to avoid GitHub push protection
        prefix = "https://hooks.slack.com/services/"
        path = "T" + "0" * 8 + "/B" + "0" * 8 + "/" + "X" * 24
        matches = scanner.scan(prefix + path)
        assert any("Slack" in m.service for m in matches)

    def test_stripe_secret_key(self, scanner):
        # Build Stripe key dynamically to avoid GitHub push protection
        key = "sk_live_" + "A" * 24
        matches = scanner.scan(key)
        assert any("Stripe" in m.service for m in matches)

    def test_openai_api_key(self, scanner):
        # Build OpenAI key dynamically to avoid push protection
        key = "sk-proj-" + "A" * 48
        matches = scanner.scan(key)
        assert any("OpenAI" in m.service for m in matches)

    def test_private_key_rsa(self, scanner):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        matches = scanner.scan(text)
        assert any("Private Key" in m.pattern_name for m in matches)

    def test_private_key_ec(self, scanner):
        text = "-----BEGIN EC PRIVATE KEY-----\nMHQC..."
        matches = scanner.scan(text)
        assert any("Private Key" in m.pattern_name for m in matches)

    def test_private_key_generic(self, scanner):
        text = "-----BEGIN PRIVATE KEY-----\nMIIE..."
        matches = scanner.scan(text)
        assert any("Private Key" in m.pattern_name for m in matches)

    def test_generic_api_key(self, scanner):
        # Should not detect plain words as secrets
        matches = scanner.scan("The api_key is not set")
        secrets = [m for m in matches if "generic" in m.pattern_name.lower()]
        # Low entropy short strings shouldn't match
        assert not any(m.value == "not" for m in secrets)


# ---------------------------------------------------------------------------
# Entropy detection
# ---------------------------------------------------------------------------

class TestEntropyDetection:
    def test_high_entropy_password(self, scanner):
        text = "DB_PASSWORD=xK9$mL3@pQ7!rT5&wV2*yU8^zA4(bN6)"
        matches = scanner.scan(text)
        entropy_matches = [m for m in matches if m.service == "entropy"]
        assert len(entropy_matches) >= 1

    def test_low_entropy_not_flagged(self, scanner):
        text = "MODE=production\nDEBUG=false\nPORT=8080"
        matches = scanner.scan(text)
        entropy_matches = [m for m in matches if m.service == "entropy"]
        assert len(entropy_matches) == 0

    def test_entropy_disabled(self, scanner_no_entropy):
        text = "SECRET_KEY=aB3$xZ9!kL7@mN5&pQ2*rT8^wV4(yU6)"
        matches = scanner_no_entropy.scan(text)
        entropy_matches = [m for m in matches if m.service == "entropy"]
        assert len(entropy_matches) == 0

    def test_short_values_ignored(self, scanner):
        """Values under 8 chars should not trigger entropy detection."""
        text = "KEY=abc123"  # 6 chars
        matches = scanner.scan(text)
        entropy_matches = [m for m in matches if m.service == "entropy"]
        assert len(entropy_matches) == 0

    def test_boolean_values_ignored(self, scanner):
        """Common boolean/null values should not trigger entropy detection."""
        for val in ("true", "false", "null", "none", "undefined"):
            matches = scanner.scan(f"SETTING={val}")
            entropy_matches = [m for m in matches if m.service == "entropy"]
            assert len(entropy_matches) == 0, f"'{val}' should not trigger entropy"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_secret_twice_on_same_line(self, scanner):
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f"{key} and again {key}"
        matches = scanner.scan(text)
        aws_matches = [m for m in matches if m.service == "Amazon"]
        assert len(aws_matches) == 1  # deduplicated

    def test_same_secret_on_different_lines(self, scanner):
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f"line1: {key}\nline2: {key}"
        matches = scanner.scan(text)
        aws_matches = [m for m in matches if m.service == "Amazon"]
        assert len(aws_matches) == 1

    def test_different_secrets_both_reported(self, scanner):
        ghp = "ghp_" + "A" * 36
        text = f"AKIAIOSFODNN7EXAMPLE {ghp}"
        matches = scanner.scan(text)
        services = {m.service for m in matches}
        assert "Amazon" in services
        assert "GitHub" in services


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string(self, scanner):
        assert scanner.scan("") == []

    def test_whitespace_only(self, scanner):
        assert scanner.scan("   \n\n  \t  ") == []

    def test_very_long_line(self, scanner):
        """Scanner should handle very long lines without crashing."""
        text = "A" * 100_000
        matches = scanner.scan(text)
        assert isinstance(matches, list)

    def test_binary_looking_text(self, scanner):
        """UTF-8 text with unusual chars shouldn't crash."""
        text = "key=\x00\x01\x02 normal text AKIAIOSFODNN7EXAMPLE"
        matches = scanner.scan(text)
        assert any(m.service == "Amazon" for m in matches)

    def test_multiline_secret_context(self, scanner):
        """Secrets embedded in larger multiline text."""
        text = """
        # Configuration file
        database:
          host: localhost
          port: 5432
        aws:
          access_key: AKIAIOSFODNN7EXAMPLE
          region: us-east-1
        """
        matches = scanner.scan(text)
        assert any(m.service == "Amazon" for m in matches)

    def test_match_line_numbers(self, scanner):
        """Match objects should carry correct line numbers."""
        text = "line 1 clean\nline 2 AKIAIOSFODNN7EXAMPLE\nline 3 clean"
        matches = scanner.scan(text)
        aws = [m for m in matches if m.service == "Amazon"]
        assert len(aws) == 1
        assert aws[0].line_number == 2


# ---------------------------------------------------------------------------
# Shannon entropy helper
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_zero_entropy_for_single_char(self):
        assert SecretScanner._entropy("aaaaaaa") == 0.0

    def test_max_entropy_for_unique_chars(self):
        # "ab" → each char has probability 0.5 → entropy = 1.0
        assert abs(SecretScanner._entropy("ab") - 1.0) < 0.001

    def test_empty_string(self):
        assert SecretScanner._entropy("") == 0.0

    def test_high_entropy_string(self):
        # All unique chars → high entropy
        s = "abcdefghijklmnop"
        assert SecretScanner._entropy(s) > 3.5
