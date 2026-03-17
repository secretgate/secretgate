"""Tests for new and fixed secret detection patterns."""
import pytest
from secretgate.secrets.scanner import SecretScanner


@pytest.fixture
def scanner():
    return SecretScanner()


# --- GitHub PAT fixes ---

class TestGitHubPatterns:
    def test_fine_grained_pat_short(self, scanner):
        """Fine-grained PATs with varying lengths should be detected."""
        # Real-world PATs are not always exactly 82 chars
        token = "github_pat_11ABCDEF0_" + "a" * 40
        matches = scanner.scan(token)
        assert any("Fine-grained PAT" in m.pattern_name for m in matches), \
            "Short fine-grained PAT should be detected"

    def test_fine_grained_pat_long(self, scanner):
        """Standard 82-char fine-grained PATs still detected."""
        token = "github_pat_" + "A" * 82
        matches = scanner.scan(token)
        assert any("Fine-grained PAT" in m.pattern_name for m in matches)

    def test_classic_pat_still_works(self, scanner):
        """Classic PATs (ghp_) still detected."""
        token = "ghp_" + "a" * 36
        matches = scanner.scan(token)
        assert any("Personal Access Token" in m.pattern_name for m in matches)


# --- OpenAI Project Key fixes ---

class TestOpenAIPatterns:
    def test_project_key_short(self, scanner):
        """sk-proj- keys with 40+ chars should be detected."""
        key = "sk-proj-" + "a" * 40
        matches = scanner.scan(key)
        assert any("Project Key" in m.pattern_name for m in matches), \
            "Short sk-proj key should be detected"

    def test_project_key_long(self, scanner):
        """Long sk-proj- keys (real format) still detected."""
        key = "sk-proj-" + "aB1-_" * 30  # 150 chars
        matches = scanner.scan(key)
        assert any("Project Key" in m.pattern_name for m in matches)

    def test_classic_key_still_works(self, scanner):
        """Classic sk- keys (T3BlbkFJ format) still detected."""
        key = "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20
        matches = scanner.scan(key)
        assert any("API Key" in m.pattern_name for m in matches)


# --- New AI provider patterns ---

class TestGroqPatterns:
    def test_api_key_detected(self, scanner):
        key = "gsk_" + "a" * 52
        matches = scanner.scan(key)
        assert any("Groq" in m.service for m in matches)

    def test_no_false_positive_short(self, scanner):
        key = "gsk_short"
        matches = scanner.scan(key)
        assert not any("Groq" in m.service for m in matches)


class TestOpenRouterPatterns:
    def test_api_key_detected(self, scanner):
        key = "sk-or-v1-" + "a" * 64
        matches = scanner.scan(key)
        assert any("OpenRouter" in m.service for m in matches)


class TestElevenLabsPatterns:
    def test_api_key_detected(self, scanner):
        key = "sk_" + "a" * 48
        matches = scanner.scan(key)
        assert any("ElevenLabs" in m.service for m in matches)


class TestFireworksPatterns:
    def test_api_key_detected(self, scanner):
        key = "fw_" + "a" * 40
        matches = scanner.scan(key)
        assert any("Fireworks" in m.service for m in matches)


# --- Regression tests: existing patterns still work ---

class TestExistingPatternsRegression:
    def test_aws_access_key(self, scanner):
        matches = scanner.scan("AKIAIOSFODNN7EXAMPLE")
        assert any("Amazon" in m.service for m in matches)

    def test_anthropic_key(self, scanner):
        key = "sk-ant-" + "a" * 80
        matches = scanner.scan(key)
        assert any("Anthropic" in m.service for m in matches)

    def test_stripe_key(self, scanner):
        key = "sk_live_" + "a" * 24
        matches = scanner.scan(key)
        assert any("Stripe" in m.service for m in matches)

    def test_clean_text_no_false_positive(self, scanner):
        text = "Hello world, no secrets here! Just a normal message."
        matches = scanner.scan(text)
        assert len(matches) == 0
