"""Tests for known-value secret scanning."""

from __future__ import annotations

import json
import os
from unittest.mock import patch

from secretgate.secrets.known_values import (
    HarvestConfig,
    KnownValueScanner,
    _entropy,
    _harvest_env,
    _parse_env_file,
    _parse_ini_file,
    _parse_json_file,
    _parse_plain_text,
    _parse_toml_file,
)
from secretgate.secrets.scanner import SecretScanner


# --- Entropy helper ---


class TestEntropy:
    def test_empty_string(self):
        assert _entropy("") == 0.0

    def test_low_entropy(self):
        assert _entropy("aaaaaaa") < 1.0

    def test_high_entropy(self):
        assert _entropy("aB3$xZ9!kL") > 3.0


# --- File parsers ---


class TestParseEnvFile:
    def test_basic(self):
        text = "API_KEY=mysecretvalue123\nDB_HOST=localhost"
        result = _parse_env_file(text)
        assert result == {"API_KEY": "mysecretvalue123", "DB_HOST": "localhost"}

    def test_quoted_values(self):
        text = "SECRET=\"double-quoted\"\nTOKEN='single-quoted'"
        result = _parse_env_file(text)
        assert result["SECRET"] == "double-quoted"
        assert result["TOKEN"] == "single-quoted"

    def test_comments_and_blank_lines(self):
        text = "# comment\n\nKEY=value\n  # another comment"
        result = _parse_env_file(text)
        assert result == {"KEY": "value"}

    def test_export_prefix(self):
        text = "export MY_SECRET=hunter2abc"
        result = _parse_env_file(text)
        assert result == {"MY_SECRET": "hunter2abc"}


class TestParseJsonFile:
    def test_basic(self):
        text = json.dumps({"api_key": "secret123456", "count": 42, "nested": {"a": "b"}})
        result = _parse_json_file(text)
        assert result == {"api_key": "secret123456"}

    def test_invalid_json(self):
        assert _parse_json_file("not json") == {}

    def test_non_dict(self):
        assert _parse_json_file("[1, 2, 3]") == {}


class TestParseTomlFile:
    def test_basic(self):
        text = 'api_key = "toml-secret-value"\ncount = 42'
        result = _parse_toml_file(text)
        assert result == {"api_key": "toml-secret-value"}


class TestParseIniFile:
    def test_basic(self):
        text = "[database]\npassword = supersecret123\nhost = localhost"
        result = _parse_ini_file(text)
        assert result["database.password"] == "supersecret123"
        assert result["database.host"] == "localhost"

    def test_invalid(self):
        assert _parse_ini_file("not valid ini {{{") == {}


class TestParsePlainText:
    def test_basic(self):
        text = "first-secret\nsecond-secret\n# comment"
        result = _parse_plain_text(text)
        assert result == {"line-1": "first-secret", "line-2": "second-secret"}

    def test_blank_lines(self):
        text = "\nvalue\n\n"
        result = _parse_plain_text(text)
        assert result == {"line-2": "value"}


# --- Environment harvesting ---


class TestHarvestEnv:
    def test_keyword_match(self):
        env = {"MY_SECRET_KEY": "supersecretvalue123"}
        config = HarvestConfig()
        with patch.dict(os.environ, env, clear=True):
            results = _harvest_env(config)
        assert len(results) == 1
        assert results[0].value == "supersecretvalue123"
        assert results[0].source == "env"
        assert results[0].key_name == "MY_SECRET_KEY"

    def test_denylist(self):
        env = {"PATH": "/usr/bin:/bin", "HOME": "/home/user"}
        config = HarvestConfig()
        with patch.dict(os.environ, env, clear=True):
            results = _harvest_env(config)
        assert len(results) == 0

    def test_secretgate_prefix_skipped(self):
        env = {"SECRETGATE_SECRET_KEY": "supersecretvalue123"}
        config = HarvestConfig()
        with patch.dict(os.environ, env, clear=True):
            results = _harvest_env(config)
        assert len(results) == 0

    def test_min_length(self):
        env = {"API_KEY": "short"}
        config = HarvestConfig(min_length=8)
        with patch.dict(os.environ, env, clear=True):
            results = _harvest_env(config)
        assert len(results) == 0

    def test_low_entropy_skipped(self):
        env = {"API_KEY": "aaaaaaaaaa"}
        config = HarvestConfig()
        with patch.dict(os.environ, env, clear=True):
            results = _harvest_env(config)
        assert len(results) == 0

    def test_no_keyword_skipped(self):
        env = {"MY_VARIABLE": "supersecretvalue123"}
        config = HarvestConfig()
        with patch.dict(os.environ, env, clear=True):
            results = _harvest_env(config)
        assert len(results) == 0


# --- File harvesting ---


class TestHarvestFile:
    def test_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DB_PASSWORD=MyS3cretP@ssw0rd\nHOST=localhost\n")
        config = HarvestConfig(secret_files=[str(env_file)])
        scanner = KnownValueScanner(config)
        # Should harvest the password (high entropy, long enough)
        assert scanner.value_count >= 1

    def test_json_file(self, tmp_path):
        json_file = tmp_path / "secrets.json"
        json_file.write_text(json.dumps({"api_token": "tk_live_abcdef123456"}))
        config = HarvestConfig(scan_env=False, secret_files=[str(json_file)])
        scanner = KnownValueScanner(config)
        assert scanner.value_count >= 1

    def test_toml_file(self, tmp_path):
        toml_file = tmp_path / "config.toml"
        toml_file.write_text('secret = "toml_s3cret_v@lue_123"')
        config = HarvestConfig(scan_env=False, secret_files=[str(toml_file)])
        scanner = KnownValueScanner(config)
        assert scanner.value_count >= 1

    def test_ini_file(self, tmp_path):
        ini_file = tmp_path / "config.ini"
        ini_file.write_text("[auth]\npassword = MyS3cretP@ssw0rd")
        config = HarvestConfig(scan_env=False, secret_files=[str(ini_file)])
        scanner = KnownValueScanner(config)
        assert scanner.value_count >= 1

    def test_plain_text_file(self, tmp_path):
        txt_file = tmp_path / "secrets.txt"
        txt_file.write_text("sk_live_abcdef123456\ngh_pat_xyzw987654ab\n")
        config = HarvestConfig(scan_env=False, secret_files=[str(txt_file)])
        scanner = KnownValueScanner(config)
        assert scanner.value_count >= 1

    def test_missing_file(self):
        config = HarvestConfig(scan_env=False, secret_files=["/nonexistent/file"])
        scanner = KnownValueScanner(config)
        assert scanner.value_count == 0


# --- Scanning ---


class TestKnownValueScanner:
    def _make_scanner(self, values: dict[str, str]) -> KnownValueScanner:
        """Create a scanner with env vars as known values."""
        config = HarvestConfig(scan_env=True)
        with patch.dict(os.environ, values, clear=True):
            return KnownValueScanner(config)

    def test_basic_detection(self):
        scanner = self._make_scanner({"MY_API_KEY": "xK9mP2nQ7rT4wZ8a"})
        matches = scanner.scan("the key is xK9mP2nQ7rT4wZ8a here")
        assert len(matches) == 1
        assert matches[0].service == "known-value"
        assert matches[0].pattern_name == "MY_API_KEY"
        assert matches[0].value == "xK9mP2nQ7rT4wZ8a"

    def test_match_fields(self):
        scanner = self._make_scanner({"SECRET_TOKEN": "abcdefghijklmnop"})
        matches = scanner.scan("token=abcdefghijklmnop")
        assert len(matches) == 1
        m = matches[0]
        assert m.line_number == 1
        assert m.start == 6
        assert m.end == 22

    def test_multiline(self):
        scanner = self._make_scanner({"SECRET_TOKEN": "xK9mP2nQ7rT4wZ8a"})
        text = "line one\nthe secret is xK9mP2nQ7rT4wZ8a\nline three"
        matches = scanner.scan(text)
        assert len(matches) == 1
        assert matches[0].line_number == 2

    def test_multiple_values(self):
        scanner = self._make_scanner(
            {
                "API_KEY": "xK9mP2nQ7rT4wZ8a",
                "SECRET_TOKEN": "yL0nP3oR8sU5xA9b",
            }
        )
        text = "key=xK9mP2nQ7rT4wZ8a token=yL0nP3oR8sU5xA9b"
        matches = scanner.scan(text)
        assert len(matches) == 2

    def test_no_match(self):
        scanner = self._make_scanner({"API_KEY": "xK9mP2nQ7rT4wZ8a"})
        matches = scanner.scan("nothing secret here at all")
        assert len(matches) == 0

    def test_empty_scanner(self):
        config = HarvestConfig(scan_env=False, secret_files=[])
        scanner = KnownValueScanner(config)
        assert scanner.scan("any text") == []

    def test_dedup_same_value(self):
        scanner = self._make_scanner({"API_KEY": "xK9mP2nQ7rT4wZ8a"})
        text = "first xK9mP2nQ7rT4wZ8a second xK9mP2nQ7rT4wZ8a"
        matches = scanner.scan(text)
        # Should deduplicate: only one match per value
        assert len(matches) == 1


# --- Naive fallback ---


class TestNaiveFallback:
    def test_scan_without_ahocorasick(self):
        """Force naive fallback by mocking import failure."""
        config = HarvestConfig(scan_env=True)
        env = {"MY_SECRET_KEY": "xK9mP2nQ7rT4wZ8a"}
        with patch.dict(os.environ, env, clear=True):
            scanner = KnownValueScanner(config)

        # Force fallback by clearing automaton
        scanner._automaton = None

        matches = scanner.scan("the secret is xK9mP2nQ7rT4wZ8a")
        assert len(matches) == 1
        assert matches[0].value == "xK9mP2nQ7rT4wZ8a"
        assert matches[0].service == "known-value"


# --- Integration with SecretScanner ---


class TestIntegration:
    def test_merged_results(self):
        """Known-value matches merge with regex matches."""
        env = {"CUSTOM_SECRET_TOKEN": "myCustomS3cretValu3"}
        config = HarvestConfig(scan_env=True)
        with patch.dict(os.environ, env, clear=True):
            scanner = SecretScanner(
                enable_entropy=False,
                enable_known_values=True,
                known_values_config=config,
            )
        text = "token is myCustomS3cretValu3"
        matches = scanner.scan(text)
        kv_matches = [m for m in matches if m.service == "known-value"]
        assert len(kv_matches) == 1

    def test_regex_takes_priority(self):
        """If regex already found a value, known-values should not duplicate it."""
        # AKIA... is a well-known AWS key pattern
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        env = {"AWS_ACCESS_KEY_ID": aws_key}
        config = HarvestConfig(scan_env=True)
        with patch.dict(os.environ, env, clear=True):
            scanner = SecretScanner(
                enable_entropy=False,
                enable_known_values=True,
                known_values_config=config,
            )
        text = f"key={aws_key}"
        matches = scanner.scan(text)
        # Should have exactly one match (regex), not two
        values = [m.value for m in matches]
        assert values.count(aws_key) == 1
        # The match should be from regex, not known-value
        aws_match = [m for m in matches if m.value == aws_key][0]
        assert aws_match.service != "known-value"

    def test_disable_flag(self):
        """enable_known_values=False should skip known-value scanning."""
        env = {"CUSTOM_SECRET_TOKEN": "myCustomS3cretValu3"}
        config = HarvestConfig(scan_env=True)
        with patch.dict(os.environ, env, clear=True):
            scanner = SecretScanner(
                enable_entropy=False,
                enable_known_values=False,
                known_values_config=config,
            )
        text = "token is myCustomS3cretValu3"
        matches = scanner.scan(text)
        kv_matches = [m for m in matches if m.service == "known-value"]
        assert len(kv_matches) == 0

    def test_end_to_end_with_redactor(self):
        """Known-value secrets get redacted with proper placeholders."""
        from secretgate.secrets.redactor import SecretRedactor

        env = {"MY_SECRET_TOKEN": "xK9mP2nQ7rT4wZ8a"}
        config = HarvestConfig(scan_env=True)
        with patch.dict(os.environ, env, clear=True):
            scanner = SecretScanner(
                enable_entropy=False,
                enable_known_values=True,
                known_values_config=config,
            )
        redactor = SecretRedactor(scanner)
        text = "the token is xK9mP2nQ7rT4wZ8a"
        result = redactor.redact(text)
        assert "xK9mP2nQ7rT4wZ8a" not in result
        assert "REDACTED<" in result


# --- Memory ---


class TestClear:
    def test_clear_overwrites(self):
        env = {"MY_SECRET_KEY": "xK9mP2nQ7rT4wZ8a"}
        config = HarvestConfig(scan_env=True)
        with patch.dict(os.environ, env, clear=True):
            scanner = KnownValueScanner(config)
        assert scanner.value_count == 1
        scanner.clear()
        assert scanner.value_count == 0
        assert scanner.scan("xK9mP2nQ7rT4wZ8a") == []


# --- Config ---


class TestConfigDefaults:
    def test_defaults(self):
        config = HarvestConfig()
        assert config.scan_env is True
        assert config.min_length == 8
        assert config.entropy_threshold == 2.5
        assert "KEY" in config.env_keywords
        assert "PATH" in config.env_denylist

    def test_custom_values(self):
        config = HarvestConfig(
            scan_env=False,
            min_length=12,
            entropy_threshold=3.0,
        )
        assert config.scan_env is False
        assert config.min_length == 12
        assert config.entropy_threshold == 3.0
