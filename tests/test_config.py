"""Tests for configuration loading and env var overrides."""

from __future__ import annotations


import yaml

from secretgate.config import Config


class TestConfigDefaults:
    """Default configuration values."""

    def test_default_port(self):
        cfg = Config()
        assert cfg.port == 8080

    def test_default_host(self):
        cfg = Config()
        assert cfg.host == "127.0.0.1"

    def test_default_mode(self):
        cfg = Config()
        assert cfg.mode == "redact"

    def test_default_known_values_enabled(self):
        cfg = Config()
        assert cfg.enable_known_values is True

    def test_default_forward_proxy_disabled(self):
        cfg = Config()
        assert cfg.forward_proxy_port is None


class TestConfigFromDict:
    """Loading config from a dict (simulates YAML file)."""

    def test_basic_fields(self):
        cfg = Config._from_dict({
            "port": 9090,
            "host": "0.0.0.0",
            "mode": "block",
            "log_level": "debug",
        })
        assert cfg.port == 9090
        assert cfg.host == "0.0.0.0"
        assert cfg.mode == "block"
        assert cfg.log_level == "debug"

    def test_providers_string_shorthand(self):
        cfg = Config._from_dict({
            "providers": {"custom": "http://localhost:1234"}
        })
        assert "custom" in cfg.providers
        assert cfg.providers["custom"].base_url == "http://localhost:1234"

    def test_providers_dict_form(self):
        cfg = Config._from_dict({
            "providers": {
                "custom": {"base_url": "http://localhost:1234", "auth_header": "X-API-Key"}
            }
        })
        assert cfg.providers["custom"].auth_header == "X-API-Key"

    def test_known_values_config(self):
        cfg = Config._from_dict({
            "known_values": {
                "scan_env": False,
                "min_length": 12,
                "entropy_threshold": 3.0,
                "secret_files": ["/tmp/secrets.env"],
            }
        })
        assert cfg.known_values.scan_env is False
        assert cfg.known_values.min_length == 12
        assert cfg.known_values.entropy_threshold == 3.0
        assert cfg.known_values.secret_files == ["/tmp/secrets.env"]

    def test_forward_proxy_port(self):
        cfg = Config._from_dict({"forward_proxy_port": 8083})
        assert cfg.forward_proxy_port == 8083

    def test_passthrough_domains(self):
        cfg = Config._from_dict({"passthrough_domains": ["example.com", "internal.corp"]})
        assert cfg.passthrough_domains == ["example.com", "internal.corp"]


class TestConfigLoad:
    """Config.load() with file and env var overrides."""

    def test_load_from_yaml(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml.dump({"port": 7777, "mode": "audit"}))
        cfg = Config.load(cfg_file)
        assert cfg.port == 7777
        assert cfg.mode == "audit"

    def test_env_var_overrides(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_PORT", "6666")
        monkeypatch.setenv("SECRETGATE_MODE", "block")
        monkeypatch.setenv("SECRETGATE_HOST", "0.0.0.0")
        cfg = Config.load()
        assert cfg.port == 6666
        assert cfg.mode == "block"
        assert cfg.host == "0.0.0.0"

    def test_env_disable_known_values(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_KNOWN_VALUES", "false")
        cfg = Config.load()
        assert cfg.enable_known_values is False

    def test_env_forward_proxy_port(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_FORWARD_PROXY_PORT", "9083")
        cfg = Config.load()
        assert cfg.forward_proxy_port == 9083

    def test_default_providers_when_none_configured(self):
        cfg = Config.load()
        assert "openai" in cfg.providers
        assert "anthropic" in cfg.providers
        assert "ollama" in cfg.providers

    def test_load_nonexistent_file(self, tmp_path):
        """Loading a non-existent config file uses defaults."""
        cfg = Config.load(tmp_path / "nope.yaml")
        assert cfg.port == 8080
