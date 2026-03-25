"""Tests for configuration loading and env var overrides."""

from __future__ import annotations

from pathlib import Path

import yaml

from secretgate.config import Config, KnownValuesConfig, ProviderConfig


class TestConfigDefaults:
    def test_default_values(self):
        cfg = Config()
        assert cfg.port == 8080
        assert cfg.host == "127.0.0.1"
        assert cfg.mode == "redact"
        assert cfg.log_level == "info"
        assert cfg.log_format == "text"
        assert cfg.entropy_threshold == 4.0
        assert cfg.use_detect_secrets is False
        assert cfg.enable_known_values is True
        assert cfg.forward_proxy_port is None
        assert cfg.passthrough_domains == []
        assert cfg.audit_log is None
        assert cfg.signatures_path is None

    def test_default_known_values_config(self):
        kv = KnownValuesConfig()
        assert kv.scan_env is True
        assert kv.min_length == 8
        assert kv.entropy_threshold == 2.5
        assert "KEY" in kv.env_keywords
        assert "SECRET" in kv.env_keywords
        assert "PATH" in kv.env_denylist
        assert "HOME" in kv.env_denylist


class TestConfigLoad:
    def test_load_no_file(self):
        cfg = Config.load(None)
        assert cfg.port == 8080
        assert len(cfg.providers) == 3  # openai, anthropic, ollama

    def test_load_default_providers(self):
        cfg = Config.load(None)
        assert "openai" in cfg.providers
        assert "anthropic" in cfg.providers
        assert "ollama" in cfg.providers
        assert cfg.providers["openai"].base_url == "https://api.openai.com"
        assert cfg.providers["anthropic"].base_url == "https://api.anthropic.com"

    def test_load_from_yaml(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "port": 9090,
                    "host": "0.0.0.0",
                    "mode": "block",
                    "log_level": "debug",
                    "entropy_threshold": 3.5,
                    "forward_proxy_port": 8888,
                    "passthrough_domains": ["example.com"],
                    "providers": {
                        "custom": "https://custom.api.com",
                    },
                }
            )
        )
        cfg = Config.load(config_file)
        assert cfg.port == 9090
        assert cfg.host == "0.0.0.0"
        assert cfg.mode == "block"
        assert cfg.log_level == "debug"
        assert cfg.entropy_threshold == 3.5
        assert cfg.forward_proxy_port == 8888
        assert cfg.passthrough_domains == ["example.com"]
        assert "custom" in cfg.providers
        assert cfg.providers["custom"].base_url == "https://custom.api.com"

    def test_load_provider_as_dict(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "providers": {
                        "myapi": {
                            "base_url": "https://myapi.com",
                            "auth_header": "X-Api-Key",
                        },
                    },
                }
            )
        )
        cfg = Config.load(config_file)
        assert cfg.providers["myapi"].base_url == "https://myapi.com"
        assert cfg.providers["myapi"].auth_header == "X-Api-Key"

    def test_load_known_values_config(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "known_values": {
                        "scan_env": False,
                        "min_length": 12,
                        "entropy_threshold": 3.0,
                        "secret_files": ["/path/to/.env"],
                    },
                }
            )
        )
        cfg = Config.load(config_file)
        assert cfg.known_values.scan_env is False
        assert cfg.known_values.min_length == 12
        assert cfg.known_values.entropy_threshold == 3.0
        assert cfg.known_values.secret_files == ["/path/to/.env"]


class TestConfigEnvOverrides:
    def test_port_override(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_PORT", "7777")
        cfg = Config.load(None)
        assert cfg.port == 7777

    def test_host_override(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_HOST", "0.0.0.0")
        cfg = Config.load(None)
        assert cfg.host == "0.0.0.0"

    def test_mode_override(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_MODE", "block")
        cfg = Config.load(None)
        assert cfg.mode == "block"

    def test_log_level_override(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_LOG_LEVEL", "debug")
        cfg = Config.load(None)
        assert cfg.log_level == "debug"

    def test_signatures_override(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_SIGNATURES", "/custom/sigs.yaml")
        cfg = Config.load(None)
        assert cfg.signatures_path == Path("/custom/sigs.yaml")

    def test_detect_secrets_override(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_DETECT_SECRETS", "true")
        cfg = Config.load(None)
        assert cfg.use_detect_secrets is True

    def test_known_values_disable(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_KNOWN_VALUES", "false")
        cfg = Config.load(None)
        assert cfg.enable_known_values is False

    def test_forward_proxy_port_override(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_FORWARD_PROXY_PORT", "9999")
        cfg = Config.load(None)
        assert cfg.forward_proxy_port == 9999

    def test_certs_dir_override(self, monkeypatch):
        monkeypatch.setenv("SECRETGATE_CERTS_DIR", "/tmp/my-certs")
        cfg = Config.load(None)
        assert cfg.certs_dir == Path("/tmp/my-certs")

    def test_env_overrides_config_file(self, tmp_path, monkeypatch):
        """Env vars should take priority over config file values."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({"port": 9090, "mode": "audit"}))
        monkeypatch.setenv("SECRETGATE_PORT", "5555")
        cfg = Config.load(config_file)
        assert cfg.port == 5555  # env wins
        assert cfg.mode == "audit"  # config file value preserved


class TestProviderConfig:
    def test_defaults(self):
        p = ProviderConfig(name="test", base_url="https://test.com")
        assert p.auth_header == "Authorization"

    def test_custom_auth_header(self):
        p = ProviderConfig(name="test", base_url="https://test.com", auth_header="X-Key")
        assert p.auth_header == "X-Key"
