"""Tests for configuration loading and env var overrides."""

from __future__ import annotations

import os
from unittest.mock import patch

import yaml

from secretgate.config import Config


class TestConfigDefaults:
    def test_default_port(self):
        cfg = Config()
        assert cfg.port == 8080

    def test_default_host(self):
        cfg = Config()
        assert cfg.host == "127.0.0.1"

    def test_default_mode(self):
        cfg = Config()
        assert cfg.mode == "redact"

    def test_default_no_forward_proxy(self):
        cfg = Config()
        assert cfg.forward_proxy_port is None

    def test_default_detect_secrets_off(self):
        cfg = Config()
        assert cfg.use_detect_secrets is False


class TestConfigLoad:
    def test_load_with_no_file(self):
        cfg = Config.load(None)
        assert cfg.port == 8080
        # Should have default providers
        assert "openai" in cfg.providers
        assert "anthropic" in cfg.providers

    def test_load_from_yaml(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "port": 9090,
            "mode": "block",
            "forward_proxy_port": 8888,
            "providers": {
                "custom": "https://custom.example.com",
            },
        }))
        cfg = Config.load(config_file)
        assert cfg.port == 9090
        assert cfg.mode == "block"
        assert cfg.forward_proxy_port == 8888
        assert "custom" in cfg.providers
        assert cfg.providers["custom"].base_url == "https://custom.example.com"

    def test_load_provider_with_dict(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "providers": {
                "custom": {
                    "base_url": "https://api.example.com",
                    "auth_header": "X-Api-Key",
                },
            },
        }))
        cfg = Config.load(config_file)
        assert cfg.providers["custom"].auth_header == "X-Api-Key"

    def test_env_var_overrides(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({"port": 9090}))
        env = {
            "SECRETGATE_PORT": "7777",
            "SECRETGATE_MODE": "audit",
            "SECRETGATE_HOST": "0.0.0.0",
            "SECRETGATE_LOG_LEVEL": "debug",
            "SECRETGATE_FORWARD_PROXY_PORT": "9999",
        }
        with patch.dict(os.environ, env):
            cfg = Config.load(config_file)
        assert cfg.port == 7777
        assert cfg.mode == "audit"
        assert cfg.host == "0.0.0.0"
        assert cfg.log_level == "debug"
        assert cfg.forward_proxy_port == 9999

    def test_env_detect_secrets(self):
        with patch.dict(os.environ, {"SECRETGATE_DETECT_SECRETS": "true"}):
            cfg = Config.load(None)
        assert cfg.use_detect_secrets is True

    def test_env_signatures_path(self, tmp_path):
        sigs = tmp_path / "sigs.yaml"
        sigs.write_text("[]")
        with patch.dict(os.environ, {"SECRETGATE_SIGNATURES": str(sigs)}):
            cfg = Config.load(None)
        assert cfg.signatures_path == sigs

    def test_env_certs_dir(self, tmp_path):
        with patch.dict(os.environ, {"SECRETGATE_CERTS_DIR": str(tmp_path)}):
            cfg = Config.load(None)
        assert cfg.certs_dir == tmp_path

    def test_passthrough_domains(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "passthrough_domains": ["example.com", "other.test"],
        }))
        cfg = Config.load(config_file)
        assert cfg.passthrough_domains == ["example.com", "other.test"]

    def test_empty_config_file(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")
        cfg = Config.load(config_file)
        # Should still work with defaults
        assert cfg.port == 8080

    def test_nonexistent_config_file(self, tmp_path):
        # load() with a path that doesn't exist should just use defaults
        cfg = Config.load(tmp_path / "nonexistent.yaml")
        assert cfg.port == 8080
