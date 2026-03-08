"""Configuration with sensible defaults. No database, no migrations, no bloat."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ProviderConfig:
    """Upstream LLM provider."""

    name: str
    base_url: str
    # Optional: override the auth header name (default: Authorization)
    auth_header: str = "Authorization"


# Built-in provider defaults — users can override or add more via config file
DEFAULT_PROVIDERS: dict[str, str] = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
    "ollama": "http://localhost:11434",
}


@dataclass
class Config:
    port: int = 8080
    host: str = "127.0.0.1"
    log_level: str = "info"
    log_format: str = "text"  # "text" or "json"

    # Secret scanning
    signatures_path: Path | None = None  # None = use built-in signatures.yaml
    entropy_threshold: float = 4.0
    mode: str = "redact"  # "redact", "block", or "audit"

    # Providers
    providers: dict[str, ProviderConfig] = field(default_factory=dict)

    # Audit log
    audit_log: Path | None = None  # None = stderr only

    @classmethod
    def load(cls, config_path: Path | None = None) -> Config:
        """Load config with priority: env vars > config file > defaults."""
        cfg = cls()

        # Load from file
        if config_path and config_path.exists():
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}
            cfg = cls._from_dict(data)

        # Env var overrides
        if port := os.environ.get("AIGATE_PORT"):
            cfg.port = int(port)
        if host := os.environ.get("AIGATE_HOST"):
            cfg.host = host
        if mode := os.environ.get("AIGATE_MODE"):
            cfg.mode = mode
        if log_level := os.environ.get("AIGATE_LOG_LEVEL"):
            cfg.log_level = log_level
        if sigs := os.environ.get("AIGATE_SIGNATURES"):
            cfg.signatures_path = Path(sigs)

        # Set up default providers if none configured
        if not cfg.providers:
            cfg.providers = {
                name: ProviderConfig(name=name, base_url=url)
                for name, url in DEFAULT_PROVIDERS.items()
            }

        return cfg

    @classmethod
    def _from_dict(cls, data: dict) -> Config:
        providers = {}
        for name, pdata in data.get("providers", {}).items():
            if isinstance(pdata, str):
                providers[name] = ProviderConfig(name=name, base_url=pdata)
            else:
                providers[name] = ProviderConfig(name=name, **pdata)

        return cls(
            port=data.get("port", cls.port),
            host=data.get("host", cls.host),
            log_level=data.get("log_level", cls.log_level),
            log_format=data.get("log_format", cls.log_format),
            signatures_path=Path(p) if (p := data.get("signatures_path")) else None,
            entropy_threshold=data.get("entropy_threshold", cls.entropy_threshold),
            mode=data.get("mode", cls.mode),
            providers=providers,
            audit_log=Path(p) if (p := data.get("audit_log")) else None,
        )
