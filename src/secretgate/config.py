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
class KnownValuesConfig:
    """Configuration for known-value secret harvesting."""

    scan_env: bool = True
    env_keywords: tuple[str, ...] = (
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "CREDENTIAL",
        "AUTH",
        "PRIVATE",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PASSPHRASE",
    )
    env_denylist: tuple[str, ...] = (
        "PATH",
        "HOME",
        "SHELL",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "USER",
        "LOGNAME",
        "PWD",
        "OLDPWD",
        "EDITOR",
        "VISUAL",
        "DISPLAY",
        "HOSTNAME",
        "SHLVL",
        "TMPDIR",
        "TMP",
        "TEMP",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "COLORTERM",
        "TERM_PROGRAM",
        "LS_COLORS",
        "_",
    )
    secret_files: list[str] = field(default_factory=list)
    min_length: int = 8
    entropy_threshold: float = 2.5


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
    use_detect_secrets: bool = False  # opt-in: pip install secretgate[detect-secrets]
    enable_known_values: bool = True
    known_values: KnownValuesConfig = field(default_factory=KnownValuesConfig)

    # Providers
    providers: dict[str, ProviderConfig] = field(default_factory=dict)

    # Forward proxy
    forward_proxy_port: int | None = None  # None = disabled
    certs_dir: Path = field(default_factory=lambda: Path.home() / ".secretgate" / "certs")
    passthrough_domains: list[str] = field(default_factory=list)

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
        if port := os.environ.get("SECRETGATE_PORT"):
            cfg.port = int(port)
        if host := os.environ.get("SECRETGATE_HOST"):
            cfg.host = host
        if mode := os.environ.get("SECRETGATE_MODE"):
            cfg.mode = mode
        if log_level := os.environ.get("SECRETGATE_LOG_LEVEL"):
            cfg.log_level = log_level
        if sigs := os.environ.get("SECRETGATE_SIGNATURES"):
            cfg.signatures_path = Path(sigs)
        if os.environ.get("SECRETGATE_DETECT_SECRETS", "").lower() in ("1", "true", "yes"):
            cfg.use_detect_secrets = True
        if os.environ.get("SECRETGATE_KNOWN_VALUES", "").lower() in ("0", "false", "no"):
            cfg.enable_known_values = False
        if fpp := os.environ.get("SECRETGATE_FORWARD_PROXY_PORT"):
            cfg.forward_proxy_port = int(fpp)
        if certs := os.environ.get("SECRETGATE_CERTS_DIR"):
            cfg.certs_dir = Path(certs)

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

        # Parse known_values config
        kv_data = data.get("known_values", {})
        kv_config = KnownValuesConfig(
            scan_env=kv_data.get("scan_env", KnownValuesConfig.scan_env),
            secret_files=kv_data.get("secret_files", []),
            min_length=kv_data.get("min_length", KnownValuesConfig.min_length),
            entropy_threshold=kv_data.get("entropy_threshold", KnownValuesConfig.entropy_threshold),
        )

        return cls(
            port=data.get("port", cls.port),
            host=data.get("host", cls.host),
            log_level=data.get("log_level", cls.log_level),
            log_format=data.get("log_format", cls.log_format),
            signatures_path=Path(p) if (p := data.get("signatures_path")) else None,
            entropy_threshold=data.get("entropy_threshold", cls.entropy_threshold),
            mode=data.get("mode", cls.mode),
            use_detect_secrets=data.get("use_detect_secrets", cls.use_detect_secrets),
            enable_known_values=data.get("enable_known_values", cls.enable_known_values),
            known_values=kv_config,
            providers=providers,
            forward_proxy_port=data.get("forward_proxy_port"),
            certs_dir=Path(p)
            if (p := data.get("certs_dir"))
            else Path.home() / ".secretgate" / "certs",
            passthrough_domains=data.get("passthrough_domains", []),
            audit_log=Path(p) if (p := data.get("audit_log")) else None,
        )
