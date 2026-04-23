"""Configuration for the AISG Gateway (self-hosted).

All settings can be overridden via environment variables or a .env file.
For provider API keys and DLP policy, use config.yaml (see config/gateway.yaml).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    presidio_url: str = "http://presidio:3000"

    default_provider: str = "groq"
    default_model: str = "llama-3.3-70b-versatile"

    upstream_timeout_seconds: int = 60

    log_level: str = "info"
    cors_origins: str = "*"
    port: int = 8000

    rate_limit_rps: int = 10

    max_body_bytes: int = 50 * 1024 * 1024

    config_path: str = "/app/config/gateway.yaml"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache
def get_settings() -> Settings:
    """Return the cached Settings singleton."""
    return Settings()


def _resolve_env_vars(value: Any) -> Any:
    """Recursively resolve ${ENV_VAR} and ${ENV_VAR:-default} patterns in strings."""
    if isinstance(value, str):
        import re
        def _replacer(m: re.Match) -> str:
            var = m.group(1)
            if ":-" in var:
                name, default = var.split(":-", 1)
                return os.environ.get(name.strip(), default)
            return os.environ.get(var.strip(), m.group(0))
        return re.sub(r"\$\{([^}]+)\}", _replacer, value)
    if isinstance(value, dict):
        return {k: _resolve_env_vars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_vars(v) for v in value]
    return value


_gateway_config: dict[str, Any] | None = None


def get_gateway_config() -> dict[str, Any]:
    """Load and cache config/gateway.yaml with env var substitution."""
    global _gateway_config
    if _gateway_config is not None:
        return _gateway_config

    config_path = Path(get_settings().config_path)
    if not config_path.exists():
        env_path = os.environ.get("AISG_CONFIG_PATH")
        if env_path:
            config_path = Path(env_path)

    if config_path.exists():
        with open(config_path) as f:
            raw = yaml.safe_load(f)
        _gateway_config = _resolve_env_vars(raw or {})
    else:
        _gateway_config = {}

    return _gateway_config


def get_provider_keys() -> dict[str, str]:
    """Return provider_name -> api_key from gateway.yaml providers section."""
    cfg = get_gateway_config()
    providers = cfg.get("providers", {})
    keys: dict[str, str] = {}
    for name, provider_cfg in providers.items():
        if isinstance(provider_cfg, dict) and provider_cfg.get("api_key"):
            keys[name] = provider_cfg["api_key"]
    return keys


def get_api_keys() -> list[dict[str, Any]]:
    """Return the list of configured API keys from gateway.yaml."""
    cfg = get_gateway_config()
    return cfg.get("api_keys", [])


def get_dlp_policy() -> dict[str, Any]:
    """Return the DLP policy from gateway.yaml."""
    cfg = get_gateway_config()
    return cfg.get("dlp", {})
