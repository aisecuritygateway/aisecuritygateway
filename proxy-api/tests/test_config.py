"""Tests for app.config — Settings, env var resolution, and gateway.yaml loading."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from app.config import Settings, _resolve_env_vars, get_gateway_config, get_provider_keys, get_api_keys, get_dlp_policy


# ── Settings defaults ─────────────────────────────────────────────────────────

class TestSettingsDefaults:
    """Verify that Settings loads sane defaults without any env vars."""

    def test_default_presidio_url(self):
        s = Settings()
        assert s.presidio_url == "http://presidio:3000"

    def test_default_provider_and_model(self):
        s = Settings()
        assert s.default_provider == "groq"
        assert "llama" in s.default_model.lower()

    def test_default_rate_limit(self):
        s = Settings()
        assert s.rate_limit_rps == 10

    def test_default_max_body_bytes(self):
        s = Settings()
        assert s.max_body_bytes == 50 * 1024 * 1024

    def test_default_log_level(self):
        s = Settings()
        assert s.log_level == "info"

    def test_env_override(self):
        with patch.dict(os.environ, {"PRESIDIO_URL": "http://custom:9999"}):
            s = Settings()
            assert s.presidio_url == "http://custom:9999"


# ── _resolve_env_vars ─────────────────────────────────────────────────────────

class TestResolveEnvVars:
    """Recursive ${VAR} and ${VAR:-default} substitution."""

    def test_simple_env_var(self):
        with patch.dict(os.environ, {"MY_KEY": "secret123"}):
            assert _resolve_env_vars("${MY_KEY}") == "secret123"

    def test_env_var_with_default_uses_env(self):
        with patch.dict(os.environ, {"MY_KEY": "from_env"}):
            assert _resolve_env_vars("${MY_KEY:-fallback}") == "from_env"

    def test_env_var_with_default_uses_fallback(self):
        env = os.environ.copy()
        env.pop("MISSING_KEY_XYZ", None)
        with patch.dict(os.environ, env, clear=True):
            assert _resolve_env_vars("${MISSING_KEY_XYZ:-fallback}") == "fallback"

    def test_unset_var_without_default_preserved(self):
        env = os.environ.copy()
        env.pop("TOTALLY_MISSING", None)
        with patch.dict(os.environ, env, clear=True):
            assert _resolve_env_vars("${TOTALLY_MISSING}") == "${TOTALLY_MISSING}"

    def test_recursive_dict(self):
        with patch.dict(os.environ, {"A": "1", "B": "2"}):
            result = _resolve_env_vars({"x": "${A}", "y": "${B}"})
            assert result == {"x": "1", "y": "2"}

    def test_recursive_list(self):
        with patch.dict(os.environ, {"V": "val"}):
            result = _resolve_env_vars(["${V}", "literal"])
            assert result == ["val", "literal"]

    def test_non_string_passthrough(self):
        assert _resolve_env_vars(42) == 42
        assert _resolve_env_vars(True) is True
        assert _resolve_env_vars(None) is None


# ── get_gateway_config ────────────────────────────────────────────────────────

class TestGetGatewayConfig:
    """Loading and caching gateway.yaml."""

    def test_returns_dict(self):
        import app.config as cfg
        cfg._gateway_config = None
        result = get_gateway_config()
        assert isinstance(result, dict)

    def test_missing_file_returns_empty(self, tmp_path):
        import app.config as cfg
        cfg._gateway_config = None
        with patch.object(cfg, "get_settings") as mock_settings:
            mock_settings.return_value = Settings(config_path=str(tmp_path / "nonexistent.yaml"))
            env = os.environ.copy()
            env.pop("AISG_CONFIG_PATH", None)
            with patch.dict(os.environ, env, clear=True):
                result = get_gateway_config()
                assert result == {}
        cfg._gateway_config = None

    def test_valid_yaml_loaded(self, tmp_path):
        import app.config as cfg
        cfg._gateway_config = None
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(textwrap.dedent("""\
            providers:
              groq:
                api_key: "test-key"
            dlp:
              action: block
        """))
        with patch.object(cfg, "get_settings") as mock_settings:
            mock_settings.return_value = Settings(config_path=str(yaml_file))
            result = get_gateway_config()
            assert result["providers"]["groq"]["api_key"] == "test-key"
            assert result["dlp"]["action"] == "block"
        cfg._gateway_config = None


# ── get_provider_keys / get_api_keys / get_dlp_policy ─────────────────────────

class TestConfigHelpers:
    """Derived helpers that read from the cached gateway config."""

    def test_get_provider_keys(self):
        import app.config as cfg
        cfg._gateway_config = {
            "providers": {
                "groq": {"api_key": "gsk_abc"},
                "openai": {"api_key": "sk-xyz"},
                "empty": {},
            }
        }
        keys = get_provider_keys()
        assert keys == {"groq": "gsk_abc", "openai": "sk-xyz"}
        cfg._gateway_config = None

    def test_get_api_keys(self):
        import app.config as cfg
        cfg._gateway_config = {"api_keys": [{"key": "k1", "name": "dev"}]}
        result = get_api_keys()
        assert len(result) == 1
        assert result[0]["key"] == "k1"
        cfg._gateway_config = None

    def test_get_dlp_policy(self):
        import app.config as cfg
        cfg._gateway_config = {"dlp": {"action": "redact", "confidence_threshold": 0.5}}
        result = get_dlp_policy()
        assert result["action"] == "redact"
        assert result["confidence_threshold"] == 0.5
        cfg._gateway_config = None

    def test_empty_config_returns_defaults(self):
        import app.config as cfg
        cfg._gateway_config = {}
        assert get_provider_keys() == {}
        assert get_api_keys() == []
        assert get_dlp_policy() == {}
        cfg._gateway_config = None
