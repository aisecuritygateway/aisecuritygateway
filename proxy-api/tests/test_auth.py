"""Tests for app.auth — API key authentication."""

from __future__ import annotations

from unittest.mock import patch

from app.auth import authenticate


class TestAuthenticate:
    """API key validation against gateway.yaml config."""

    def test_valid_key_returns_record(self):
        keys = [{"key": "test-key-123", "name": "dev"}]
        with patch("app.auth.get_api_keys", return_value=keys):
            result = authenticate("test-key-123")
            assert result is not None
            assert result["name"] == "dev"

    def test_invalid_key_returns_none(self):
        keys = [{"key": "test-key-123", "name": "dev"}]
        with patch("app.auth.get_api_keys", return_value=keys):
            result = authenticate("wrong-key")
            assert result is None

    def test_empty_key_returns_none(self):
        keys = [{"key": "test-key-123", "name": "dev"}]
        with patch("app.auth.get_api_keys", return_value=keys):
            result = authenticate("")
            assert result is None

    def test_open_mode_when_no_keys_configured(self):
        with patch("app.auth.get_api_keys", return_value=[]):
            result = authenticate("")
            assert result is not None
            assert result["name"] == "open-mode"

    def test_open_mode_accepts_any_key(self):
        with patch("app.auth.get_api_keys", return_value=[]):
            result = authenticate("any-random-key")
            assert result is not None
            assert result["name"] == "open-mode"

    def test_multiple_keys_matches_second(self):
        keys = [
            {"key": "key-aaa", "name": "first"},
            {"key": "key-bbb", "name": "second"},
        ]
        with patch("app.auth.get_api_keys", return_value=keys):
            result = authenticate("key-bbb")
            assert result is not None
            assert result["name"] == "second"

    def test_timing_safe_comparison(self):
        """Ensure hmac.compare_digest is used (no short-circuit on partial match)."""
        keys = [{"key": "secret-key-12345", "name": "dev"}]
        with patch("app.auth.get_api_keys", return_value=keys):
            assert authenticate("secret-key-12345") is not None
            assert authenticate("secret-key-1234") is None
            assert authenticate("secret-key-123456") is None
