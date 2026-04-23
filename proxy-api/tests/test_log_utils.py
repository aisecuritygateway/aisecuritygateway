"""Tests for app.log_utils — key masking and log scrubbing."""

from __future__ import annotations

from app.log_utils import mask_key, _scrub_value, log_scrubber


class TestMaskKey:
    """mask_key() truncation behavior."""

    def test_short_key(self):
        assert mask_key("abcd") == "abcd..."

    def test_exactly_12_chars(self):
        assert mask_key("123456789012") == "1234..."

    def test_long_key(self):
        result = mask_key("sk-abcdefghijklmnop")
        assert result.startswith("sk-abc")
        assert result.endswith("mnop")
        assert "..." in result

    def test_empty_key(self):
        result = mask_key("")
        assert result == "..."


class TestScrubValue:
    """_scrub_value() masks secrets in nested structures."""

    def test_scrubs_openai_key(self):
        result = _scrub_value("My key is sk-abcdefghijklmnopqrstuvwxyz")
        assert "sk-abcdefghijklmnopqrstuvwxyz" not in result
        assert "..." in result

    def test_scrubs_anthropic_key(self):
        result = _scrub_value("sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        assert "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZ" not in result

    def test_scrubs_aws_key(self):
        result = _scrub_value("AKIAIOSFODNN7EXAMPLE1")
        assert "AKIAIOSFODNN7EXAMPLE1" not in result

    def test_scrubs_groq_key(self):
        result = _scrub_value("gsk_abcdefghijklmnopqrstuvwxyz")
        assert "gsk_abcdefghijklmnopqrstuvwxyz" not in result

    def test_scrubs_bearer_token(self):
        result = _scrub_value("Bearer sk-abcdefghijklmnopqrstuvwxyz")
        assert "sk-abcdefghijklmnopqrstuvwxyz" not in result

    def test_preserves_safe_strings(self):
        safe = "Hello, this is a normal log message"
        assert _scrub_value(safe) == safe

    def test_scrubs_dict_values(self):
        result = _scrub_value({"key": "sk-abcdefghijklmnopqrstuvwxyz", "safe": "ok"})
        assert "..." in result["key"]
        assert result["safe"] == "ok"

    def test_scrubs_nested_list(self):
        result = _scrub_value(["sk-abcdefghijklmnopqrstuvwxyz", "safe"])
        assert isinstance(result, list)
        assert "..." in result[0]
        assert result[1] == "safe"

    def test_scrubs_tuple(self):
        result = _scrub_value(("sk-abcdefghijklmnopqrstuvwxyz",))
        assert isinstance(result, tuple)

    def test_non_string_passthrough(self):
        assert _scrub_value(42) == 42
        assert _scrub_value(None) is None
        assert _scrub_value(True) is True


class TestLogScrubber:
    """log_scrubber() structlog processor integration."""

    def test_scrubs_event_dict(self):
        event = {
            "event": "auth_attempt",
            "api_key": "sk-abcdefghijklmnopqrstuvwxyz",
            "user": "test",
        }
        result = log_scrubber(None, "info", event)
        assert "..." in result["api_key"]
        assert result["user"] == "test"
        assert result["event"] == "auth_attempt"
