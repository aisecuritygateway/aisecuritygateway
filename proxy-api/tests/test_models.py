"""Tests for app.models — Pydantic model validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models import ChatMessage, ChatCompletionRequest, Usage, DLPViolation, DLPBlockResponse


class TestChatMessage:
    """ChatMessage model validation."""

    def test_basic_message(self):
        msg = ChatMessage(role="user", content="Hello")
        assert msg.role == "user"
        assert msg.content == "Hello"

    def test_message_with_none_content(self):
        msg = ChatMessage(role="system", content=None)
        assert msg.content is None

    def test_message_with_list_content(self):
        parts = [{"type": "text", "text": "Hi"}, {"type": "image_url", "image_url": {"url": "data:..."}}]
        msg = ChatMessage(role="user", content=parts)
        assert isinstance(msg.content, list)
        assert len(msg.content) == 2

    def test_message_with_name(self):
        msg = ChatMessage(role="assistant", content="Reply", name="bot")
        assert msg.name == "bot"

    def test_missing_role_raises(self):
        with pytest.raises(ValidationError):
            ChatMessage(content="Hello")


class TestChatCompletionRequest:
    """ChatCompletionRequest model validation."""

    def test_minimal_request(self):
        req = ChatCompletionRequest(
            messages=[ChatMessage(role="user", content="Hi")]
        )
        assert len(req.messages) == 1
        assert req.stream is False
        assert req.model is None

    def test_with_model_and_temperature(self):
        req = ChatCompletionRequest(
            model="gpt-4o",
            messages=[ChatMessage(role="user", content="Hi")],
            temperature=0.7,
        )
        assert req.model == "gpt-4o"
        assert req.temperature == 0.7

    def test_empty_messages_raises(self):
        with pytest.raises(ValidationError):
            ChatCompletionRequest(messages=[])

    def test_stream_defaults_false(self):
        req = ChatCompletionRequest(
            messages=[ChatMessage(role="user", content="Hi")]
        )
        assert req.stream is False

    def test_extra_fields_ignored(self):
        req = ChatCompletionRequest(
            messages=[ChatMessage(role="user", content="Hi")],
            unknown_field="should_be_ignored",
        )
        assert not hasattr(req, "unknown_field")

    def test_optional_fields_none(self):
        req = ChatCompletionRequest(
            messages=[ChatMessage(role="user", content="Hi")]
        )
        assert req.max_tokens is None
        assert req.tools is None
        assert req.response_format is None
        assert req.reasoning_effort is None


class TestUsage:
    """Usage model defaults and validation."""

    def test_defaults_to_zero(self):
        u = Usage()
        assert u.prompt_tokens == 0
        assert u.completion_tokens == 0
        assert u.total_tokens == 0

    def test_with_values(self):
        u = Usage(prompt_tokens=10, completion_tokens=20, total_tokens=30)
        assert u.total_tokens == 30


class TestDLPViolation:
    """DLPViolation model."""

    def test_basic_violation(self):
        v = DLPViolation(entity_type="EMAIL_ADDRESS", start=0, end=20, score=0.95)
        assert v.entity_type == "EMAIL_ADDRESS"
        assert v.score == 0.95


class TestDLPBlockResponse:
    """DLPBlockResponse model."""

    def test_default_error_message(self):
        resp = DLPBlockResponse(
            request_id="req_abc",
            violations=[DLPViolation(entity_type="US_SSN", start=0, end=11, score=0.9)],
        )
        assert resp.error == "pii_policy_violation"
        assert "PII" in resp.message
        assert len(resp.violations) == 1

    def test_custom_error(self):
        resp = DLPBlockResponse(
            error="image_pii_violation",
            message="Custom message",
            request_id="req_xyz",
            violations=[],
        )
        assert resp.error == "image_pii_violation"
