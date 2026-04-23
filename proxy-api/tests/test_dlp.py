"""Tests for app.dlp — text extraction, violations breakdown."""

from __future__ import annotations

import pytest

from app.dlp import (
    violations_breakdown,
    _message_text,
)
from app.models import ChatMessage, DLPViolation


# ── violations_breakdown ──────────────────────────────────────────────────────

class TestViolationsBreakdown:
    """Count violations by entity type."""

    def test_empty_list(self):
        assert violations_breakdown([]) == {}

    def test_single_type(self):
        vs = [
            DLPViolation(entity_type="EMAIL_ADDRESS", start=0, end=10, score=0.9),
            DLPViolation(entity_type="EMAIL_ADDRESS", start=20, end=30, score=0.8),
        ]
        assert violations_breakdown(vs) == {"EMAIL_ADDRESS": 2}

    def test_multiple_types(self):
        vs = [
            DLPViolation(entity_type="EMAIL_ADDRESS", start=0, end=10, score=0.9),
            DLPViolation(entity_type="US_SSN", start=20, end=31, score=0.95),
            DLPViolation(entity_type="EMAIL_ADDRESS", start=40, end=60, score=0.85),
        ]
        result = violations_breakdown(vs)
        assert result["EMAIL_ADDRESS"] == 2
        assert result["US_SSN"] == 1


# ── _message_text ─────────────────────────────────────────────────────────────

class TestMessageText:
    """Extract plain text from ChatMessage content."""

    def test_string_content(self):
        msg = ChatMessage(role="user", content="Hello world")
        assert _message_text(msg) == "Hello world"

    def test_list_content_with_text_parts(self):
        msg = ChatMessage(role="user", content=[
            {"type": "text", "text": "Hello"},
            {"type": "text", "text": "world"},
        ])
        assert _message_text(msg) == "Hello world"

    def test_list_content_skips_image_parts(self):
        msg = ChatMessage(role="user", content=[
            {"type": "text", "text": "Hello"},
            {"type": "image_url", "image_url": {"url": "data:..."}},
        ])
        assert _message_text(msg) == "Hello"

    def test_none_content(self):
        msg = ChatMessage(role="user", content=None)
        assert _message_text(msg) == ""

    def test_plain_string_parts_in_list(self):
        msg = ChatMessage(role="user", content=["Hello", "world"])
        assert _message_text(msg) == "Hello world"
