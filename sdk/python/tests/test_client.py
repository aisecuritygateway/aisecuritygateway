"""Unit tests for SDK client construction and error mapping."""

import pytest

from aisg import AISG, AsyncAISG, AuthenticationError
from aisg.client import _raise_for_status, _resolve_api_key, _resolve_base_url
from aisg.exceptions import (
    BudgetExhaustedError,
    DLPBlockError,
    ModelNotFoundError,
    RateLimitError,
)


def test_resolve_base_url_default():
    assert _resolve_base_url(None) == "https://api.aisecuritygateway.ai/v1"


def test_resolve_base_url_explicit():
    assert _resolve_base_url("http://localhost:8000/v1/") == "http://localhost:8000/v1"


def test_resolve_base_url_env(monkeypatch):
    monkeypatch.setenv("AISG_BASE_URL", "http://my-host:9000/v1")
    assert _resolve_base_url(None) == "http://my-host:9000/v1"


def test_resolve_api_key_missing():
    with pytest.raises(AuthenticationError, match="No API key"):
        _resolve_api_key(None)


def test_resolve_api_key_env(monkeypatch):
    monkeypatch.setenv("AISG_API_KEY", "oah_test123")
    assert _resolve_api_key(None) == "oah_test123"


def test_resolve_api_key_explicit():
    assert _resolve_api_key("oah_explicit") == "oah_explicit"


def test_client_context_manager():
    client = AISG(api_key="oah_test")
    with client:
        assert client._base_url == "https://api.aisecuritygateway.ai/v1"
    # should not raise after close


def test_client_namespaces():
    client = AISG(api_key="oah_test")
    assert hasattr(client, "chat")
    assert hasattr(client, "models")
    assert hasattr(client.chat, "completions")
    assert client.chat.completions is client.chat
    client.close()


class _FakeResponse:
    """Minimal httpx.Response stand-in for testing _raise_for_status."""

    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body
        self.text = str(body)
        self.is_success = 200 <= status_code < 300

    def json(self):
        return self._body


def test_raise_for_status_401():
    resp = _FakeResponse(401, {"detail": "Missing API key"})
    with pytest.raises(AuthenticationError):
        _raise_for_status(resp)


def test_raise_for_status_429():
    resp = _FakeResponse(429, {"detail": {"error": "rate_limit_exceeded", "message": "Too fast"}})
    with pytest.raises(RateLimitError):
        _raise_for_status(resp)


def test_raise_for_status_402():
    resp = _FakeResponse(402, {"detail": {"error": "budget_exhausted", "message": "No credits"}})
    with pytest.raises(BudgetExhaustedError):
        _raise_for_status(resp)


def test_raise_for_status_dlp_block():
    resp = _FakeResponse(400, {
        "detail": {
            "error": "pii_policy_violation",
            "message": "PII detected",
        },
        "violations": [{"entity_type": "SSN", "start": 0, "end": 11, "score": 0.95}],
        "request_id": "req_123",
    })
    with pytest.raises(DLPBlockError) as exc_info:
        _raise_for_status(resp)
    assert exc_info.value.request_id == "req_123"
    assert len(exc_info.value.violations) == 1


def test_raise_for_status_model_not_found():
    resp = _FakeResponse(400, {
        "detail": {
            "error": "model_not_available",
            "message": "Model unavailable",
            "suggested_model": "oah/llama-4-maverick",
        },
    })
    with pytest.raises(ModelNotFoundError) as exc_info:
        _raise_for_status(resp)
    assert exc_info.value.suggested_model == "oah/llama-4-maverick"


def test_raise_for_status_success():
    resp = _FakeResponse(200, {"ok": True})
    _raise_for_status(resp)  # should not raise
