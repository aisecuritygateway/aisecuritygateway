"""Unit tests for SDK response model parsing."""

from aisg.models import AISGMetadata, ChatCompletion, ModelInfo, ModelPricing


def test_aisg_metadata_from_dict():
    raw = {
        "requested_model": "oah/llama-4-maverick",
        "provider_selected": "together",
        "routing_mode": "smart_route",
        "mode": "managed",
        "latency_ms": 383.0,
        "dlp_latency_ms": 34.0,
        "pii_detected": True,
        "wholesale_cost_usd": 0.00003,
        "cost_usd": 0.000042,
        "request_type": "text",
        "intent": "GENERAL_CHAT",
        "tokens_per_sec": 52.0,
        "upstream_latency_ms": 1247.0,
        "dlp_action": "redact",
        "violations_count": 2,
        "entity_types_detected": ["EMAIL_ADDRESS", "PHONE_NUMBER"],
        "unknown_future_field": "should be ignored",
    }
    meta = AISGMetadata.from_dict(raw)
    assert meta.provider_selected == "together"
    assert meta.pii_detected is True
    assert meta.dlp_action == "redact"
    assert meta.violations_count == 2
    assert meta.entity_types_detected == ["EMAIL_ADDRESS", "PHONE_NUMBER"]
    assert meta.latency_ms == 383.0


def test_aisg_metadata_from_empty_dict():
    meta = AISGMetadata.from_dict({})
    assert meta.pii_detected is False
    assert meta.provider_selected == ""


def test_chat_completion_from_dict():
    raw = {
        "id": "chatcmpl-abc123",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "oah/llama-4-maverick",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Hello!"},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15,
        },
        "x_request_id": "req_abc123",
        "aisg_metadata": {
            "requested_model": "oah/llama-4-maverick",
            "provider_selected": "together",
            "routing_mode": "smart_route",
            "mode": "managed",
            "latency_ms": 28.0,
            "dlp_latency_ms": 12.0,
            "pii_detected": False,
            "wholesale_cost_usd": 0.0001,
            "cost_usd": 0.00014,
            "request_type": "text",
            "intent": "GENERAL_CHAT",
            "tokens_per_sec": 45.0,
            "upstream_latency_ms": 800.0,
        },
    }
    comp = ChatCompletion.from_dict(raw)
    assert comp.content == "Hello!"
    assert comp.id == "chatcmpl-abc123"
    assert comp.usage.total_tokens == 15
    assert comp.aisg_metadata is not None
    assert comp.aisg_metadata.provider_selected == "together"
    assert comp.x_request_id == "req_abc123"


def test_chat_completion_content_shortcut_empty():
    comp = ChatCompletion.from_dict({"choices": []})
    assert comp.content is None


def test_model_info_from_dict():
    raw = {
        "id": "oah/llama-4-maverick",
        "object": "model",
        "owned_by": "ai-security-gateway",
        "family": "llama",
        "supports_vision": True,
        "supports_tools": True,
        "supports_json_mode": True,
        "supports_reasoning": False,
        "context_window": 131072,
        "max_output_tokens": 8192,
        "providers": ["together", "deepinfra"],
        "pricing": {
            "input_per_1m_tokens": 0.27,
            "output_per_1m_tokens": 0.35,
        },
    }
    model = ModelInfo.from_dict(raw)
    assert model.id == "oah/llama-4-maverick"
    assert model.family == "llama"
    assert model.supports_vision is True
    assert model.providers == ["together", "deepinfra"]
    assert model.pricing.input_per_1m_tokens == 0.27
