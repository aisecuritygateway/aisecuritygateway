"""Typed response models for the AI Security Gateway SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DLPViolation:
    """A single PII entity detected by the DLP scanner."""

    entity_type: str
    start: int
    end: int
    score: float


@dataclass(frozen=True)
class AISGMetadata:
    """Security and routing metadata returned with every chat response.

    Present as ``response.aisg_metadata`` on non-streaming responses.
    For streaming, use response headers (``x-request-id``, ``x-aisg-latency``).
    """

    requested_model: str = ""
    provider_selected: str = ""
    routing_mode: str = ""
    mode: str = ""
    latency_ms: float = 0.0
    dlp_latency_ms: float = 0.0
    pii_detected: bool = False
    wholesale_cost_usd: float = 0.0
    cost_usd: float = 0.0
    request_type: str = ""
    intent: str = ""
    tokens_per_sec: float = 0.0
    upstream_latency_ms: float = 0.0
    # Conditional fields
    media_events: int | None = None
    dlp_action: str | None = None
    violations_count: int | None = None
    entity_types_detected: list[str] = field(default_factory=list)
    redacted_prompt: str | None = None
    new_balance_usd: float | None = None
    is_managed: bool | None = None
    tokens_truncated: bool | None = None
    model_deprecated: bool | None = None
    model_status: str | None = None
    suggested_replacement: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AISGMetadata:
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass(frozen=True)
class ModelPricing:
    """Token pricing for a model (per 1M tokens, USD)."""

    input_per_1m_tokens: float | None = None
    output_per_1m_tokens: float | None = None


@dataclass(frozen=True)
class ModelInfo:
    """A model entry from ``GET /v1/models``."""

    id: str
    object: str = "model"
    owned_by: str = ""
    family: str | None = None
    supports_vision: bool = False
    supports_tools: bool = False
    supports_json_mode: bool = False
    supports_reasoning: bool = False
    context_window: int | None = None
    max_output_tokens: int | None = None
    providers: list[str] = field(default_factory=list)
    pricing: ModelPricing = field(default_factory=ModelPricing)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModelInfo:
        pricing_raw = data.pop("pricing", {}) or {}
        pricing = ModelPricing(**pricing_raw)
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in data.items() if k in known}
        filtered["pricing"] = pricing
        return cls(**filtered)


@dataclass(frozen=True)
class Usage:
    """Token usage stats from a chat completion."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True)
class ChoiceMessage:
    """A message in a chat completion choice."""

    role: str = "assistant"
    content: str | None = None
    tool_calls: list[dict[str, Any]] | None = None


@dataclass(frozen=True)
class Choice:
    """A completion choice."""

    index: int = 0
    message: ChoiceMessage = field(default_factory=ChoiceMessage)
    finish_reason: str | None = None


@dataclass
class ChatCompletion:
    """Full chat completion response including AISG metadata."""

    id: str = ""
    object: str = "chat.completion"
    created: int = 0
    model: str = ""
    choices: list[Choice] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    aisg_metadata: AISGMetadata | None = None
    x_request_id: str = ""
    _raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def content(self) -> str | None:
        """Shortcut to the first choice's message content."""
        if self.choices:
            return self.choices[0].message.content
        return None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChatCompletion:
        meta_raw = data.pop("aisg_metadata", None)
        aisg = AISGMetadata.from_dict(meta_raw) if meta_raw else None

        usage_raw = data.get("usage", {}) or {}
        usage = Usage(**{k: v for k, v in usage_raw.items() if k in ("prompt_tokens", "completion_tokens", "total_tokens")})

        choices_raw = data.get("choices", [])
        choices: list[Choice] = []
        for c in choices_raw:
            msg_raw = c.get("message", {})
            msg = ChoiceMessage(
                role=msg_raw.get("role", "assistant"),
                content=msg_raw.get("content"),
                tool_calls=msg_raw.get("tool_calls"),
            )
            choices.append(Choice(
                index=c.get("index", 0),
                message=msg,
                finish_reason=c.get("finish_reason"),
            ))

        return cls(
            id=data.get("id", ""),
            object=data.get("object", "chat.completion"),
            created=data.get("created", 0),
            model=data.get("model", ""),
            choices=choices,
            usage=usage,
            aisg_metadata=aisg,
            x_request_id=data.get("x_request_id", ""),
            _raw=data,
        )
