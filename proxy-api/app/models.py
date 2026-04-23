"""Pydantic request / response models for the AISG Gateway."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """A single message in the OpenAI chat format."""

    role: str
    content: str | list[Any] | None = None
    name: str | None = None


class ChatCompletionRequest(BaseModel):
    """Incoming /v1/chat/completions request body (OpenAI-compatible)."""

    model: str | None = None
    messages: list[ChatMessage] = Field(..., min_length=1)
    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    max_completion_tokens: int | None = None
    stop: str | list[str] | None = None
    stream: bool = False
    stream_options: dict[str, Any] | None = None
    n: int | None = None
    presence_penalty: float | None = None
    frequency_penalty: float | None = None
    logit_bias: dict[str, float] | None = None
    logprobs: bool | None = None
    top_logprobs: int | None = None
    user: str | None = None
    seed: int | None = None
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict[str, Any] | None = None
    functions: list[dict[str, Any]] | None = None
    function_call: str | dict[str, Any] | None = None
    parallel_tool_calls: bool | None = None
    response_format: dict[str, Any] | None = None
    reasoning_effort: str | None = None
    thinking: dict[str, Any] | None = None
    top_k: int | None = None
    extra_headers: dict[str, str] | None = None
    service_tier: str | None = None

    model_config = {"extra": "ignore"}


class Usage(BaseModel):
    """Token usage summary returned by the upstream LLM."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class DLPViolation(BaseModel):
    """A single PII entity detected by the DLP scan."""

    entity_type: str
    start: int
    end: int
    score: float


class DLPBlockResponse(BaseModel):
    """Error response returned when a request is blocked for PII or prompt injection."""

    error: str = "pii_policy_violation"
    message: str = "Request blocked: PII detected in prompt"
    request_id: str
    violations: list[DLPViolation]
