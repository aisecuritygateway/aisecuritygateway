"""Provider registry and upstream forwarding via LiteLLM.

Provider metadata is loaded from config/providers.json.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import litellm
import structlog

from .config import get_settings

litellm.drop_params = True
litellm.set_verbose = False

log = structlog.get_logger()


def _load_providers_json() -> dict[str, Any]:
    """Load provider metadata from config/providers.json."""
    env = os.environ.get("PROVIDERS_CONFIG_PATH")
    candidates = []
    if env:
        candidates.append(Path(env))
    candidates.append(Path("/app/config/providers.json"))
    candidates.append(Path(__file__).resolve().parent.parent / "config" / "providers.json")

    for p in candidates:
        if p.exists():
            with open(p) as f:
                return json.load(f)
    return {"providers": {}}


_PROVIDERS_DATA = _load_providers_json()


PROVIDER_PREFIX: dict[str, str] = {
    k: v["litellm_prefix"] for k, v in _PROVIDERS_DATA.get("providers", {}).items()
}


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """Immutable descriptor for an LLM provider (name + LiteLLM prefix)."""

    name: str
    litellm_prefix: str


PROVIDERS: dict[str, ProviderSpec] = {
    name: ProviderSpec(name=name, litellm_prefix=prefix)
    for name, prefix in PROVIDER_PREFIX.items()
}


def get_provider(name: str) -> ProviderSpec | None:
    """Look up a ProviderSpec by case-insensitive provider name."""
    return PROVIDERS.get(name.lower())


def list_providers() -> list[str]:
    """Return a sorted list of all configured provider names."""
    return sorted(PROVIDERS.keys())


def litellm_model_name(provider: ProviderSpec, model: str) -> str:
    """Build the 'prefix/model' string that LiteLLM expects."""
    return f"{provider.litellm_prefix}/{model}"


async def forward_chat_completion(
    provider: ProviderSpec,
    api_key: str,
    body: dict[str, Any],
    *,
    base_url_override: str | None = None,
) -> litellm.ModelResponse:
    """Call the upstream LLM via LiteLLM's async completion."""
    raw_model = body.pop("model", "")
    model_str = litellm_model_name(provider, raw_model)
    timeout = get_settings().upstream_timeout_seconds

    log.info("upstream_forward", provider=provider.name, litellm_model=model_str)

    _KNOWN_COMPLETION_PARAMS = {
        "messages", "temperature", "top_p", "max_tokens", "max_completion_tokens",
        "stop", "stream", "stream_options", "n",
        "presence_penalty", "frequency_penalty",
        "logit_bias", "logprobs", "top_logprobs",
        "user", "seed",
        "tools", "tool_choice", "functions", "function_call",
        "parallel_tool_calls",
        "response_format",
        "reasoning_effort",
        "thinking",
        "top_k",
        "extra_headers",
        "service_tier",
    }
    clean_body = {k: v for k, v in body.items() if k in _KNOWN_COMPLETION_PARAMS}

    kwargs: dict[str, Any] = {
        "model": model_str,
        "timeout": timeout,
        "api_key": api_key,
        **clean_body,
    }

    if base_url_override:
        kwargs["api_base"] = base_url_override.rstrip("/")

    return await litellm.acompletion(**kwargs)
