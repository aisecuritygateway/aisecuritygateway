"""AI Security Gateway Python SDK client.

Provides both synchronous and asynchronous clients for the AISG API.
Works with both the managed cloud service and self-hosted deployments.

Usage::

    from aisg import AISG

    client = AISG(api_key="oah_...")
    response = client.chat.create(
        model="oah/llama-4-maverick",
        messages=[{"role": "user", "content": "Hello!"}],
    )
    print(response.content)
    print(response.aisg_metadata.pii_detected)
"""

from __future__ import annotations

import json
import os
from typing import Any, Generator, Iterator

import httpx

from .exceptions import (
    AISGError,
    AuthenticationError,
    BudgetExhaustedError,
    DLPBlockError,
    ModelNotFoundError,
    RateLimitError,
    UpstreamError,
)
from .models import AISGMetadata, ChatCompletion, ModelInfo

_CLOUD_BASE_URL = "https://api.aisecuritygateway.ai/v1"
_DEFAULT_TIMEOUT = 120.0
_USER_AGENT = "aisg-python/{version}"


def _resolve_base_url(base_url: str | None) -> str:
    if base_url:
        return base_url.rstrip("/")
    return os.environ.get("AISG_BASE_URL", _CLOUD_BASE_URL).rstrip("/")


def _resolve_api_key(api_key: str | None) -> str:
    key = api_key or os.environ.get("AISG_API_KEY", "")
    if not key:
        raise AuthenticationError(
            "No API key provided. Pass api_key= or set the AISG_API_KEY environment variable.",
            status_code=401,
        )
    return key


def _raise_for_status(resp: httpx.Response) -> None:
    """Convert AISG HTTP error responses to typed exceptions."""
    if resp.is_success:
        return

    try:
        body = resp.json()
    except Exception:
        body = {"detail": resp.text}

    detail = body.get("detail", body)
    if isinstance(detail, dict):
        error_code = detail.get("error", "")
        message = detail.get("message", str(detail))
    else:
        error_code = ""
        message = str(detail)

    status = resp.status_code

    if status in (401, 403):
        raise AuthenticationError(message, status_code=status, body=body)

    if status == 429:
        raise RateLimitError(message, status_code=429, body=body)

    if status == 402:
        raise BudgetExhaustedError(message, status_code=402, body=body)

    if error_code == "pii_policy_violation":
        raise DLPBlockError(
            message,
            violations=body.get("violations", detail.get("violations", [])),
            request_id=body.get("request_id", detail.get("request_id", "")),
            body=body,
        )

    if error_code in ("model_not_available", "model_not_found"):
        raise ModelNotFoundError(
            message,
            suggested_model=detail.get("suggested_model") if isinstance(detail, dict) else None,
            status_code=status,
            body=body,
        )

    if error_code in ("upstream_bad_request", "upstream_error"):
        raise UpstreamError(message, status_code=status, body=body)

    raise AISGError(message, status_code=status, body=body)


class _ChatNamespace:
    """Namespace for chat completion methods (``client.chat.create(...)``).

    Mirrors the OpenAI SDK pattern: ``client.chat.completions.create()``,
    but simplified to ``client.chat.create()`` for ergonomics.
    """

    def __init__(self, client: AISG):
        self._client = client
        self.completions = self

    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        stream: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
        top_p: float | None = None,
        stop: str | list[str] | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        response_format: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> ChatCompletion | Iterator[dict[str, Any]]:
        """Create a chat completion.

        Args:
            model: Model ID (e.g. ``"oah/llama-4-maverick"`` for smart routing).
            messages: List of message dicts with ``role`` and ``content``.
            stream: If True, returns an iterator of SSE chunks.
            temperature: Sampling temperature (0-2).
            max_tokens: Maximum tokens in the response.
            extra_headers: Optional routing headers (``x-provider``, ``x-feature``, etc.).
            **kwargs: Additional OpenAI-compatible parameters.

        Returns:
            A :class:`ChatCompletion` with typed ``aisg_metadata``, or
            an iterator of SSE chunk dicts if ``stream=True``.

        Raises:
            DLPBlockError: If the DLP scanner blocked the request.
            BudgetExhaustedError: If the project budget is exhausted.
            ModelNotFoundError: If the model is unavailable.
        """
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": stream,
        }
        for key, val in [
            ("temperature", temperature),
            ("max_tokens", max_tokens),
            ("top_p", top_p),
            ("stop", stop),
            ("tools", tools),
            ("tool_choice", tool_choice),
            ("response_format", response_format),
        ]:
            if val is not None:
                payload[key] = val
        payload.update(kwargs)

        headers = dict(extra_headers or {})

        if stream:
            return self._stream(payload, headers)

        resp = self._client._post("/chat/completions", json_body=payload, extra_headers=headers)
        return ChatCompletion.from_dict(resp)

    def _stream(
        self,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> Generator[dict[str, Any], None, None]:
        """Yield parsed SSE chunks from a streaming response."""
        with self._client._http.stream(
            "POST",
            f"{self._client._base_url}/chat/completions",
            json=payload,
            headers={**self._client._headers, **headers},
            timeout=self._client._timeout,
        ) as resp:
            if not resp.is_success:
                resp.read()
                _raise_for_status(resp)

            for line in resp.iter_lines():
                if not line or not line.startswith("data: "):
                    continue
                data_str = line[len("data: "):]
                if data_str.strip() == "[DONE]":
                    return
                try:
                    yield json.loads(data_str)
                except json.JSONDecodeError:
                    continue


class _ModelsNamespace:
    """Namespace for model discovery methods (``client.models.list(...)``).

    Mirrors the OpenAI SDK pattern.
    """

    def __init__(self, client: AISG):
        self._client = client

    def list(
        self,
        *,
        family: str | None = None,
        capability: str | None = None,
        provider: str | None = None,
    ) -> list[ModelInfo]:
        """List available models.

        Args:
            family: Filter by model family (e.g. ``"llama"``, ``"claude"``).
            capability: Filter by capability (``"vision"``, ``"tools"``,
                ``"json_mode"``, ``"reasoning"``).
            provider: Filter by provider (e.g. ``"together"``, ``"openai"``).

        Returns:
            List of :class:`ModelInfo` with pricing and capability flags.
        """
        params: dict[str, str] = {}
        if family:
            params["family"] = family
        if capability:
            params["capability"] = capability
        if provider:
            params["provider"] = provider

        resp = self._client._get("/models", params=params)
        return [ModelInfo.from_dict(m) for m in resp.get("data", [])]


class AISG:
    """AI Security Gateway client.

    Works with both the managed cloud service and self-hosted deployments.

    Args:
        api_key: Your AISG API key (``oah_...`` project key or ``os_hub_...`` hub key).
            Falls back to ``AISG_API_KEY`` env var.
        base_url: API base URL. Defaults to the managed cloud service.
            Set to ``http://localhost:8000/v1`` for self-hosted.
            Falls back to ``AISG_BASE_URL`` env var.
        timeout: Request timeout in seconds (default 120).
        default_headers: Extra headers sent with every request.

    Example::

        # Cloud (default)
        client = AISG(api_key="oah_abc123")

        # Self-hosted
        client = AISG(
            api_key="my-gateway-key",
            base_url="http://localhost:8000/v1",
        )
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        default_headers: dict[str, str] | None = None,
    ):
        self._api_key = _resolve_api_key(api_key)
        self._base_url = _resolve_base_url(base_url)
        self._timeout = timeout

        from ._version import __version__

        self._headers: dict[str, str] = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT.format(version=__version__),
        }
        if default_headers:
            self._headers.update(default_headers)

        self._http = httpx.Client(timeout=timeout)

        self.chat = _ChatNamespace(self)
        self.models = _ModelsNamespace(self)

    def _get(self, path: str, *, params: dict[str, str] | None = None) -> dict[str, Any]:
        resp = self._http.get(
            f"{self._base_url}{path}",
            headers=self._headers,
            params=params,
            timeout=self._timeout,
        )
        _raise_for_status(resp)
        return resp.json()

    def _post(self, path: str, *, json_body: dict[str, Any], extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {**self._headers, **(extra_headers or {})}
        resp = self._http.post(
            f"{self._base_url}{path}",
            json=json_body,
            headers=headers,
            timeout=self._timeout,
        )
        _raise_for_status(resp)
        return resp.json()

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()

    def __enter__(self) -> AISG:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class AsyncAISG:
    """Async AI Security Gateway client.

    Same API as :class:`AISG` but uses ``async``/``await``.

    Example::

        async with AsyncAISG(api_key="oah_abc123") as client:
            response = await client.chat.create(
                model="oah/llama-4-maverick",
                messages=[{"role": "user", "content": "Hello!"}],
            )
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        default_headers: dict[str, str] | None = None,
    ):
        self._api_key = _resolve_api_key(api_key)
        self._base_url = _resolve_base_url(base_url)
        self._timeout = timeout

        from ._version import __version__

        self._headers: dict[str, str] = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT.format(version=__version__),
        }
        if default_headers:
            self._headers.update(default_headers)

        self._http = httpx.AsyncClient(timeout=timeout)

        self.chat = _AsyncChatNamespace(self)
        self.models = _AsyncModelsNamespace(self)

    async def _get(self, path: str, *, params: dict[str, str] | None = None) -> dict[str, Any]:
        resp = await self._http.get(
            f"{self._base_url}{path}",
            headers=self._headers,
            params=params,
            timeout=self._timeout,
        )
        _raise_for_status(resp)
        return resp.json()

    async def _post(self, path: str, *, json_body: dict[str, Any], extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        headers = {**self._headers, **(extra_headers or {})}
        resp = await self._http.post(
            f"{self._base_url}{path}",
            json=json_body,
            headers=headers,
            timeout=self._timeout,
        )
        _raise_for_status(resp)
        return resp.json()

    async def close(self) -> None:
        """Close the underlying async HTTP connection pool."""
        await self._http.aclose()

    async def __aenter__(self) -> AsyncAISG:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


class _AsyncChatNamespace:
    """Async chat completion namespace."""

    def __init__(self, client: AsyncAISG):
        self._client = client
        self.completions = self

    async def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        stream: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
        top_p: float | None = None,
        stop: str | list[str] | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, Any] | None = None,
        response_format: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> ChatCompletion | Any:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": stream,
        }
        for key, val in [
            ("temperature", temperature),
            ("max_tokens", max_tokens),
            ("top_p", top_p),
            ("stop", stop),
            ("tools", tools),
            ("tool_choice", tool_choice),
            ("response_format", response_format),
        ]:
            if val is not None:
                payload[key] = val
        payload.update(kwargs)

        headers = dict(extra_headers or {})

        if stream:
            return self._stream(payload, headers)

        resp = await self._client._post("/chat/completions", json_body=payload, extra_headers=headers)
        return ChatCompletion.from_dict(resp)

    async def _stream(
        self,
        payload: dict[str, Any],
        headers: dict[str, str],
    ) -> Any:
        """Return an async generator of SSE chunks."""
        async with self._client._http.stream(
            "POST",
            f"{self._client._base_url}/chat/completions",
            json=payload,
            headers={**self._client._headers, **headers},
            timeout=self._client._timeout,
        ) as resp:
            if not resp.is_success:
                await resp.aread()
                _raise_for_status(resp)

            async for line in resp.aiter_lines():
                if not line or not line.startswith("data: "):
                    continue
                data_str = line[len("data: "):]
                if data_str.strip() == "[DONE]":
                    return
                try:
                    yield json.loads(data_str)
                except json.JSONDecodeError:
                    continue


class _AsyncModelsNamespace:
    """Async model discovery namespace."""

    def __init__(self, client: AsyncAISG):
        self._client = client

    async def list(
        self,
        *,
        family: str | None = None,
        capability: str | None = None,
        provider: str | None = None,
    ) -> list[ModelInfo]:
        params: dict[str, str] = {}
        if family:
            params["family"] = family
        if capability:
            params["capability"] = capability
        if provider:
            params["provider"] = provider

        resp = await self._client._get("/models", params=params)
        return [ModelInfo.from_dict(m) for m in resp.get("data", [])]
