"""Custom exceptions for the AI Security Gateway SDK."""

from __future__ import annotations

from typing import Any


class AISGError(Exception):
    """Base exception for all AISG SDK errors."""

    def __init__(self, message: str, *, status_code: int | None = None, body: dict[str, Any] | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body or {}


class AuthenticationError(AISGError):
    """Raised on 401/403 — invalid, missing, or revoked API key."""


class DLPBlockError(AISGError):
    """Raised when the DLP scanner blocks a request (HTTP 400, error=pii_policy_violation).

    Attributes:
        violations: List of detected PII entities.
        request_id: The AISG request ID for this blocked request.
    """

    def __init__(self, message: str, *, violations: list[dict[str, Any]], request_id: str, **kwargs: Any):
        super().__init__(message, status_code=400, **kwargs)
        self.violations = violations
        self.request_id = request_id


class RateLimitError(AISGError):
    """Raised on HTTP 429 — per-key rate limit exceeded."""


class BudgetExhaustedError(AISGError):
    """Raised on HTTP 402 — project or key budget is exhausted."""


class ModelNotFoundError(AISGError):
    """Raised when the requested model is unavailable or deprecated.

    Attributes:
        suggested_model: An alternative model name, if the server suggested one.
    """

    def __init__(self, message: str, *, suggested_model: str | None = None, **kwargs: Any):
        super().__init__(message, **kwargs)
        self.suggested_model = suggested_model


class UpstreamError(AISGError):
    """Raised when the upstream LLM provider returns an error."""
