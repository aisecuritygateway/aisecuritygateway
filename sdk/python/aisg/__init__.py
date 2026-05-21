"""AI Security Gateway Python SDK.

Drop-in client for the AISG API — works with both the managed cloud
service (``api.aisecuritygateway.ai``) and self-hosted deployments.

Quickstart::

    from aisg import AISG

    client = AISG(api_key="oah_...")

    # Chat completion with PII redaction + smart routing
    response = client.chat.create(
        model="oah/llama-4-maverick",
        messages=[{"role": "user", "content": "Hello!"}],
    )
    print(response.content)
    print(response.aisg_metadata.pii_detected)

    # List available models
    models = client.models.list(family="llama")
    for m in models:
        print(m.id, m.pricing.input_per_1m_tokens)

Environment variables::

    AISG_API_KEY     — Default API key
    AISG_BASE_URL    — Default base URL (cloud if unset)
"""

from ._version import __version__
from .client import AISG, AsyncAISG
from .exceptions import (
    AISGError,
    AuthenticationError,
    BudgetExhaustedError,
    DLPBlockError,
    ModelNotFoundError,
    RateLimitError,
    UpstreamError,
)
from .models import (
    AISGMetadata,
    ChatCompletion,
    Choice,
    ChoiceMessage,
    DLPViolation,
    ModelInfo,
    ModelPricing,
    Usage,
)

__all__ = [
    "__version__",
    "AISG",
    "AsyncAISG",
    "AISGError",
    "AuthenticationError",
    "BudgetExhaustedError",
    "DLPBlockError",
    "ModelNotFoundError",
    "RateLimitError",
    "UpstreamError",
    "AISGMetadata",
    "ChatCompletion",
    "Choice",
    "ChoiceMessage",
    "DLPViolation",
    "ModelInfo",
    "ModelPricing",
    "Usage",
]
