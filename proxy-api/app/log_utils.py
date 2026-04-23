"""Log-scrubbing utilities — masks API keys in debug output."""

from __future__ import annotations

import re
from typing import Any

_KEY_PATTERNS = re.compile(
    r"(gsk_|tok_|sk-|sk-ant-|AKIA|Bearer\s+)\S{6,}",
    re.IGNORECASE,
)


def mask_key(key: str) -> str:
    """Return ``key[:6]...key[-4:]`` for debugging — never the full secret."""
    if len(key) <= 12:
        return key[:4] + "..."
    return key[:6] + "..." + key[-4:]


def _scrub_value(value: Any) -> Any:
    """Recursively mask API-key-like patterns in strings, dicts, and lists."""
    if isinstance(value, str):
        return _KEY_PATTERNS.sub(lambda m: mask_key(m.group(0)), value)
    if isinstance(value, dict):
        return {k: _scrub_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_scrub_value(v) for v in value)
    return value


def log_scrubber(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Structlog processor: scrub all values for key-like secrets."""
    return {k: _scrub_value(v) for k, v in event_dict.items()}
