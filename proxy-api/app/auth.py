"""API key authentication backed by gateway.yaml.

Keys are defined in gateway.yaml under the ``api_keys`` section.
API key auth is enabled by default and recommended for all environments.

If no api_keys are configured the gateway falls back to unauthenticated
mode for local development **only** — never deploy without keys.
"""

from __future__ import annotations

import hmac

import structlog

from .config import get_api_keys

log = structlog.get_logger()


def authenticate(raw_key: str) -> dict | None:
    """Validate an API key against gateway.yaml config.

    Returns the key record dict if valid, None if invalid.
    Returns a synthetic record if no keys are configured (open mode).
    """
    configured_keys = get_api_keys()

    if not configured_keys:
        return {"name": "open-mode", "key": "none"}

    for key_record in configured_keys:
        stored_key = key_record.get("key", "")
        if stored_key and hmac.compare_digest(raw_key, stored_key):
            return key_record

    return None
