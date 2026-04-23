"""DLP policy enforcement — calls Presidio, then blocks or redacts.

Security model: **fail-closed**.  If Presidio is unreachable or returns an
error, the request MUST NOT proceed to the upstream LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from .config import get_settings
from .models import ChatMessage, DLPViolation

log = structlog.get_logger()


class PresidioError(Exception):
    """Raised when Presidio is unreachable or returns a non-2xx response."""


@dataclass
class ProcessResult:
    """Aggregated output from a Presidio DLP scan across all messages."""

    violations: list[DLPViolation] = field(default_factory=list)
    redacted_messages: list[ChatMessage] | None = None


async def process_messages(
    client: httpx.AsyncClient,
    messages: list[ChatMessage],
    entities: list[str] | None = None,
    score_threshold: float = 0.4,
    anonymize: bool = False,
) -> ProcessResult:
    """Scan (and optionally redact) all text messages via Presidio."""
    base = get_settings().presidio_url.rstrip("/")

    all_violations: list[DLPViolation] = []
    redacted: list[ChatMessage] = []

    for msg in messages:
        text = _message_text(msg)
        if not text:
            if anonymize:
                redacted.append(msg)
            continue

        payload: dict[str, Any] = {
            "text": text,
            "language": "en",
            "entities": entities or None,
            "score_threshold": score_threshold,
            "anonymize": anonymize,
        }
        if anonymize:
            payload["operators"] = {
                "DEFAULT": {"type": "replace", "new_value": "[REDACTED]"},
            }

        try:
            resp = await client.post(f"{base}/process", json=payload, timeout=5.0)
            resp.raise_for_status()
            data = resp.json()

            for r in data.get("results", []):
                all_violations.append(DLPViolation(
                    entity_type=r["entity_type"],
                    start=r["start"],
                    end=r["end"],
                    score=r["score"],
                ))

            if anonymize:
                anon_text = data.get("anonymized_text")
                if anon_text is not None:
                    redacted.append(msg.model_copy(update={"content": anon_text}))
                else:
                    redacted.append(msg)

        except httpx.HTTPError as exc:
            log.exception("presidio_process_error")
            raise PresidioError(f"Presidio process failed: {exc}") from exc

    return ProcessResult(
        violations=all_violations,
        redacted_messages=redacted if anonymize else None,
    )


def violations_breakdown(violations: list[DLPViolation]) -> dict[str, int]:
    """Count violations by entity_type and return a {type: count} dict."""
    counts: dict[str, int] = {}
    for v in violations:
        counts[v.entity_type] = counts.get(v.entity_type, 0) + 1
    return counts


def _message_text(msg: ChatMessage) -> str:
    """Extract plain text from a ChatMessage's string or multimodal content."""
    if isinstance(msg.content, str):
        return msg.content
    if isinstance(msg.content, list):
        parts: list[str] = []
        for part in msg.content:
            if isinstance(part, dict) and part.get("type") == "text":
                parts.append(part.get("text", ""))
            elif isinstance(part, str):
                parts.append(part)
        return " ".join(parts)
    return ""
