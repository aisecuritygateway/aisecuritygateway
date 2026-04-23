"""Pydantic request/response models for the AISG Presidio Service."""

from __future__ import annotations

from pydantic import BaseModel, Field


# ── Shared ────────────────────────────────────────────────────────────────────

class RecognizerResult(BaseModel):
    """A single PII entity span detected by the analyzer."""

    entity_type: str
    start: int
    end: int
    score: float


class OperatorConfig(BaseModel):
    """Anonymization operator configuration (replace, mask, hash, etc.)."""

    type: str = "replace"
    new_value: str | None = None
    mask_char: str | None = None
    chars_to_mask: int | None = None
    from_end: bool | None = None
    hash_type: str | None = None


class AnonymizedItem(BaseModel):
    """Details of a single anonymized span in the output text."""

    start: int
    end: int
    entity_type: str
    text: str
    operator: str


# ── /process (combined analyze + anonymize in one call) ──────────────────────

class CustomRegexRule(BaseModel):
    """A per-request custom regex pattern that creates a temporary recognizer."""

    label: str
    pattern: str
    score: float = 0.9


class ProcessRequest(BaseModel):
    """Request body for POST /process (combined analyze + anonymize)."""

    text: str
    language: str = "en"
    entities: list[str] | None = Field(
        default=None,
        description="Restrict analysis to these entity types. None = all enabled.",
    )
    score_threshold: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )
    anonymize: bool = Field(
        default=True,
        description="When True, returns anonymized text alongside analysis results.",
    )
    operators: dict[str, OperatorConfig] | None = Field(
        default=None,
        description='Per-entity operator overrides. Key "DEFAULT" applies to all unmatched.',
    )
    custom_regex_rules: list[CustomRegexRule] | None = Field(
        default=None,
        description="Per-request custom regex patterns. Each rule creates a temporary recognizer.",
    )


class ProcessResponse(BaseModel):
    """Response body for POST /process."""

    results: list[RecognizerResult]
    anonymized_text: str | None = None
    items: list[AnonymizedItem] | None = None


# ── /health ───────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    """Response body for GET /health."""

    status: str
    recognizers: int
    entities: list[str]
