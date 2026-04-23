"""
Configure the Presidio AnalyzerEngine with custom recognizers.

Built-in recognizers already cover EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD,
US_SSN, IP_ADDRESS, IBAN_CODE, PERSON, LOCATION via spaCy NER + regex.

This module adds:
  1. Developer secret recognizers (API keys, AWS keys, PEM keys, GitHub tokens)
  2. A basic prompt injection / jailbreak detector
"""

from __future__ import annotations

import logging

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern

_log = logging.getLogger(__name__)


REQUIRED_ENTITIES = frozenset({
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
})


def _custom_recognizers() -> list[PatternRecognizer]:
    """Core custom recognizers for OSS release — developer secrets + basic injection."""
    return [
        # ── Developer Secrets ─────────────────────────────────────────────
        PatternRecognizer(
            supported_entity="API_KEY",
            name="ApiKeyRecognizer",
            supported_language="en",
            patterns=[
                Pattern("openai_key", r"sk-[a-zA-Z0-9]{20,}", 0.9),
                Pattern("anthropic_key", r"sk-ant-[a-zA-Z0-9]{20,}", 0.9),
                Pattern("google_ai_key", r"AIza[0-9A-Za-z\-_]{35}", 0.9),
            ],
        ),
        PatternRecognizer(
            supported_entity="AWS_ACCESS_KEY",
            name="AwsAccessKeyRecognizer",
            supported_language="en",
            patterns=[
                Pattern("aws_access_key_id", r"AKIA[0-9A-Z]{16}", 0.95),
            ],
        ),
        PatternRecognizer(
            supported_entity="PRIVATE_KEY",
            name="PrivateKeyRecognizer",
            supported_language="en",
            patterns=[
                Pattern("pem_private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 0.95),
                Pattern("ssh_private_key", r"-----BEGIN OPENSSH PRIVATE KEY-----", 0.95),
            ],
        ),
        PatternRecognizer(
            supported_entity="GITHUB_TOKEN",
            name="GitHubTokenRecognizer",
            supported_language="en",
            patterns=[
                Pattern("github_pat", r"ghp_[A-Za-z0-9]{36}", 0.95),
                Pattern("github_oauth", r"gho_[A-Za-z0-9]{36}", 0.95),
                Pattern("github_fine_grained", r"github_pat_[A-Za-z0-9_]{82}", 0.95),
            ],
        ),
        PatternRecognizer(
            supported_entity="SLACK_WEBHOOK",
            name="SlackWebhookRecognizer",
            supported_language="en",
            patterns=[
                Pattern("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", 0.95),
            ],
        ),

        # ── Prompt Injection / Jailbreak Detection (core patterns) ────────
        PatternRecognizer(
            supported_entity="PROMPT_INJECTION",
            name="PromptInjectionRecognizer",
            supported_language="en",
            patterns=[
                Pattern("ignore_previous",
                        r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|rules?|prompts?|directives?|guidelines?|constraints?)",
                        0.85),
                Pattern("disregard_instructions",
                        r"(?i)(disregard|forget|override|bypass|skip|drop)\s+(all\s+)?(previous|prior|above|your|the|system)?\s*(instructions?|rules?|prompts?|guidelines?|constraints?|programming|training)",
                        0.85),
                Pattern("reveal_system_prompt",
                        r"(?i)(reveal|show|display|print|output|repeat|echo|tell\s+me|give\s+me|what\s+(is|are))\s+(your|the)\s+(system|initial|original|hidden|secret|internal)\s*(prompt|instructions?|rules?|message|configuration|directives?)",
                        0.9),
                Pattern("dan_jailbreak",
                        r"(?i)(you\s+are|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as|imagine\s+you\s+are|from\s+now\s+on\s+you\s+are)\s+(DAN|an?\s+unrestricted|an?\s+uncensored|an?\s+unfiltered|a\s+jailbroken|evil|Developer\s*Mode|god\s*mode)",
                        0.9),
                Pattern("developer_mode",
                        r"(?i)(enable|activate|enter|switch\s+to|turn\s+on)\s+(developer|debug|admin|god|unrestricted|jailbreak|sudo)\s*(mode|access)",
                        0.85),
            ],
        ),
    ]


def build_analyzer() -> AnalyzerEngine:
    """Return an AnalyzerEngine with built-in + core custom recognizers."""
    engine = AnalyzerEngine()

    for rec in _custom_recognizers():
        engine.registry.add_recognizer(rec)

    loaded = {
        ent
        for r in engine.registry.recognizers
        for ent in (r.supported_entities or [])
    }
    missing = REQUIRED_ENTITIES - loaded
    if missing:
        raise RuntimeError(
            f"Presidio engine missing required recognizers: {missing}. "
            "Check that the spaCy en_core_web_lg model is installed."
        )

    return engine
