"""AISG Presidio Service — PII detection and anonymization.

Wraps Microsoft Presidio with custom recognizers, CSV-aware thresholds,
and a combined /process endpoint for the AISG Gateway.
"""

from __future__ import annotations

import json
import logging
import sys
import time
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from presidio_analyzer import PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig as PresidioOperatorConfig

from .models import (
    AnonymizedItem,
    HealthResponse,
    ProcessRequest,
    ProcessResponse,
    RecognizerResult,
)
from .post_processor import filter_false_positives
from .recognizers import build_analyzer

class _JsonHandler(logging.StreamHandler):
    """JSON logging handler that emits one structured log line per record."""

    def emit(self, record: logging.LogRecord) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "service": "aisg-presidio",
            "message": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info and record.exc_info[1]:
            entry["error"] = str(record.exc_info[1])
            entry["traceback"] = "".join(traceback.format_exception(*record.exc_info))
        self.stream.write(json.dumps(entry) + "\n")
        self.stream.flush()


_handler = _JsonHandler(sys.stdout)
logging.root.handlers = [_handler]
logging.root.setLevel(logging.INFO)

_log = logging.getLogger("aisg.presidio")

_analyzer: Any = None
_anonymizer: Any = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build the Presidio analyzer and anonymizer engines on startup."""
    global _analyzer, _anonymizer
    _analyzer = build_analyzer()
    _anonymizer = AnonymizerEngine()
    yield


app = FastAPI(
    title="AISG Presidio Service",
    description="PII detection and anonymization powered by Microsoft Presidio",
    version="0.1.0",
    lifespan=lifespan,
)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log inbound request method/path and outbound status/duration."""

    async def dispatch(self, request, call_next):
        path = request.url.path
        method = request.method
        content_length = request.headers.get("content-length")
        _log.info(
            "request_in method=%s path=%s content_length=%s",
            method,
            path,
            content_length,
        )
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = int((time.monotonic() - start) * 1000)
        _log.info(
            "request_out method=%s path=%s status_code=%s duration_ms=%s",
            method,
            path,
            response.status_code,
            duration_ms,
        )
        return response


app.add_middleware(RequestLoggingMiddleware)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Return a 500 JSON response for uncaught exceptions."""
    _log.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "message": "PII service encountered an unexpected error."},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return a 422 JSON response for request validation errors."""
    _log.warning("Validation error on %s %s: %s", request.method, request.url.path, exc.errors())
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "message": "Invalid request format.", "details": exc.errors()},
    )


def _remove_temp_recognizers(analyzer: Any, recognizers: list[PatternRecognizer]) -> None:
    """Remove temporarily-registered recognizers after a request completes."""
    for rec in recognizers:
        try:
            analyzer.registry.remove_recognizer(rec.name)
        except Exception:
            pass


@app.get("/health", response_model=HealthResponse)
async def health():
    """Return recognizer count and supported entity types."""
    _log.info("health_start")
    entities = sorted({
        ent
        for r in _analyzer.registry.recognizers
        for ent in r.supported_entities
    })
    recognizer_count = len(_analyzer.registry.recognizers)
    _log.info(
        "health_complete recognizers=%s entity_type_count=%s entity_types=%s",
        recognizer_count,
        len(entities),
        entities,
    )
    return HealthResponse(
        status="ok",
        recognizers=recognizer_count,
        entities=entities,
    )


@app.post("/process", response_model=ProcessResponse)
async def process(req: ProcessRequest):
    """Combined analyze + anonymize in a single call."""
    analyzer = _analyzer
    temp_recognizers: list[PatternRecognizer] = []
    request_entities = list(req.entities) if req.entities else None
    entities_requested = req.entities if req.entities is not None else "all"
    _log.info("process_start entities_requested=%s", entities_requested)

    scan_text = req.text

    if req.custom_regex_rules:
        for rule in req.custom_regex_rules:
            entity_name = f"CUSTOM_{rule.label.upper().replace(' ', '_')}"
            rec = PatternRecognizer(
                supported_entity=entity_name,
                name=f"custom_{rule.label}",
                supported_language="en",
                patterns=[Pattern(rule.label, rule.pattern, rule.score)],
            )
            analyzer.registry.add_recognizer(rec)
            temp_recognizers.append(rec)
            if request_entities is not None:
                request_entities.append(entity_name)

    analyze_start = time.monotonic()
    try:
        raw_results = analyzer.analyze(
            text=scan_text,
            language=req.language,
            entities=request_entities,
            score_threshold=req.score_threshold,
        )
    except Exception as exc:
        _remove_temp_recognizers(analyzer, temp_recognizers)
        _log.warning("process_analyze_error before_422 detail=%s", exc)
        raise HTTPException(status_code=422, detail=str(exc))

    _remove_temp_recognizers(analyzer, temp_recognizers)

    raw_results = filter_false_positives(scan_text, raw_results)
    analyze_duration_ms = int((time.monotonic() - analyze_start) * 1000)
    _log.info(
        "analyze_complete entities_found=%s entity_types=%s duration_ms=%s",
        len(raw_results),
        sorted({r.entity_type for r in raw_results}),
        analyze_duration_ms,
    )

    results = [
        RecognizerResult(
            entity_type=r.entity_type,
            start=r.start,
            end=r.end,
            score=r.score,
        )
        for r in raw_results
    ]

    anonymized_text = None
    items = None

    if req.anonymize and raw_results:
        operators = None
        if req.operators:
            operators = {
                entity: _to_presidio_operator(cfg)
                for entity, cfg in req.operators.items()
            }

        try:
            anon_result = _anonymizer.anonymize(
                text=scan_text,
                analyzer_results=raw_results,
                operators=operators,
            )
        except Exception as exc:
            _log.warning("process_anonymize_error before_422 detail=%s", exc)
            raise HTTPException(status_code=422, detail=str(exc))

        anonymized_text = anon_result.text
        items = [
            AnonymizedItem(
                start=item.start,
                end=item.end,
                entity_type=item.entity_type,
                text=item.text,
                operator=item.operator,
            )
            for item in anon_result.items
        ]

    _log.info(
        "process_complete entities_found=%s entity_types=%s anonymize=%s",
        len(results),
        sorted({r.entity_type for r in results}),
        req.anonymize,
    )

    return ProcessResponse(
        results=results,
        anonymized_text=anonymized_text,
        items=items,
    )


def _to_presidio_operator(cfg) -> PresidioOperatorConfig:
    """Map an API OperatorConfig to a Presidio OperatorConfig."""
    params: dict[str, Any] = {}
    if cfg.new_value is not None:
        params["new_value"] = cfg.new_value
    if cfg.mask_char is not None:
        params["masking_char"] = cfg.mask_char
    if cfg.chars_to_mask is not None:
        params["chars_to_mask"] = cfg.chars_to_mask
    if cfg.from_end is not None:
        params["from_end"] = cfg.from_end
    if cfg.hash_type is not None:
        params["hash_type"] = cfg.hash_type
    return PresidioOperatorConfig(cfg.type, params)
