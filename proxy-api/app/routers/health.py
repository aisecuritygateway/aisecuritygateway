"""Health check endpoint."""

from __future__ import annotations

import time

import httpx
import structlog
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..config import get_settings
from ..providers import list_providers

log = structlog.get_logger()
router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    """Health check: verify Presidio reachability and return status with provider list."""
    settings = get_settings()
    start = time.monotonic()
    checks: dict[str, str] = {}

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{settings.presidio_url.rstrip('/')}/health")
            checks["presidio"] = "ok" if resp.status_code == 200 else "degraded"
    except Exception:
        checks["presidio"] = "unreachable"

    elapsed_ms = int((time.monotonic() - start) * 1000)
    all_ok = all(v == "ok" for v in checks.values())
    status_label = "healthy" if all_ok else "degraded"

    log.info("health_check", overall=status_label, checks=checks, check_ms=elapsed_ms)

    return JSONResponse(
        status_code=200 if all_ok else 207,
        content={
            "status": status_label,
            "checks": checks,
            "providers": list_providers(),
            "check_ms": elapsed_ms,
        },
        headers={"Cache-Control": "no-cache, no-store"},
    )
