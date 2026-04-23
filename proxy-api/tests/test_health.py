"""Tests for GET /health — Presidio reachability and provider listing."""

from __future__ import annotations

from unittest.mock import patch, AsyncMock

import httpx
import pytest
from starlette.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    """Yield a TestClient wired to the proxy-api FastAPI app."""
    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    """GET /health checks Presidio and returns provider + status info."""

    def test_healthy_when_presidio_up(self, client):
        mock_resp = httpx.Response(200, json={"status": "ok"})
        with patch("app.routers.health.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get = AsyncMock(return_value=mock_resp)
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            resp = client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "healthy"
            assert data["checks"]["presidio"] == "ok"
            assert "providers" in data
            assert "check_ms" in data

    def test_degraded_when_presidio_returns_error(self, client):
        mock_resp = httpx.Response(500, text="error")
        with patch("app.routers.health.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get = AsyncMock(return_value=mock_resp)
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            resp = client.get("/health")
            assert resp.status_code == 207
            data = resp.json()
            assert data["status"] == "degraded"
            assert data["checks"]["presidio"] == "degraded"

    def test_degraded_when_presidio_unreachable(self, client):
        with patch("app.routers.health.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            resp = client.get("/health")
            assert resp.status_code == 207
            data = resp.json()
            assert data["status"] == "degraded"
            assert data["checks"]["presidio"] == "unreachable"

    def test_cache_control_header(self, client):
        mock_resp = httpx.Response(200, json={"status": "ok"})
        with patch("app.routers.health.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get = AsyncMock(return_value=mock_resp)
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            resp = client.get("/health")
            assert "no-cache" in resp.headers.get("cache-control", "")

    def test_providers_list_populated(self, client):
        mock_resp = httpx.Response(200, json={"status": "ok"})
        with patch("app.routers.health.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.get = AsyncMock(return_value=mock_resp)
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            resp = client.get("/health")
            providers = resp.json()["providers"]
            assert isinstance(providers, list)
