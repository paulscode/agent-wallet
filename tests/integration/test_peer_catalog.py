# SPDX-License-Identifier: MIT
"""Integration tests for the small-channel peer-catalog endpoints.

Covers two surfaces that read from
:mod:`app.services.small_channel_peers`:

* ``GET /v1/peer-catalog/small-channel`` — API-key auth (any key).
* ``GET /dashboard/api/peer-catalog/small-channel`` — session auth via
  the dashboard's HMAC-signed cookie.

Both endpoints share the same body shape so dashboard JS can fetch
the catalog through whichever credential path is convenient.
"""

from __future__ import annotations

import importlib
import time
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import settings
from app.core.database import get_db
from app.dashboard.auth import COOKIE_NAME


def _make_session_cookie() -> str:
    """Mint a valid HMAC-signed session cookie for the dashboard tests."""
    from app.dashboard.auth import _sign

    expires = int(time.time()) + 86400
    import secrets as _secrets

    payload = f"sess-itest-{_secrets.token_urlsafe(8)}:{expires}"
    return f"{payload}.{_sign(payload)}"


@pytest_asyncio.fixture
async def dashboard_app_client(db_engine) -> AsyncGenerator[AsyncClient, None]:
    """Test client with the dashboard router mounted — exercises the
    session-authed wrapper."""
    from fastapi import FastAPI

    from app.dashboard.api import router as dashboard_api

    app = FastAPI()
    app.include_router(dashboard_api)

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        follow_redirects=False,
        headers={"X-Requested-With": "XMLHttpRequest"},
    ) as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def v1_app_client(db_engine) -> AsyncGenerator[AsyncClient, None]:
    """Test client with the v1 peer-catalog router mounted — exercises
    the API-key-authed surface. ``get_api_key`` is dependency-overridden
    to accept any caller so the catalog body can be inspected without
    creating a full API-key fixture (the catalog is non-sensitive
    public data; per-key authentication is exercised in the
    security suite)."""
    from fastapi import FastAPI

    from app.api.peer_catalog import router as peer_catalog_router
    from app.core.security import get_api_key

    app = FastAPI()
    app.include_router(peer_catalog_router)

    async def _stub_api_key():
        # Return a sentinel object the route's signature accepts.
        class _StubKey:
            id = "stub"

        return _StubKey()

    app.dependency_overrides[get_api_key] = _stub_api_key

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _reset_catalog_module_at_setup():
    """Reload the catalog module at setup so this file's tests inherit
    the bundled view regardless of what the previous file's tests
    left behind.

    Teardown-side reload is intentionally absent: the endpoint reads
    ``settings.small_channel_peer_catalog_enabled`` and
    ``settings.bitcoin_network`` at request time (not at module load),
    so a ``monkeypatch.setattr`` inside the test body covers the
    feature-flag-off / non-mainnet cases without needing to reload the
    catalog data. The unit-test fixture in
    ``tests/unit/test_small_channel_peers.py`` does need to reload —
    it tests load-time behavior of the overrides file — but its
    teardown explicitly re-pins the settings to bundled defaults so
    the reload picks up a clean state.
    """
    from app.services import small_channel_peers as scp_module

    importlib.reload(scp_module)
    yield


class TestV1Endpoint:
    @pytest.mark.asyncio
    async def test_returns_full_catalog_on_mainnet(self, v1_app_client, monkeypatch):
        monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
        resp = await v1_app_client.get("/v1/peer-catalog/small-channel")
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is True
        assert body["network"] == "bitcoin"
        assert len(body["peers"]) == 16
        assert body["snapshot_date"]

    @pytest.mark.asyncio
    async def test_peer_entries_carry_every_field_consumers_rely_on(
        self, v1_app_client, monkeypatch,
    ):
        monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
        resp = await v1_app_client.get("/v1/peer-catalog/small-channel")
        body = resp.json()
        for peer in body["peers"]:
            assert peer["alias"]
            assert len(peer["node_id_hex"]) == 66
            assert peer["address"]
            assert peer["network"] == "bitcoin"
            assert peer["min_channel_size_sats"] > 0
            assert peer["typical"]["fee_base_msat"] >= 0
            assert peer["typical"]["fee_rate_milli_msat"] >= 0
            assert peer["fee_tier"]
            assert peer["connectivity_tier"]
            assert peer["verified_at"]
            assert peer["funding_txid"]
            # ``caveats`` is always present (possibly empty) so dashboard
            # JS can ``.length`` it without a null guard.
            assert isinstance(peer["caveats"], list)

    @pytest.mark.asyncio
    async def test_recommended_default_starred_peers_visible(
        self, v1_app_client, monkeypatch,
    ):
        monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
        resp = await v1_app_client.get("/v1/peer-catalog/small-channel")
        body = resp.json()
        starred = [p for p in body["peers"] if "recommended_default" in p["tags"]]
        assert starred, "catalog should ship at least one ⭐ peer"

    @pytest.mark.asyncio
    async def test_returns_empty_when_feature_flag_off(
        self, v1_app_client, monkeypatch,
    ):
        monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
        monkeypatch.setattr(settings, "small_channel_peer_catalog_enabled", False)
        resp = await v1_app_client.get("/v1/peer-catalog/small-channel")
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is False
        assert body["peers"] == []
        # Snapshot date still surfaces so the dashboard's "verified N
        # days ago" line can render against an empty list.
        assert body["snapshot_date"]

    @pytest.mark.asyncio
    async def test_returns_empty_on_non_mainnet_network(
        self, v1_app_client, monkeypatch,
    ):
        monkeypatch.setattr(settings, "bitcoin_network", "regtest")
        resp = await v1_app_client.get("/v1/peer-catalog/small-channel")
        assert resp.status_code == 200
        body = resp.json()
        # The feature is enabled, but the catalog is mainnet-only.
        assert body["enabled"] is True
        assert body["network"] == "regtest"
        assert body["peers"] == []


class TestDashboardWrapper:
    @pytest.fixture
    def auth_cookies(self, dashboard_app_client):
        cookie = _make_session_cookie()
        dashboard_app_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_returns_same_shape_as_v1_endpoint(
        self, dashboard_app_client, auth_cookies, monkeypatch,
    ):
        monkeypatch.setattr(settings, "bitcoin_network", "bitcoin")
        resp = await dashboard_app_client.get("/dashboard/api/peer-catalog/small-channel")
        assert resp.status_code == 200
        body = resp.json()
        # Same keys as the v1 endpoint so dashboard JS can share parsing
        # code regardless of which surface fetched the catalog.
        assert set(body) == {"enabled", "snapshot_date", "network", "peers"}
        assert body["enabled"] is True
        assert body["network"] == "bitcoin"
        assert len(body["peers"]) == 16

    @pytest.mark.asyncio
    async def test_rejects_request_without_session(self, dashboard_app_client):
        resp = await dashboard_app_client.get("/dashboard/api/peer-catalog/small-channel")
        # ``_require_auth`` raises 401 when the signed cookie is absent.
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_honors_feature_flag(
        self, dashboard_app_client, auth_cookies, monkeypatch,
    ):
        monkeypatch.setattr(settings, "small_channel_peer_catalog_enabled", False)
        resp = await dashboard_app_client.get("/dashboard/api/peer-catalog/small-channel")
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is False
        assert body["peers"] == []
