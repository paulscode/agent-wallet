# SPDX-License-Identifier: MIT
"""Error-path coverage for the dashboard JSON API.

The dashboard router gates reads behind a signed session cookie
(``_require_auth``) and writes behind session + CSRF
(``_require_auth_csrf``). These tests pin the request->response
contract for the failure modes the happy-path suites in
``tests/integration/test_dashboard*.py`` don't exercise exhaustively:

* anonymous reads/writes → 401,
* authenticated writes without a CSRF header → 403/503,
* request-body validation rejections → 422,
* malformed path params → 400,
* upstream (LND/mempool) failures surfaced as 502 with a sanitized
  ``detail`` body.

The tests mirror the ``dashboard_client`` fixture + session-cookie
helpers used by the existing dashboard suite so they stay consistent
with that style.
"""

from __future__ import annotations

import time
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import settings
from app.core.database import get_db
from app.dashboard.auth import COOKIE_NAME


def _make_session_cookie() -> str:
    """A valid HMAC-signed session cookie, minted with the production
    ``_sign`` so the test tracks the cookie-signing key derivation."""
    import secrets

    from app.dashboard.auth import _sign

    expires = int(time.time()) + 86400
    payload = f"sess-errpath-{secrets.token_urlsafe(8)}:{expires}"
    return f"{payload}.{_sign(payload)}"


@pytest_asyncio.fixture
async def dashboard_client(db_engine) -> AsyncGenerator[AsyncClient, None]:
    """Test client with the dashboard routers mounted."""
    from fastapi import FastAPI

    from app.dashboard.api import router as dashboard_api
    from app.dashboard.routes import router as dashboard_routes

    app = FastAPI()
    app.include_router(dashboard_routes)
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


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


@pytest.fixture
def _authed(dashboard_client):
    """Attach a valid session cookie to the client and return it."""
    dashboard_client.cookies.set(COOKIE_NAME, _make_session_cookie())
    return dashboard_client


# ── Anonymous access is rejected (401) ──────────────────────────────


_READ_ENDPOINTS = (
    "/dashboard/api/summary",
    "/dashboard/api/channels",
    "/dashboard/api/channels/pending",
    "/dashboard/api/payments",
    "/dashboard/api/invoices",
    "/dashboard/api/transactions",
    "/dashboard/api/fees",
    "/dashboard/api/info",
)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", _READ_ENDPOINTS)
async def test_read_endpoints_require_session(dashboard_client, path) -> None:
    """Every dashboard read endpoint rejects a request with no session
    cookie with 401."""
    resp = await dashboard_client.get(path)
    assert resp.status_code == 401


_WRITE_ENDPOINTS = (
    ("/dashboard/api/address", {"address_type": "p2tr"}),
    ("/dashboard/api/invoice", {"amount_sats": 1000}),
    ("/dashboard/api/decode", {"payment_request": "lnbc1"}),
    ("/dashboard/api/pay", {"payment_request": "lnbc1"}),
)


@pytest.mark.asyncio
@pytest.mark.parametrize("path,body", _WRITE_ENDPOINTS)
async def test_write_endpoints_require_session(dashboard_client, path, body) -> None:
    """Dashboard write endpoints reject an anonymous (no-cookie) POST
    with 401 before any CSRF check."""
    resp = await dashboard_client.post(path, json=body)
    assert resp.status_code == 401


# ── Authenticated writes need a CSRF token (403/503) ────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("path,body", _WRITE_ENDPOINTS)
async def test_write_endpoints_require_csrf(_authed, path, body) -> None:
    """An authenticated write with no ``X-CSRF-Token`` header is
    rejected: 403 for a genuine violation (503 only if the CSRF
    backend is unavailable)."""
    resp = await _authed.post(path, json=body)
    assert resp.status_code in (403, 503)


# ── Request-body validation (422) ───────────────────────────────────


@pytest.mark.asyncio
async def test_create_invoice_rejects_non_positive_amount(_authed) -> None:
    """``InvoiceRequest.amount_sats`` is ``gt=0``; a zero amount fails
    Pydantic validation with 422 before the CSRF/LND path runs."""
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        resp = await _authed.post("/dashboard/api/invoice", json={"amount_sats": 0})
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "amount_sats" for err in resp.json()["detail"])


@pytest.mark.asyncio
async def test_create_invoice_rejects_out_of_range_expiry(_authed) -> None:
    """``expiry`` is bounded 60..86400; an over-long expiry is rejected
    with 422."""
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        resp = await _authed.post(
            "/dashboard/api/invoice",
            json={"amount_sats": 1000, "expiry": 999_999},
        )
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "expiry" for err in resp.json()["detail"])


@pytest.mark.asyncio
async def test_pay_rejects_out_of_range_fee_limit(_authed) -> None:
    """``PayRequest.fee_limit_sats`` is bounded 0..1_000_000; a value
    above the ceiling fails request validation with 422."""
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        resp = await _authed.post(
            "/dashboard/api/pay",
            json={"payment_request": "lnbc1", "fee_limit_sats": 5_000_000},
        )
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "fee_limit_sats" for err in resp.json()["detail"])


# ── Malformed path param (400) ──────────────────────────────────────


@pytest.mark.asyncio
async def test_invoice_status_rejects_non_hex_hash(_authed) -> None:
    """``/invoice/{r_hash}`` only accepts a 64-char hex payment hash;
    a malformed value is rejected with 400 before any LND lookup."""
    resp = await _authed.get("/dashboard/api/invoice/not-a-valid-hash")
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid invoice hash"


# ── Upstream failures surfaced as 502 ───────────────────────────────


@pytest.mark.asyncio
async def test_channels_surfaces_lnd_error_as_502(_authed) -> None:
    """When ``get_channels`` returns an error tuple the endpoint
    returns 502 with a sanitized ``detail`` rather than raising."""
    with patch(
        "app.dashboard.api.lnd_service.get_channels",
        new_callable=AsyncMock,
        return_value=(None, "connection refused"),
    ):
        resp = await _authed.get("/dashboard/api/channels")
    assert resp.status_code == 502
    assert "LND" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_payments_surfaces_lnd_error_as_502(_authed) -> None:
    """``/payments`` maps an LND error tuple to 502."""
    with patch(
        "app.dashboard.api.lnd_service.get_recent_payments",
        new_callable=AsyncMock,
        return_value=(None, "rpc deadline exceeded"),
    ):
        resp = await _authed.get("/dashboard/api/payments")
    assert resp.status_code == 502
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_transactions_surfaces_lnd_error_as_502(_authed) -> None:
    """``/transactions`` maps an LND error tuple to 502."""
    with patch(
        "app.dashboard.api.lnd_service.get_onchain_transactions",
        new_callable=AsyncMock,
        return_value=(None, "unavailable"),
    ):
        resp = await _authed.get("/dashboard/api/transactions")
    assert resp.status_code == 502
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_fees_surfaces_mempool_error_as_502(_authed) -> None:
    """``/fees`` maps a mempool-service error tuple to 502 with a
    Mempool-scoped sanitized detail."""
    with patch(
        "app.dashboard.api.mempool_fee_service.get_recommended_fees",
        new_callable=AsyncMock,
        return_value=(None, "mempool.space timeout"),
    ):
        resp = await _authed.get("/dashboard/api/fees")
    assert resp.status_code == 502
    assert "Mempool" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_info_surfaces_lnd_error_as_502(_authed) -> None:
    """``/info`` maps an LND ``get_info`` error tuple to 502."""
    with patch(
        "app.dashboard.api.lnd_service.get_info",
        new_callable=AsyncMock,
        return_value=(None, "wallet locked"),
    ):
        resp = await _authed.get("/dashboard/api/info")
    assert resp.status_code == 502
    assert resp.json()["detail"]


# ── Write-endpoint body validation (422) ────────────────────────────


@pytest.mark.asyncio
async def test_open_channel_rejects_malformed_pubkey(_authed) -> None:
    """``OpenChannelRequest.pubkey`` must be 66 hex chars; a malformed
    value fails Pydantic validation with 422 even with CSRF bypassed."""
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        resp = await _authed.post(
            "/dashboard/api/channel/open",
            json={"pubkey": "zz", "local_funding_amount": 1000},
        )
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "pubkey" for err in resp.json()["detail"])


@pytest.mark.asyncio
async def test_close_channel_rejects_malformed_channel_point(_authed) -> None:
    """``CloseChannelRequest.channel_point`` must be ``txid:vout``; a
    bad value is rejected with 422."""
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        resp = await _authed.post(
            "/dashboard/api/channel/close",
            json={"channel_point": "not-an-outpoint"},
        )
    assert resp.status_code == 422
    assert any(err["loc"][-1] == "channel_point" for err in resp.json()["detail"])


@pytest.mark.asyncio
async def test_send_onchain_rejects_invalid_destination_address(_authed) -> None:
    """``send-onchain`` validates the destination address against the
    configured network; a malformed address fails with 422."""
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        resp = await _authed.post(
            "/dashboard/api/send-onchain",
            json={"address": "definitely-not-an-address", "amount_sats": 1000},
        )
    assert resp.status_code == 422


# ── Write-endpoint upstream failures (502) ──────────────────────────


@pytest.mark.asyncio
async def test_estimate_fee_surfaces_lnd_error_as_502(_authed) -> None:
    """``estimate-fee`` maps an LND error tuple to 502."""
    with (
        patch(
            "app.dashboard.api.check_csrf_token",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.dashboard.api.lnd_service.estimate_fee",
            new_callable=AsyncMock,
            return_value=(None, "lnd unavailable"),
        ),
    ):
        resp = await _authed.post(
            "/dashboard/api/estimate-fee",
            json={
                "address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                "amount_sats": 1000,
            },
        )
    assert resp.status_code == 502
    assert "LND" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_open_channel_peer_connect_failure_is_502(_authed) -> None:
    """When a host is supplied, ``channel/open`` connects the peer
    first; a connect failure short-circuits to 502 before any channel
    is opened."""
    with (
        patch(
            "app.dashboard.api.check_csrf_token",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.dashboard.api.lnd_service.connect_peer",
            new_callable=AsyncMock,
            return_value=(None, "connection refused"),
        ),
    ):
        resp = await _authed.post(
            "/dashboard/api/channel/open",
            json={
                "pubkey": "0" * 66,
                "host": "1.2.3.4:9735",
                "local_funding_amount": 1000,
            },
        )
    assert resp.status_code == 502
    assert resp.json()["detail"]


@pytest.mark.asyncio
async def test_decode_invoice_surfaces_lnd_error_as_502(_authed) -> None:
    """``/decode`` maps an LND decode error tuple to 502 (CSRF
    bypassed)."""
    with (
        patch(
            "app.dashboard.api.check_csrf_token",
            new_callable=AsyncMock,
            return_value="ok",
        ),
        patch(
            "app.dashboard.api.lnd_service.decode_payment_request",
            new_callable=AsyncMock,
            return_value=(None, "invalid bech32 checksum"),
        ),
    ):
        resp = await _authed.post(
            "/dashboard/api/decode",
            json={"payment_request": "lnbc1bogus"},
        )
    assert resp.status_code == 502
    assert resp.json()["detail"]
