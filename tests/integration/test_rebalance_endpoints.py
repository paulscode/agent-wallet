# SPDX-License-Identifier: MIT
"""Integration tests for the dashboard rebalance endpoints.

Drives the real FastAPI router via ``ASGITransport`` so we exercise
auth (session cookie), CSRF gating, JSON validation, and the audit-log
DB write end-to-end. Only the LND service layer is mocked.
"""

from __future__ import annotations

import time
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.database import get_db
from app.dashboard import DASHBOARD_KEY_ID
from app.dashboard.auth import COOKIE_NAME
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog


def _make_session_cookie() -> str:
    expires = int(time.time()) + 86400
    # Modern cookie format: ``session_id:expires`` (the legacy id-less
    # format is rejected). Use a UNIQUE session id per cookie so a
    # revoke/logout test can't poison the process-local revocation
    # cache for other tests sharing this helper.
    import secrets as _secrets

    payload = f"sess-itest-{_secrets.token_urlsafe(8)}:{expires}"
    from app.dashboard.auth import _sign  # production (domain-separated) signer

    return f"{payload}.{_sign(payload)}"


@pytest_asyncio.fixture
async def dashboard_client(db_engine) -> AsyncGenerator[AsyncClient, None]:
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


@pytest.fixture
def auth_cookies(dashboard_client):
    cookie = _make_session_cookie()
    dashboard_client.cookies.set(COOKIE_NAME, cookie)
    return {COOKIE_NAME: cookie}


@pytest.fixture(autouse=True)
def _bypass_csrf():
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        yield


@pytest_asyncio.fixture
async def dashboard_sentinel_key(db_engine):
    """Insert the ``__dashboard__`` sentinel APIKey row (Alembic 002 in prod)."""
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        existing = await session.get(APIKey, DASHBOARD_KEY_ID)
        if existing is None:
            session.add(
                APIKey(
                    id=DASHBOARD_KEY_ID,
                    name="__dashboard__",
                    key_hash="dashboard-sentinel-no-login",
                    is_admin=True,
                    is_active=True,
                )
            )
            await session.commit()
    yield


def _channels_fixture() -> list[dict]:
    return [
        {
            "chan_id": "111",
            "active": True,
            "capacity": 200_000,
            "local_balance": 150_000,
            "remote_balance": 48_000,
            "local_chan_reserve_sat": 2_000,
            "remote_chan_reserve_sat": 2_000,
            "unsettled_balance": 0,
            "remote_pubkey": "02" + "a" * 64,
            "peer_alias": "src-peer",
        },
        {
            "chan_id": "222",
            "active": True,
            "capacity": 200_000,
            "local_balance": 30_000,
            "remote_balance": 168_000,
            "local_chan_reserve_sat": 2_000,
            "remote_chan_reserve_sat": 2_000,
            "unsettled_balance": 0,
            "remote_pubkey": "03" + "b" * 64,
            "peer_alias": "dst-peer",
        },
    ]


# ── Auth + CSRF gating ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_quote_unauth_returns_401(dashboard_client):
    resp = await dashboard_client.post(
        "/dashboard/api/rebalance/quote",
        json={"source_chan_id": "111", "dest_chan_id": "222", "amount_sats": 1000},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rebalance_unauth_returns_401(dashboard_client):
    resp = await dashboard_client.post(
        "/dashboard/api/rebalance",
        json={
            "source_chan_id": "111",
            "dest_chan_id": "222",
            "amount_sats": 1000,
            "fee_limit_sats": 10,
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_recent_unauth_returns_401(dashboard_client):
    resp = await dashboard_client.get("/dashboard/api/rebalance/recent")
    assert resp.status_code == 401


# ── Validation rejections (live HTTP) ─────────────────────────────────


@pytest.mark.asyncio
async def test_quote_rejects_bad_chan_id(dashboard_client, auth_cookies):
    resp = await dashboard_client.post(
        "/dashboard/api/rebalance/quote",
        json={"source_chan_id": "abc", "dest_chan_id": "222", "amount_sats": 1000},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_rebalance_rejects_fee_exceeding_amount(dashboard_client, auth_cookies):
    """Plan defensive cap: fee must not exceed principal."""
    resp = await dashboard_client.post(
        "/dashboard/api/rebalance",
        json={
            "source_chan_id": "111",
            "dest_chan_id": "222",
            "amount_sats": 100,
            "fee_limit_sats": 200,
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_rebalance_rejects_zero_amount(dashboard_client, auth_cookies):
    resp = await dashboard_client.post(
        "/dashboard/api/rebalance",
        json={
            "source_chan_id": "111",
            "dest_chan_id": "222",
            "amount_sats": 0,
            "fee_limit_sats": 0,
        },
    )
    assert resp.status_code == 422


# ── Quote happy path ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_quote_happy_path(dashboard_client, auth_cookies):
    with (
        patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(_channels_fixture(), None),
        ),
        patch(
            "app.dashboard.api.lnd_service.get_info",
            new_callable=AsyncMock,
            return_value=({"identity_pubkey": "02" + "f" * 64}, None),
        ),
        patch(
            "app.dashboard.api.lnd_service.query_routes",
            new_callable=AsyncMock,
            return_value=(
                {
                    "hops": 2,
                    "total_amt_sat": 10_001,
                    "total_fees_sat": 1,
                    "total_amt_msat": 10_001_000,
                    "total_fees_msat": 1_000,
                    "total_time_lock": 700,
                    "ppm": 100,
                },
                None,
            ),
        ),
    ):
        resp = await dashboard_client.post(
            "/dashboard/api/rebalance/quote",
            json={
                "source_chan_id": "111",
                "dest_chan_id": "222",
                "amount_sats": 10_000,
                "fee_limit_sats": 50,
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["route"]["hops"] == 2
    assert body["max_sendable_sats"] > 0
    assert body["max_receivable_sats"] > 0
    assert body["source"]["chan_id"] == "111"
    assert body["dest"]["chan_id"] == "222"


# ── Rebalance happy path + audit row ──────────────────────────────────


@pytest.mark.asyncio
async def test_rebalance_happy_path_writes_audit(
    dashboard_client,
    auth_cookies,
    dashboard_sentinel_key,
    db_engine,
):
    with (
        patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(_channels_fixture(), None),
        ),
        patch(
            "app.dashboard.api.lnd_service.create_invoice",
            new_callable=AsyncMock,
            return_value=(
                {"payment_request": "lnbc1...", "r_hash": "YWJj", "add_index": "1"},
                None,
            ),
        ),
        patch(
            "app.dashboard.api.lnd_service.send_payment_v2",
            new_callable=AsyncMock,
            return_value=(
                {
                    "payment_hash": "abc",
                    "payment_preimage": "def",
                    "amount_sats": 10_000,
                    "fee_sats": 1,
                    "fee_msat": 1_000,
                    "hops": 2,
                    "duration_ms": 500,
                },
                None,
            ),
        ),
    ):
        resp = await dashboard_client.post(
            "/dashboard/api/rebalance",
            json={
                "source_chan_id": "111",
                "dest_chan_id": "222",
                "amount_sats": 10_000,
                "fee_limit_sats": 50,
                "timeout_seconds": 10,
            },
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] is True
    assert body["result"]["fee_sats"] == 1

    # Verify audit row was written.
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog).where(AuditLog.action == "rebalance_channel"))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.success is True
    assert row.amount_sats == 10_000
    assert (row.details or {})["source_chan_id"] == "111"


# ── Rebalance failure path also audits ────────────────────────────────


@pytest.mark.asyncio
async def test_rebalance_send_failure_audits_with_error(
    dashboard_client,
    auth_cookies,
    dashboard_sentinel_key,
    db_engine,
):
    with (
        patch(
            "app.dashboard.api.lnd_service.get_channels",
            new_callable=AsyncMock,
            return_value=(_channels_fixture(), None),
        ),
        patch(
            "app.dashboard.api.lnd_service.create_invoice",
            new_callable=AsyncMock,
            return_value=(
                {"payment_request": "lnbc1...", "r_hash": "YWJj", "add_index": "1"},
                None,
            ),
        ),
        patch(
            "app.dashboard.api.lnd_service.send_payment_v2",
            new_callable=AsyncMock,
            return_value=(None, "Payment failed: TIMEOUT"),
        ),
    ):
        resp = await dashboard_client.post(
            "/dashboard/api/rebalance",
            json={
                "source_chan_id": "111",
                "dest_chan_id": "222",
                "amount_sats": 10_000,
                "fee_limit_sats": 50,
            },
        )

    assert resp.status_code == 502

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog).where(AuditLog.action == "rebalance_channel"))).scalars().all()
    assert len(rows) == 1
    assert rows[0].success is False
    assert rows[0].error_message is not None and "TIMEOUT" in rows[0].error_message


# ── Recent endpoint round-trip ────────────────────────────────────────


@pytest.mark.asyncio
async def test_recent_returns_only_successes(
    dashboard_client,
    auth_cookies,
    dashboard_sentinel_key,
    db_engine,
):
    """End-to-end: write three audit rows directly, then read them via
    the HTTP endpoint."""
    from app.services.audit_service import log_dashboard_action

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        await log_dashboard_action(
            session,
            DASHBOARD_KEY_ID,
            "rebalance_channel",
            "channel",
            amount_sats=1_000,
            success=True,
            details={
                "source_chan_id": "111",
                "dest_chan_id": "222",
                "fee_sats": 1,
                "hops": 2,
                "source_alias": "a",
                "dest_alias": "b",
            },
        )
        await log_dashboard_action(
            session,
            DASHBOARD_KEY_ID,
            "rebalance_channel",
            "channel",
            amount_sats=2_000,
            success=False,
            error_message="NO_ROUTE",
            details={"source_chan_id": "x", "dest_chan_id": "y"},
        )
        await log_dashboard_action(
            session,
            DASHBOARD_KEY_ID,
            "rebalance_channel",
            "channel",
            amount_sats=3_000,
            success=True,
            details={
                "source_chan_id": "555",
                "dest_chan_id": "666",
                "fee_sats": 5,
                "hops": 4,
                "source_alias": "c",
                "dest_alias": "d",
            },
        )
        await session.commit()

    resp = await dashboard_client.get(
        "/dashboard/api/rebalance/recent?limit=5",
    )
    assert resp.status_code == 200
    items = resp.json()["rebalances"]
    # Failed rebalance must not appear.
    amounts = {it["amount_sats"] for it in items}
    assert 2_000 not in amounts
    assert {1_000, 3_000} <= amounts
    # Newest first.
    assert items[0]["amount_sats"] == 3_000


@pytest.mark.asyncio
async def test_recent_limit_param(
    dashboard_client,
    auth_cookies,
    dashboard_sentinel_key,
    db_engine,
):
    from app.services.audit_service import log_dashboard_action

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        for i in range(4):
            await log_dashboard_action(
                session,
                DASHBOARD_KEY_ID,
                "rebalance_channel",
                "channel",
                amount_sats=1_000 + i,
                success=True,
                details={"source_chan_id": str(i), "dest_chan_id": str(i + 1)},
            )
        await session.commit()

    resp = await dashboard_client.get(
        "/dashboard/api/rebalance/recent?limit=2",
    )
    assert resp.status_code == 200
    assert len(resp.json()["rebalances"]) == 2


@pytest.mark.asyncio
async def test_recent_limit_validation(dashboard_client, auth_cookies):
    """``limit`` is bounded ``[1, 20]``."""
    resp = await dashboard_client.get(
        "/dashboard/api/rebalance/recent?limit=0",
    )
    assert resp.status_code == 422
    resp = await dashboard_client.get(
        "/dashboard/api/rebalance/recent?limit=999",
    )
    assert resp.status_code == 422
