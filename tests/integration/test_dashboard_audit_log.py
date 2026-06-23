# SPDX-License-Identifier: MIT
"""
Integration tests for the dashboard audit log endpoints
(``/dashboard/api/audit-log``, ``/audit-log/verify``,
``/audit-log/actions``).
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
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
from app.models.audit_log import AuditLog
from app.services.audit_service import log_dashboard_action


def _session_cookie() -> str:
    from app.dashboard.auth import _sign  # production (domain-separated) signer

    expires = int(time.time()) + 86400
    # Modern cookie format: ``session_id:expires`` (the legacy id-less
    # format is rejected). Use a UNIQUE session id per cookie so a
    # revoke/logout test can't poison the process-local revocation
    # cache for other tests sharing this helper.
    import secrets as _secrets

    payload = f"sess-itest-{_secrets.token_urlsafe(8)}:{expires}"
    return f"{payload}.{_sign(payload)}"


@pytest_asyncio.fixture
async def dash_client(db_engine) -> AsyncGenerator[tuple[AsyncClient, async_sessionmaker], None]:
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
        yield ac, session_factory

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def authed_dash_client(dash_client):
    ac, sf = dash_client
    ac.cookies.set(COOKIE_NAME, _session_cookie())
    yield ac, sf


@pytest.fixture(autouse=True)
def _bypass_csrf():
    with patch(
        "app.dashboard.api.check_csrf_token",
        new_callable=AsyncMock,
        return_value="ok",
    ):
        yield


async def _seed_actions(session_factory, count: int, *, action: str = "test_action"):
    async with session_factory() as s:
        for _ in range(count):
            await log_dashboard_action(s, DASHBOARD_KEY_ID, action, "test")


@pytest_asyncio.fixture
async def sf_seed_with_old_rows():
    """Seed one row backdated 30 days plus two recent rows.

    The hash chain stamps ``created_at`` at insert time and refuses to
    go backwards, so we have to seed in chronological order and then
    backdate the first row in-place. We do not recompute ``entry_hash``
    after the backdate — these tests don't exercise the verify
    endpoint, only the time-range filter.
    """

    async def _seed(session_factory):
        async with session_factory() as s:
            old = await log_dashboard_action(
                s,
                DASHBOARD_KEY_ID,
                "old_action",
                "test",
            )
            await log_dashboard_action(s, DASHBOARD_KEY_ID, "recent_action", "test")
            await log_dashboard_action(s, DASHBOARD_KEY_ID, "recent_action", "test")
            old.created_at = datetime.now(timezone.utc) - timedelta(days=30)
            await s.merge(old)
            await s.commit()

    return _seed


# ── auth ───────────────────────────────────────────────────────────────


class TestAuth:
    @pytest.mark.asyncio
    async def test_audit_log_requires_session(self, dash_client):
        ac, _ = dash_client
        resp = await ac.get("/dashboard/api/audit-log")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_verify_requires_session(self, dash_client):
        ac, _ = dash_client
        resp = await ac.get("/dashboard/api/audit-log/verify")
        assert resp.status_code == 401


# ── pagination ─────────────────────────────────────────────────────────


class TestPagination:
    @pytest.mark.asyncio
    async def test_cursor_walk_is_stable_and_non_overlapping(self, authed_dash_client):
        ac, sf = authed_dash_client
        await _seed_actions(sf, 7)

        resp1 = await ac.get("/dashboard/api/audit-log", params={"limit": 3})
        assert resp1.status_code == 200
        page1 = resp1.json()
        assert len(page1["entries"]) == 3
        assert page1["next_cursor"] is not None

        resp2 = await ac.get(
            "/dashboard/api/audit-log",
            params={"limit": 3, "cursor": page1["next_cursor"]},
        )
        assert resp2.status_code == 200, resp2.text
        page2 = resp2.json()
        assert len(page2["entries"]) == 3
        assert page2["next_cursor"] is not None

        resp3 = await ac.get(
            "/dashboard/api/audit-log",
            params={"limit": 3, "cursor": page2["next_cursor"]},
        )
        assert resp3.status_code == 200, resp3.text
        page3 = resp3.json()
        assert len(page3["entries"]) == 1  # 7 total
        assert page3["next_cursor"] is None

        # No overlap between pages.
        ids = (
            [e["id"] for e in page1["entries"]]
            + [e["id"] for e in page2["entries"]]
            + [e["id"] for e in page3["entries"]]
        )
        assert len(ids) == len(set(ids))

    @pytest.mark.asyncio
    async def test_invalid_cursor_returns_400(self, authed_dash_client):
        ac, _ = authed_dash_client
        resp = await ac.get("/dashboard/api/audit-log?cursor=not-a-cursor")
        assert resp.status_code == 400


# ── filters ────────────────────────────────────────────────────────────


class TestFilters:
    @pytest.mark.asyncio
    async def test_action_filter(self, authed_dash_client):
        ac, sf = authed_dash_client
        await _seed_actions(sf, 3, action="alpha_action")
        await _seed_actions(sf, 2, action="beta_action")

        resp = await ac.get("/dashboard/api/audit-log?action=alpha_action")
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) == 3
        assert all(e["action"] == "alpha_action" for e in entries)

    @pytest.mark.asyncio
    async def test_action_filter_rejects_unsafe_chars(self, authed_dash_client):
        ac, _ = authed_dash_client
        resp = await ac.get("/dashboard/api/audit-log?action=foo;DROP")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_api_key_name_filter_uses_ilike(self, authed_dash_client):
        ac, sf = authed_dash_client
        # Dashboard-sourced rows all have api_key_name == "__dashboard__".
        await _seed_actions(sf, 2)
        resp = await ac.get("/dashboard/api/audit-log?api_key_name=dashboard")
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) == 2
        assert all(e["api_key_name"] == "__dashboard__" for e in entries)

    @pytest.mark.asyncio
    async def test_api_key_name_filter_rejects_unsafe_chars(self, authed_dash_client):
        ac, _ = authed_dash_client
        resp = await ac.get("/dashboard/api/audit-log?api_key_name=%27%20OR%201%3D1")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_invalid_since_returns_400(self, authed_dash_client):
        ac, _ = authed_dash_client
        resp = await ac.get("/dashboard/api/audit-log?since=garbage")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_invalid_until_returns_400(self, authed_dash_client):
        ac, _ = authed_dash_client
        resp = await ac.get("/dashboard/api/audit-log?until=garbage")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_since_filter_excludes_old_rows(self, authed_dash_client, sf_seed_with_old_rows):
        ac, sf = authed_dash_client
        await sf_seed_with_old_rows(sf)
        # Cutoff between the old and the recent rows.
        cutoff = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
        resp = await ac.get(
            "/dashboard/api/audit-log",
            params={"since": cutoff},
        )
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        # Only the 2 "recent" rows survive; the 30-day-old one is excluded.
        assert len(entries) == 2
        for e in entries:
            assert e["action"] == "recent_action"

    @pytest.mark.asyncio
    async def test_until_filter_excludes_new_rows(self, authed_dash_client, sf_seed_with_old_rows):
        ac, sf = authed_dash_client
        await sf_seed_with_old_rows(sf)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
        resp = await ac.get(
            "/dashboard/api/audit-log",
            params={"until": cutoff},
        )
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) == 1
        assert entries[0]["action"] == "old_action"

    @pytest.mark.asyncio
    async def test_combined_filters(self, authed_dash_client):
        ac, sf = authed_dash_client
        await _seed_actions(sf, 2, action="alpha_action")
        await _seed_actions(sf, 2, action="beta_action")
        resp = await ac.get(
            "/dashboard/api/audit-log",
            params={"action": "alpha_action", "api_key_name": "dashboard"},
        )
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert len(entries) == 2
        assert all(e["action"] == "alpha_action" for e in entries)

    @pytest.mark.asyncio
    async def test_limit_clamped_at_200(self, authed_dash_client):
        ac, _ = authed_dash_client
        # limit > 200 — Pydantic Query rejects with 422.
        resp = await ac.get("/dashboard/api/audit-log?limit=999")
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_response_shape(self, authed_dash_client):
        ac, sf = authed_dash_client
        await _seed_actions(sf, 1)
        resp = await ac.get("/dashboard/api/audit-log?limit=1")
        assert resp.status_code == 200
        body = resp.json()
        assert set(body.keys()) == {"entries", "next_cursor"}
        e = body["entries"][0]
        for field in (
            "id",
            "api_key_name",
            "action",
            "resource",
            "details",
            "amount_sats",
            "success",
            "error_message",
            "ip_address",
            "created_at",
        ):
            assert field in e


# ── verify endpoint ────────────────────────────────────────────────────


class TestVerify:
    @pytest.mark.asyncio
    async def test_verify_clean_chain(self, authed_dash_client):
        ac, sf = authed_dash_client
        await _seed_actions(sf, 3)
        resp = await ac.get("/dashboard/api/audit-log/verify")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        assert body["first_bad_id"] is None

    @pytest.mark.asyncio
    async def test_verify_detects_tamper(self, authed_dash_client):
        ac, sf = authed_dash_client
        await _seed_actions(sf, 3)

        # Tamper: corrupt the action of one row without recomputing
        # entry_hash, so the chain verify must flag it.
        async with sf() as s:
            rows = (await s.execute(select(AuditLog).order_by(AuditLog.created_at.asc()))).scalars().all()
            rows[1].action = "tampered_action"
            await s.commit()

        resp = await ac.get("/dashboard/api/audit-log/verify")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert body["first_bad_id"] is not None


# ── actions enum ───────────────────────────────────────────────────────


class TestActions:
    @pytest.mark.asyncio
    async def test_actions_requires_session(self, dash_client):
        ac, _ = dash_client
        resp = await ac.get("/dashboard/api/audit-log/actions")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_actions_empty_when_no_audit_rows(self, authed_dash_client):
        ac, _ = authed_dash_client
        resp = await ac.get("/dashboard/api/audit-log/actions")
        assert resp.status_code == 200
        assert resp.json()["actions"] == []

    @pytest.mark.asyncio
    async def test_actions_returns_distinct_sorted(self, authed_dash_client):
        ac, sf = authed_dash_client
        await _seed_actions(sf, 2, action="zz_action")
        await _seed_actions(sf, 1, action="aa_action")
        resp = await ac.get("/dashboard/api/audit-log/actions")
        assert resp.status_code == 200
        actions = resp.json()["actions"]
        assert actions == sorted(actions)
        assert "aa_action" in actions
        assert "zz_action" in actions
