# SPDX-License-Identifier: MIT
"""
Integration tests for the dashboard API key management endpoints
(``/dashboard/api/api-keys`` and ``/dashboard/api/api-keys/{id}/...``).

These tests go through the FastAPI app via httpx ASGITransport so
that auth, CSRF, and the service-layer audit emission are all
exercised together. The CSRF check is patched out since it requires
a Redis backend that the test suite doesn't run.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import settings
from app.core.database import get_db
from app.dashboard.auth import COOKIE_NAME
from app.models.api_key import APIKey
from app.models.audit_log import AuditLog


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


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


# ── auth boundary ──────────────────────────────────────────────────────


class TestAuthBoundary:
    @pytest.mark.asyncio
    async def test_list_requires_session(self, dash_client):
        ac, _ = dash_client
        resp = await ac.get("/dashboard/api/api-keys")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_create_requires_session(self, dash_client):
        ac, _ = dash_client
        resp = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "x", "is_admin": False, "expires_in_days": 7},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_create_requires_csrf(self, dash_client):
        # The autouse fixture patches CSRF away — undo for this one test.
        ac, _ = dash_client
        ac.cookies.set(COOKIE_NAME, _session_cookie())
        with patch(
            "app.dashboard.api.check_csrf_token",
            new=AsyncMock(side_effect=HTTPException(status_code=403, detail="csrf")),
        ):
            resp = await ac.post(
                "/dashboard/api/api-keys",
                json={"name": "x", "is_admin": False, "expires_in_days": 7},
            )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "verb,path,body",
        [
            ("patch", "/dashboard/api/api-keys/00000000-0000-0000-0000-000000000001", {"name": "x"}),
            ("delete", "/dashboard/api/api-keys/00000000-0000-0000-0000-000000000001", None),
            ("post", "/dashboard/api/api-keys/00000000-0000-0000-0000-000000000001/purge", None),
        ],
    )
    async def test_mutations_require_session(self, dash_client, verb, path, body):
        ac, _ = dash_client
        kwargs = {"json": body} if body is not None else {}
        resp = await getattr(ac, verb)(path, **kwargs)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "verb,path,body",
        [
            ("patch", "/dashboard/api/api-keys/00000000-0000-0000-0000-000000000001", {"name": "x"}),
            ("delete", "/dashboard/api/api-keys/00000000-0000-0000-0000-000000000001", None),
            ("post", "/dashboard/api/api-keys/00000000-0000-0000-0000-000000000001/purge", None),
        ],
    )
    async def test_mutations_require_csrf(self, dash_client, verb, path, body):
        ac, _ = dash_client
        ac.cookies.set(COOKIE_NAME, _session_cookie())
        with patch(
            "app.dashboard.api.check_csrf_token",
            new=AsyncMock(side_effect=HTTPException(status_code=403, detail="csrf")),
        ):
            kwargs = {"json": body} if body is not None else {}
            resp = await getattr(ac, verb)(path, **kwargs)
        assert resp.status_code == 403


# ── happy-path lifecycle ───────────────────────────────────────────────


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_create_returns_plaintext_key(self, authed_dash_client):
        ac, _ = authed_dash_client
        resp = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "bot-1", "is_admin": False, "expires_in_days": 30},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["name"] == "bot-1"
        assert body["key"].startswith("lwk_")
        assert "warning" in body
        assert body["status"] in ("active", "expiring")
        assert body["is_admin"] is False

    @pytest.mark.asyncio
    async def test_list_includes_status_and_purge_eligibility(self, authed_dash_client):
        ac, _ = authed_dash_client
        await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "k1", "is_admin": False, "expires_in_days": 30},
        )
        resp = await ac.get("/dashboard/api/api-keys")
        assert resp.status_code == 200
        keys = resp.json()["keys"]
        assert any(k["name"] == "k1" for k in keys)
        for k in keys:
            assert "status" in k
            assert "purge_eligible_at" in k
            assert "key_hash" not in k  # secret never leaks

    @pytest.mark.asyncio
    async def test_full_lifecycle_create_rename_disable_revoke_purge(self, authed_dash_client, monkeypatch):
        # Tight retention so we can purge in the same test.
        monkeypatch.setattr(settings, "audit_log_retention_days", 1)
        ac, sf = authed_dash_client

        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "lifecycle", "is_admin": False, "expires_in_days": 7},
        )
        assert create.status_code == 200
        key_id = create.json()["id"]

        # Rename
        rename = await ac.patch(
            f"/dashboard/api/api-keys/{key_id}",
            json={"name": "renamed"},
        )
        assert rename.status_code == 200
        assert rename.json()["changes"] == {"name": "renamed"}

        # Disable
        disable = await ac.patch(
            f"/dashboard/api/api-keys/{key_id}",
            json={"is_active": False},
        )
        assert disable.status_code == 200
        assert disable.json()["key"]["status"] == "disabled"

        # Re-enable
        enable = await ac.patch(
            f"/dashboard/api/api-keys/{key_id}",
            json={"is_active": True},
        )
        assert enable.status_code == 200
        assert enable.json()["key"]["status"] in ("active", "expiring")

        # Soft delete (revoke)
        revoke = await ac.delete(f"/dashboard/api/api-keys/{key_id}")
        assert revoke.status_code == 200
        assert revoke.json()["key"]["status"] == "revoked"
        assert revoke.json()["key"]["purge_eligible_at"] is not None

        # Purge blocked while inside retention window
        purge_blocked = await ac.post(f"/dashboard/api/api-keys/{key_id}/purge")
        assert purge_blocked.status_code == 400

        # Backdate deleted_at past retention via the test session.
        async with sf() as s:
            row = (await s.execute(select(APIKey).where(APIKey.id == UUID(key_id)))).scalar_one()
            row.deleted_at = datetime.now(timezone.utc) - timedelta(days=10)
            await s.commit()

        purge_ok = await ac.post(f"/dashboard/api/api-keys/{key_id}/purge")
        assert purge_ok.status_code == 200, purge_ok.text
        assert purge_ok.json()["status"] == "purged"

        # Audit log captured every mutation
        async with sf() as s:
            actions = [
                row.action
                for row in (await s.execute(select(AuditLog).order_by(AuditLog.created_at.asc()))).scalars().all()
            ]
        assert "create_api_key" in actions
        assert actions.count("update_api_key") >= 3  # rename + disable + enable
        assert "delete_api_key" in actions
        assert "purge_api_key" in actions

    @pytest.mark.asyncio
    async def test_expires_in_days_capped(self, authed_dash_client):
        ac, sf = authed_dash_client
        max_days = settings.api_key_max_ttl_days
        # Pydantic on the dashboard request model caps at 3650 — but
        # the service further clamps to api_key_max_ttl_days.
        resp = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "huge", "is_admin": False, "expires_in_days": 3650},
        )
        assert resp.status_code == 200
        async with sf() as s:
            row = (await s.execute(select(APIKey).where(APIKey.name == "huge"))).scalar_one()
        expected = datetime.now(timezone.utc) + timedelta(days=max_days)
        delta = abs((row.expires_at.replace(tzinfo=timezone.utc) - expected).total_seconds())
        assert delta < 5

    @pytest.mark.asyncio
    async def test_create_validates_request_schema(self, authed_dash_client):
        ac, _ = authed_dash_client
        # name too long (>128) — Pydantic rejects with 422.
        resp = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "x" * 129, "is_admin": False, "expires_in_days": 7},
        )
        assert resp.status_code == 422


# ── plaintext leak prevention ──────────────────────────────────────────


class TestPlaintextLeak:
    """``key`` field must appear *only* on the POST create response.

    Regression guard against accidentally serialising the plaintext on
    list / patch / delete responses (the model never has it back —
    only the in-flight ``raw_key`` returned by ``create_key`` does —
    but a future refactor could re-introduce a leak by reading from
    a wrapper object).
    """

    @pytest.mark.asyncio
    async def test_only_post_returns_key(self, authed_dash_client):
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "leak-check", "is_admin": False, "expires_in_days": 7},
        )
        assert create.status_code == 200
        assert "key" in create.json()
        key_id = create.json()["id"]

        # GET list — no plaintext on any row.
        listed = await ac.get("/dashboard/api/api-keys")
        for k in listed.json()["keys"]:
            assert "key" not in k
            assert "key_hash" not in k

        # PATCH — wrapped serialised key has no ``key`` field.
        patched = await ac.patch(
            f"/dashboard/api/api-keys/{key_id}",
            json={"name": "leak-check2"},
        )
        assert "key" not in patched.json()["key"]

        # DELETE — same shape.
        deleted = await ac.delete(f"/dashboard/api/api-keys/{key_id}")
        assert "key" not in deleted.json()["key"]


# ── promote / demote (scope toggle) ────────────────────────────────────


class TestScopeToggle:
    @pytest.mark.asyncio
    async def test_promote_read_to_admin(self, authed_dash_client):
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "to-promote", "is_admin": False, "expires_in_days": 7},
        )
        key_id = create.json()["id"]

        promote = await ac.patch(
            f"/dashboard/api/api-keys/{key_id}",
            json={"is_admin": True},
        )
        assert promote.status_code == 200
        # Change set is reported in canonical scope terms.
        assert promote.json()["changes"] == {"scope": "admin"}
        assert promote.json()["key"]["is_admin"] is True
        assert promote.json()["key"]["scope"] == "admin"

    @pytest.mark.asyncio
    async def test_demote_admin_to_read(self, authed_dash_client):
        # The dashboard actor is a sentinel, not a real key, so the
        # service-layer self-demote guard never fires here. The
        # last-active-admin guard is purely client-side.
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "to-demote", "is_admin": True, "expires_in_days": 7},
        )
        key_id = create.json()["id"]

        demote = await ac.patch(
            f"/dashboard/api/api-keys/{key_id}",
            json={"is_admin": False},
        )
        assert demote.status_code == 200
        assert demote.json()["key"]["is_admin"] is False

    @pytest.mark.asyncio
    async def test_create_spend_scope_key(self, authed_dash_client):
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "agent", "scope": "spend", "expires_in_days": 7},
        )
        assert create.status_code == 200
        body = create.json()
        assert body["scope"] == "spend"
        assert body["is_admin"] is False

    @pytest.mark.asyncio
    async def test_change_scope_to_spend(self, authed_dash_client):
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "to-spend", "scope": "monitor", "expires_in_days": 7},
        )
        key_id = create.json()["id"]

        patched = await ac.patch(
            f"/dashboard/api/api-keys/{key_id}",
            json={"scope": "spend"},
        )
        assert patched.status_code == 200
        assert patched.json()["changes"] == {"scope": "spend"}
        assert patched.json()["key"]["scope"] == "spend"

    @pytest.mark.asyncio
    async def test_create_invalid_scope_rejected(self, authed_dash_client):
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "bad", "scope": "root", "expires_in_days": 7},
        )
        assert create.status_code == 400


# ── error paths ────────────────────────────────────────────────────────


class TestErrorPaths:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "verb,path_suffix,body",
        [
            ("patch", "", {"name": "x"}),
            ("delete", "", None),
            ("post", "/purge", None),
        ],
    )
    async def test_invalid_uuid_returns_400(
        self,
        authed_dash_client,
        verb,
        path_suffix,
        body,
    ):
        ac, _ = authed_dash_client
        path = f"/dashboard/api/api-keys/not-a-uuid{path_suffix}"
        kwargs = {"json": body} if body is not None else {}
        resp = await getattr(ac, verb)(path, **kwargs)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "verb,path_suffix,body",
        [
            ("patch", "", {"name": "x"}),
            ("delete", "", None),
            ("post", "/purge", None),
        ],
    )
    async def test_unknown_key_returns_404(
        self,
        authed_dash_client,
        verb,
        path_suffix,
        body,
    ):
        ac, _ = authed_dash_client
        path = f"/dashboard/api/api-keys/{uuid4()}{path_suffix}"
        kwargs = {"json": body} if body is not None else {}
        resp = await getattr(ac, verb)(path, **kwargs)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_purge_without_soft_delete_400(self, authed_dash_client):
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "alive", "is_admin": False, "expires_in_days": 7},
        )
        key_id = create.json()["id"]
        resp = await ac.post(f"/dashboard/api/api-keys/{key_id}/purge")
        assert resp.status_code == 400


# ── status pill computation ────────────────────────────────────────────


class TestStatusPill:
    @pytest.mark.asyncio
    async def test_expiring_within_14d(self, authed_dash_client, monkeypatch):
        # api_key_max_ttl_days >= 14, so a 7-day key starts in the
        # ``expiring`` band (≤14d to expiry).
        ac, _ = authed_dash_client
        resp = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "soon", "is_admin": False, "expires_in_days": 7},
        )
        assert resp.json()["status"] == "expiring"

    @pytest.mark.asyncio
    async def test_expired_when_past_due(self, authed_dash_client, db_engine):
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "stale", "is_admin": False, "expires_in_days": 30},
        )
        key_id = create.json()["id"]
        # Backdate expires_at directly.
        sf = async_sessionmaker(db_engine, expire_on_commit=False)
        async with sf() as s:
            row = (await s.execute(select(APIKey).where(APIKey.id == UUID(key_id)))).scalar_one()
            row.expires_at = datetime.now(timezone.utc) - timedelta(days=1)
            await s.commit()

        listed = await ac.get("/dashboard/api/api-keys")
        row = next(k for k in listed.json()["keys"] if k["id"] == key_id)
        assert row["status"] == "expired"

    @pytest.mark.asyncio
    async def test_disabled_status(self, authed_dash_client):
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "off", "is_admin": False, "expires_in_days": 365},
        )
        key_id = create.json()["id"]
        await ac.patch(
            f"/dashboard/api/api-keys/{key_id}",
            json={"is_active": False},
        )
        listed = await ac.get("/dashboard/api/api-keys")
        row = next(k for k in listed.json()["keys"] if k["id"] == key_id)
        assert row["status"] == "disabled"

    @pytest.mark.asyncio
    async def test_purge_eligible_at_present_only_when_revoked(
        self,
        authed_dash_client,
    ):
        ac, _ = authed_dash_client
        create = await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "pending", "is_admin": False, "expires_in_days": 365},
        )
        assert create.json()["purge_eligible_at"] is None

        revoked = await ac.delete(
            f"/dashboard/api/api-keys/{create.json()['id']}",
        )
        assert revoked.json()["key"]["purge_eligible_at"] is not None


# ── audit-log attribution from dashboard ───────────────────────────────


class TestAuditAttribution:
    @pytest.mark.asyncio
    async def test_dashboard_mutations_attributed_to_sentinel(
        self,
        authed_dash_client,
    ):
        from app.dashboard import DASHBOARD_KEY_ID

        ac, sf = authed_dash_client
        await ac.post(
            "/dashboard/api/api-keys",
            json={"name": "tracked", "is_admin": False, "expires_in_days": 30},
        )
        async with sf() as s:
            rows = (await s.execute(select(AuditLog).where(AuditLog.action == "create_api_key"))).scalars().all()
        assert len(rows) == 1
        assert rows[0].api_key_id == DASHBOARD_KEY_ID
        assert rows[0].api_key_name == "__dashboard__"
        # IP from ASGI transport — empty/test client client.host is "testclient".
        assert rows[0].ip_address is not None
