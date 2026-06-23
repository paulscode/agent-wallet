# SPDX-License-Identifier: MIT
"""Integration tests for the LNURL dashboard endpoints.

Mocks the underlying ``lnurl_service`` so we exercise routing,
authentication, audit logging and request-validation but not the
network layer (which is covered by ``tests/unit/test_lnurl_service.py``).
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


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


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


class TestLnurlResolveEndpoint:
    @pytest.mark.asyncio
    async def test_resolve_success(self, dashboard_client, auth_cookies):
        fake = {
            "handle": "a" * 32,
            "source_kind": "lightning_address",
            "source_input": "alice@x.test",
            "callback_host": "x.test",
            "min_sendable_sats": 1,
            "max_sendable_sats": 1000,
            "metadata_text": "Pay alice",
            "metadata_long": None,
            "metadata_image_data_uri": None,
            "comment_allowed": 0,
        }
        with patch(
            "app.dashboard.api.get_lnurl_service",
            return_value=type("S", (), {"resolve_recipient": AsyncMock(return_value=(fake, None))})(),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/lnurl/resolve",
                json={"text": "alice@x.test"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["handle"] == fake["handle"]
        assert body["callback_host"] == "x.test"

    @pytest.mark.asyncio
    async def test_resolve_failure_returns_400(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.get_lnurl_service",
            return_value=type("S", (), {"resolve_recipient": AsyncMock(return_value=(None, "user not found"))})(),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/lnurl/resolve",
                json={"text": "bob@x.test"},
            )
        assert resp.status_code == 400
        assert "user not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_resolve_requires_auth(self, dashboard_client):
        resp = await dashboard_client.post(
            "/dashboard/api/lnurl/resolve",
            json={"text": "alice@x.test"},
        )
        assert resp.status_code == 401


class TestLnurlInvoiceEndpoint:
    @pytest.mark.asyncio
    async def test_invoice_success(self, dashboard_client, auth_cookies):
        fake_inv = {
            "payment_request": "lnbcrt...",
            "payment_hash": "deadbeef",
            "amount_sats": 100,
            "description": "Pay alice",
            "expiry_seconds": 3600,
            "success_action": None,
            "cache_hit": False,
        }
        with patch(
            "app.dashboard.api.get_lnurl_service",
            return_value=type("S", (), {"request_invoice": AsyncMock(return_value=(fake_inv, None))})(),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/lnurl/invoice",
                json={"handle": "a" * 32, "amount_sats": 100, "comment": ""},
            )
        assert resp.status_code == 200
        assert resp.json()["payment_request"] == "lnbcrt..."

    @pytest.mark.asyncio
    async def test_invoice_validates_handle_format(self, dashboard_client, auth_cookies):
        # 32-char but not all hex → 422 from pydantic.
        resp = await dashboard_client.post(
            "/dashboard/api/lnurl/invoice",
            json={"handle": "Z" * 32, "amount_sats": 100, "comment": ""},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_invoice_enforces_dashboard_payment_cap(self, dashboard_client, auth_cookies):
        original = settings.dashboard_max_payment_sats
        settings.dashboard_max_payment_sats = 50
        try:
            resp = await dashboard_client.post(
                "/dashboard/api/lnurl/invoice",
                json={"handle": "a" * 32, "amount_sats": 100, "comment": ""},
            )
            assert resp.status_code == 400
            assert "limit" in resp.json()["detail"].lower()
        finally:
            settings.dashboard_max_payment_sats = original

    @pytest.mark.asyncio
    async def test_invoice_recipient_failure_returns_400(self, dashboard_client, auth_cookies):
        with patch(
            "app.dashboard.api.get_lnurl_service",
            return_value=type(
                "S",
                (),
                {"request_invoice": AsyncMock(return_value=(None, "BOLT11 amount mismatch"))},
            )(),
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/lnurl/invoice",
                json={"handle": "a" * 32, "amount_sats": 100, "comment": ""},
            )
        assert resp.status_code == 400
        assert "amount mismatch" in resp.json()["detail"]


# ── Input validation (Pydantic 422s) ───────────────────────────────


class TestLnurlInputValidation:
    @pytest.mark.asyncio
    async def test_resolve_empty_text_rejected(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/lnurl/resolve",
            json={"text": ""},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_resolve_oversized_text_rejected(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/lnurl/resolve",
            json={"text": "x" * 3000},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_invoice_zero_amount_rejected(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/lnurl/invoice",
            json={"handle": "a" * 32, "amount_sats": 0, "comment": ""},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_invoice_comment_over_280_rejected(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/lnurl/invoice",
            json={
                "handle": "a" * 32,
                "amount_sats": 100,
                "comment": "x" * 500,
            },
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_invoice_uppercase_handle_rejected(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/lnurl/invoice",
            json={"handle": "ABCDEF" + "0" * 26, "amount_sats": 100, "comment": ""},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_invoice_short_handle_rejected(self, dashboard_client, auth_cookies):
        resp = await dashboard_client.post(
            "/dashboard/api/lnurl/invoice",
            json={"handle": "a" * 16, "amount_sats": 100, "comment": ""},
        )
        assert resp.status_code == 422


# ── Audit logging ──────────────────────────────────────────────────


class TestLnurlAudit:
    @pytest.mark.asyncio
    async def test_resolve_writes_audit_row(self, dashboard_client, auth_cookies):
        fake = {
            "handle": "a" * 32,
            "source_kind": "lightning_address",
            "source_input": "alice@x.test",
            "callback_host": "x.test",
            "min_sendable_sats": 1,
            "max_sendable_sats": 1000,
            "metadata_text": "Pay alice",
            "metadata_long": None,
            "metadata_image_data_uri": None,
            "comment_allowed": 0,
        }
        with (
            patch(
                "app.dashboard.api.get_lnurl_service",
                return_value=type("S", (), {"resolve_recipient": AsyncMock(return_value=(fake, None))})(),
            ),
            patch(
                "app.dashboard.api.log_dashboard_action",
                new_callable=AsyncMock,
            ) as audit_mock,
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/lnurl/resolve",
                json={"text": "alice@x.test"},
            )
        assert resp.status_code == 200
        # The success-path audit row.
        success_calls = [
            c
            for c in audit_mock.call_args_list
            if len(c.args) >= 3
            and c.args[2] == "lnurl_resolve"
            and c.kwargs.get("details", {}).get("source_kind") == "lightning_address"
        ]
        assert len(success_calls) == 1
        assert success_calls[0].kwargs["details"]["callback_host"] == "x.test"

    @pytest.mark.asyncio
    async def test_invoice_audit_truncates_long_comment(self, dashboard_client, auth_cookies):
        long_comment = "x" * 250
        fake_inv = {
            "payment_request": "lnbcrt...",
            "payment_hash": "deadbeef",
            "amount_sats": 100,
            "description": "Pay alice",
            "expiry_seconds": 3600,
            "success_action": None,
            "cache_hit": False,
        }
        with (
            patch(
                "app.dashboard.api.get_lnurl_service",
                return_value=type("S", (), {"request_invoice": AsyncMock(return_value=(fake_inv, None))})(),
            ),
            patch(
                "app.dashboard.api.log_dashboard_action",
                new_callable=AsyncMock,
            ) as audit_mock,
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/lnurl/invoice",
                json={
                    "handle": "a" * 32,
                    "amount_sats": 100,
                    "comment": long_comment,
                },
            )
        assert resp.status_code == 200
        # Find the success-path audit call.
        invoice_calls = [
            c
            for c in audit_mock.call_args_list
            if len(c.args) >= 3
            and c.args[2] == "lnurl_request_invoice"
            and c.kwargs.get("details", {}).get("payment_hash") == "deadbeef"
        ]
        assert len(invoice_calls) == 1
        details = invoice_calls[0].kwargs["details"]
        # comment truncated to ~200 chars with marker.
        assert len(details["comment"]) <= 200
        assert "[truncated]" in details["comment"]
        # full length preserved separately.
        assert details["comment_len"] == 250

    @pytest.mark.asyncio
    async def test_invoice_failure_writes_audit_row(self, dashboard_client, auth_cookies):
        with (
            patch(
                "app.dashboard.api.get_lnurl_service",
                return_value=type(
                    "S",
                    (),
                    {"request_invoice": AsyncMock(return_value=(None, "BOLT11 expired"))},
                )(),
            ),
            patch(
                "app.dashboard.api.log_dashboard_action",
                new_callable=AsyncMock,
            ) as audit_mock,
        ):
            resp = await dashboard_client.post(
                "/dashboard/api/lnurl/invoice",
                json={"handle": "a" * 32, "amount_sats": 100, "comment": ""},
            )
        assert resp.status_code == 400
        failure_calls = [
            c
            for c in audit_mock.call_args_list
            if c.kwargs.get("success") is False and len(c.args) >= 3 and c.args[2] == "lnurl_request_invoice"
        ]
        assert len(failure_calls) == 1
        assert "BOLT11 expired" in failure_calls[0].kwargs["error_message"]


# ── Auth gate (CSRF) ──────────────────────────────────────────────


class TestLnurlAuthGate:
    @pytest.mark.asyncio
    async def test_invoice_requires_auth(self, dashboard_client):
        resp = await dashboard_client.post(
            "/dashboard/api/lnurl/invoice",
            json={"handle": "a" * 32, "amount_sats": 100, "comment": ""},
        )
        assert resp.status_code == 401
