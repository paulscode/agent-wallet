# SPDX-License-Identifier: MIT
"""Integration tests for the dashboard BOLT 12 endpoints.

Exercises the live FastAPI dashboard router via the same fixture
pattern (``dashboard_client``, ``_make_session_cookie``, CSRF bypass)
used by ``tests/integration/test_dashboard.py``. We construct real
encoded offer strings via the field-level codec so the decode path
runs end-to-end (no fixture mocking).
"""

from __future__ import annotations

import time
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.database import get_db
from app.dashboard.auth import COOKIE_NAME
from app.services.bolt12 import Bolt12Codec, Offer

_ISSUER_ID = bytes.fromhex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619")


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


def _make_offer_string(
    *,
    description: str = "coffee",
    amount: int | None = 1500,
    issuer: str | None = "alice",
) -> str:
    o = Offer(
        amount=amount,
        description=description,
        issuer=issuer,
        issuer_id=_ISSUER_ID,
    )
    return Bolt12Codec.encode(o.to_bolt12_string())


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


@pytest.mark.asyncio
async def test_decode_endpoint_happy_path(dashboard_client, auth_cookies) -> None:
    s = _make_offer_string()
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/decode",
        json={"offer": s},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["amount_msat"] == 1500
    assert body["description"] == "coffee"
    assert body["issuer_id_hex"] == _ISSUER_ID.hex()


@pytest.mark.asyncio
async def test_decode_rejects_garbage(dashboard_client, auth_cookies) -> None:
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/decode",
        json={"offer": "not-an-offer"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_endpoints_require_auth(dashboard_client) -> None:
    resp = await dashboard_client.get("/dashboard/api/bolt12/offers")
    assert resp.status_code == 401

    resp = await dashboard_client.post("/dashboard/api/bolt12/decode", json={"offer": "x"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_import_creates_then_idempotent(dashboard_client, auth_cookies) -> None:
    s = _make_offer_string(description="beer", amount=2500)
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/offers",
        json={"offer": s},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["bolt12"] == s
    assert body["amount_msat"] == 2500
    assert body["status"] == "active"
    offer_id = body["id"]

    # Repeat — same row.
    resp2 = await dashboard_client.post(
        "/dashboard/api/bolt12/offers",
        json={"offer": s},
    )
    assert resp2.status_code == 200
    assert resp2.json()["id"] == offer_id


@pytest.mark.asyncio
async def test_list_returns_imported_offers(dashboard_client, auth_cookies) -> None:
    a = _make_offer_string(description="a")
    b = _make_offer_string(description="b", amount=99)
    await dashboard_client.post("/dashboard/api/bolt12/offers", json={"offer": a})
    await dashboard_client.post("/dashboard/api/bolt12/offers", json={"offer": b})

    resp = await dashboard_client.get("/dashboard/api/bolt12/offers")
    assert resp.status_code == 200
    descs = [o["description"] for o in resp.json()]
    assert {"a", "b"} <= set(descs)


@pytest.mark.asyncio
async def test_delete_imported_offer_removes_payee(dashboard_client, auth_cookies) -> None:
    """Imported / paid offers are payees: DELETE soft-removes them.

    The dashboard's *Pay* tab treats these rows as the user's
    address book, so removal means "I don't deal with this payee
    anymore" \u2014 not "stop honouring this offer protocol-side".
    """
    s = _make_offer_string(description="kill-me")
    created = await dashboard_client.post("/dashboard/api/bolt12/offers", json={"offer": s})
    offer_id = created.json()["id"]

    resp = await dashboard_client.delete(f"/dashboard/api/bolt12/offers/{offer_id}")
    assert resp.status_code == 204

    listed = await dashboard_client.get("/dashboard/api/bolt12/offers")
    assert all(o["id"] != offer_id for o in listed.json()), "soft-deleted payee row should not appear in the list"


@pytest.mark.asyncio
async def test_delete_issued_offer_marks_disabled(dashboard_client, auth_cookies, db_engine) -> None:
    """Issued offers (``source=ISSUED``) are disabled, not deleted.

    We still want the row to appear on the dashboard so historical
    invreq/invoice rows that join to it render correctly, but the
    orchestrator should reject new invreqs.
    """
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferSource

    s = _make_offer_string(description="my-issued")
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        row = Bolt12Offer(
            api_key_id=DASHBOARD_KEY_ID,
            bolt12=s,
            description="my-issued",
            amount_msat=1500,
            issuer="alice",
            issuer_id_hex=_ISSUER_ID.hex(),
            source=Bolt12OfferSource.ISSUED,
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)
        offer_id = str(row.id)

    resp = await dashboard_client.delete(f"/dashboard/api/bolt12/offers/{offer_id}")
    assert resp.status_code == 204

    listed = await dashboard_client.get("/dashboard/api/bolt12/offers")
    row = next(o for o in listed.json() if o["id"] == offer_id)
    assert row["status"] == "disabled"


@pytest.mark.asyncio
async def test_disable_unknown_offer_returns_404(dashboard_client, auth_cookies) -> None:
    resp = await dashboard_client.delete(
        "/dashboard/api/bolt12/offers/00000000-0000-0000-0000-000000000000",
    )
    assert resp.status_code == 404


# ── dashboard issue / pay ───────────────────────────────────────


@pytest_asyncio.fixture
async def dashboard_sentinel_key(db_engine):
    """Insert the sentinel ``__dashboard__`` APIKey row.

    The production DB gets this from Alembic migration 002, but the
    test fixture builds the schema with ``create_all`` which skips
    migrations. The dashboard issue/pay endpoints look up this row
    via ``_load_dashboard_api_key``, so we need it present.
    """
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.api_key import APIKey

    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
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


@pytest.mark.asyncio
async def test_issue_endpoint_creates_offer(dashboard_client, auth_cookies, dashboard_sentinel_key) -> None:
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/offers/issue",
        json={"description": "dashboard coffee", "amount_msat": 2500},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["bolt12"].startswith("lno1")
    assert body["description"] == "dashboard coffee"
    assert body["amount_msat"] == 2500
    # 33-byte compressed pubkey hex.
    assert len(body["issuer_id_hex"]) == 66


@pytest.mark.asyncio
async def test_issue_endpoint_requires_auth(dashboard_client, dashboard_sentinel_key) -> None:
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/offers/issue",
        json={"description": "x", "amount_msat": 1},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_issue_endpoint_validates_inputs(dashboard_client, auth_cookies, dashboard_sentinel_key) -> None:
    # Description is required + min_length=1.
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/offers/issue",
        json={"amount_msat": 1},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_issue_endpoint_each_call_unique(dashboard_client, auth_cookies, dashboard_sentinel_key) -> None:
    """Two issues with identical inputs must yield distinct offers."""
    body = {"description": "twice", "amount_msat": 100}
    r1 = await dashboard_client.post("/dashboard/api/bolt12/offers/issue", json=body)
    r2 = await dashboard_client.post("/dashboard/api/bolt12/offers/issue", json=body)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["bolt12"] != r2.json()["bolt12"]
    assert r1.json()["issuer_id_hex"] != r2.json()["issuer_id_hex"]


@pytest.mark.asyncio
async def test_pay_endpoint_returns_503_without_runtime(dashboard_client, auth_cookies, dashboard_sentinel_key) -> None:
    """Without a running BOLT 12 service the pay endpoint must return
    503 (matches the public route's contract)."""
    s = _make_offer_string()
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/pay",
        json={"offer": s},
    )
    # 503 from get_bolt12_service() when no runtime is started.
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_pay_endpoint_rejects_offer_without_issuer(
    dashboard_client, auth_cookies, dashboard_sentinel_key
) -> None:
    """An offer with neither issuer_id nor blinded paths is unpayable."""
    o = Offer(amount=1500, description="anon", issuer="alice")
    s = Bolt12Codec.encode(o.to_bolt12_string())
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/pay",
        json={"offer": s},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_pay_endpoint_accepts_paths_only_offer(dashboard_client, auth_cookies, dashboard_sentinel_key) -> None:
    """An offer with offer_paths but no issuer_id must NOT be rejected
    with 400. Without a running BOLT 12 runtime the route reaches
    ``get_bolt12_service`` and returns 503, proving the prior
    offer_paths-only rejection has been lifted.
    """
    # Build a syntactically valid offer_paths blob: 33-byte first
    # node id + 33-byte first_path_key + 1-byte num_hops=1 + one hop
    # (33-byte blinded_node_id + 2-byte enclen + 16-byte payload).
    first_node = b"\x02" + b"\x11" * 32
    first_pk = b"\x02" + b"\x22" * 32
    hop_blinded = b"\x02" + b"\x33" * 32
    hop_enc = b"\x44" * 16
    paths_blob = first_node + first_pk + bytes([1]) + hop_blinded + len(hop_enc).to_bytes(2, "big") + hop_enc
    o = Offer(amount=1500, description="paths-only", paths=paths_blob)
    s = Bolt12Codec.encode(o.to_bolt12_string())
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/pay",
        json={"offer": s},
    )
    # Past the 400 gate; no runtime -> 503 from get_bolt12_service.
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_pay_endpoint_requires_auth(dashboard_client, dashboard_sentinel_key) -> None:
    resp = await dashboard_client.post(
        "/dashboard/api/bolt12/pay",
        json={"offer": "x"},
    )
    assert resp.status_code == 401
