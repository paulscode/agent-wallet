# SPDX-License-Identifier: MIT
"""POST /anonymize/sessions create endpoint."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.dashboard.api import (
    dash_anonymize_create_session,
    dash_anonymize_quote,
)
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.service import reset_anonymize_service

_REGTEST_P2TR = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"


@pytest.fixture
def _quote_keyset(monkeypatch):
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )


@pytest.fixture(autouse=True)
def _reset_service():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


def _mock_request(
    *,
    body: dict | None,
    cookie: str | None = "abc123",
    source_ip: str | None = "127.0.0.1",
) -> MagicMock:
    """Build a mock Starlette request for one endpoint call."""
    raw = json.dumps(body).encode("utf-8") if body is not None else b""
    req = MagicMock()
    req.body = AsyncMock(return_value=raw)
    # The anonymize endpoints bind to the dashboard's actual session
    # cookie ``dashboard_session`` (see app.dashboard.auth.COOKIE_NAME);
    # the test helper stages the same name so the per-cookie rate-
    # limiter sees a usable identity bucket.
    req.cookies = {"dashboard_session": cookie} if cookie else {}
    req.app.state.anonymize_health = {
        "egress_endpoints_onion_only": True,
        "operator_registry_size": 1,
        # A healthy deployment has Tor bootstrapped; the create gate now
        # fails closed without a positive signal.
        "tor_bootstrap_ready": True,
    }
    if source_ip is None:
        req.client = None
    else:
        req.client = MagicMock()
        req.client.host = source_ip
    return req


async def _get_quote_token(*, cookie: str = "abc123") -> str:
    """Round-trip through the quote endpoint to get a valid token."""
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            },
            cookie=cookie,
        )
    )
    assert isinstance(out, dict), f"quote returned {out}"
    return out["quote_token"]


# ── Disabled / unset ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_returns_404_when_disabled(db_engine, db_session) -> None:
    settings.anonymize_enabled = False
    try:
        resp = await dash_anonymize_create_session(
            _mock_request(body={"quote_token": "x"}),
            db=db_session,
        )
        assert resp.status_code == 404
    finally:
        settings.anonymize_enabled = True


@pytest.mark.asyncio
async def test_create_returns_503_when_tor_not_bootstrapped(
    db_session,
    _quote_keyset,
) -> None:
    """Refuse session creation when Tor is mid-bootstrap."""
    settings.anonymize_enabled = True
    token = await _get_quote_token()
    req = _mock_request(body={"quote_token": token})
    req.app.state.anonymize_health = {
        "egress_endpoints_onion_only": True,
        "operator_registry_size": 1,
        "clock_skew_within_threshold": True,
        "tor_bootstrap_ready": False,
    }
    resp = await dash_anonymize_create_session(req, db=db_session)
    assert resp.status_code == 503
    body = json.loads(resp.body.decode("utf-8"))
    assert body["detail"] == "anonymize_tor_not_bootstrapped"


@pytest.mark.asyncio
async def test_create_returns_503_when_keyset_missing(
    db_session,
    monkeypatch,
) -> None:
    settings.anonymize_enabled = True
    monkeypatch.setattr(settings, "anonymize_quote_token_hmac_key_fernet", "")
    resp = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": "x"}),
        db=db_session,
    )
    assert resp.status_code == 503


# ── Token validation ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_returns_422_for_missing_quote_token(
    db_session,
    _quote_keyset,
) -> None:
    settings.anonymize_enabled = True
    resp = await dash_anonymize_create_session(
        _mock_request(body={}),
        db=db_session,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_returns_422_for_malformed_quote_token(
    db_session,
    _quote_keyset,
) -> None:
    settings.anonymize_enabled = True
    resp = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": "not-a-token"}),
        db=db_session,
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_returns_422_for_invalid_json_body(
    db_session,
    _quote_keyset,
) -> None:
    settings.anonymize_enabled = True
    req = _mock_request(body=None)
    req.body = AsyncMock(return_value=b"not-json{")
    resp = await dash_anonymize_create_session(req, db=db_session)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_returns_409_for_expired_token(
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """An expired token returns 409 quote_expired (byte-pinned)."""
    settings.anonymize_enabled = True
    monkeypatch.setattr(settings, "anonymize_quote_token_ttl_s", 0)
    token = await _get_quote_token()
    # The TTL=0 token expires the instant it's issued; any later
    # decode raises QuoteTokenError("quote token expired").
    import time

    time.sleep(0.001)
    resp = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}),
        db=db_session,
    )
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_create_returns_422_for_cookie_rebinding(
    db_session,
    _quote_keyset,
) -> None:
    """A token signed under one cookie can't be redeemed by another."""
    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="alice")
    resp = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="bob"),
        db=db_session,
    )
    assert resp.status_code == 422


# ── Happy path ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_persists_session_and_spawns_task(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """Happy path: create persists a CREATED row and spawns a task."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )

    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="charlie")
    out = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="charlie"),
        db=db_session,
    )
    assert isinstance(out, dict)
    assert out["status"] == AnonymizeStatus.CREATED.value
    assert out["source_kind"] == "ext-lightning"
    assert out["bin_amount_sat"] == 250_000

    # Row exists in the DB (read via a fresh session).
    async with factory() as fresh:
        from uuid import UUID

        from sqlalchemy import select

        sess = (
            await fresh.execute(select(AnonymizeSession).where(AnonymizeSession.id == UUID(out["id"])))
        ).scalar_one()
        assert sess.status == AnonymizeStatus.CREATED.value

    # Cancel any spawned task to keep test isolation clean.
    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


@pytest.mark.asyncio
async def test_create_response_does_not_leak_destination(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """The returned summary uses the projection — no destination bytes."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )

    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="dora")
    out = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="dora"),
        db=db_session,
    )
    blob = json.dumps(out, default=str)
    assert "destination_address_enc" not in blob
    assert "quote_hmac" not in blob

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


# ── Admission gate integration ────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_returns_429_when_tier_cap_exhausted(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """The DB-state-based in-flight count gates the create path."""
    from uuid import uuid4

    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    # Tighten the weak-tier cap to 1 in-flight session.
    monkeypatch.setattr(
        settings,
        "anonymize_tier_concurrency_cap",
        "weak=1,moderate=2,strong=1",
    )

    # Seed one already-in-flight non-terminal session so the cap is full.
    existing = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.HOPPING.value,
        source_kind="ext-lightning",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={},
        quote_hmac=b"y" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xcd" * 32,
        destination_reuse_key_generation=0,
    )
    db_session.add(existing)
    await db_session.commit()

    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="elena")
    resp = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="elena"),
        db=db_session,
    )
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_create_returns_429_when_creation_window_exhausted(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """#3 — once the rolling 1h window count hits the limit, refuse."""
    from datetime import datetime, timezone
    from uuid import uuid4

    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )

    # Pin the configurable window so the test is deterministic
    # regardless of the deployment's ANONYMIZE_CREATE_WINDOW_MAX_PER_HOUR.
    from app.core.config import settings as _settings

    monkeypatch.setattr(_settings, "anonymize_create_window_max_per_hour", 10)

    # Seed 10 recently-completed sessions — window_max is pinned to 10.
    # They're terminal so they don't add to in-flight count.
    now = datetime.now(timezone.utc)
    for _ in range(10):
        db_session.add(
            AnonymizeSession(
                id=uuid4(),
                status=AnonymizeStatus.COMPLETED.value,
                source_kind="ext-lightning",
                requested_amount_sat=250_000,
                bin_amount_sat=250_000,
                pipeline_json={},
                quote_hmac=b"z" * 32,
                destination_address_enc=b"ct",
                destination_script_type="p2tr",
                pipeline_schema_version=10,
                destination_address_blake2b_keyed=b"\xef" * 32,
                destination_reuse_key_generation=0,
                created_at=now,
                completed_at=now,
            )
        )
    await db_session.commit()

    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="frank")
    resp = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="frank"),
        db=db_session,
    )
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_create_returns_503_when_clock_skew_unhealthy(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """The create endpoint refuses when the persisted health
    snapshot reports the clock skew is over threshold."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="gertrude")
    req = _mock_request(body={"quote_token": token}, cookie="gertrude")
    # Override the default health snapshot to mark skew unhealthy.
    req.app.state.anonymize_health["clock_skew_within_threshold"] = False
    resp = await dash_anonymize_create_session(req, db=db_session)
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_create_issues_blinded_deposit_invoice_for_ext_lightning(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """Ext-lightning create issues a blinded BOLT11 deposit invoice."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )

    # Mock the LND client used by issue_ext_lightning_deposit_invoice.
    # add_blinded_invoice returns a BlindedInvoiceResult TypedDict (a dict):
    # r_hash is the hex payment hash; blinded_paths is the raw per-path list.
    fake_inv = {
        "r_hash": "ab" * 32,
        "payment_request": "lnbcrt1000blinded",
        "add_index": "1",
        "payment_addr": "cd" * 32,
        "blinded_paths": [{}, {}],
    }
    mock_lnd = MagicMock()
    mock_lnd.add_blinded_invoice = AsyncMock(return_value=(fake_inv, None))
    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service",
        mock_lnd,
    )

    settings.anonymize_enabled = True
    # Get a quote for ext-lightning.
    quote = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
            },
            cookie="extdep",
        )
    )
    assert isinstance(quote, dict)
    out = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": quote["quote_token"]}, cookie="extdep"),
        db=db_session,
    )
    assert isinstance(out, dict)

    # Verify the persisted pipeline_json carries the deposit invoice.
    from uuid import UUID

    from sqlalchemy import select

    async with factory() as fresh:
        row = (await fresh.execute(select(AnonymizeSession).where(AnonymizeSession.id == UUID(out["id"])))).scalar_one()
        deposit_invoice = row.pipeline_json.get("source", {}).get("deposit_invoice")
        assert deposit_invoice == "lnbcrt1000blinded"

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


@pytest.mark.asyncio
async def test_create_returns_429_when_three_budget_cookie_exhausted(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """Once the per-cookie budget exhausts, refuse."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    # Limit to 2 creations per cookie per hour so the third trips it.
    monkeypatch.setattr(
        settings,
        "anonymize_reuse_check_rate_limit_per_hour",
        2,
    )
    # Disable destination-reuse detection so the second/third creates
    # against the shared regtest destination aren't rejected by the
    # hard-block before they reach the budget gate the test
    # is exercising.
    monkeypatch.setattr(
        settings,
        "anonymize_reuse_detection_key_fernet",
        "",
    )
    settings.anonymize_enabled = True

    # Each create needs a fresh quote token, so issue 3 of them.
    tokens = [await _get_quote_token(cookie="gabe") for _ in range(3)]

    # First two admit; third is rate-limited.
    out1 = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": tokens[0]}, cookie="gabe"),
        db=db_session,
    )
    assert isinstance(out1, dict)
    out2 = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": tokens[1]}, cookie="gabe"),
        db=db_session,
    )
    assert isinstance(out2, dict)
    resp3 = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": tokens[2]}, cookie="gabe"),
        db=db_session,
    )
    assert resp3.status_code == 429

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


# ── BOLT 12 / BIP-353 deposit acceptance ──────────


async def _get_bolt12_deposit_quote_token(
    *,
    cookie: str = "abc123",
    with_bip353_domain: bool = False,
) -> str:
    """Build a quote token for an ext-lightning + BOLT 12 deposit session."""
    out = await dash_anonymize_quote(
        _mock_request(
            body={
                "source_kind": "ext-lightning",
                "destination_address": _REGTEST_P2TR,
                "requested_amount_sat": 250_000,
                "deposit_method": "bolt12",
            },
            cookie=cookie,
        )
    )
    assert isinstance(out, dict), f"quote returned {out}"
    return out["quote_token"]


@pytest.mark.asyncio
async def test_create_with_bolt12_deposit_mints_offer(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """End-to-end: a BOLT 12 deposit-method quote produces a session
    row whose ``pipeline_json["source"]`` carries a freshly-minted
    BOLT 12 offer and the matching ``Bolt12Offer`` row exists in DB."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    # Stub the offer-paths builder so we don't need a live gateway.
    from app.api import bolt12 as bolt12_api

    monkeypatch.setattr(
        bolt12_api,
        "_build_offer_paths_for_issuance",
        AsyncMock(return_value=None),
    )

    # Seed the DASHBOARD_KEY_ID API key row (the minter attributes
    # the offer to this row).
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.api_key import APIKey

    db_session.add(
        APIKey(
            id=DASHBOARD_KEY_ID,
            name="dashboard",
            key_hash="d" * 64,
            is_admin=True,
            is_active=True,
        )
    )
    await db_session.commit()

    settings.anonymize_enabled = True
    token = await _get_bolt12_deposit_quote_token(cookie="hank")
    out = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="hank"),
        db=db_session,
    )
    assert isinstance(out, dict)
    assert out["status"] == AnonymizeStatus.CREATED.value

    # Deposit block surfaces the BOLT 12 offer string for the SPA.
    deposit = out.get("deposit") or {}
    assert deposit.get("method") == "bolt12"
    bolt12_offer = deposit.get("bolt12_offer")
    assert isinstance(bolt12_offer, str) and bolt12_offer.startswith("lno1")
    # No BIP-353 handle without a configured domain.
    assert "bip353_handle" not in deposit

    # The corresponding Bolt12Offer row exists with the right amount.
    async with factory() as fresh:
        from sqlalchemy import select

        from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferSource

        row = (await fresh.execute(select(Bolt12Offer).where(Bolt12Offer.bolt12 == bolt12_offer))).scalar_one()
        assert row.source == Bolt12OfferSource.ISSUED
        assert row.amount_msat == 250_000 * 1000

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


@pytest.mark.asyncio
async def test_create_with_bolt12_deposit_and_bip353_domain_emits_handle(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """With ``ANONYMIZE_BIP353_DEPOSIT_DOMAIN`` configured, the
    deposit block also carries a per-session BIP-353 handle + the
    zone-file TXT-record fragment so the operator can publish it."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_bip353_deposit_domain",
        "wallet.example.com",
    )
    from app.api import bolt12 as bolt12_api

    monkeypatch.setattr(
        bolt12_api,
        "_build_offer_paths_for_issuance",
        AsyncMock(return_value=None),
    )

    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.api_key import APIKey

    db_session.add(
        APIKey(
            id=DASHBOARD_KEY_ID,
            name="dashboard",
            key_hash="d" * 64,
            is_admin=True,
            is_active=True,
        )
    )
    await db_session.commit()

    settings.anonymize_enabled = True
    token = await _get_bolt12_deposit_quote_token(cookie="iris")
    out = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="iris"),
        db=db_session,
    )
    deposit = out["deposit"]
    assert deposit["method"] == "bolt12"
    assert deposit["bip353_handle"].endswith("@wallet.example.com")
    assert "_bitcoin-payment.wallet.example.com" in deposit["bip353_txt_record"]
    assert deposit["bolt12_offer"] in deposit["bip353_txt_record"]

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


@pytest.mark.asyncio
async def test_create_with_bolt12_falls_back_when_dashboard_key_missing(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
    caplog,
) -> None:
    """A deployment without the ``DASHBOARD_KEY_ID`` sentinel API key
    row would crash on FK insert; the endpoint detects this and
    falls back to a no-deposit session with a clear operator log
    line (no cryptic 500)."""
    import logging

    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    # IMPORTANT: do NOT seed the DASHBOARD_KEY_ID row this time.

    settings.anonymize_enabled = True
    token = await _get_bolt12_deposit_quote_token(cookie="kara")
    with caplog.at_level(
        logging.WARNING,
        logger="app.services.anonymize",
    ):
        out = await dash_anonymize_create_session(
            _mock_request(body={"quote_token": token}, cookie="kara"),
            db=db_session,
        )
    assert isinstance(out, dict)
    assert out["status"] == AnonymizeStatus.CREATED.value
    deposit = out.get("deposit") or {}
    # No offer was minted — the deposit block carries only ``method``.
    assert "bolt12_offer" not in deposit
    # Operator-facing warning line names the missing sentinel row.
    assert any("DASHBOARD_KEY_ID row missing" in r.message for r in caplog.records)

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


@pytest.mark.asyncio
async def test_create_with_bolt12_logs_when_mint_refused(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
    caplog,
) -> None:
    """When the minter raises ``DepositOfferError`` (e.g., the BIP-353
    domain is malformed), the endpoint logs a clear warning rather
    than swallowing the exception silently."""
    import logging

    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    from app.api import bolt12 as bolt12_api

    monkeypatch.setattr(
        bolt12_api,
        "_build_offer_paths_for_issuance",
        AsyncMock(return_value=None),
    )
    # Setting a malformed BIP-353 domain forces the minter to raise.
    monkeypatch.setattr(
        settings,
        "anonymize_bip353_deposit_domain",
        "not a valid domain",
    )

    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.api_key import APIKey

    db_session.add(
        APIKey(
            id=DASHBOARD_KEY_ID,
            name="dashboard",
            key_hash="d" * 64,
            is_admin=True,
            is_active=True,
        )
    )
    await db_session.commit()

    settings.anonymize_enabled = True
    token = await _get_bolt12_deposit_quote_token(cookie="liam")
    with caplog.at_level(
        logging.WARNING,
        logger="app.services.anonymize",
    ):
        out = await dash_anonymize_create_session(
            _mock_request(body={"quote_token": token}, cookie="liam"),
            db=db_session,
        )
    assert isinstance(out, dict)
    assert out["status"] == AnonymizeStatus.CREATED.value
    assert any("deposit-offer mint refused" in r.message for r in caplog.records)

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


@pytest.mark.asyncio
async def test_create_with_bolt11_default_does_not_emit_offer(
    db_engine,
    db_session,
    _quote_keyset,
    monkeypatch,
) -> None:
    """The legacy BOLT 11 deposit path (default) does NOT carry a
    BOLT 12 offer in the response — the deposit block only has the
    bolt11 invoice string (when LND has the wallet's blinded-invoice
    capability) or omits it entirely (stubbed-LND deployments)."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )

    settings.anonymize_enabled = True
    token = await _get_quote_token(cookie="jules")
    out = await dash_anonymize_create_session(
        _mock_request(body={"quote_token": token}, cookie="jules"),
        db=db_session,
    )
    deposit = out.get("deposit") or {}
    assert deposit.get("method") in {"bolt11", None}
    assert "bolt12_offer" not in deposit
    assert "bip353_handle" not in deposit

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()


@pytest.mark.asyncio
async def test_finalize_liquid_submarine_refund_terminalizes_session(db_session) -> None:
    """After a Liquid leg-2 lockup refund, the helper records the refund
    marker and moves the session to FAILED, so the per-session loop stops
    polling for a settlement that will never come and the dashboard stops
    offering the (now spent-UTXO) refund button."""
    from uuid import uuid4

    from app.dashboard.api import _finalize_liquid_submarine_refund

    sess = AnonymizeSession(
        id=uuid4(),
        status=AnonymizeStatus.AWAITING_LIQUID_DWELL.value,
        source_kind="onchain-self",
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={"liquid_submarine_lock_txid": "ab" * 32},
        quote_hmac=b"z" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xef" * 32,
        destination_reuse_key_generation=0,
    )
    db_session.add(sess)
    await db_session.commit()

    await _finalize_liquid_submarine_refund(db_session, session=sess, txid="refundtx123")

    assert sess.status == AnonymizeStatus.FAILED.value
    assert sess.pipeline_json["liquid_submarine_refund_txid"] == "refundtx123"
    assert sess.last_error and "refund" in sess.last_error.lower()
