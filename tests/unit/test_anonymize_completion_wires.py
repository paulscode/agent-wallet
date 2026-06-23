# SPDX-License-Identifier: MIT
"""Lightning self-source completion wires: ext-lightning observer,
circuit-rebuild guard, quote-cache instance, set_feature_enabled_at_day,
rotation tick, observation router."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus
from app.services.anonymize.circuit_rebuild import (
    CircuitRebuildGuard,
    get_circuit_rebuild_guard,
    reset_circuit_rebuild_guard,
)
from app.services.anonymize.hops.ext_lightning_observe import (
    observe_ext_lightning,
)
from app.services.anonymize.observation_router import default_observation_fn
from app.services.anonymize.quote_cache import (
    CacheEntry,
    CacheKey,
    QuoteCacheInstance,
    get_quote_cache,
    reset_quote_cache,
)


def _session(*, status: str, source_kind: str = "ext-lightning", dwell: int = 0, age_s: float = 0) -> AnonymizeSession:
    now = datetime.now(timezone.utc)
    return AnonymizeSession(
        id=uuid4(),
        status=status,
        source_kind=source_kind,
        requested_amount_sat=250_000,
        bin_amount_sat=250_000,
        pipeline_json={"delay_policy": {"min_seconds": dwell}},
        quote_hmac=b"x" * 32,
        destination_address_enc=b"ct",
        destination_script_type="p2tr",
        pipeline_schema_version=10,
        destination_address_blake2b_keyed=b"\xab" * 32,
        destination_reuse_key_generation=0,
        created_at=now - timedelta(seconds=age_s),
        updated_at=now - timedelta(seconds=age_s),
    )


# ── ext-lightning observer ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_ext_lightning_created_signals_settlement(db_session) -> None:
    s = _session(status=AnonymizeStatus.CREATED.value)
    obs = await observe_ext_lightning(db_session, s)
    assert obs.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_ext_lightning_funding_signals_settlement(db_session) -> None:
    s = _session(status=AnonymizeStatus.FUNDING.value)
    obs = await observe_ext_lightning(db_session, s)
    assert obs.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_ext_lightning_delaying_waits_for_dwell(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_ext_deposit_min_dwell_s", 7200)
    s = _session(
        status=AnonymizeStatus.DELAYING.value,
        dwell=0,
        age_s=60,
    )
    obs = await observe_ext_lightning(db_session, s)
    assert obs.delay_window_elapsed is False


@pytest.mark.asyncio
async def test_ext_lightning_delaying_advances_past_dwell(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_ext_deposit_min_dwell_s", 60)
    s = _session(
        status=AnonymizeStatus.DELAYING.value,
        dwell=0,
        age_s=120,
    )
    obs = await observe_ext_lightning(db_session, s)
    assert obs.delay_window_elapsed is True
    assert obs.is_last_hop is True


@pytest.mark.asyncio
async def test_router_dispatches_ext_lightning_to_observer(
    db_session,
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "anonymize_ext_deposit_min_dwell_s", 60)
    s = _session(
        status=AnonymizeStatus.CREATED.value,
        source_kind="ext-lightning",
    )
    obs = await default_observation_fn(db_session, s)
    assert obs.funding_invoice_settled is True


# ── BOLT 12 deposit observer ──────────────────────


def _bolt12_session(
    *,
    status: str,
    deposit_offer_id: str | None = "ffffffff-ffff-ffff-ffff-ffffffffffff",
) -> AnonymizeSession:
    """An ext-lightning session pinned to the BOLT 12 deposit path."""
    src: dict = {"deposit_method": "bolt12"}
    if deposit_offer_id is not None:
        src["deposit_offer_id"] = deposit_offer_id
    s = _session(status=status, source_kind="ext-lightning")
    s.pipeline_json = {
        "delay_policy": {"min_seconds": 0},
        "source": src,
    }
    return s


@pytest.mark.asyncio
async def test_bolt12_deposit_unsettled_signals_not_settled(
    db_session,
    monkeypatch,
) -> None:
    """When the deposit_method is bolt12 and no paid inbound invoice
    exists, the observer reports ``funding_invoice_settled=False``
    (preventing the legacy time-based signal from advancing the
    session before payment lands)."""
    s = _bolt12_session(status=AnonymizeStatus.CREATED.value)
    obs = await observe_ext_lightning(db_session, s)
    assert obs.funding_invoice_settled is False


@pytest.mark.asyncio
async def test_bolt12_deposit_paid_signals_settled(
    db_session,
    monkeypatch,
) -> None:
    """A paid inbound BOLT 12 invoice for the session's bound offer
    flips the observer's funding signal to True."""
    from datetime import datetime, timezone
    from uuid import uuid4

    from app.models.api_key import APIKey
    from app.models.bolt12_invoice import (
        Bolt12Direction,
        Bolt12Invoice,
        Bolt12InvoiceRequest,
        Bolt12InvoiceRequestStatus,
        Bolt12InvoiceStatus,
    )
    from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferSource

    api_key = APIKey(
        id=uuid4(),
        name="t",
        key_hash="d" * 64,
        is_admin=True,
        is_active=True,
    )
    db_session.add(api_key)
    await db_session.flush()

    offer = Bolt12Offer(
        api_key_id=api_key.id,
        bolt12="lno1seedoffer",
        amount_msat=250_000_000,
        source=Bolt12OfferSource.ISSUED,
        issuer_id_hex="02" + "00" * 32,
    )
    db_session.add(offer)
    await db_session.flush()

    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key.id,
        offer_id=offer.id,
        direction=Bolt12Direction.INBOUND,
        invreq_bolt12="lnr1seedreq",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
    )
    db_session.add(invreq)
    await db_session.flush()
    db_session.add(
        Bolt12Invoice(
            api_key_id=api_key.id,
            invoice_request_id=invreq.id,
            direction=Bolt12Direction.INBOUND,
            invoice_bolt12="lni1seedinvoice",
            amount_msat=250_000_000,
            payment_hash_hex="aa" * 32,
            node_id_hex="02" + "00" * 32,
            status=Bolt12InvoiceStatus.PAID,
            paid_at=datetime.now(timezone.utc),
        )
    )
    await db_session.commit()

    s = _bolt12_session(
        status=AnonymizeStatus.CREATED.value,
        deposit_offer_id=str(offer.id),
    )
    obs = await observe_ext_lightning(db_session, s)
    assert obs.funding_invoice_settled is True


@pytest.mark.asyncio
async def test_bolt11_deposit_keeps_legacy_time_based_signal(
    db_session,
) -> None:
    """Sessions without ``deposit_method=bolt12`` keep the legacy
    time-based signal (returns True unconditionally for CREATED /
    FUNDING for Lightning self-source)."""
    s = _session(status=AnonymizeStatus.CREATED.value)
    # Mark the source as explicit BOLT 11 so the test is unambiguous.
    s.pipeline_json = {
        "delay_policy": {"min_seconds": 0},
        "source": {"deposit_method": "bolt11"},
    }
    obs = await observe_ext_lightning(db_session, s)
    assert obs.funding_invoice_settled is True


# ── Quote cache instance ─────────────────────────────────────────────


def test_quote_cache_singleton_is_isolated_per_test() -> None:
    reset_quote_cache()
    a = get_quote_cache()
    b = get_quote_cache()
    assert a is b
    assert isinstance(a, QuoteCacheInstance)
    reset_quote_cache()
    c = get_quote_cache()
    assert c is not a


def test_quote_cache_put_get_remove_round_trip() -> None:
    reset_quote_cache()
    cache = get_quote_cache()
    key = CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC")
    entry = CacheEntry(
        key=key,
        payload={"fee": 100},
        fetched_at_unix_s=1_000.0,
        operator_signature=None,
        signing_key_generation=0,
    )
    cache.put(entry)
    assert cache.get(key) is entry
    assert cache.size() == 1
    cache.remove(key)
    assert cache.get(key) is None
    reset_quote_cache()


def test_quote_cache_separates_per_operator() -> None:
    """A poisoned response from operator A cannot affect operator B."""
    reset_quote_cache()
    cache = get_quote_cache()
    key_a = CacheKey(operator_id="op-a", pair="BTC/BTC", asset="BTC")
    key_b = CacheKey(operator_id="op-b", pair="BTC/BTC", asset="BTC")
    cache.put(
        CacheEntry(
            key=key_a,
            payload={"fee": 100},
            fetched_at_unix_s=1_000.0,
        )
    )
    cache.put(
        CacheEntry(
            key=key_b,
            payload={"fee": 999},
            fetched_at_unix_s=1_000.0,
        )
    )
    assert cache.get(key_a).payload["fee"] == 100
    assert cache.get(key_b).payload["fee"] == 999
    reset_quote_cache()


# ── Circuit-rebuild guard ────────────────────────────────────────────


def test_circuit_rebuild_guard_admits_under_budget() -> None:
    reset_circuit_rebuild_guard()
    g = get_circuit_rebuild_guard()
    assert isinstance(g, CircuitRebuildGuard)
    # Fresh deployment admits the first call.
    assert g.admit("boltz_reverse") is True
    reset_circuit_rebuild_guard()


def test_circuit_rebuild_guard_refuses_when_listener_starved() -> None:
    """Drain the per-listener bucket; further admits refuse."""
    reset_circuit_rebuild_guard()
    g = get_circuit_rebuild_guard()
    # Consume the bucket aggressively until refused.
    admitted = 0
    for _ in range(200):
        if g.admit("test_listener"):
            admitted += 1
        else:
            break
    assert admitted > 0  # at least one admit
    # Once refused, subsequent admits stay refused.
    assert g.admit("test_listener") is False
    reset_circuit_rebuild_guard()


def test_circuit_rebuild_guard_singleton_is_isolated() -> None:
    reset_circuit_rebuild_guard()
    a = get_circuit_rebuild_guard()
    b = get_circuit_rebuild_guard()
    assert a is b
    reset_circuit_rebuild_guard()
    c = get_circuit_rebuild_guard()
    assert c is not a


# ── set_feature_enabled_at_day from create endpoint ──────────────────


@pytest.mark.asyncio
async def test_create_endpoint_writes_feature_enabled_at_day(
    db_engine,
    db_session,
    monkeypatch,
) -> None:
    """The create endpoint sets the day-quantized
    ``feature_enabled_at_day`` on first session."""
    import json
    from unittest.mock import AsyncMock, MagicMock

    from cryptography.fernet import Fernet
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.dashboard.api import (
        dash_anonymize_create_session,
        dash_anonymize_quote,
    )
    from app.services.anonymize.service import reset_anonymize_service
    from app.services.anonymize.settings_store import (
        get_feature_enabled_at_day,
    )

    reset_anonymize_service()
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )
    monkeypatch.setattr(
        settings,
        "anonymize_quote_token_hmac_key_fernet",
        Fernet.generate_key().decode("ascii"),
    )

    addr = "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"

    def _req(body, cookie="abc"):
        raw = json.dumps(body).encode("utf-8")
        req = MagicMock()
        req.body = AsyncMock(return_value=raw)
        req.cookies = {"dashboard_session": cookie}
        req.app.state.anonymize_health = {
            "egress_endpoints_onion_only": True,
            "operator_registry_size": 1,
            "tor_bootstrap_ready": True,
        }
        req.client = MagicMock()
        req.client.host = "127.0.0.1"
        return req

    settings.anonymize_enabled = True
    quote = await dash_anonymize_quote(
        _req(
            {
                "source_kind": "lightning-self",
                "destination_address": addr,
                "requested_amount_sat": 250_000,
            }
        )
    )
    assert isinstance(quote, dict)

    # Before create: feature_enabled_at_day is unset.
    async with factory() as s:
        assert await get_feature_enabled_at_day(s) is None

    out = await dash_anonymize_create_session(
        _req({"quote_token": quote["quote_token"]}),
        db=db_session,
    )
    assert isinstance(out, dict)

    # After create: the day-quantized row exists.
    async with factory() as s:
        day = await get_feature_enabled_at_day(s)
        assert day is not None
        # Sanity: today's UTC day (settings_store uses UTC).
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        assert day <= _dt.now(_tz.utc).date()

    from app.services.anonymize.service import get_anonymize_service

    await get_anonymize_service().stop()
    reset_anonymize_service()


# ── Rotation tick ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rotation_tick_run_walks_policies_without_raising(
    db_engine,
    monkeypatch,
) -> None:
    """Rotation tick reads + writes runtime_state rows
    without raising on a fresh deployment."""
    from sqlalchemy.ext.asyncio import async_sessionmaker

    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    monkeypatch.setattr(
        "app.core.database.get_session_maker",
        lambda: factory,
    )

    from app.services.anonymize.service import _rotation_tick_run

    await _rotation_tick_run()

    # Re-running should be idempotent against the timestamp the
    # first run stamped.
    await _rotation_tick_run()
