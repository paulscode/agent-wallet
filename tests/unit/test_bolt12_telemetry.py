# SPDX-License-Identifier: MIT
"""Tests for the 2026-06-05 BOLT 12 telemetry additions.

Covers (against the 4 telemetry adds in the post-mortem brief):

* #1 HtlcEvent subscriber: extraction + classification + kill switch.
* #2 Channel snapshot at mint: helper produces the right shape;
     ``_maybe_capture_channel_snapshot`` honours the setting + is
     best-effort on failure.
* #3 Settle watchdog: emits one audit row per stale invoice, then
     stamps the flag so subsequent ticks no-op.
* #6 Wire-send confirmation: counter bumps after a successful
     gateway send.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceRequest,
    Bolt12InvoiceRequestStatus,
    Bolt12InvoiceStatus,
)

# ── Telemetry #1: HtlcEvent subscriber ────────────────────────


def test_normalise_hash_accepts_hex_and_base64():
    import base64

    from app.services.bolt12.htlc_event_subscriber import _normalise_hash

    raw = bytes.fromhex("ab" * 32)
    assert _normalise_hash(raw.hex()) == "ab" * 32
    assert _normalise_hash(base64.b64encode(raw).decode()) == "ab" * 32
    assert _normalise_hash("junk") is None
    assert _normalise_hash("") is None


def test_extract_payment_hash_walks_subevent_shapes():
    """LND surfaces payment_hash in different sub-events depending
    on lifecycle stage. The helper must find it wherever it is."""
    from app.services.bolt12.htlc_event_subscriber import _extract_payment_hash

    # Top-level (LND >=0.18 link_fail).
    assert _extract_payment_hash({"payment_hash": "ab" * 32}) == "ab" * 32

    # Buried in forward_event.info (older versions).
    assert _extract_payment_hash({"forward_event": {"info": {"payment_hash": "cd" * 32}}}) == "cd" * 32

    # Settle event.
    assert _extract_payment_hash({"settle_event": {"payment_hash": "ef" * 32}}) == "ef" * 32

    # None when the hash is missing entirely.
    assert _extract_payment_hash({"event_type": "RECEIVE"}) is None


def test_classify_maps_lnd_events_to_actions():
    from app.services.bolt12.htlc_event_subscriber import _classify

    # Settle.
    action, _err, _details = _classify({"settle_event": {}})
    assert action == "bolt12_htlc_settled"

    # Link fail with detail.
    action, err, details = _classify(
        {
            "link_fail_event": {
                "wire_failure": "INSUFFICIENT_CAPACITY",
                "failure_detail": "INSUFFICIENT_BALANCE",
                "failure_string": "channel balance insufficient",
            },
        }
    )
    assert action == "bolt12_htlc_link_failed_at_node"
    assert "balance" in err
    assert details["wire_failure"] == "INSUFFICIENT_CAPACITY"

    # Forward event (HTLC arrived).
    action, _err, _details = _classify({"forward_event": {}})
    assert action == "bolt12_htlc_received_at_node"

    # Unknown shape → None.
    action, _err, _details = _classify({"event_type": "RECEIVE"})
    assert action is None


@pytest.mark.asyncio
async def test_htlc_event_subscriber_honors_kill_switch(monkeypatch):
    """When the setting is False, the subscriber returns
    immediately without ever opening a stream — same contract as
    the settlement subscriber."""
    from app.services.bolt12 import htlc_event_subscriber as sub

    monkeypatch.setattr(
        sub.settings,
        "bolt12_htlc_event_subscriber_enabled",
        False,
    )
    called = {"n": 0}

    async def _boom(*_a, **_k):
        called["n"] += 1
        raise AssertionError("should not open a stream")

    monkeypatch.setattr(sub, "_stream_once", _boom)

    stop = asyncio.Event()
    await asyncio.wait_for(sub.run_htlc_event_subscriber(stop), timeout=1.0)
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_htlc_event_handler_silently_ignores_unknown_hash(
    db_session,
    monkeypatch,
):
    """Events for payment_hashes we don't have in our Bolt12Invoice
    table must be silent no-ops (they're regular BOLT 11 HTLCs
    LND is forwarding for unrelated reasons)."""
    from app.services.bolt12 import htlc_event_subscriber as sub

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    audit_calls: list = []

    async def _spy_audit(*args, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _spy_audit,
    )

    await sub._handle_htlc_event(
        {
            "event_type": "RECEIVE",
            "settle_event": {"payment_hash": "aa" * 32},
        }
    )
    assert audit_calls == []


@pytest.mark.asyncio
async def test_htlc_event_handler_emits_audit_for_matched_hash(
    db_session,
    monkeypatch,
):
    """A settle event for a payment_hash we DO have minted must
    emit ``bolt12_htlc_settled`` with the invoice's metadata in
    ``details``."""
    from app.services.bolt12 import htlc_event_subscriber as sub

    # Seed an INBOUND invoice for the test hash.
    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=3345000,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=3345000,
        payment_hash_hex="bb" * 32,
        status=Bolt12InvoiceStatus.OPEN,
    )
    db_session.add(inv)
    await db_session.commit()
    inv_id = inv.id

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    audit_calls: list = []

    async def _spy_audit(*args, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _spy_audit,
    )

    await sub._handle_htlc_event(
        {
            "event_type": "RECEIVE",
            "settle_event": {"payment_hash": "bb" * 32},
            "incoming_channel_id": "12345",
        }
    )

    assert len(audit_calls) == 1
    kw = audit_calls[0]
    assert kw["action"] == "bolt12_htlc_settled"
    assert kw["details"]["payment_hash"] == "bb" * 32
    assert kw["details"]["invoice_id"] == str(inv_id)
    assert kw["details"]["incoming_channel_id"] == "12345"


# ── Follow-up #4: breaker is fed by HtlcEvent signals ────────


@pytest.mark.asyncio
async def test_htlc_event_link_failed_records_breaker_failure(
    db_session,
    monkeypatch,
):
    """A ``link_fail`` event for one of our minted payment_hashes
    must call ``breaker.record_failure(intro)`` for every intro
    in the invoice's ``blinded_paths_summary``. This is the only
    cross-event failure signal the API-process breaker can
    observe — the watchdog runs in Celery and its breaker is
    process-local."""
    from app.services.bolt12 import htlc_event_subscriber as sub
    from app.services.bolt12.path_postprocess import get_path_breaker

    breaker = get_path_breaker()
    breaker.reset_for_tests()

    # Seed an INBOUND invoice with a non-trivial paths_summary.
    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=3345000,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=3345000,
        payment_hash_hex="dd" * 32,
        status=Bolt12InvoiceStatus.OPEN,
        blinded_paths_summary={
            "paths": [
                {"intro_pubkey": "intro_aaa", "real_hops": 2},
                {"intro_pubkey": "intro_bbb", "real_hops": 2},
            ],
        },
    )
    db_session.add(inv)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    async def _noop_audit(*args, **kwargs):
        pass

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _noop_audit,
    )

    # Set failures_to_open=1 so a single event suffices to open.
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)
    monkeypatch.setattr(settings, "bolt12_path_breaker_initial_cooldown_s", 600)

    await sub._handle_htlc_event(
        {
            "event_type": "RECEIVE",
            "link_fail_event": {
                "payment_hash": "dd" * 32,
                "wire_failure": "INSUFFICIENT_BALANCE",
                "failure_string": "channel balance",
            },
        }
    )

    # Both intros from the paths_summary were opened by the single
    # link_fail event.
    assert breaker.is_open("intro_aaa") is True
    assert breaker.is_open("intro_bbb") is True

    breaker.reset_for_tests()


@pytest.mark.asyncio
async def test_htlc_event_forward_failed_inbound_also_records_failure(
    db_session,
    monkeypatch,
):
    """A ``forward_fail_event`` for an inbound BOLT 12 HTLC is
    rare but plausible (e.g., LND cancels mid-acceptance). Verify
    it triggers ``record_failure`` the same way ``link_fail`` does
    — both belong to the "HTLC reached us and was rejected"
    failure class."""
    from app.services.bolt12 import htlc_event_subscriber as sub
    from app.services.bolt12.path_postprocess import get_path_breaker

    breaker = get_path_breaker()
    breaker.reset_for_tests()

    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=3345000,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=3345000,
        payment_hash_hex="ff" * 32,
        status=Bolt12InvoiceStatus.OPEN,
        blinded_paths_summary={"paths": [{"intro_pubkey": "intro_fwd"}]},
    )
    db_session.add(inv)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    async def _noop_audit(*args, **kwargs):
        pass

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _noop_audit,
    )

    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)

    await sub._handle_htlc_event(
        {
            "event_type": "RECEIVE",
            "forward_fail_event": {"payment_hash": "ff" * 32},
        }
    )

    assert breaker.is_open("intro_fwd") is True
    breaker.reset_for_tests()


@pytest.mark.asyncio
async def test_htlc_event_settled_closes_breaker_for_each_intro(
    db_session,
    monkeypatch,
):
    """A ``settle`` event resets the breaker for each intro in
    the paths_summary. Verifies cross-event success signal."""
    from app.services.bolt12 import htlc_event_subscriber as sub
    from app.services.bolt12.path_postprocess import get_path_breaker

    breaker = get_path_breaker()
    breaker.reset_for_tests()

    # Pre-open both intros so we can verify they're closed.
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)
    breaker.record_failure("intro_xxx")
    breaker.record_failure("intro_yyy")
    assert breaker.is_open("intro_xxx") and breaker.is_open("intro_yyy")

    # Seed an invoice that settled, with paths_summary.
    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=3345000,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=3345000,
        payment_hash_hex="ee" * 32,
        status=Bolt12InvoiceStatus.OPEN,
        blinded_paths_summary={
            "paths": [
                {"intro_pubkey": "intro_xxx"},
                {"intro_pubkey": "intro_yyy"},
            ],
        },
    )
    db_session.add(inv)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    async def _noop_audit(*args, **kwargs):
        pass

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _noop_audit,
    )

    await sub._handle_htlc_event(
        {
            "event_type": "RECEIVE",
            "settle_event": {"payment_hash": "ee" * 32},
        }
    )

    assert breaker.is_open("intro_xxx") is False
    assert breaker.is_open("intro_yyy") is False

    breaker.reset_for_tests()


# ── Telemetry #2: channel snapshot at mint ────────────────────


@pytest.mark.asyncio
async def test_capture_mint_time_channel_snapshot_shape():
    """The snapshot helper wraps drift rows with a captured_at
    timestamp + a channels list."""
    from app.services.bolt12 import path_diagnostics as pd

    fake_lnd = MagicMock()
    fake_lnd.get_channels = AsyncMock(
        return_value=(
            [
                {
                    "chan_id": "abc",
                    "remote_pubkey": "02_peer",
                    "peer_alias": "P",
                    "capacity": 150_000,
                    "local_balance": 36_500,
                    "remote_balance": 112_500,
                    "active": True,
                },
            ],
            None,
        )
    )
    fake_lnd.get_info = AsyncMock(
        return_value=({"identity_pubkey": "03_ours"}, None),
    )
    fake_lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": "02_peer",
                "node2_pub": "03_ours",
                "node1_policy": {"max_htlc_msat": "133650000"},
                "node2_policy": {"max_htlc_msat": "0"},
            },
            None,
        )
    )

    snap = await pd.capture_mint_time_channel_snapshot(fake_lnd)
    assert snap is not None
    assert "captured_at" in snap
    assert len(snap["channels"]) == 1
    ch = snap["channels"][0]
    assert ch["chan_id"] == "abc"
    assert ch["gossiped_inbound_max_htlc_sat"] == 133_650


@pytest.mark.asyncio
async def test_capture_mint_time_channel_snapshot_returns_none_on_failure():
    """Any underlying error must surface as ``None`` so the mint
    hot path is never blocked by telemetry."""
    from app.services.bolt12 import path_diagnostics as pd

    fake_lnd = MagicMock()
    fake_lnd.get_channels = AsyncMock(side_effect=RuntimeError("kaboom"))

    snap = await pd.capture_mint_time_channel_snapshot(fake_lnd)
    assert snap is None


@pytest.mark.asyncio
async def test_maybe_capture_channel_snapshot_respects_kill_switch(monkeypatch):
    """When ``bolt12_channel_snapshot_at_mint_enabled=False``, the
    helper short-circuits without calling LND."""
    from app.core.config import settings
    from app.services.bolt12 import responder as resp_mod

    monkeypatch.setattr(
        settings,
        "bolt12_channel_snapshot_at_mint_enabled",
        False,
    )

    # If capture_mint_time_channel_snapshot got called, this would
    # explode (no fake LND wired up). The fact it doesn't proves
    # the short-circuit.
    out = await resp_mod._maybe_capture_channel_snapshot()
    assert out is None


# ── Telemetry #3: settle watchdog ─────────────────────────────


@pytest.mark.asyncio
async def test_settle_watchdog_emits_audit_for_stale_open_invoice(
    db_session,
    monkeypatch,
):
    """An OPEN invoice older than the watchdog window must get
    exactly one ``bolt12_invoice_settle_timeout`` audit row, and
    ``settle_timeout_audited_at`` must be stamped."""
    from app.core.config import settings
    from app.tasks import boltz_tasks

    monkeypatch.setattr(settings, "bolt12_invoice_settle_watchdog_minutes", 5)

    # Seed an OPEN invoice 10 minutes old.
    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=3345000,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=3345000,
        payment_hash_hex="cc" * 32,
        status=Bolt12InvoiceStatus.OPEN,
    )
    inv.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.add(inv)
    await db_session.commit()
    inv_id = inv.id

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    # ``settle_watchdog`` does ``from app.core.database import get_db_context``
    # so we must patch the imported binding on the watchdog
    # module — patching ``app.core.database.get_db_context``
    # alone doesn't update the already-bound reference.
    from app.services.bolt12 import settle_watchdog as _sw

    monkeypatch.setattr(_sw, "get_db_context", _fake_ctx)

    audit_calls: list = []

    async def _spy_audit(*args, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _spy_audit,
    )

    summary = await boltz_tasks._run_bolt12_settle_watchdog()
    assert summary["scanned"] == 1
    assert summary["alerted"] == 1
    assert len(audit_calls) == 1
    assert audit_calls[0]["action"] == "bolt12_invoice_settle_timeout"
    assert audit_calls[0]["details"]["payment_hash"] == "cc" * 32

    # Flag was stamped → second run is a no-op for this row.
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv_id))).scalar_one()
    assert refreshed.settle_timeout_audited_at is not None

    audit_calls.clear()
    summary2 = await boltz_tasks._run_bolt12_settle_watchdog()
    assert summary2["scanned"] == 0
    assert summary2["alerted"] == 0
    assert audit_calls == []


@pytest.mark.asyncio
async def test_settle_watchdog_api_process_feeds_breaker(
    db_session,
    monkeypatch,
):
    """Fix from 2026-06-06: when the watchdog runs in the API
    process (via ``settle_watchdog.tick_settle_watchdog``), its
    ``record_failure`` calls land in the same in-memory breaker
    the responder reads from. This pins the cross-event upstream-
    death failure signal that the Celery-side watchdog couldn't
    deliver."""
    from app.core.config import settings
    from app.services.bolt12 import settle_watchdog as sw
    from app.services.bolt12.path_postprocess import get_path_breaker

    breaker = get_path_breaker()
    breaker.reset_for_tests()

    monkeypatch.setattr(settings, "bolt12_invoice_settle_watchdog_minutes", 5)
    monkeypatch.setattr(settings, "bolt12_path_breaker_failures_to_open", 1)

    # Seed an OPEN invoice >5min old with a paths_summary.
    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=3345000,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=3345000,
        payment_hash_hex="aa" * 32,
        status=Bolt12InvoiceStatus.OPEN,
        blinded_paths_summary={
            "paths": [
                {"intro_pubkey": "intro_upstream_a"},
                {"intro_pubkey": "intro_upstream_b"},
            ],
        },
    )
    inv.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.add(inv)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    # Patch BOTH the watchdog's own bound import AND the audit
    # helper's import path — the audit helper looks up
    # ``get_db_context`` via its argument, but the watchdog's
    # own session context comes from its imported binding.
    monkeypatch.setattr(sw, "get_db_context", _fake_ctx)

    async def _noop_audit(*args, **kwargs):
        pass

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _noop_audit,
    )

    summary = await sw.tick_settle_watchdog()
    assert summary["alerted"] == 1

    # Both intros now opened in the API breaker — the very thing
    # the Celery-side watchdog could not deliver.
    assert breaker.is_open("intro_upstream_a") is True
    assert breaker.is_open("intro_upstream_b") is True

    breaker.reset_for_tests()


@pytest.mark.asyncio
async def test_settle_watchdog_disabled_when_window_is_zero(monkeypatch):
    """Setting the window to 0 short-circuits without scanning."""
    from app.core.config import settings
    from app.tasks import boltz_tasks

    monkeypatch.setattr(settings, "bolt12_invoice_settle_watchdog_minutes", 0)

    summary = await boltz_tasks._run_bolt12_settle_watchdog()
    assert summary == {"scanned": 0, "alerted": 0, "skipped": "disabled"}


# ── 2026-06-13 failure-diagnostic enrichment ────────────────


@pytest.mark.asyncio
async def test_settle_watchdog_enriches_audit_with_policy_drift_and_htlc_state(
    db_session,
    monkeypatch,
):
    """When a stale OPEN invoice fires the watchdog, the audit row
    must carry the per-intro encoded-vs-current policy comparison
    AND the LND-side HTLC state. These two signals together
    discriminate "Tor blip" vs "policy-update race" vs "rejected at
    our LND" on the next Ocean failure."""
    from app.core.config import settings
    from app.tasks import boltz_tasks

    monkeypatch.setattr(settings, "bolt12_invoice_settle_watchdog_minutes", 5)

    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=4058000,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=4058000,
        payment_hash_hex="ab" * 32,
        status=Bolt12InvoiceStatus.OPEN,
        # Mint-time encoded policy for one intro — what the
        # responder put into the blinded path. The current
        # advertised policy from gossip diverges on the fee_rate
        # field below, simulating a Megalithic policy update
        # between mint and HTLC arrival.
        blinded_paths_summary={
            "paths": [
                {
                    "intro_pubkey": "02a98c86ef366ce2" + "00" * 25,
                    "real_hops": 1,
                    "htlc_max_msat_advertised": 133650000,
                    "htlc_max_msat_clamped": 111335000,
                    "terminal_peer_pubkey": "02a98c86ef366ce2" + "00" * 25,
                    "encoded_base_fee_msat": 1100,
                    "encoded_proportional_fee_rate": 1206,
                    "encoded_total_cltv_delta": 201,
                    "encoded_htlc_min_msat": 1100,
                }
            ]
        },
    )
    inv.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.add(inv)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    from app.services.bolt12 import settle_watchdog as _sw

    monkeypatch.setattr(_sw, "get_db_context", _fake_ctx)

    # Stub the LND service with synthetic responses that the
    # failure-diagnostics helpers will consume.
    our_pubkey = "031234567890abcdef" + "00" * 24
    intro_pubkey = "02a98c86ef366ce2" + "00" * 25

    fake_channel = {
        "chan_id": "1042763633773182977",
        "remote_pubkey": intro_pubkey,
    }
    fake_edge = {
        "node1_pub": intro_pubkey,
        "node2_pub": our_pubkey,
        "node1_policy": {
            "fee_base_msat": "1100",
            # Diverged from encoded 1206 → 1500 simulates a policy
            # update by Megalithic between mint and HTLC arrival.
            "fee_rate_milli_msat": "1500",
            "time_lock_delta": 80,
            "min_htlc": "1100",
            "max_htlc_msat": "133650000",
            "disabled": False,
            "last_update": 1718000000,
        },
        "node2_policy": {"fee_base_msat": "0"},
    }
    # /v1/invoice/{hex} returns one ACCEPTED HTLC — proves the
    # forward DID reach our LND (so the next failure on this
    # shape ISN'T "never arrived").
    fake_invoice_get = {
        "state": "OPEN",
        "amt_paid_msat": "0",
        "htlcs": [
            {
                "state": "ACCEPTED",
                "amt_msat": "4058000",
                "accept_time": "1718000010",
                "chan_id": "1042763633773182977",
                "htlc_index": "1",
                "expiry_height": 953700,
            }
        ],
    }

    fake_lnd = MagicMock()
    fake_lnd.get_info = AsyncMock(
        return_value=({"identity_pubkey": our_pubkey}, None),
    )
    fake_lnd.get_channels = AsyncMock(return_value=([fake_channel], None))
    fake_lnd.get_channel_edge = AsyncMock(return_value=(fake_edge, None))
    fake_lnd._request = AsyncMock(return_value=(fake_invoice_get, None))
    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service",
        fake_lnd,
    )

    audit_calls: list = []

    async def _spy_audit(*args, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _spy_audit,
    )

    summary = await boltz_tasks._run_bolt12_settle_watchdog()
    assert summary == {"scanned": 1, "alerted": 1}
    assert len(audit_calls) == 1
    details = audit_calls[0]["details"]

    # Policy-drift enrichment present and surfacing the fee_rate
    # divergence (encoded 1206 vs current 1500).
    drift = details["policy_drift_per_intro"]
    assert isinstance(drift, list) and len(drift) == 1
    entry = drift[0]
    assert entry["intro_pubkey"] == intro_pubkey
    assert entry["current"]["chan_id"] == "1042763633773182977"
    assert entry["current"]["policy"]["fee_rate_milli_msat"] == "1500"
    # Divergence keys use the LND wire field name.
    assert entry["divergence"]["fee_rate_milli_msat"] == {
        "encoded": 1206,
        "current": 1500,
    }
    # fee_base + min_htlc + max_htlc match → omitted from divergence.
    assert "fee_base_msat" not in entry["divergence"]
    assert "min_htlc" not in entry["divergence"]
    assert "max_htlc_msat" not in entry["divergence"]
    # total_cltv_delta is NEVER auto-flagged (path-aggregate vs
    # per-hop comparison is semantically wrong).
    assert "time_lock_delta" not in entry["divergence"]

    # LND HTLC-state enrichment present and proves the forward
    # reached our LND (htlcs list is non-empty with ACCEPTED).
    htlc_state = details["lnd_invoice_htlc_state"]
    assert htlc_state["state"] == "OPEN"
    assert len(htlc_state["htlcs"]) == 1
    assert htlc_state["htlcs"][0]["state"] == "ACCEPTED"
    assert htlc_state["htlcs"][0]["amt_msat"] == "4058000"


@pytest.mark.asyncio
async def test_settle_watchdog_does_not_flag_legacy_row_as_divergent(
    db_session,
    monkeypatch,
):
    """Regression: an invoice row minted BEFORE the encoded-triplet
    enrichment shipped has a ``blinded_paths_summary`` without
    ``encoded_*`` fields. The watchdog must NOT flag every legacy
    row as having "all fields drifted" — that would falsely
    suggest a policy-update race on every old in-flight invoice.

    Divergence dict must be empty for legacy rows; ``encoded``
    block makes the absence explicit (all None) so the reader
    knows why."""
    from app.core.config import settings
    from app.tasks import boltz_tasks

    monkeypatch.setattr(settings, "bolt12_invoice_settle_watchdog_minutes", 5)

    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=4058000,
    )
    db_session.add(invreq)
    await db_session.flush()
    intro_pubkey = "02a98c86ef366ce2" + "00" * 25
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=4058000,
        payment_hash_hex="ef" * 32,
        status=Bolt12InvoiceStatus.OPEN,
        # Legacy summary — only the pre-enrichment fields are
        # present. The watchdog must handle this without
        # generating false-positive divergence flags.
        blinded_paths_summary={
            "paths": [
                {
                    "intro_pubkey": intro_pubkey,
                    "real_hops": 1,
                    "htlc_max_msat_advertised": 133650000,
                    "htlc_max_msat_clamped": 111335000,
                    "terminal_peer_pubkey": intro_pubkey,
                }
            ]
        },
    )
    inv.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.add(inv)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    from app.services.bolt12 import settle_watchdog as _sw

    monkeypatch.setattr(_sw, "get_db_context", _fake_ctx)

    our_pubkey = "031234567890abcdef" + "00" * 24
    fake_lnd = MagicMock()
    fake_lnd.get_info = AsyncMock(
        return_value=({"identity_pubkey": our_pubkey}, None),
    )
    fake_lnd.get_channels = AsyncMock(
        return_value=(
            [{"chan_id": "104276", "remote_pubkey": intro_pubkey}],
            None,
        ),
    )
    fake_lnd.get_channel_edge = AsyncMock(
        return_value=(
            {
                "node1_pub": intro_pubkey,
                "node2_pub": our_pubkey,
                "node1_policy": {
                    "fee_base_msat": "1100",
                    "fee_rate_milli_msat": "1500",
                    "min_htlc": "1100",
                    "max_htlc_msat": "133650000",
                },
                "node2_policy": {},
            },
            None,
        ),
    )
    fake_lnd._request = AsyncMock(
        return_value=({"state": "OPEN", "htlcs": []}, None),
    )
    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service",
        fake_lnd,
    )

    audit_calls: list = []

    async def _spy_audit(*args, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _spy_audit,
    )

    summary = await boltz_tasks._run_bolt12_settle_watchdog()
    assert summary == {"scanned": 1, "alerted": 1}
    drift = audit_calls[0]["details"]["policy_drift_per_intro"]
    assert len(drift) == 1
    entry = drift[0]
    # Encoded block makes the legacy nature explicit.
    assert entry["encoded"]["base_fee_msat"] is None
    assert entry["encoded"]["proportional_fee_rate"] is None
    # max_htlc_msat_advertised IS present on legacy rows.
    assert entry["encoded"]["htlc_max_msat_advertised"] == 133650000
    # Current gossip recorded.
    assert entry["current"]["policy"]["fee_rate_milli_msat"] == "1500"
    # NO false-positive divergence flags.
    assert entry["divergence"] == {}


@pytest.mark.asyncio
async def test_settle_watchdog_audit_emits_when_diagnostics_raise(
    db_session,
    monkeypatch,
):
    """A failing LND lookup (transient breaker, Tor blip) MUST
    NOT block the audit-row emit. We still alert; we just record
    empty diagnostics for that row."""
    from app.core.config import settings
    from app.tasks import boltz_tasks

    monkeypatch.setattr(settings, "bolt12_invoice_settle_watchdog_minutes", 5)

    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=1000,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=1000,
        payment_hash_hex="cd" * 32,
        status=Bolt12InvoiceStatus.OPEN,
        blinded_paths_summary={"paths": [{"intro_pubkey": "0299"}]},
    )
    inv.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.add(inv)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    from app.services.bolt12 import settle_watchdog as _sw

    monkeypatch.setattr(_sw, "get_db_context", _fake_ctx)

    # Every LND call raises — simulating a breaker-open episode.
    fake_lnd = MagicMock()

    async def _explode(*_a, **_kw):
        raise RuntimeError("breaker open")

    fake_lnd.get_info = _explode
    fake_lnd.get_channels = _explode
    fake_lnd.get_channel_edge = _explode
    fake_lnd._request = _explode
    monkeypatch.setattr(
        "app.services.lnd_service.lnd_service",
        fake_lnd,
    )

    audit_calls: list = []

    async def _spy_audit(*args, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(
        "app.services.bolt12.responder._audit_inbound",
        _spy_audit,
    )

    summary = await boltz_tasks._run_bolt12_settle_watchdog()
    assert summary == {"scanned": 1, "alerted": 1}
    # Audit row still emitted, diagnostics fields are present but
    # empty/None (graceful degradation).
    assert len(audit_calls) == 1
    details = audit_calls[0]["details"]
    assert details["payment_hash"] == "cd" * 32
    assert details["policy_drift_per_intro"] == [
        {
            "intro_pubkey": "0299",
            "encoded": {
                "base_fee_msat": None,
                "proportional_fee_rate": None,
                "total_cltv_delta": None,
                "htlc_min_msat": None,
                "htlc_max_msat_advertised": None,
            },
            "current": None,
            "divergence": {},
            # 2026-06-14: margin fields surface as 0 on legacy
            # rows (where the mint pre-dates the margin stage).
            "safety_margin_ppm_applied": 0,
            "safety_margin_base_msat_applied": 0,
        }
    ]
    assert details["lnd_invoice_htlc_state"] is None


# ── Telemetry #6: wire-send counter ──────────────────────────


@pytest.mark.asyncio
async def test_wire_send_counter_bumps_on_successful_gateway_send(monkeypatch):
    """After a responder returns invoice bytes and the gateway
    accepts them, ``inbound_invoice_replied_total`` must be
    incremented by 1. A widening gap between minted-mark and
    this counter is the wire-loss signal."""
    from app.services.bolt12.orchestrator import Bolt12Service
    from app.services.bolt12_gateway.types import InboundMessage

    @asynccontextmanager
    async def _noop_ctx():
        yield MagicMock()

    monkeypatch.setattr("app.core.database.get_db_context", _noop_ctx)

    async def _responder(ctx):
        return b"\x00\x01"

    fake_gateway = MagicMock()
    fake_gateway.send_onion_message = AsyncMock()
    svc = Bolt12Service(fake_gateway, invoice_responder=_responder)

    msg = InboundMessage(
        recv_id="r1",
        payload_tlv_type=64,
        payload=b"payload",
        reply_path=b"reply_path_bytes",
        received_at_ms=0,
        inbound_context=b"ctx",
    )

    await asyncio.wait_for(
        svc._handle_inbound_invreq(msg),
        timeout=2.0,
    )
    assert svc.metrics.inbound_invoice_replied_total == 1
    # gateway_send_failure_total stays zero on the success path.
    assert svc.metrics.gateway_send_failure_total == 0
