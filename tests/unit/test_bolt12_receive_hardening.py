# SPDX-License-Identifier: MIT
"""Tests for the BOLT 12 receive-path hardening plan items.

Covers items implemented in:

* ``app/services/bolt12/inbound_rate_limit.py`` (Item 7)
* ``app/services/bolt12/orchestrator.py`` (Item 8)
* ``app/services/bolt12/reconcile.py`` (Item 9)
* ``app/services/bolt12/runtime.py`` (Item 12)
* ``app/services/bolt12/responder.py`` (Item 15)
* ``app/services/bolt12/settlement_subscriber.py`` (Item 13)
* ``app/tasks/boltz_tasks.py`` cleanup task (Item 14)

These are unit-level tests — they exercise the new code paths
with stubs / fakes, not the live LND or Redis.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest


@pytest.fixture(autouse=True)
def _disable_warmup_and_onion_detect(monkeypatch):
    """S4 + S2 (2026-06-12): the subscriber loops now do a GET
    /v1/getinfo warmup before each reconnect AND an onion-only
    auto-detect that ALSO hits get_info. Unit tests stub
    ``_stream_once`` directly and would hit those probes' 10 s
    timeouts (their own test deadline is 2 s). Disable both
    globally for this file — neither behaviour is what these
    tests cover (those have their own coverage in
    ``test_bolt12_stability_telemetry_2026_06_12.py``)."""
    monkeypatch.setattr(
        "app.core.config.settings.bolt12_subscriber_warmup_probe_enabled",
        False,
    )

    # Force the onion-only detector to return False so it doesn't
    # call get_info during polling-mode evaluation.
    async def _no_auto_polling():
        return False

    monkeypatch.setattr(
        "app.services.bolt12.onion_only_detect.detect_onion_only",
        _no_auto_polling,
    )


import pytest
from sqlalchemy import select

from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceRequest,
    Bolt12InvoiceRequestStatus,
    Bolt12InvoiceStatus,
)

# ── Item 7: two-tier rate limit ───────────────────────────────


class _FakeRedis:
    """Minimal Redis stub for the two-key Lua admission script.

    Tracks call counts and returns canned responses. The Lua script
    is opaque to the test — we only check call shape + that the
    function correctly unpacks the 4-tuple result.
    """

    def __init__(self, response):
        self._response = response
        self.eval_calls: list[tuple] = []

    async def eval(self, script, num_keys, *args):
        self.eval_calls.append((script, num_keys, args))
        return self._response


@pytest.mark.asyncio
async def test_rate_limit_allowed_returns_no_cap(monkeypatch):
    from app.services.bolt12 import inbound_rate_limit

    fake = _FakeRedis([1, b"5", b"7", b"42", b""])
    monkeypatch.setattr(inbound_rate_limit, "get_redis", AsyncMock(return_value=fake))
    # Ensure limits non-zero so the function dispatches.
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_count", 100)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_per_offer_count", 200)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_global_count", 1000)

    allowed, reason, cap = await inbound_rate_limit.check_inbound_invreq_rate("peer_abc", "issuer_xyz")

    assert allowed is True
    assert reason is None
    assert cap is None
    assert len(fake.eval_calls) == 1
    # 3 keys passed to EVAL: per-peer + per-offer + global.
    _, num_keys, args = fake.eval_calls[0]
    assert num_keys == 3
    assert "peer_abc" in args[0]
    assert "issuer_xyz" in args[1]
    assert args[2] == inbound_rate_limit._GLOBAL_KEY


@pytest.mark.asyncio
async def test_rate_limit_per_peer_cap_returns_distinct_reason(monkeypatch):
    from app.services.bolt12 import inbound_rate_limit

    fake = _FakeRedis([0, b"100", b"7", b"42", b"per_peer"])
    monkeypatch.setattr(inbound_rate_limit, "get_redis", AsyncMock(return_value=fake))
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_count", 100)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_per_offer_count", 200)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_global_count", 1000)

    allowed, reason, cap = await inbound_rate_limit.check_inbound_invreq_rate("peer_abc", "issuer_xyz")

    assert allowed is False
    assert cap == "per_peer"
    assert reason is not None and "per_peer" in reason


@pytest.mark.asyncio
async def test_rate_limit_per_offer_cap_returns_distinct_reason(monkeypatch):
    from app.services.bolt12 import inbound_rate_limit

    fake = _FakeRedis([0, b"5", b"200", b"42", b"per_offer"])
    monkeypatch.setattr(inbound_rate_limit, "get_redis", AsyncMock(return_value=fake))
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_count", 100)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_per_offer_count", 200)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_global_count", 1000)

    allowed, reason, cap = await inbound_rate_limit.check_inbound_invreq_rate("peer_abc", "issuer_xyz")

    assert allowed is False
    assert cap == "per_offer"
    assert reason is not None and "per_offer" in reason


@pytest.mark.asyncio
async def test_rate_limit_global_cap_returns_distinct_reason(monkeypatch):
    from app.services.bolt12 import inbound_rate_limit

    fake = _FakeRedis([0, b"50", b"7", b"1000", b"global"])
    monkeypatch.setattr(inbound_rate_limit, "get_redis", AsyncMock(return_value=fake))
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_count", 100)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_per_offer_count", 200)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_global_count", 1000)

    allowed, reason, cap = await inbound_rate_limit.check_inbound_invreq_rate("peer_abc", "issuer_xyz")

    assert allowed is False
    assert cap == "global"
    assert reason is not None and "global" in reason


@pytest.mark.asyncio
async def test_rate_limit_disabled_when_both_zero(monkeypatch):
    from app.services.bolt12 import inbound_rate_limit

    fake = _FakeRedis([0, b"0", b"0", b"0", b"per_peer"])
    monkeypatch.setattr(inbound_rate_limit, "get_redis", AsyncMock(return_value=fake))
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_count", 0)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_per_offer_count", 0)
    monkeypatch.setattr(inbound_rate_limit.settings, "bolt12_inbound_rate_limit_global_count", 0)

    allowed, reason, cap = await inbound_rate_limit.check_inbound_invreq_rate("p")
    assert (allowed, reason, cap) == (True, None, None)
    # Skipped EVAL entirely.
    assert fake.eval_calls == []


# ── Item 9: reconcile per-row commit + recovery ─────────────


async def _seed_open(db, payment_hash_hex):
    invreq = Bolt12InvoiceRequest(
        api_key_id=uuid4(),
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=1000,
    )
    db.add(invreq)
    await db.flush()
    inv = Bolt12Invoice(
        api_key_id=invreq.api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=1000,
        payment_hash_hex=payment_hash_hex,
        status=Bolt12InvoiceStatus.OPEN,
    )
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    return inv


@pytest.mark.asyncio
async def test_reconcile_one_row_failure_does_not_poison_others(db_session):
    """A per-row exception lands as errored and the next row still
    commits — verifies per-row commit rolled out by Item 9."""
    from app.services.bolt12.reconcile import reconcile_open_invoices

    bad = await _seed_open(db_session, "11" * 32)
    good = await _seed_open(db_session, "22" * 32)
    # Capture identifiers before reconcile because the per-row
    # commits will expire these ORM objects.
    bad_hash = bad.payment_hash_hex
    good_hash = good.payment_hash_hex

    class _LndStub:
        def __init__(self):
            self.calls = 0

        async def lookup_invoice(self, h):
            self.calls += 1
            if h == bad_hash:
                raise RuntimeError("simulated LND blip")
            return (
                {
                    "state": "SETTLED",
                    "settled": True,
                    "settle_date": 1_700_000_000,
                    "r_preimage": "cd" * 32,
                },
                None,
            )

    summary = await reconcile_open_invoices(db_session, _LndStub())

    assert summary.scanned == 2
    assert summary.paid == 1
    assert summary.errored == 1
    # The good row was committed — re-fetch by hash so we don't rely
    # on a stale ORM identifier on the seeded instance.
    refreshed = (
        await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.payment_hash_hex == good_hash))
    ).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.PAID


@pytest.mark.asyncio
async def test_reconcile_paid_transition_feeds_path_breaker_success(
    db_session,
    monkeypatch,
):
    """2026-06-11: ``reconcile_open_invoices`` must call
    ``path_breaker.record_success`` on every intro present in the
    row's ``blinded_paths_summary`` when it transitions OPEN→PAID.
    Mirrors what the HTLC subscriber's ``bolt12_htlc_settled``
    branch does — needed so polling-mode deployments (where the
    HTLC subscriber is a no-op) still feed the breaker.
    """
    from app.services.bolt12.path_postprocess import get_path_breaker
    from app.services.bolt12.reconcile import reconcile_open_invoices

    monkeypatch.setattr("app.core.config.settings.bolt12_path_breaker_enabled", True)
    monkeypatch.setattr("app.core.config.settings.bolt12_path_breaker_failures_to_open", 1)

    breaker = get_path_breaker()
    breaker.reset_for_tests()
    # Pre-open both intros so we can observe the close transition
    # caused by reconcile.
    intro_a = "02" + "aa" * 32
    intro_b = "02" + "bb" * 32
    breaker.record_failure(intro_a)
    breaker.record_failure(intro_b)
    assert breaker.is_open(intro_a)
    assert breaker.is_open(intro_b)

    inv = await _seed_open(db_session, "33" * 32)
    inv.blinded_paths_summary = {
        "paths": [
            {"intro_pubkey": intro_a, "real_hops": 1},
            {"intro_pubkey": intro_b, "real_hops": 2},
        ],
    }
    await db_session.commit()

    class _LndPaid:
        async def lookup_invoice(self, h):
            return (
                {
                    "state": "SETTLED",
                    "settled": True,
                    "settle_date": 1_700_000_000,
                    "r_preimage": "fe" * 32,
                },
                None,
            )

    summary = await reconcile_open_invoices(db_session, _LndPaid())
    assert summary.paid == 1

    # Both intros must be CLOSED again — record_success reset them.
    assert not breaker.is_open(intro_a), "reconcile must call record_success on intro_a"
    assert not breaker.is_open(intro_b), "reconcile must call record_success on intro_b"

    breaker.reset_for_tests()


# ── Item 12: receive-side runtime fields ────────────────────


def test_mark_inbound_error_bumps_rate_limit_counter_when_running():
    """The receive-side ``/status`` rate-limit-hit field depends on
    the orchestrator exposing the underlying counter: rate-limit drops
    should be surfaced both as a snapshot field AND as a monotonic
    counter. Verify the helper bumps the orchestrator metric when a
    service is registered, and silently no-ops when not."""
    from app.services.bolt12 import runtime as rt
    from app.services.bolt12.orchestrator import Bolt12ServiceMetrics

    rt._reset_for_tests()
    try:
        # No service running → mark_inbound_error must not raise.
        rt.mark_inbound_error("rate_limit:per_peer")
        assert rt._runtime.service is None  # sanity

        # Inject a stand-in service whose only relevant attribute is
        # ``metrics``. Avoid ``MagicMock(spec=Bolt12Service)``: spec
        # auto-builds awaitable proxies for the service's async
        # methods (``__aenter__`` / ``__aexit__`` / ``start`` /
        # ``stop``) that can leak unawaited coroutine warnings into
        # subsequent tests run in the same process.
        class _FakeService:
            def __init__(self) -> None:
                self.metrics = Bolt12ServiceMetrics()

        fake = _FakeService()
        rt._inject_for_tests(fake)  # type: ignore[arg-type]

        rt.mark_inbound_error("rate_limit:global")
        assert fake.metrics.inbound_rate_limit_drops_total == 1

        rt.mark_inbound_error("rate_limit:per_peer")
        assert fake.metrics.inbound_rate_limit_drops_total == 2

        # Non-rate-limit reasons must NOT bump the rate-limit counter.
        rt.mark_inbound_error("concurrency_rejected")
        assert fake.metrics.inbound_rate_limit_drops_total == 2
    finally:
        rt._reset_for_tests()


def test_runtime_mark_helpers_update_snapshot():
    from app.services.bolt12 import runtime as rt

    rt._reset_for_tests()

    state = rt.get_bolt12_runtime_state()
    assert state.last_inbound_mint_at is None
    assert state.last_inbound_error is None
    assert state.last_inbound_error_at is None
    assert state.node_address_cache_size is None
    assert state.node_address_last_push_at is None
    assert state.node_address_last_push_accepted is None

    rt.mark_inbound_mint_success()
    rt.mark_node_address_push(42)
    state = rt.get_bolt12_runtime_state()
    assert state.last_inbound_mint_at is not None
    assert state.last_inbound_error is None  # cleared on success
    assert state.last_inbound_error_at is None  # also cleared
    assert state.node_address_cache_size == 42
    assert state.node_address_last_push_accepted == 42
    assert state.node_address_last_push_at is not None

    rt.mark_inbound_error("rate_limit:global")
    state = rt.get_bolt12_runtime_state()
    assert state.last_inbound_error == "rate_limit:global"
    assert state.last_inbound_error_at is not None

    rt._reset_for_tests()


# ── Item 13: settlement subscriber ───────────────────────────


def test_settlement_subscriber_r_hash_extraction_hex_and_b64():
    """``r_hash`` may arrive as either hex (some endpoints) or base64
    (subscribe). Normalised to hex."""
    import base64

    from app.services.bolt12.settlement_subscriber import _extract_r_hash_hex

    raw = bytes.fromhex("ab" * 32)
    assert _extract_r_hash_hex({"r_hash": raw.hex()}) == "ab" * 32
    assert _extract_r_hash_hex({"r_hash": base64.b64encode(raw).decode()}) == "ab" * 32
    assert _extract_r_hash_hex({"r_hash": ""}) is None
    assert _extract_r_hash_hex({"r_hash": "junk"}) is None
    # 33-byte raw must be rejected (wrong length).
    assert _extract_r_hash_hex({"r_hash": base64.b64encode(b"\x00" * 33).decode()}) is None


@pytest.mark.asyncio
async def test_settlement_subscriber_projects_settled_onto_row(db_session, monkeypatch):
    """A SETTLED update for a known row flips status to PAID."""
    from app.services.bolt12 import settlement_subscriber as sub

    inv = await _seed_open(db_session, "ab" * 32)

    # Patch get_db_context to return *our* session in the helper.
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    await sub._project_settled(
        {
            "state": "SETTLED",
            "settle_date": 1_700_000_000,
            "r_preimage": "cd" * 32,
        },
        "ab" * 32,
    )

    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.PAID
    assert refreshed.paid_at is not None


@pytest.mark.asyncio
async def test_settlement_subscriber_idempotent_on_paid_row(db_session, monkeypatch):
    """Second projection on an already-PAID row is a no-op."""
    from contextlib import asynccontextmanager

    from app.services.bolt12 import settlement_subscriber as sub

    inv = await _seed_open(db_session, "cd" * 32)
    inv.status = Bolt12InvoiceStatus.PAID
    inv.paid_at = datetime.now(timezone.utc)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    # Should not raise / not flip anything.
    await sub._project_settled(
        {"state": "SETTLED", "settle_date": 1, "r_preimage": "ef" * 32},
        "cd" * 32,
    )

    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.PAID


# ── Item 14: retention cleanup ───────────────────────────────


@pytest.mark.asyncio
async def test_cleanup_prunes_old_terminal_invoices(db_session, monkeypatch):
    """Old PAID / EXPIRED / FAILED invoices are pruned; OPEN rows
    are preserved."""
    from contextlib import asynccontextmanager

    from app.tasks import boltz_tasks

    # Three invoices: an old PAID (should prune), an old OPEN (must
    # NOT prune — owned by reconcile), a recent PAID (must NOT prune).
    old = datetime.now(timezone.utc) - timedelta(days=200)
    recent = datetime.now(timezone.utc) - timedelta(days=5)

    old_paid = await _seed_open(db_session, "01" * 32)
    old_paid.status = Bolt12InvoiceStatus.PAID
    old_paid.created_at = old
    old_open = await _seed_open(db_session, "02" * 32)
    old_open.created_at = old  # but still OPEN
    fresh_paid = await _seed_open(db_session, "03" * 32)
    fresh_paid.status = Bolt12InvoiceStatus.PAID
    fresh_paid.created_at = recent
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    # Patch get_db_context locally inside _run_bolt12_cleanup_old_rows.
    monkeypatch.setattr("app.core.database.get_db_context", _fake_ctx)

    result = await boltz_tasks._run_bolt12_cleanup_old_rows()

    assert result["invoices_deleted"] >= 1

    remaining = (await db_session.execute(select(Bolt12Invoice.payment_hash_hex))).scalars().all()
    assert "01" * 32 not in remaining  # pruned
    assert "02" * 32 in remaining  # preserved (OPEN)
    assert "03" * 32 in remaining  # preserved (recent)


# ── Item 14 extra: preserve invoices linked to non-deleted offers ──


@pytest.mark.asyncio
async def test_cleanup_preserves_invoices_linked_to_active_offer(db_session, monkeypatch):
    """Even an old PAID invoice must NOT be pruned if its linked
    offer is still alive (``deleted_at IS NULL``). The operator
    expects to be able to scroll through history of an in-use
    offer regardless of retention age."""
    from contextlib import asynccontextmanager

    from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferStatus
    from app.tasks import boltz_tasks

    old = datetime.now(timezone.utc) - timedelta(days=200)
    api_key_id = uuid4()

    # Seed an offer + linked invreq + linked PAID invoice, all old.
    offer = Bolt12Offer(
        api_key_id=api_key_id,
        bolt12="lno1test",
        status=Bolt12OfferStatus.ACTIVE,
    )
    db_session.add(offer)
    await db_session.flush()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        offer_id=offer.id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1test",
        invreq_bolt12="lnr1test",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=1000,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1test",
        amount_msat=1000,
        payment_hash_hex="dd" * 32,
        status=Bolt12InvoiceStatus.PAID,
    )
    inv.created_at = old
    db_session.add(inv)
    await db_session.commit()

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr("app.core.database.get_db_context", _fake_ctx)
    await boltz_tasks._run_bolt12_cleanup_old_rows()

    remaining = (await db_session.execute(select(Bolt12Invoice.payment_hash_hex))).scalars().all()
    assert "dd" * 32 in remaining  # preserved: offer still ACTIVE


# ── Item 15: _refetch_and_replay helper ──────────────────────


@pytest.mark.asyncio
async def test_refetch_and_replay_returns_none_when_no_prior_row(db_session):
    from app.services.bolt12.responder import _refetch_and_replay

    ctx = MagicMock()
    ctx.recv_id = "test_recv"

    replay = await _refetch_and_replay(
        db_session,
        api_key_id=uuid4(),
        invreq_metadata_hex="ff" * 16,
        ctx=ctx,
    )
    assert replay is None


@pytest.mark.asyncio
async def test_refetch_and_replay_skips_expired_prior_invoice(db_session):
    """If a prior invoice exists but its row says FAILED, the
    helper returns ``None`` so the caller mints fresh. Pins
    Item 1's PAID-vs-FAILED branch through the Item 15 helper."""
    from app.services.bolt12.responder import _refetch_and_replay

    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1x",
        invreq_bolt12="lnr1x",
        status=Bolt12InvoiceRequestStatus.FAILED,
        invreq_metadata_hex="aa" * 16,
        amount_msat=500,
    )
    db_session.add(invreq)
    await db_session.flush()
    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1x",
        amount_msat=500,
        payment_hash_hex="bb" * 32,
        status=Bolt12InvoiceStatus.FAILED,  # _invoice_expired -> True
    )
    db_session.add(inv)
    await db_session.commit()

    ctx = MagicMock()
    ctx.recv_id = "test_recv"

    replay = await _refetch_and_replay(
        db_session,
        api_key_id=api_key_id,
        invreq_metadata_hex="aa" * 16,
        ctx=ctx,
    )
    assert replay is None  # FAILED → caller must mint fresh


# ── Item 1: _invoice_expired semantics ─────────────────────────


def test_invoice_expired_paid_row_is_never_expired():
    """PAID rows MUST be replayed verbatim per BOLT 12 idempotency
    (keyed on ``invreq_metadata``, replaying the same invoice lets the
    payer's CLN dedup rather than risk a double-pay from minting
    fresh). Pin so a future refactor can't flip the boolean
    unnoticed."""
    from app.services.bolt12.responder import _invoice_expired

    row = MagicMock()
    row.status = Bolt12InvoiceStatus.PAID
    row.expiry = None
    assert _invoice_expired(row) is False


def test_invoice_expired_failed_row_triggers_fresh_mint():
    from app.services.bolt12.responder import _invoice_expired

    row = MagicMock()
    row.status = Bolt12InvoiceStatus.FAILED
    row.expiry = None
    assert _invoice_expired(row) is True


def test_invoice_expired_expired_row_triggers_fresh_mint():
    from app.services.bolt12.responder import _invoice_expired

    row = MagicMock()
    row.status = Bolt12InvoiceStatus.EXPIRED
    row.expiry = None
    assert _invoice_expired(row) is True


def test_invoice_expired_open_row_with_future_expiry_replays():
    from app.services.bolt12.responder import _invoice_expired

    row = MagicMock()
    row.status = Bolt12InvoiceStatus.OPEN
    row.expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    assert _invoice_expired(row) is False


def test_invoice_expired_open_row_past_expiry_mints_fresh():
    from app.services.bolt12.responder import _invoice_expired

    row = MagicMock()
    row.status = Bolt12InvoiceStatus.OPEN
    row.expiry = datetime.now(timezone.utc) - timedelta(hours=1)
    assert _invoice_expired(row) is True


# ── Item 11: sticky-peer reconciler covers non-default offers ──


@pytest.mark.asyncio
async def test_sticky_peer_reconciler_selects_all_active_offers(monkeypatch):
    """Item 11: the reconciler now drops the ``is_default_receive``
    filter so a rotation-target offer that still receives from a
    well-known payer keeps the sticky connection."""
    from app.services.bolt12 import sticky_peer_reconciler as spr

    captured: dict = {}

    class _Result:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class _DB:
        async def execute(self, stmt):
            # Capture the compiled SQL text so we can confirm the
            # filter mentions only the status + deleted_at checks
            # (no ``is_default_receive`` predicate).
            captured["sql"] = str(stmt)
            return _Result([])

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _fake_ctx():
        yield _DB()

    monkeypatch.setattr(spr, "get_db_context", _fake_ctx)
    monkeypatch.setattr(spr, "WELL_KNOWN_PAYERS", [object()], raising=False)

    # Invoke the desired-set builder.
    desired = await spr._compute_desired_peers()
    assert isinstance(desired, tuple)
    assert "is_default_receive" not in captured["sql"]


# ── Item 13: kill switch ─────────────────────────────────────


@pytest.mark.asyncio
async def test_settlement_subscriber_reconnects_after_stream_failure(monkeypatch):
    """Item 13: stream blip → backoff → reconnect → resume from
    last seen settle_index. Verifies the supervisor never gives up
    while ``stop_event`` is unset."""
    from app.services.bolt12 import settlement_subscriber as sub

    monkeypatch.setattr(sub.settings, "bolt12_settlement_subscriber_enabled", True)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MIN_S", 0.01)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MAX_S", 0.05)

    # First call: raise to simulate stream failure.
    # Second call: return a higher settle_index then stop the loop.
    calls: list[int] = []
    stop = asyncio.Event()

    async def _flaky_stream(settle_index, stop_event):
        calls.append(settle_index)
        if len(calls) == 1:
            raise RuntimeError("simulated stream blip")
        # Successful tick: advance the index, then signal stop.
        stop.set()
        return settle_index + 5

    monkeypatch.setattr(sub, "_stream_once", _flaky_stream)

    await asyncio.wait_for(sub.run_settlement_subscriber(stop), timeout=2.0)

    assert len(calls) == 2  # one fail + one success
    # Second call resumed from settle_index = 0 (the failed call
    # didn't return a new index) — backoff scheduled the retry
    # without losing the resume point.
    assert calls[0] == 0
    assert calls[1] == 0


@pytest.mark.asyncio
async def test_settlement_subscriber_logs_exception_class_even_when_str_empty(
    monkeypatch,
    caplog,
):
    """Several httpx long-stream errors (``RemoteProtocolError``,
    ``ReadError``, etc.) raise with an empty ``str()`` representation.
    The pre-fix subscriber logged ``"stream failed ()"`` which gave
    operators no signal. The fix surfaces the exception class so
    operators see *what kind* of failure is happening, even when
    the message is blank."""
    from app.services.bolt12 import settlement_subscriber as sub

    monkeypatch.setattr(sub.settings, "bolt12_settlement_subscriber_enabled", True)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MIN_S", 0.01)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MAX_S", 0.05)

    class _EmptyStringError(RuntimeError):
        def __str__(self) -> str:  # type: ignore[override]
            return ""

    stop = asyncio.Event()
    call_count = 0

    async def _flaky(_settle_index, _stop_event):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise _EmptyStringError()
        stop.set()
        return 0

    monkeypatch.setattr(sub, "_stream_once", _flaky)

    caplog.set_level("WARNING", logger=sub.logger.name)
    await asyncio.wait_for(sub.run_settlement_subscriber(stop), timeout=2.0)

    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert warnings, "expected a WARNING log on stream failure"
    msg = warnings[0].getMessage()
    # Class name must appear so operators have a debuggable signal.
    assert "_EmptyStringError" in msg
    # And the fallback "no message" placeholder must be used in
    # place of empty parentheses.
    assert "no message" in msg


@pytest.mark.asyncio
async def test_settlement_subscriber_fires_newnym_on_transport_error(
    monkeypatch,
    caplog,
):
    """A (2026-06-11): on transport-class errors (httpx ReadError,
    RemoteProtocolError, ProxyError, etc.) the subscriber must
    fire NEWNYM and use a SHORT fixed backoff rather than letting
    the exponential ceiling kick in. Verifies:
    - NEWNYM helper was called
    - The short transport-error backoff was used (not the exp tier)
    - The log message tags the failure as ``[transport, ...]``
    """
    from app.services.bolt12 import settlement_subscriber as sub
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(sub.settings, "bolt12_settlement_subscriber_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_newnym_on_transport_error", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_transport_error_backoff_s", 0.01)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MIN_S", 0.5)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MAX_S", 10.0)

    rec._reset_throttle_for_tests()

    newnym_calls: list[bool] = []

    async def _fake_newnym():
        newnym_calls.append(True)
        return True

    monkeypatch.setattr(rec, "try_newnym_throttled", _fake_newnym)

    stop = asyncio.Event()
    call_count = 0

    async def _flaky(_settle_index, _stop_event):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # The empirically observed failure mode against onion LND.
            raise httpx.ReadError("")
        stop.set()
        return 0

    monkeypatch.setattr(sub, "_stream_once", _flaky)

    caplog.set_level("WARNING", logger=sub.logger.name)
    # Time-bound: if the code regressed and used the exponential
    # backoff (0.5 s) instead of the short transport backoff
    # (0.01 s), the second tick still arrives within 2 s — so
    # this assertion's value is in checking the *log* + NEWNYM
    # signal, not in distinguishing the timings.
    await asyncio.wait_for(sub.run_settlement_subscriber(stop), timeout=2.0)

    assert len(newnym_calls) == 1, "NEWNYM helper must fire exactly once on the transport error"
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert warnings, "expected a WARNING log"
    msg = warnings[0].getMessage()
    assert "[transport" in msg
    assert "ReadError" in msg

    rec._reset_throttle_for_tests()


@pytest.mark.asyncio
async def test_htlc_event_subscriber_logs_exception_class_even_when_str_empty(
    monkeypatch,
    caplog,
):
    """Same fix as the settlement-subscriber test: the HTLC event
    subscriber must also surface the exception class for empty-
    string stream errors so operators can diagnose the silent
    ``stream failed ()`` loop observed against onion-only LNDs."""
    from app.services.bolt12 import htlc_event_subscriber as sub

    monkeypatch.setattr(sub.settings, "bolt12_htlc_event_subscriber_enabled", True)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MIN_S", 0.01)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MAX_S", 0.05)

    class _EmptyStringError(RuntimeError):
        def __str__(self) -> str:  # type: ignore[override]
            return ""

    stop = asyncio.Event()
    call_count = 0

    async def _flaky(_stop_event):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise _EmptyStringError()
        stop.set()
        return None

    monkeypatch.setattr(sub, "_stream_once", _flaky)

    caplog.set_level("WARNING", logger=sub.logger.name)
    await asyncio.wait_for(sub.run_htlc_event_subscriber(stop), timeout=2.0)

    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert warnings, "expected a WARNING log on stream failure"
    msg = warnings[0].getMessage()
    assert "_EmptyStringError" in msg
    assert "no message" in msg


@pytest.mark.asyncio
async def test_htlc_event_subscriber_fires_newnym_on_transport_error(
    monkeypatch,
    caplog,
):
    """A (2026-06-11): mirror of the settlement test for the HTLC
    subscriber. Transport errors fire NEWNYM and use the short
    backoff."""
    from app.services.bolt12 import htlc_event_subscriber as sub
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(sub.settings, "bolt12_htlc_event_subscriber_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_newnym_on_transport_error", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_transport_error_backoff_s", 0.01)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MIN_S", 0.5)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MAX_S", 10.0)

    rec._reset_throttle_for_tests()
    newnym_calls: list[bool] = []

    async def _fake_newnym():
        newnym_calls.append(True)
        return True

    monkeypatch.setattr(rec, "try_newnym_throttled", _fake_newnym)

    stop = asyncio.Event()
    call_count = 0

    async def _flaky(_stop_event):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # Exactly the ProxyError pattern we saw on 2026-06-11.
            raise httpx.ProxyError("Proxy Server could not connect: TTL expired.")
        stop.set()
        return None

    monkeypatch.setattr(sub, "_stream_once", _flaky)

    caplog.set_level("WARNING", logger=sub.logger.name)
    await asyncio.wait_for(sub.run_htlc_event_subscriber(stop), timeout=2.0)

    assert len(newnym_calls) == 1
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    msg = warnings[0].getMessage()
    assert "[transport" in msg
    assert "ProxyError" in msg

    rec._reset_throttle_for_tests()


@pytest.mark.asyncio
async def test_subscriber_does_not_fire_newnym_on_non_transport_error(
    monkeypatch,
):
    """A (2026-06-11): non-transport errors (LND-level RuntimeErrors,
    parser bugs, etc.) must NOT fire NEWNYM — those aren't Tor's
    fault and rolling circuits would just churn for nothing. They
    should also keep the exponential backoff."""
    from app.services.bolt12 import settlement_subscriber as sub
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(sub.settings, "bolt12_settlement_subscriber_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_newnym_on_transport_error", True)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MIN_S", 0.01)
    monkeypatch.setattr(sub, "_RECONNECT_BACKOFF_MAX_S", 0.05)

    rec._reset_throttle_for_tests()
    newnym_calls: list[bool] = []

    async def _fake_newnym():
        newnym_calls.append(True)
        return True

    monkeypatch.setattr(rec, "try_newnym_throttled", _fake_newnym)

    stop = asyncio.Event()
    call_count = 0

    async def _flaky(_settle_index, _stop_event):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("LND returned a malformed envelope")
        stop.set()
        return 0

    monkeypatch.setattr(sub, "_stream_once", _flaky)
    await asyncio.wait_for(sub.run_settlement_subscriber(stop), timeout=2.0)

    assert newnym_calls == [], "non-transport errors must not roll Tor circuits"

    rec._reset_throttle_for_tests()


@pytest.mark.asyncio
async def test_lnd_keepalive_fires_newnym_after_inbound_burst_threshold(
    monkeypatch,
):
    """B (2026-06-11): when ``num_inactive_channels`` goes from
    0→positive multiple times within the burst window, the
    keepalive must fire NEWNYM (throttled via the shared helper).
    Threshold default is 2 — two transitions == burst.
    """
    from app.services import lnd_keepalive as ka
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(ka._STATE, "last_num_inactive_channels", 0)
    monkeypatch.setattr(ka._STATE, "inbound_inactivity_events", [])
    monkeypatch.setattr(ka._STATE, "inbound_burst_newnyms_total", 0)
    from app.core.config import settings as cfg

    monkeypatch.setattr(cfg, "lnd_inbound_burst_newnym_threshold", 2)
    monkeypatch.setattr(cfg, "lnd_inbound_burst_window_s", 300)

    rec._reset_throttle_for_tests()
    newnym_calls: list[bool] = []

    async def _fake_newnym():
        newnym_calls.append(True)
        return True

    monkeypatch.setattr(rec, "try_newnym_throttled", _fake_newnym)

    # Tick 1: 0→1 (transition recorded; below threshold)
    await ka._maybe_fire_inbound_burst_newnym(1)
    assert newnym_calls == []
    # Tick 2: reset to 0 (no transition; we only count 0→positive)
    await ka._maybe_fire_inbound_burst_newnym(0)
    assert newnym_calls == []
    # Tick 3: 0→2 (second transition → reaches threshold → NEWNYM)
    await ka._maybe_fire_inbound_burst_newnym(2)
    assert len(newnym_calls) == 1
    assert ka._STATE.inbound_burst_newnyms_total == 1
    # Window cleared after firing so the next burst measures fresh.
    assert ka._STATE.inbound_inactivity_events == []

    rec._reset_throttle_for_tests()


@pytest.mark.asyncio
async def test_lnd_keepalive_burst_detector_disabled_when_threshold_zero(
    monkeypatch,
):
    """B (2026-06-11): operators can disable the inbound-burst
    NEWNYM trigger by setting the threshold to 0. The detector
    must short-circuit before touching the helper."""
    from app.core.config import settings as cfg
    from app.services import lnd_keepalive as ka
    from app.services.bolt12 import subscriber_recovery as rec

    monkeypatch.setattr(ka._STATE, "last_num_inactive_channels", 0)
    monkeypatch.setattr(ka._STATE, "inbound_inactivity_events", [])
    monkeypatch.setattr(ka._STATE, "inbound_burst_newnyms_total", 0)
    monkeypatch.setattr(cfg, "lnd_inbound_burst_newnym_threshold", 0)

    rec._reset_throttle_for_tests()
    newnym_calls: list[bool] = []

    async def _fake_newnym():
        newnym_calls.append(True)
        return True

    monkeypatch.setattr(rec, "try_newnym_throttled", _fake_newnym)

    # Hammer the detector with transitions — none should fire.
    for n in (5, 0, 5, 0, 5, 0, 5):
        await ka._maybe_fire_inbound_burst_newnym(n)
    assert newnym_calls == []
    assert ka._STATE.inbound_burst_newnyms_total == 0


@pytest.mark.asyncio
async def test_settlement_subscriber_polling_mode_skips_stream_and_calls_reconcile(
    monkeypatch,
):
    """C (2026-06-11): polling mode bypasses ``_stream_once`` and
    runs ``reconcile_open_invoices`` on a tight timer. Verifies
    the stream entrypoint is NEVER called and the reconcile
    function IS called at least once before shutdown."""
    from app.services.bolt12 import settlement_subscriber as sub

    monkeypatch.setattr(sub.settings, "bolt12_settlement_subscriber_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_polling_mode_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_polling_interval_s", 1)

    stream_called = False

    async def _explode_if_called(*args, **kwargs):
        nonlocal stream_called
        stream_called = True
        raise AssertionError("polling mode must NOT touch the stream")

    monkeypatch.setattr(sub, "_stream_once", _explode_if_called)

    reconcile_calls: list[int] = []

    async def _fake_reconcile(db, lnd):
        reconcile_calls.append(1)
        # Stop after the first tick to keep the test fast.
        from app.services.bolt12.reconcile import ReconcileSummary

        return ReconcileSummary(scanned=0, paid=0, expired=0, failed=0, errored=0)

    # Patch the import target inside the polling helper.
    import app.services.bolt12.reconcile as reconcile_mod

    monkeypatch.setattr(reconcile_mod, "reconcile_open_invoices", _fake_reconcile)

    stop = asyncio.Event()

    async def _stop_after_first_call():
        # Wait briefly for the first reconcile to happen, then stop.
        for _ in range(50):
            if reconcile_calls:
                stop.set()
                return
            await asyncio.sleep(0.05)
        stop.set()

    await asyncio.gather(
        sub.run_settlement_subscriber(stop),
        _stop_after_first_call(),
    )
    assert stream_called is False
    assert reconcile_calls, "reconcile must run at least once in polling mode"


@pytest.mark.asyncio
async def test_htlc_event_subscriber_polling_mode_is_noop(monkeypatch):
    """C (2026-06-11): LND has no polling REST equivalent for
    HTLC events, so polling mode for the HTLC subscriber is an
    intentional no-op. Verify the stream entrypoint is NEVER
    touched."""
    from app.services.bolt12 import htlc_event_subscriber as sub

    monkeypatch.setattr(sub.settings, "bolt12_htlc_event_subscriber_enabled", True)
    monkeypatch.setattr(sub.settings, "bolt12_subscriber_polling_mode_enabled", True)

    stream_called = False

    async def _explode_if_called(*args, **kwargs):
        nonlocal stream_called
        stream_called = True
        raise AssertionError("polling mode must NOT touch the stream")

    monkeypatch.setattr(sub, "_stream_once", _explode_if_called)

    stop = asyncio.Event()

    async def _quick_stop():
        await asyncio.sleep(0.05)
        stop.set()

    await asyncio.gather(
        sub.run_htlc_event_subscriber(stop),
        _quick_stop(),
    )
    assert stream_called is False


@pytest.mark.asyncio
async def test_settlement_subscriber_ignores_unknown_payment_hash(db_session, monkeypatch):
    """Item 13: SETTLED events for r_hashes NOT in our DB are
    silently ignored. The subscriber sees ALL LND invoices
    (including legacy BOLT 11), and must no-op on the non-BOLT12
    ones rather than spam WARN logs."""
    from contextlib import asynccontextmanager

    from app.services.bolt12 import settlement_subscriber as sub

    @asynccontextmanager
    async def _fake_ctx():
        yield db_session

    monkeypatch.setattr(sub, "get_db_context", _fake_ctx)

    # No row in DB matching this hash. Must complete without
    # raising or mutating anything.
    unknown_hash = "ee" * 32
    await sub._project_settled(
        {"state": "SETTLED", "settle_date": 1, "r_preimage": "ff" * 32},
        unknown_hash,
    )
    # Sanity: still no rows in DB with that hash.
    found = (
        await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.payment_hash_hex == unknown_hash))
    ).scalar_one_or_none()
    assert found is None


# ── Item 9: commit-failure recovery ──────────────────────────


@pytest.mark.asyncio
async def test_reconcile_recovers_from_commit_failure(db_session, monkeypatch):
    """Item 9 spec: a commit failure on row N must roll back the
    session and let row N+1 still process. The session-state
    recovery is the load-bearing piece."""
    from app.services.bolt12.reconcile import reconcile_open_invoices

    await _seed_open(db_session, "11" * 32)
    good = await _seed_open(db_session, "22" * 32)
    good_hash = good.payment_hash_hex

    class _LndStub:
        async def lookup_invoice(self, h):
            return (
                {
                    "state": "SETTLED",
                    "settled": True,
                    "settle_date": 1_700_000_000,
                    "r_preimage": "cd" * 32,
                },
                None,
            )

    # Patch db.commit to raise once (for bad_hash's row), then
    # behave normally for the next row.
    real_commit = db_session.commit
    commits = {"count": 0}

    async def _flaky_commit():
        commits["count"] += 1
        if commits["count"] == 1:
            # Force the underlying transaction into "pending
            # rollback" state, mimicking a real commit failure.
            from sqlalchemy.exc import SQLAlchemyError

            raise SQLAlchemyError("simulated commit failure")
        return await real_commit()

    monkeypatch.setattr(db_session, "commit", _flaky_commit)

    summary = await reconcile_open_invoices(db_session, _LndStub())

    # First row errored; second row succeeded.
    assert summary.errored >= 1
    assert summary.paid >= 1
    # Good row landed PAID despite the prior failure.
    refreshed = (
        await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.payment_hash_hex == good_hash))
    ).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.PAID


# ── Item 12: /status endpoint integration ─────────────────────


@pytest.mark.asyncio
async def test_status_endpoint_surfaces_receive_side_diagnostics(monkeypatch):
    """Item 12 integration: hit ``get_bolt12_runtime_state``'s
    serialisation path after marking a mint + an error + a push.
    All six new fields should appear in the dict with the
    expected shapes (timestamps as ISO strings, counts as ints).
    Pinning here so a refactor of the endpoint's response shape
    breaks visibly."""
    from app.services.bolt12 import runtime as rt

    rt._reset_for_tests()
    rt.mark_inbound_mint_success()
    rt.mark_node_address_push(7)
    state = rt.get_bolt12_runtime_state()

    # Mint timestamp populated, paired error fields cleared.
    assert state.last_inbound_mint_at is not None
    assert state.last_inbound_error is None
    assert state.last_inbound_error_at is None

    # Push count surfaces as BOTH legacy ``cache_size`` and the
    # operationally-precise ``last_push_accepted``.
    assert state.node_address_cache_size == 7
    assert state.node_address_last_push_accepted == 7
    assert state.node_address_last_push_at is not None

    # Now an error after success: timestamp updates, error appears.
    rt.mark_inbound_error("lnd_mint_failed")
    state = rt.get_bolt12_runtime_state()
    assert state.last_inbound_error == "lnd_mint_failed"
    assert state.last_inbound_error_at is not None
    # Prior mint_at still preserved — error doesn't unset success.
    assert state.last_inbound_mint_at is not None

    rt._reset_for_tests()


# ── Item 8: concurrent-mint semaphore ────────────────────────


def _make_inbound_message(recv_id: str = "r1"):
    from app.services.bolt12_gateway.types import InboundMessage

    return InboundMessage(
        recv_id=recv_id,
        payload_tlv_type=64,
        payload=b"payload",
        reply_path=b"reply_path_bytes_padding_for_realism",
        received_at_ms=0,
        inbound_context=b"ctx",
    )


@pytest.mark.asyncio
async def test_inbound_mint_semaphore_caps_concurrency(monkeypatch):
    """Item 8: with cap=2 and 5 concurrent invreqs, at most 2 are
    in the responder call at once; the rest queue at the
    semaphore. Verifies load-shedding correctness, not just
    rate-shedding."""
    from contextlib import asynccontextmanager

    from app.core.config import settings as cfg
    from app.services.bolt12.orchestrator import Bolt12Service

    monkeypatch.setattr(cfg, "bolt12_inbound_max_concurrent_mints", 2)
    monkeypatch.setattr(cfg, "bolt12_inbound_mint_acquire_timeout_s", 5.0)

    # The success path now writes a wire-send confirmation audit
    # row (Telemetry #6). Stub get_db_context so the 5 concurrent
    # fires don't each hit a real DB session.
    @asynccontextmanager
    async def _noop_ctx():
        yield MagicMock()

    monkeypatch.setattr("app.core.database.get_db_context", _noop_ctx)

    in_flight = {"current": 0, "peak": 0}
    release = asyncio.Event()

    async def _slow_responder(ctx):
        in_flight["current"] += 1
        in_flight["peak"] = max(in_flight["peak"], in_flight["current"])
        await release.wait()
        in_flight["current"] -= 1
        return b"\x00\x01\x02"  # opaque non-None reply

    fake_gateway = MagicMock()
    fake_gateway.send_onion_message = AsyncMock()
    svc = Bolt12Service(fake_gateway, invoice_responder=_slow_responder)

    async def _fire():
        msg = _make_inbound_message(recv_id=f"r{uuid4().hex[:8]}")
        await svc._handle_inbound_invreq(msg)

    # Fire 5 concurrently; let them race to enter the responder.
    tasks = [asyncio.create_task(_fire()) for _ in range(5)]
    # Brief settle so each task makes it past the semaphore acquire.
    await asyncio.sleep(0.05)
    # Peak concurrency must respect the cap of 2.
    assert in_flight["peak"] <= 2
    # Let all of them drain.
    release.set()
    await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_inbound_mint_semaphore_acquire_timeout_drops_invreq(monkeypatch):
    """Item 8: when the acquire times out, the
    ``inbound_concurrent_mint_throttled_total`` counter bumps and
    the responder is never invoked."""
    from app.core.config import settings as cfg
    from app.services.bolt12.orchestrator import Bolt12Service

    monkeypatch.setattr(cfg, "bolt12_inbound_max_concurrent_mints", 1)
    monkeypatch.setattr(cfg, "bolt12_inbound_mint_acquire_timeout_s", 0.05)

    block = asyncio.Event()
    responder_calls = {"n": 0}

    async def _blocking_responder(ctx):
        responder_calls["n"] += 1
        await block.wait()
        return b"\x00"

    fake_gateway = MagicMock()
    fake_gateway.send_onion_message = AsyncMock()
    svc = Bolt12Service(fake_gateway, invoice_responder=_blocking_responder)

    msg1 = _make_inbound_message(recv_id="r1")
    msg2 = _make_inbound_message(recv_id="r2")

    # First invreq: enters responder and holds the semaphore.
    t1 = asyncio.create_task(svc._handle_inbound_invreq(msg1))
    await asyncio.sleep(0.01)  # let it grab the semaphore
    # Second invreq: must time out at the semaphore (~50ms).
    await asyncio.wait_for(svc._handle_inbound_invreq(msg2), timeout=2.0)

    # Counter bumped under the concurrent-mint-throttle metric name;
    # responder NOT called for msg2.
    assert svc.metrics.inbound_concurrent_mint_throttled_total == 1
    assert responder_calls["n"] == 1  # only msg1

    # Drain the first invreq cleanly.
    block.set()
    await asyncio.wait_for(t1, timeout=2.0)


# ── Item 15: cancel_invoice contract on LNDService ────────────


@pytest.mark.asyncio
async def test_cancel_invoice_method_exists_with_correct_shape():
    """Item 15: ``LNDService.cancel_invoice`` returns
    ``(bool, str | None)`` and validates the r_hash hex input.
    Smoke-tests the method's surface — the live LND call is
    exercised by the responder integration tests via patch."""
    from app.services.lnd_service import LNDService

    svc = LNDService()
    # Invalid hex must be rejected with a clear error and never
    # touch the network.
    ok, err = await svc.cancel_invoice("not-a-hex-string")
    assert ok is False
    assert err is not None and "invalid" in err.lower()
