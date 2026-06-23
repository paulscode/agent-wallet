# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.reconcile``."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.core.encryption import decrypt_field
from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceRequest,
    Bolt12InvoiceRequestStatus,
    Bolt12InvoiceStatus,
)
from app.services.bolt12.reconcile import reconcile_open_invoices

_HASH = "aa" * 32


@pytest.fixture
def fake_lnd():
    """LNDService stub with ``lookup_invoice`` + ``lookup_payment`` mocked.

    Inbound BOLT 12 rows reconcile via ``lookup_invoice``; outbound
    (J2) rows reconcile via ``lookup_payment``. Both are needed so
    the reconciler can branch on direction.
    """

    class _Stub:
        def __init__(self) -> None:
            self.lookup_invoice = AsyncMock()
            self.lookup_payment = AsyncMock()

    return _Stub()


async def _seed_open_invoice(
    db_session,
    *,
    payment_hash_hex: str = _HASH,
    expiry: datetime | None = None,
    amount_msat: int = 1500,
) -> Bolt12Invoice:
    invreq = Bolt12InvoiceRequest(
        api_key_id=uuid4(),
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
        amount_msat=amount_msat,
    )
    db_session.add(invreq)
    await db_session.flush()
    invoice = Bolt12Invoice(
        api_key_id=invreq.api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=amount_msat,
        payment_hash_hex=payment_hash_hex,
        status=Bolt12InvoiceStatus.OPEN,
        expiry=expiry,
    )
    db_session.add(invoice)
    await db_session.commit()
    await db_session.refresh(invoice)
    return invoice


@pytest.mark.asyncio
async def test_reconcile_settled_invoice_flips_to_paid(db_session, fake_lnd):
    inv = await _seed_open_invoice(db_session)
    settle_ts = 1_700_000_000
    fake_lnd.lookup_invoice.return_value = (
        {"state": "SETTLED", "settled": True, "settle_date": settle_ts, "r_preimage": "cd" * 32},
        None,
    )

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary == summary.__class__(scanned=1, paid=1, expired=0, failed=0, errored=0)
    fake_lnd.lookup_invoice.assert_awaited_once_with(_HASH)

    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.PAID
    assert refreshed.paid_at == datetime.fromtimestamp(settle_ts, tz=timezone.utc)
    assert refreshed.encrypted_preimage is not None
    assert decrypt_field(refreshed.encrypted_preimage) == "cd" * 32


@pytest.mark.asyncio
async def test_reconcile_canceled_invoice_flips_to_expired(db_session, fake_lnd):
    inv = await _seed_open_invoice(db_session)
    fake_lnd.lookup_invoice.return_value = (
        {"state": "CANCELED", "settled": False, "settle_date": 0},
        None,
    )

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary.expired == 1
    assert summary.paid == 0
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.EXPIRED


@pytest.mark.asyncio
async def test_reconcile_lnd_expired_state_flips_to_expired(db_session, fake_lnd):
    """LND ≥ 0.18 reports `state="EXPIRED"` once its expiry fires."""
    inv = await _seed_open_invoice(db_session)
    fake_lnd.lookup_invoice.return_value = (
        {"state": "EXPIRED", "settled": False, "settle_date": 0},
        None,
    )

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary.expired == 1
    assert summary.paid == 0
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.EXPIRED
    assert refreshed.error_message == "LND invoice expired"


@pytest.mark.asyncio
async def test_reconcile_open_past_expiry_flips_to_expired(db_session, fake_lnd):
    expired_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    inv = await _seed_open_invoice(db_session, expiry=expired_at)
    fake_lnd.lookup_invoice.return_value = (
        {"state": "OPEN", "settled": False, "settle_date": 0},
        None,
    )

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary.expired == 1
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.EXPIRED


@pytest.mark.asyncio
async def test_reconcile_open_future_expiry_remains_open(db_session, fake_lnd):
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    inv = await _seed_open_invoice(db_session, expiry=future)
    fake_lnd.lookup_invoice.return_value = (
        {"state": "OPEN", "settled": False, "settle_date": 0},
        None,
    )

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary == summary.__class__(scanned=1, paid=0, expired=0, failed=0, errored=0)
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.OPEN


@pytest.mark.asyncio
async def test_reconcile_lnd_error_skips_row(db_session, fake_lnd):
    inv = await _seed_open_invoice(db_session)
    fake_lnd.lookup_invoice.return_value = (None, "404 Not Found")

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary == summary.__class__(scanned=1, paid=0, expired=0, failed=0, errored=0)
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.OPEN


@pytest.mark.asyncio
async def test_reconcile_is_idempotent(db_session, fake_lnd):
    """Running twice on a settled row produces no extra mutations."""
    await _seed_open_invoice(db_session)
    fake_lnd.lookup_invoice.return_value = (
        {"state": "SETTLED", "settled": True, "settle_date": 1_700_000_000, "r_preimage": "cd" * 32},
        None,
    )

    s1 = await reconcile_open_invoices(db_session, fake_lnd)
    assert s1.paid == 1

    # Second pass: row is no longer OPEN, so it isn't selected.
    fake_lnd.lookup_invoice.reset_mock()
    s2 = await reconcile_open_invoices(db_session, fake_lnd)
    assert s2 == s2.__class__(scanned=0, paid=0, expired=0, failed=0, errored=0)
    fake_lnd.lookup_invoice.assert_not_awaited()


@pytest.mark.asyncio
async def test_reconcile_accepts_base64_preimage(db_session, fake_lnd):
    inv = await _seed_open_invoice(db_session)
    # 32-byte preimage as base64.
    import base64

    raw = bytes.fromhex("ab" * 32)
    b64 = base64.b64encode(raw).decode()
    fake_lnd.lookup_invoice.return_value = (
        {"state": "SETTLED", "settled": True, "settle_date": 1, "r_preimage": b64},
        None,
    )

    await reconcile_open_invoices(db_session, fake_lnd)

    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.encrypted_preimage is not None
    assert decrypt_field(refreshed.encrypted_preimage) == "ab" * 32


@pytest.mark.asyncio
async def test_reconcile_respects_batch_limit(db_session, fake_lnd):
    for i in range(5):
        await _seed_open_invoice(db_session, payment_hash_hex=f"{i:02x}" + "00" * 31)
    fake_lnd.lookup_invoice.return_value = (
        {"state": "OPEN", "settled": False, "settle_date": 0},
        None,
    )

    summary = await reconcile_open_invoices(db_session, fake_lnd, batch=2)

    assert summary.scanned == 2


# ── J2 outbound reconciliation ─────────────────────────────────────


async def _seed_open_outbound_invoice(
    db_session,
    *,
    payment_hash_hex: str = "ee" * 32,
    amount_msat: int = 1500,
) -> Bolt12Invoice:
    """Seed an OPEN outbound row mirroring what ``_perform_pay_offer``
    would persist mid-settlement."""
    invreq = Bolt12InvoiceRequest(
        api_key_id=uuid4(),
        direction=Bolt12Direction.OUTBOUND,
        offer_bolt12="lno1placeholder",
        invreq_bolt12="lnr1placeholder",
        status=Bolt12InvoiceRequestStatus.INVOICE_RECEIVED,
        amount_msat=amount_msat,
    )
    db_session.add(invreq)
    await db_session.flush()
    invoice = Bolt12Invoice(
        api_key_id=invreq.api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.OUTBOUND,
        invoice_bolt12="lni1placeholder",
        amount_msat=amount_msat,
        payment_hash_hex=payment_hash_hex,
        status=Bolt12InvoiceStatus.OPEN,
    )
    db_session.add(invoice)
    await db_session.commit()
    await db_session.refresh(invoice)
    return invoice


@pytest.mark.asyncio
async def test_reconcile_outbound_succeeded_flips_to_paid(
    db_session,
    fake_lnd,
):
    inv = await _seed_open_outbound_invoice(db_session)
    fake_lnd.lookup_payment.return_value = (
        {
            "status": "SUCCEEDED",
            "payment_hash": "ee" * 32,
            "fee_sat": 5,
            "payment_preimage": "ff" * 32,
            "value_sat": 1500,
        },
        None,
    )

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary == summary.__class__(
        scanned=1,
        paid=1,
        expired=0,
        failed=0,
        errored=0,
    )
    # OUTBOUND rows MUST NOT call lookup_invoice (no LND-minted row).
    fake_lnd.lookup_invoice.assert_not_awaited()
    fake_lnd.lookup_payment.assert_awaited_once_with("ee" * 32)

    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.PAID
    assert refreshed.paid_at is not None
    assert refreshed.encrypted_preimage is not None
    assert decrypt_field(refreshed.encrypted_preimage) == "ff" * 32


@pytest.mark.asyncio
async def test_reconcile_outbound_failed_flips_to_failed(
    db_session,
    fake_lnd,
):
    inv = await _seed_open_outbound_invoice(db_session)
    fake_lnd.lookup_payment.return_value = (
        {
            "status": "FAILED",
            "payment_hash": "ee" * 32,
            "fee_sat": 0,
            "payment_preimage": "",
            "value_sat": 0,
        },
        None,
    )

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary.failed == 1
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.FAILED
    assert refreshed.error_message  # populated with terminal-failure note


@pytest.mark.asyncio
async def test_reconcile_outbound_in_flight_leaves_row_open(
    db_session,
    fake_lnd,
):
    """An IN_FLIGHT payment is not yet terminal; reconciliation must
    leave the row OPEN so the next pass catches up."""
    inv = await _seed_open_outbound_invoice(db_session)
    fake_lnd.lookup_payment.return_value = (
        {
            "status": "IN_FLIGHT",
            "payment_hash": "ee" * 32,
            "fee_sat": 0,
            "payment_preimage": "",
            "value_sat": 1500,
        },
        None,
    )

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary.paid == 0
    assert summary.failed == 0
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.OPEN


@pytest.mark.asyncio
async def test_reconcile_outbound_lnd_error_skips_row(
    db_session,
    fake_lnd,
):
    inv = await _seed_open_outbound_invoice(db_session)
    fake_lnd.lookup_payment.return_value = (None, "lnd transient error")

    summary = await reconcile_open_invoices(db_session, fake_lnd)

    assert summary == summary.__class__(
        scanned=1,
        paid=0,
        expired=0,
        failed=0,
        errored=0,
    )
    refreshed = (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.id == inv.id))).scalar_one()
    assert refreshed.status == Bolt12InvoiceStatus.OPEN
