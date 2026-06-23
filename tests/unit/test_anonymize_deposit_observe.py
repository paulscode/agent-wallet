# SPDX-License-Identifier: MIT
"""BOLT 12 deposit settlement observation helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceRequest,
    Bolt12InvoiceRequestStatus,
    Bolt12InvoiceStatus,
)
from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferSource
from app.services.anonymize.deposit_observe import (
    find_paid_inbound_bolt12_invoice_for_session,
)


async def _seed_offer(db, *, api_key_id, amount_msat: int = 250_000_000):
    """Insert a Bolt12Offer the helper can join against."""
    row = Bolt12Offer(
        api_key_id=api_key_id,
        bolt12="lno1seedoffer",
        amount_msat=amount_msat,
        source=Bolt12OfferSource.ISSUED,
        issuer_id_hex="02" + "00" * 32,
    )
    db.add(row)
    await db.flush()
    await db.refresh(row)
    return row


async def _seed_inbound_invoice(
    db,
    *,
    offer_id,
    api_key_id,
    status: Bolt12InvoiceStatus,
    paid_at: datetime | None = None,
):
    """Insert a paired Bolt12InvoiceRequest + Bolt12Invoice row in
    the INBOUND direction."""
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        offer_id=offer_id,
        direction=Bolt12Direction.INBOUND,
        invreq_bolt12="lnr1seedreq",
        status=Bolt12InvoiceRequestStatus.INVOICE_SENT,
    )
    db.add(invreq)
    await db.flush()

    inv = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.INBOUND,
        invoice_bolt12="lni1seedinvoice",
        amount_msat=250_000_000,
        payment_hash_hex="aa" * 32,
        node_id_hex="02" + "00" * 32,
        status=status,
        paid_at=paid_at,
    )
    db.add(inv)
    await db.flush()
    await db.refresh(inv)
    return inv


@pytest.fixture
async def api_key_id(db_session):
    """A persisted API key UUID for FK satisfaction."""
    from app.models.api_key import APIKey

    row = APIKey(
        id=uuid4(),
        name="bolt12-observe-test",
        key_hash="deadbeef" * 8,
        is_admin=True,
        is_active=True,
    )
    db_session.add(row)
    await db_session.commit()
    return row.id


@pytest.mark.asyncio
async def test_returns_paid_at_for_settled_inbound_invoice(
    db_session,
    api_key_id,
) -> None:
    """Happy path — joined paid invoice surfaces its ``paid_at``."""
    offer = await _seed_offer(db_session, api_key_id=api_key_id)
    paid_at = datetime.now(timezone.utc)
    await _seed_inbound_invoice(
        db_session,
        offer_id=offer.id,
        api_key_id=api_key_id,
        status=Bolt12InvoiceStatus.PAID,
        paid_at=paid_at,
    )

    pj = {"source": {"deposit_offer_id": str(offer.id)}}
    result_paid_at, err = await find_paid_inbound_bolt12_invoice_for_session(
        db_session,
        session_pipeline_json=pj,
    )
    assert err is None
    assert result_paid_at is not None
    # SQLite (the test backend) strips tz on round-trip; normalise
    # before comparing so the assertion is portable across postgres
    # + sqlite.
    expected_naive = paid_at.replace(tzinfo=None)
    observed_naive = result_paid_at.replace(tzinfo=None)
    assert observed_naive == expected_naive


@pytest.mark.asyncio
async def test_returns_none_when_invoice_is_open(
    db_session,
    api_key_id,
) -> None:
    """An OPEN inbound invoice (depositor's wallet has invreq'd but
    hasn't paid) yields no settlement signal yet."""
    offer = await _seed_offer(db_session, api_key_id=api_key_id)
    await _seed_inbound_invoice(
        db_session,
        offer_id=offer.id,
        api_key_id=api_key_id,
        status=Bolt12InvoiceStatus.OPEN,
        paid_at=None,
    )

    pj = {"source": {"deposit_offer_id": str(offer.id)}}
    result_paid_at, err = await find_paid_inbound_bolt12_invoice_for_session(
        db_session,
        session_pipeline_json=pj,
    )
    assert err is None
    assert result_paid_at is None


@pytest.mark.asyncio
async def test_returns_none_when_no_invoice_yet(
    db_session,
    api_key_id,
) -> None:
    """The offer is bound but the depositor hasn't even invreq'd
    yet — no Bolt12Invoice row exists."""
    offer = await _seed_offer(db_session, api_key_id=api_key_id)

    pj = {"source": {"deposit_offer_id": str(offer.id)}}
    result_paid_at, err = await find_paid_inbound_bolt12_invoice_for_session(
        db_session,
        session_pipeline_json=pj,
    )
    assert err is None
    assert result_paid_at is None


@pytest.mark.asyncio
async def test_returns_none_when_offer_id_missing(db_session) -> None:
    """A session without a bound ``deposit_offer_id`` returns
    ``(None, None)`` — the observer falls back to time-based logic."""
    pj = {"source": {"deposit_method": "bolt11"}}
    result_paid_at, err = await find_paid_inbound_bolt12_invoice_for_session(
        db_session,
        session_pipeline_json=pj,
    )
    assert result_paid_at is None
    assert err is None


@pytest.mark.asyncio
async def test_returns_error_on_malformed_offer_id(db_session) -> None:
    pj = {"source": {"deposit_offer_id": "not-a-uuid"}}
    result_paid_at, err = await find_paid_inbound_bolt12_invoice_for_session(
        db_session,
        session_pipeline_json=pj,
    )
    assert result_paid_at is None
    assert err is not None
    assert "UUID" in err


@pytest.mark.asyncio
async def test_returns_none_on_no_pipeline_json(db_session) -> None:
    result_paid_at, err = await find_paid_inbound_bolt12_invoice_for_session(
        db_session,
        session_pipeline_json=None,
    )
    assert result_paid_at is None
    assert err is not None  # "no pipeline_json"
