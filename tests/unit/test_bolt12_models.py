# SPDX-License-Identifier: MIT
"""Unit tests for BOLT 12 SQLAlchemy models.

Verifies basic round-trip persistence under the SQLite-backed test
fixture and that the cross-table FKs / enums behave as declared.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferStatus


@pytest.mark.asyncio
async def test_offer_round_trip(db_session) -> None:
    api_key_id = uuid4()
    offer = Bolt12Offer(
        api_key_id=api_key_id,
        bolt12="lno1minimal",
        description="coffee",
        amount_msat=2500,
        currency="BTC",
        issuer="alice@example.com",
        issuer_id_hex="02" + "11" * 32,
    )
    db_session.add(offer)
    await db_session.commit()

    row = (await db_session.execute(select(Bolt12Offer).where(Bolt12Offer.bolt12 == "lno1minimal"))).scalar_one()

    assert row.api_key_id == api_key_id
    assert row.amount_msat == 2500
    assert row.status is Bolt12OfferStatus.ACTIVE
    assert row.deleted_at is None
    assert row.created_at is not None


@pytest.mark.asyncio
async def test_offer_unique_bolt12(db_session) -> None:
    api_key_id = uuid4()
    db_session.add(Bolt12Offer(api_key_id=api_key_id, bolt12="lno1dup"))
    await db_session.commit()

    db_session.add(Bolt12Offer(api_key_id=api_key_id, bolt12="lno1dup"))
    with pytest.raises(Exception):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_invreq_links_to_offer(db_session) -> None:
    api_key_id = uuid4()
    offer = Bolt12Offer(api_key_id=api_key_id, bolt12="lno1abc")
    db_session.add(offer)
    await db_session.commit()
    await db_session.refresh(offer)

    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        offer_id=offer.id,
        direction=Bolt12Direction.OUTBOUND,
        offer_bolt12="lno1abc",
        invreq_bolt12="lnr1xyz",
        amount_msat=1500,
        payer_id_hex="03" + "22" * 32,
    )
    db_session.add(invreq)
    await db_session.commit()
    await db_session.refresh(invreq)

    assert invreq.status is Bolt12InvoiceRequestStatus.PENDING
    assert invreq.offer_id == offer.id


@pytest.mark.asyncio
async def test_inbound_invreq_allows_null_offer_id(db_session) -> None:
    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        offer_id=None,
        direction=Bolt12Direction.INBOUND,
        offer_bolt12="lno1unknown",
        invreq_bolt12="lnr1unknown",
    )
    db_session.add(invreq)
    await db_session.commit()
    await db_session.refresh(invreq)

    assert invreq.offer_id is None
    assert invreq.direction is Bolt12Direction.INBOUND


@pytest.mark.asyncio
async def test_invoice_round_trip(db_session) -> None:
    api_key_id = uuid4()
    invreq = Bolt12InvoiceRequest(
        api_key_id=api_key_id,
        offer_id=None,
        direction=Bolt12Direction.OUTBOUND,
        offer_bolt12="lno1abc",
        invreq_bolt12="lnr1abc",
    )
    db_session.add(invreq)
    await db_session.commit()
    await db_session.refresh(invreq)

    invoice = Bolt12Invoice(
        api_key_id=api_key_id,
        invoice_request_id=invreq.id,
        direction=Bolt12Direction.OUTBOUND,
        invoice_bolt12="lni1abc",
        amount_msat=1500,
        payment_hash_hex="aa" * 32,
        node_id_hex="02" + "33" * 32,
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(invoice)
    await db_session.commit()
    await db_session.refresh(invoice)

    assert invoice.status is Bolt12InvoiceStatus.OPEN
    assert invoice.invoice_request_id == invreq.id
    assert invoice.paid_at is None
