# SPDX-License-Identifier: MIT
"""BOLT 12 inbound ``invoice_request`` responder tests.

Calls ``make_invreq_responder()`` directly with a session factory
backed by the conftest in-memory SQLite engine, and a mocked
``lnd_service.add_blinded_invoice``. Exercises:

* Happy path: invreq for an active offer mints a signed invoice and
  persists ``Bolt12InvoiceRequest`` (INBOUND, INVOICE_SENT) +
  ``Bolt12Invoice`` (INBOUND, OPEN).
* Reject paths (return ``None``): unknown issuer, disabled offer,
  bad signature, malformed bytes, amount mismatch, expired offer,
  LND failure, quantity-cap violation.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import settings
from app.core.encryption import encrypt_field
from app.models.bolt12_invoice import (
    Bolt12Direction,
    Bolt12Invoice,
    Bolt12InvoiceRequest,
    Bolt12InvoiceRequestStatus,
    Bolt12InvoiceStatus,
)
from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferStatus
from app.services.bolt12 import (
    Bolt12Codec,
    Bolt12String,
    CoincurveSigner,
    InboundInvreqContext,
    Invoice,
    InvoiceRequest,
    Offer,
    sign_invoice_request,
)
from app.services.bolt12 import decode as decode_bolt12
from app.services.bolt12.chain_hash import REGTEST_CHAIN_HASH
from app.services.bolt12.responder import make_invreq_responder
from app.services.bolt12.tlv import (
    decode_stream as tlv_decode_stream,
)
from app.services.bolt12.tlv import (
    encode_stream as tlv_encode_stream,
)

_DEFAULT_AMOUNT = 1500
_PAYMENT_HASH = "11" * 32  # 32-byte hex placeholder

# Realistic-ish LND blinded_paths fixture: one path, one hop.
# All binary fields are hex (the encoder accepts hex *or* base64).
_LND_BLINDED_PATHS_FIXTURE = [
    {
        "blinded_path": {
            "introduction_node": "02" + "33" * 32,
            "blinding_point": "03" + "44" * 32,
            "blinded_hops": [
                {
                    "blinded_node": "02" + "55" * 32,
                    "encrypted_data": "de" * 16,
                },
            ],
        },
        "base_fee_msat": 1000,
        "proportional_fee_rate": 100,
        "total_cltv_delta": 144,
        "htlc_min_msat": "1",
        "htlc_max_msat": "100000000",
        "features": "",
    },
]


@pytest.fixture
def session_factory_for(db_engine):
    """Build a SessionFactory bound to the conftest test engine."""
    sm = async_sessionmaker(db_engine, expire_on_commit=False)

    @asynccontextmanager
    async def _factory():
        async with sm() as session:
            try:
                yield session
            finally:
                await session.close()

    return _factory


@pytest.fixture
def mock_lnd(monkeypatch):
    """Patch ``lnd_service.add_blinded_invoice`` to a deterministic stub."""
    from app.services.bolt12 import responder as responder_mod

    mock = AsyncMock(
        return_value=(
            {
                "r_hash": _PAYMENT_HASH,
                "payment_request": "lnbc...",
                "add_index": "1",
                "payment_addr": "ab" * 32,
                "blinded_paths": _LND_BLINDED_PATHS_FIXTURE,
            },
            None,
        )
    )
    monkeypatch.setattr(responder_mod.lnd_service, "add_blinded_invoice", mock)
    return mock


async def _seed_offer(
    db_session,
    *,
    issuer_signer: CoincurveSigner,
    amount: int | None = _DEFAULT_AMOUNT,
    description: str = "responder-test",
    status: Bolt12OfferStatus = Bolt12OfferStatus.ACTIVE,
    quantity_max: int | None = None,
    absolute_expiry: datetime | None = None,
) -> Bolt12Offer:
    """Insert a wallet-issued offer + return the row."""
    offer_obj = Offer(
        chains=(REGTEST_CHAIN_HASH,),
        description=description,
        amount=amount,
        issuer_id=issuer_signer.public_key,
        metadata=b"\x01" * 16,
        quantity_max=quantity_max,
        absolute_expiry=int(absolute_expiry.timestamp()) if absolute_expiry is not None else None,
    )
    bolt12 = Bolt12Codec.encode(offer_obj.to_bolt12_string())
    row = Bolt12Offer(
        api_key_id=uuid4(),
        bolt12=bolt12,
        description=description,
        amount_msat=amount,
        issuer_id_hex=issuer_signer.public_key.hex(),
        status=status,
        quantity_max=quantity_max,
        absolute_expiry=absolute_expiry,
        encrypted_metadata=encrypt_field(issuer_signer.secret.hex()),
    )
    db_session.add(row)
    await db_session.commit()
    await db_session.refresh(row)
    return row


def _build_signed_invreq_bytes(
    offer_row: Bolt12Offer,
    *,
    payer: CoincurveSigner | None = None,
    amount_msat: int | None = _DEFAULT_AMOUNT,
    quantity: int | None = None,
    payer_note: str | None = None,
) -> tuple[bytes, InvoiceRequest, CoincurveSigner]:
    """Build a real signed invreq TLV stream targeting ``offer_row``."""
    # Re-decode the wallet's encoded offer to recover the typed Offer
    # (so any edge-case round-trip differences surface).
    decoded = decode_bolt12(offer_row.bolt12)
    offer = Offer.parse(decoded)
    payer = payer or CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(
        offer,
        metadata=b"\x42" * 16,
        payer_id=payer.public_key,
        amount=amount_msat,
        quantity=quantity,
        payer_note=payer_note,
        chain=REGTEST_CHAIN_HASH,
    )
    signed = sign_invoice_request(invreq, payer)
    return tlv_encode_stream(signed.to_records()), signed, payer


def _make_ctx(payload: bytes) -> InboundInvreqContext:
    return InboundInvreqContext(
        invreq_payload=payload,
        reply_path=b"\xaa" * 32,
        inbound_context=b"\xbb" * 16,
        recv_id="test-recv-1",
    )


# ── happy path ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_responder_mints_signed_invoice_for_active_offer(session_factory_for, db_session, mock_lnd) -> None:
    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _signed_invreq, _payer = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))

    assert out is not None and isinstance(out, bytes)
    # Returned bytes are TLV-encoded; parse + validate.
    invoice = Invoice.parse(Bolt12String(hrp="lni", records=tlv_decode_stream(out)))
    assert invoice.amount == _DEFAULT_AMOUNT
    assert invoice.payment_hash is not None
    assert invoice.payment_hash.hex() == _PAYMENT_HASH
    assert invoice.node_id == issuer.public_key
    # Blinded paths from LND were encoded into the BOLT 12 TLVs.
    assert invoice.paths is not None and len(invoice.paths) > 0
    assert invoice.blindedpay is not None and len(invoice.blindedpay) > 0
    # blinded_payinfo subtype is exactly 28 bytes when features is empty
    # (4 + 4 + 2 + 8 + 8 + 2 + 0). Single payinfo for our single path.
    assert len(invoice.blindedpay) == 28
    # The signature is valid against the issuer key.
    assert invoice.signature is not None
    from app.services.bolt12.signing import verify_bip340

    assert verify_bip340(
        pubkey33=issuer.public_key,
        message32=invoice.signature_digest(),
        signature64=invoice.signature,
    )

    # LND was called with the right amount + memo.
    mock_lnd.assert_awaited_once()
    kwargs = mock_lnd.await_args.kwargs
    assert mock_lnd.await_args.args[0] == _DEFAULT_AMOUNT
    assert kwargs.get("memo") == "responder-test"

    # DB rows persisted.
    invreq_rows = (
        (await db_session.execute(select(Bolt12InvoiceRequest).where(Bolt12InvoiceRequest.offer_id == offer_row.id)))
        .scalars()
        .all()
    )
    assert len(invreq_rows) == 1
    invreq_row = invreq_rows[0]
    assert invreq_row.direction == Bolt12Direction.INBOUND
    assert invreq_row.status == Bolt12InvoiceRequestStatus.INVOICE_SENT
    assert invreq_row.amount_msat == _DEFAULT_AMOUNT

    invoice_rows = (
        (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.invoice_request_id == invreq_row.id)))
        .scalars()
        .all()
    )
    assert len(invoice_rows) == 1
    invoice_row = invoice_rows[0]
    assert invoice_row.direction == Bolt12Direction.INBOUND
    assert invoice_row.status == Bolt12InvoiceStatus.OPEN
    assert invoice_row.amount_msat == _DEFAULT_AMOUNT
    assert invoice_row.payment_hash_hex == _PAYMENT_HASH
    assert invoice_row.node_id_hex == issuer.public_key.hex()


@pytest.mark.asyncio
async def test_responder_dedups_metadata_less_invreq(session_factory_for, db_session, mock_lnd) -> None:
    """A payer that omits ``invreq_metadata`` (spec-permitted) must still
    dedup: two byte-identical signed invreqs map to one idempotency key
    (the signature digest), so the second is an idempotent replay rather
    than a fresh LND mint."""
    from dataclasses import replace as _replace

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)

    decoded = decode_bolt12(offer_row.bolt12)
    offer = Offer.parse(decoded)
    payer = CoincurveSigner.generate()

    def _metadataless_payload() -> bytes:
        base = InvoiceRequest.from_offer(
            offer,
            metadata=b"\x42" * 16,
            payer_id=payer.public_key,
            amount=_DEFAULT_AMOUNT,
            chain=REGTEST_CHAIN_HASH,
        )
        # Omit invreq_metadata entirely, then sign over the remaining
        # (deterministic) content. Two such invreqs share a digest.
        without = _replace(base, metadata=None)
        signed = sign_invoice_request(without, payer)
        return tlv_encode_stream(signed.to_records())

    responder = make_invreq_responder(session_factory=session_factory_for)

    first = await responder(_make_ctx(_metadataless_payload()))
    second = await responder(_make_ctx(_metadataless_payload()))

    assert first is not None and second is not None
    # Only one LND mint — the second invreq replayed the first invoice.
    mock_lnd.assert_awaited_once()

    invreq_rows = (
        (await db_session.execute(select(Bolt12InvoiceRequest).where(Bolt12InvoiceRequest.offer_id == offer_row.id)))
        .scalars()
        .all()
    )
    assert len(invreq_rows) == 1
    invoice_rows = (
        (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.invoice_request_id == invreq_rows[0].id)))
        .scalars()
        .all()
    )
    assert len(invoice_rows) == 1


# ── reject paths ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_responder_drops_invreq_for_unknown_issuer(session_factory_for, mock_lnd) -> None:
    """No matching offer in the DB → silent drop."""
    issuer = CoincurveSigner.generate()  # never persisted
    # Build a fake offer row purely to satisfy the helper signature.
    fake_offer = Bolt12Offer(
        api_key_id=uuid4(),
        bolt12=Bolt12Codec.encode(
            Offer(
                chains=(REGTEST_CHAIN_HASH,),
                description="ghost",
                amount=_DEFAULT_AMOUNT,
                issuer_id=issuer.public_key,
                metadata=b"\x00" * 16,
            ).to_bolt12_string()
        ),
        issuer_id_hex=issuer.public_key.hex(),
        amount_msat=_DEFAULT_AMOUNT,
    )
    payload, _, _ = _build_signed_invreq_bytes(fake_offer)

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None
    mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_invreq_for_disabled_offer(session_factory_for, db_session, mock_lnd) -> None:
    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer, status=Bolt12OfferStatus.DISABLED)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None
    mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_rejects_invalid_invreq_signature(session_factory_for, db_session, mock_lnd) -> None:
    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)

    # Build, then strip the signature → invreq fails verify.
    decoded = decode_bolt12(offer_row.bolt12)
    offer = Offer.parse(decoded)
    payer = CoincurveSigner.generate()
    unsigned = InvoiceRequest.from_offer(
        offer,
        metadata=b"\x99" * 16,
        payer_id=payer.public_key,
        amount=_DEFAULT_AMOUNT,
        chain=REGTEST_CHAIN_HASH,
    )
    # Use a 64-byte garbage signature.
    from dataclasses import replace as _replace

    tampered = _replace(unsigned, signature=b"\x00" * 64)
    payload = tlv_encode_stream(tampered.to_records())

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None
    mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_malformed_payload(session_factory_for, mock_lnd) -> None:
    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(b"not-a-tlv-stream")) is None
    mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_rejects_invreq_amount_mismatch(session_factory_for, db_session, mock_lnd) -> None:
    """If the offer pinned an amount, invreq amount must equal it."""
    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer, amount=2000)
    # Send invreq with a different amount.
    payload, _, _ = _build_signed_invreq_bytes(offer_row, amount_msat=999)

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None
    mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_when_offer_expired(session_factory_for, db_session, mock_lnd) -> None:
    issuer = CoincurveSigner.generate()
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    offer_row = await _seed_offer(db_session, issuer_signer=issuer, absolute_expiry=past)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None
    mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_when_lnd_fails(session_factory_for, db_session, monkeypatch) -> None:
    from app.services.bolt12 import responder as responder_mod

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    monkeypatch.setattr(
        responder_mod.lnd_service,
        "add_blinded_invoice",
        AsyncMock(return_value=(None, "lnd unreachable")),
    )

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None


@pytest.mark.asyncio
async def test_responder_drops_when_lnd_returns_no_blinded_paths(session_factory_for, db_session, monkeypatch) -> None:
    """LND must return at least one blinded path; otherwise we can't
    mint a spec-compliant BOLT 12 invoice and silently drop."""
    from app.services.bolt12 import responder as responder_mod

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    monkeypatch.setattr(
        responder_mod.lnd_service,
        "add_blinded_invoice",
        AsyncMock(
            return_value=(
                {
                    "r_hash": _PAYMENT_HASH,
                    "payment_request": "lnbc...",
                    "add_index": "1",
                    "payment_addr": "ab" * 32,
                    "blinded_paths": [],
                },
                None,
            )
        ),
    )

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None


@pytest.mark.asyncio
async def test_responder_falls_back_to_num_hops_1_when_2_returns_no_paths(
    session_factory_for, db_session, monkeypatch
) -> None:
    """When LND can't build any path at the configured min_real_hops,
    the responder retries at num_hops=1 and uses that result."""
    from app.services.bolt12 import responder as responder_mod

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    empty_result = (
        {
            "r_hash": _PAYMENT_HASH,
            "payment_request": "lnbc...",
            "add_index": "1",
            "payment_addr": "ab" * 32,
            "blinded_paths": [],
        },
        None,
    )
    good_result = (
        {
            "r_hash": _PAYMENT_HASH,
            "payment_request": "lnbc...",
            "add_index": "2",
            "payment_addr": "ab" * 32,
            "blinded_paths": _LND_BLINDED_PATHS_FIXTURE,
        },
        None,
    )
    mock = AsyncMock(side_effect=[empty_result, good_result])
    monkeypatch.setattr(responder_mod.lnd_service, "add_blinded_invoice", mock)

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is not None

    # Two calls: first at the configured min_real_hops (default 2),
    # second at the 1-hop fallback.
    assert mock.await_count == 2
    first_kwargs = mock.await_args_list[0].kwargs
    second_kwargs = mock.await_args_list[1].kwargs
    assert first_kwargs["num_hops"] >= 2
    assert second_kwargs["num_hops"] == 1


@pytest.mark.asyncio
async def test_responder_rejects_quantity_over_max(session_factory_for, db_session, mock_lnd) -> None:
    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer, quantity_max=3)
    payload, _, _ = _build_signed_invreq_bytes(offer_row, quantity=4)

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None
    mock_lnd.assert_not_awaited()


# ── offer-less invreqs (J1) ──────────────────────────────────────


def _build_signed_offerless_invreq_bytes(
    *,
    payer: CoincurveSigner | None = None,
    amount_msat: int | None = _DEFAULT_AMOUNT,
    payer_note: str | None = None,
) -> tuple[bytes, InvoiceRequest, CoincurveSigner]:
    """Build a real signed invreq with an *empty* Offer (no
    ``offer_issuer_id``) — the BOLT 12 offer-less / refund flow.
    """
    payer = payer or CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(
        Offer(chains=(REGTEST_CHAIN_HASH,)),
        metadata=b"\x77" * 16,
        payer_id=payer.public_key,
        amount=amount_msat,
        payer_note=payer_note,
        chain=REGTEST_CHAIN_HASH,
    )
    signed = sign_invoice_request(invreq, payer)
    return tlv_encode_stream(signed.to_records()), signed, payer


@pytest.mark.asyncio
async def test_responder_drops_offerless_invreq_when_disabled(
    session_factory_for, db_session, mock_lnd, monkeypatch
) -> None:
    """Default policy: no offer_issuer_id ⇒ silently drop, no LND call."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_accept_offerless_invreqs", False)
    payload, _, _ = _build_signed_offerless_invreq_bytes()

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None
    mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_accepts_offerless_invreq_when_enabled(
    session_factory_for, db_session, mock_lnd, monkeypatch
) -> None:
    """With the policy flag on, offer-less invreqs mint a fresh-key
    invoice and persist with ``offer_id=None``."""
    from app.core.config import settings
    from app.dashboard import DASHBOARD_KEY_ID

    monkeypatch.setattr(settings, "bolt12_accept_offerless_invreqs", True)
    payload, signed_invreq, payer = _build_signed_offerless_invreq_bytes(
        amount_msat=4242,
        payer_note="refund please",
    )

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))

    assert out is not None and isinstance(out, bytes)
    invoice = Invoice.parse(Bolt12String(hrp="lni", records=tlv_decode_stream(out)))
    assert invoice.amount == 4242
    assert invoice.payment_hash is not None
    assert invoice.payment_hash.hex() == _PAYMENT_HASH
    # Invoice was signed by an ephemeral key — not the payer key.
    assert invoice.node_id is not None
    assert invoice.node_id != payer.public_key
    # Signature verifies against that ephemeral key.
    assert invoice.signature is not None
    from app.services.bolt12.signing import verify_bip340

    assert verify_bip340(
        pubkey33=invoice.node_id,
        message32=invoice.signature_digest(),
        signature64=invoice.signature,
    )
    # No offer_issuer_id leaked into the invoice.
    assert invoice.invreq.offer.issuer_id is None

    mock_lnd.assert_awaited_once()
    assert mock_lnd.await_args.args[0] == 4242
    # Memo falls back to the payer note when present.
    assert mock_lnd.await_args.kwargs.get("memo") == "refund please"

    # Persistence: one offer-less row attributed to the dashboard
    # sentinel, with offer_id=None.
    invreq_rows = (
        (await db_session.execute(select(Bolt12InvoiceRequest).where(Bolt12InvoiceRequest.offer_id.is_(None))))
        .scalars()
        .all()
    )
    assert len(invreq_rows) == 1
    invreq_row = invreq_rows[0]
    assert invreq_row.api_key_id == DASHBOARD_KEY_ID
    assert invreq_row.direction == Bolt12Direction.INBOUND
    assert invreq_row.status == Bolt12InvoiceRequestStatus.INVOICE_SENT
    assert invreq_row.amount_msat == 4242
    assert invreq_row.offer_bolt12 is None

    invoice_rows = (
        (await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.invoice_request_id == invreq_row.id)))
        .scalars()
        .all()
    )
    assert len(invoice_rows) == 1
    assert invoice_rows[0].direction == Bolt12Direction.INBOUND
    assert invoice_rows[0].status == Bolt12InvoiceStatus.OPEN
    assert invoice_rows[0].amount_msat == 4242


@pytest.mark.asyncio
async def test_responder_drops_offerless_invreq_without_amount(
    session_factory_for, db_session, mock_lnd, monkeypatch
) -> None:
    """Even with the flag on, offer-less invreqs must carry an
    explicit ``invreq_amount`` (BOLT 12 §"Requirements for the
    Sender")."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "bolt12_accept_offerless_invreqs", True)
    payload, _, _ = _build_signed_offerless_invreq_bytes(amount_msat=None)

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None
    mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_invreq_with_wrong_chain(session_factory_for, db_session, mock_lnd) -> None:
    """An invreq pinned to a different chain than ``bitcoin_network``
    must be dropped before any LND call.

    The wallet runs on regtest in tests; signing an invreq for the
    mainnet chain hash should silently fail-closed.
    """
    from app.services.bolt12.chain_hash import MAINNET_CHAIN_HASH

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)

    decoded = decode_bolt12(offer_row.bolt12)
    offer = Offer.parse(decoded)
    payer = CoincurveSigner.generate()
    unsigned = InvoiceRequest.from_offer(
        offer,
        metadata=b"\x55" * 16,
        payer_id=payer.public_key,
        amount=_DEFAULT_AMOUNT,
        chain=MAINNET_CHAIN_HASH,
    )
    signed = sign_invoice_request(unsigned, payer)
    payload = tlv_encode_stream(signed.to_records())

    responder = make_invreq_responder(session_factory=session_factory_for)
    assert await responder(_make_ctx(payload)) is None
    mock_lnd.assert_not_awaited()


# ── invreq_metadata idempotency ──────────────────────────────


@pytest.mark.asyncio
async def test_responder_replays_invoice_for_same_metadata(session_factory_for, db_session, mock_lnd) -> None:
    """Re-sending the same signed invreq bytes must yield the same
    invoice without a second LND mint (BOLT 12 idempotency MUST)."""
    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _signed, _payer = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)

    out1 = await responder(_make_ctx(payload))
    out2 = await responder(_make_ctx(payload))

    assert out1 is not None and out2 is not None
    # Byte-identical replay (same signed invoice TLV stream).
    assert out1 == out2
    # LND was hit exactly once \u2014 the second call replayed.
    assert mock_lnd.await_count == 1

    # Only one invreq row + one invoice row persisted.
    invreq_rows = (
        (await db_session.execute(select(Bolt12InvoiceRequest).where(Bolt12InvoiceRequest.offer_id == offer_row.id)))
        .scalars()
        .all()
    )
    assert len(invreq_rows) == 1
    assert invreq_rows[0].invreq_metadata_hex == ("42" * 16)


@pytest.mark.asyncio
async def test_responder_does_not_collide_metadata_across_keys(session_factory_for, db_session, mock_lnd) -> None:
    """Same ``invreq_metadata`` against two different tenants'
    offers must not be deduped (each api_key has its own scope)."""
    issuer1 = CoincurveSigner.generate()
    offer1 = await _seed_offer(db_session, issuer_signer=issuer1)
    issuer2 = CoincurveSigner.generate()
    offer2 = await _seed_offer(db_session, issuer_signer=issuer2)
    # Sanity: ``_seed_offer`` randomises ``api_key_id`` per call.
    assert offer1.api_key_id != offer2.api_key_id

    payload1, *_ = _build_signed_invreq_bytes(offer1)
    payload2, *_ = _build_signed_invreq_bytes(offer2)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out1 = await responder(_make_ctx(payload1))
    out2 = await responder(_make_ctx(payload2))

    assert out1 is not None and out2 is not None
    # Both LND-minted (no cross-tenant collision on metadata).
    assert mock_lnd.await_count == 2


# ── Item 1: PAID-row replay vs FAILED-row mint-fresh ─────────────


@pytest.mark.asyncio
async def test_responder_mints_fresh_after_failed_invoice(session_factory_for, db_session, mock_lnd) -> None:
    """A pre-seeded FAILED invoice for the same metadata MUST trigger
    a fresh LND mint per ``_invoice_expired``'s FAILED branch (Item 1
    Interpretation A). PAID is replay, FAILED/EXPIRED is mint-fresh."""
    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _signed, _payer = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    # First call mints normally (OPEN).
    out1 = await responder(_make_ctx(payload))
    assert out1 is not None
    assert mock_lnd.await_count == 1

    # Flip the row to FAILED — simulates the case where the prior
    # mint reached LND but the payment never landed and reconcile
    # projected a terminal failure.
    invoice = (
        await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.api_key_id == offer_row.api_key_id))
    ).scalar_one()
    invoice.status = Bolt12InvoiceStatus.FAILED
    await db_session.commit()

    # Second call with the SAME metadata must mint fresh (LND called
    # a second time), not replay the FAILED row.
    out2 = await responder(_make_ctx(payload))
    assert out2 is not None
    assert mock_lnd.await_count == 2  # fresh mint, not replayed


# ── Item 2: payer_note in success log + audit ─────────────────────


@pytest.mark.asyncio
async def test_responder_includes_payer_note_in_audit(session_factory_for, db_session, mock_lnd, caplog) -> None:
    """Per Item 2: ``payer_note`` must surface in both the INFO log
    line and the ``bolt12_invoice_minted`` audit row's ``details``."""
    import logging

    from app.models.audit_log import AuditLog

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payer_note = (
        "OCEAN lightning payout running at block 00000000000000000001545d6f6b"
        "0ad023c4ca1b7e36c5edf1a35eafe1a89234 at height 952226"
    )
    payload, _signed, _payer = _build_signed_invreq_bytes(
        offer_row,
        payer_note=payer_note,
    )

    responder = make_invreq_responder(session_factory=session_factory_for)
    with caplog.at_level(logging.INFO):
        out = await responder(_make_ctx(payload))
    assert out is not None

    # INFO log line must include the payer_note (truncated at 200).
    minted_line = next(
        (r for r in caplog.records if "minted invoice" in r.getMessage()),
        None,
    )
    assert minted_line is not None
    assert "OCEAN lightning payout" in minted_line.getMessage()
    assert "height 952226" in minted_line.getMessage()

    # Audit row's details must include the same payer_note.
    audit_row = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "bolt12_invoice_minted"))
    ).scalar_one()
    assert audit_row.details["payer_note"] == payer_note[:200]
    assert audit_row.details["payer_id_hex"] is not None


@pytest.mark.asyncio
async def test_responder_truncates_long_payer_note_in_audit(session_factory_for, db_session, mock_lnd) -> None:
    """``payer_note`` is sender-supplied free text; we truncate at
    200 chars before logging/auditing to bound storage and avoid
    enabling a peer-controlled log-line-length amplification."""
    from app.models.audit_log import AuditLog

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    long_note = "x" * 500
    payload, _signed, _payer = _build_signed_invreq_bytes(
        offer_row,
        payer_note=long_note,
    )

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None

    audit_row = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "bolt12_invoice_minted"))
    ).scalar_one()
    assert len(audit_row.details["payer_note"]) == 200


# ── Item 3: INFO-log of LND-chosen blinded-path policy ─────────


@pytest.mark.asyncio
async def test_responder_info_logs_blinded_path_policy(session_factory_for, db_session, mock_lnd, caplog) -> None:
    """Per Item 3 + 2026-06-05 diagnostic-B promotion: each blinded
    path LND chose must emit one INFO line with intro-prefix,
    real_hops, base_fee, ppm, cltv_delta, htlc_min, htlc_max.

    The line is INFO (not DEBUG) so operators running at the
    default ``log_level=info`` can see what LND advertised
    without enabling DEBUG. The Ocean-payout failure showed this
    was the only signal that would have explained CLN's
    "insufficient capacity" error, and we couldn't see it at
    DEBUG."""
    import logging

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    with caplog.at_level(logging.INFO, logger="app.services.bolt12.responder"):
        out = await responder(_make_ctx(payload))
    assert out is not None

    # Find the per-path INFO line.
    path_log = next(
        (r for r in caplog.records if "minted path" in r.getMessage() and r.levelno == logging.INFO),
        None,
    )
    assert path_log is not None, "expected per-path INFO line not emitted"
    msg = path_log.getMessage()
    # Every blinded-path policy field must appear in the per-path log.
    for field in ("intro=", "real_hops=", "base_fee=", "ppm=", "cltv_delta=", "htlc_min=", "htlc_max="):
        assert field in msg, f"DEBUG log missing field {field!r}: {msg!r}"


# ── Item 6: per-mint INFO log shows clamped-vs-advertised ────────


@pytest.mark.asyncio
async def test_responder_info_log_shows_clamped_from_advertised(
    session_factory_for,
    db_session,
    mock_lnd,
    caplog,
    monkeypatch,
) -> None:
    """When the Item-6 postprocess clamps a path's htlc_max, the
    per-mint INFO log line should show both the final value AND
    the original LND-advertised value: ``htlc_max=X (clamped from Y)``.
    Otherwise operators can't tell from the log whether a clamp
    happened or whether LND's gossip was already accurate."""
    import logging

    from app.services.bolt12 import responder as resp_mod

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    # Force postprocess to MUTATE the htlc_max on the path so the
    # log can detect "clamped from". Patch _postprocess_paths to
    # return paths annotated with ``_htlc_max_msat_advertised``
    # differing from the final value.
    async def _clamp_simulator(raw_paths, *, amount_msat):
        for p in raw_paths:
            p["_htlc_max_msat_advertised"] = int(p.get("htlc_max_msat") or 0)
            p["htlc_max_msat"] = 12_345_678  # clamped value
        return raw_paths, {"paths": []}

    monkeypatch.setattr(resp_mod, "_postprocess_paths", _clamp_simulator)

    responder = make_invreq_responder(session_factory=session_factory_for)
    with caplog.at_level(logging.INFO, logger="app.services.bolt12.responder"):
        out = await responder(_make_ctx(payload))
    assert out is not None

    path_log = next(
        (r for r in caplog.records if "minted path" in r.getMessage() and r.levelno == logging.INFO),
        None,
    )
    assert path_log is not None
    msg = path_log.getMessage()
    assert "12345678" in msg
    assert "clamped from" in msg


# ── Option B-adaptive (2026-06-08): depth fallback on breaker ───


@pytest.mark.asyncio
async def test_responder_adaptive_flips_to_alt_depth_when_all_intros_open(
    session_factory_for,
    db_session,
    monkeypatch,
) -> None:
    """When the breaker has opened every intro the primary-depth
    mint produces, the responder retries at the alternative depth
    and uses whichever set has a healthy intro. Pin the flip via:
    - Primary depth=1 → intro `aaaaa` (pre-opened in breaker).
    - Alt depth=2 → intro `bbbbb` (healthy).
    - Expect: alt result used, primary's r_hash cancelled.
    """
    from unittest.mock import AsyncMock

    from app.core.config import settings as cfg
    from app.services.bolt12 import responder as resp_mod
    from app.services.bolt12.path_postprocess import get_path_breaker

    monkeypatch.setattr(cfg, "bolt12_blinded_path_min_real_hops", 1)
    monkeypatch.setattr(cfg, "bolt12_adaptive_depth_fallback_enabled", True)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_enabled", True)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_failures_to_open", 1)

    # Pre-open the primary intro so the primary-depth mint trips
    # the adaptive check.
    breaker = get_path_breaker()
    breaker.reset_for_tests()
    breaker.record_failure("02" + "aa" * 32)

    # Force postprocess to leave paths annotated with the intros
    # we control (no real LND data here).
    # Use realistic 33-byte intro/blinding-point hex like the
    # existing fixture so encode_invoice_paths doesn't reject.
    # Each path's _intro_pubkey_hex will be re-derived by the
    # postprocess passthrough below.
    primary_path = {
        "_intro_pubkey_hex": "02" + "aa" * 32,
        "blinded_path": {
            "introduction_node": "02" + "aa" * 32,
            "blinding_point": "03" + "11" * 32,
            "blinded_hops": [
                {"blinded_node": "02" + "55" * 32, "encrypted_data": "de" * 16},
                {"blinded_node": "02" + "66" * 32, "encrypted_data": "ee" * 16},
            ],
        },
        "base_fee_msat": 1000,
        "proportional_fee_rate": 100,
        "total_cltv_delta": 40,
        "htlc_min_msat": "1",
        "htlc_max_msat": "100000000",
        "features": "",
    }
    alt_path = {
        "_intro_pubkey_hex": "02" + "bb" * 32,
        "blinded_path": {
            "introduction_node": "02" + "bb" * 32,
            "blinding_point": "03" + "22" * 32,
            "blinded_hops": [
                {"blinded_node": "02" + "77" * 32, "encrypted_data": "ff" * 16},
                {"blinded_node": "02" + "88" * 32, "encrypted_data": "aa" * 16},
                {"blinded_node": "02" + "99" * 32, "encrypted_data": "bb" * 16},
            ],
        },
        "base_fee_msat": 2000,
        "proportional_fee_rate": 200,
        "total_cltv_delta": 80,
        "htlc_min_msat": "1",
        "htlc_max_msat": "100000000",
        "features": "",
    }

    # Two LND mint calls with distinct r_hashes:
    primary_result = {
        "r_hash": "11" * 32,
        "payment_request": "lnbc...",
        "add_index": "1",
        "payment_addr": "ab" * 32,
        "blinded_paths": [primary_path],
    }
    alt_result = {
        "r_hash": "22" * 32,
        "payment_request": "lnbc...",
        "add_index": "2",
        "payment_addr": "cd" * 32,
        "blinded_paths": [alt_path],
    }
    mint_mock = AsyncMock(
        side_effect=[
            (primary_result, None),
            (alt_result, None),
        ]
    )
    monkeypatch.setattr(
        resp_mod.lnd_service,
        "add_blinded_invoice",
        mint_mock,
    )

    cancel_calls: list[str] = []

    async def _spy_cancel(h):
        cancel_calls.append(h)
        return True, None

    monkeypatch.setattr(
        resp_mod.lnd_service,
        "cancel_invoice",
        _spy_cancel,
    )

    # Skip the channel-snapshot enrichment so postprocess doesn't
    # try to reach LND for channels/edges.
    async def _passthrough_postprocess(raw_paths, *, amount_msat):
        # Leave _intro_pubkey_hex annotations intact (already set
        # on the fixture above).
        return raw_paths, {"paths": [{"intro_pubkey": p["_intro_pubkey_hex"]} for p in raw_paths]}

    monkeypatch.setattr(resp_mod, "_postprocess_paths", _passthrough_postprocess)

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None  # mint succeeded (via alt depth)

    # Both LND mints fired.
    assert mint_mock.await_count == 2
    primary_kwargs = mint_mock.await_args_list[0].kwargs
    alt_kwargs = mint_mock.await_args_list[1].kwargs
    assert primary_kwargs["num_hops"] == 1
    assert alt_kwargs["num_hops"] == 2  # alternative depth

    # The PRIMARY's r_hash was cancelled (orphan cleanup).
    assert "11" * 32 in cancel_calls

    # The invoice persisted should have the ALT r_hash.
    persisted = (
        await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.api_key_id == offer_row.api_key_id))
    ).scalar_one()
    assert persisted.payment_hash_hex == "22" * 32

    breaker.reset_for_tests()


@pytest.mark.asyncio
async def test_responder_skips_adaptive_when_setting_disabled(
    session_factory_for,
    db_session,
    monkeypatch,
) -> None:
    """When ``BOLT12_ADAPTIVE_DEPTH_FALLBACK_ENABLED=false``, the
    responder never makes a second LND mint even when every
    primary-depth intro is in the breaker's open state (which
    would otherwise trigger the flip)."""
    from unittest.mock import AsyncMock

    from app.core.config import settings as cfg
    from app.services.bolt12 import responder as resp_mod
    from app.services.bolt12.path_postprocess import get_path_breaker

    monkeypatch.setattr(cfg, "bolt12_adaptive_depth_fallback_enabled", False)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_enabled", True)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_failures_to_open", 1)
    monkeypatch.setattr(cfg, "bolt12_blinded_path_min_real_hops", 1)

    # Pre-open the primary intro. If the kill switch were not
    # honoured, the responder would attempt a second mint here.
    breaker = get_path_breaker()
    breaker.reset_for_tests()
    breaker.record_failure("02" + "aa" * 32)

    primary_path = {
        "_intro_pubkey_hex": "02" + "aa" * 32,
        "blinded_path": {
            "introduction_node": "02" + "aa" * 32,
            "blinding_point": "03" + "11" * 32,
            "blinded_hops": [
                {"blinded_node": "02" + "55" * 32, "encrypted_data": "de" * 16},
                {"blinded_node": "02" + "66" * 32, "encrypted_data": "ee" * 16},
            ],
        },
        "base_fee_msat": 1000,
        "proportional_fee_rate": 100,
        "total_cltv_delta": 40,
        "htlc_min_msat": "1",
        "htlc_max_msat": "100000000",
        "features": "",
    }
    primary_result = {
        "r_hash": "11" * 32,
        "payment_request": "lnbc...",
        "add_index": "1",
        "payment_addr": "ab" * 32,
        "blinded_paths": [primary_path],
    }
    mint_mock = AsyncMock(return_value=(primary_result, None))
    monkeypatch.setattr(
        resp_mod.lnd_service,
        "add_blinded_invoice",
        mint_mock,
    )

    cancel_mock = AsyncMock(return_value=(True, None))
    monkeypatch.setattr(
        resp_mod.lnd_service,
        "cancel_invoice",
        cancel_mock,
    )

    async def _passthrough_postprocess(raw_paths, *, amount_msat):
        return raw_paths, {"paths": [{"intro_pubkey": p["_intro_pubkey_hex"]} for p in raw_paths]}

    monkeypatch.setattr(resp_mod, "_postprocess_paths", _passthrough_postprocess)

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None

    # Only ONE mint call. The flip would have made a second one
    # if the setting kill switch weren't honoured (we proved this
    # in test_responder_adaptive_flips_to_alt_depth_when_all_intros_open
    # by sharing the same breaker-opened intro setup).
    assert mint_mock.await_count == 1
    # Nothing to cancel since we didn't flip.
    assert cancel_mock.await_count == 0

    breaker.reset_for_tests()


@pytest.mark.asyncio
async def test_offerless_responder_adaptive_flips_to_alt_depth(
    session_factory_for,
    db_session,
    monkeypatch,
) -> None:
    """The offer-less branch shares the same ``_maybe_flip_to_alt_depth``
    helper as the offer-bound branch, so the breaker-driven flip
    must trigger here too. Same shape as
    ``test_responder_adaptive_flips_to_alt_depth_when_all_intros_open``,
    swapped over to ``_build_signed_offerless_invreq_bytes``."""
    from unittest.mock import AsyncMock

    from app.core.config import settings as cfg
    from app.services.bolt12 import responder as resp_mod
    from app.services.bolt12.path_postprocess import get_path_breaker

    monkeypatch.setattr(cfg, "bolt12_accept_offerless_invreqs", True)
    monkeypatch.setattr(cfg, "bolt12_blinded_path_min_real_hops", 1)
    monkeypatch.setattr(cfg, "bolt12_adaptive_depth_fallback_enabled", True)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_enabled", True)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_failures_to_open", 1)

    breaker = get_path_breaker()
    breaker.reset_for_tests()
    breaker.record_failure("02" + "aa" * 32)

    primary_path = {
        "_intro_pubkey_hex": "02" + "aa" * 32,
        "blinded_path": {
            "introduction_node": "02" + "aa" * 32,
            "blinding_point": "03" + "11" * 32,
            "blinded_hops": [
                {"blinded_node": "02" + "55" * 32, "encrypted_data": "de" * 16},
                {"blinded_node": "02" + "66" * 32, "encrypted_data": "ee" * 16},
            ],
        },
        "base_fee_msat": 1000,
        "proportional_fee_rate": 100,
        "total_cltv_delta": 40,
        "htlc_min_msat": "1",
        "htlc_max_msat": "100000000",
        "features": "",
    }
    alt_path = {
        "_intro_pubkey_hex": "02" + "bb" * 32,
        "blinded_path": {
            "introduction_node": "02" + "bb" * 32,
            "blinding_point": "03" + "22" * 32,
            "blinded_hops": [
                {"blinded_node": "02" + "77" * 32, "encrypted_data": "ff" * 16},
                {"blinded_node": "02" + "88" * 32, "encrypted_data": "aa" * 16},
                {"blinded_node": "02" + "99" * 32, "encrypted_data": "bb" * 16},
            ],
        },
        "base_fee_msat": 2000,
        "proportional_fee_rate": 200,
        "total_cltv_delta": 80,
        "htlc_min_msat": "1",
        "htlc_max_msat": "100000000",
        "features": "",
    }
    primary_result = {
        "r_hash": "11" * 32,
        "payment_request": "lnbc...",
        "add_index": "1",
        "payment_addr": "ab" * 32,
        "blinded_paths": [primary_path],
    }
    alt_result = {
        "r_hash": "22" * 32,
        "payment_request": "lnbc...",
        "add_index": "2",
        "payment_addr": "cd" * 32,
        "blinded_paths": [alt_path],
    }
    mint_mock = AsyncMock(
        side_effect=[
            (primary_result, None),
            (alt_result, None),
        ]
    )
    monkeypatch.setattr(
        resp_mod.lnd_service,
        "add_blinded_invoice",
        mint_mock,
    )

    cancel_calls: list[str] = []

    async def _spy_cancel(h):
        cancel_calls.append(h)
        return True, None

    monkeypatch.setattr(
        resp_mod.lnd_service,
        "cancel_invoice",
        _spy_cancel,
    )

    async def _passthrough_postprocess(raw_paths, *, amount_msat):
        return raw_paths, {"paths": [{"intro_pubkey": p["_intro_pubkey_hex"]} for p in raw_paths]}

    monkeypatch.setattr(resp_mod, "_postprocess_paths", _passthrough_postprocess)

    payload, _, _ = _build_signed_offerless_invreq_bytes(amount_msat=4242)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None

    # Both LND mints fired (primary depth=1, alt depth=2).
    assert mint_mock.await_count == 2
    assert mint_mock.await_args_list[0].kwargs["num_hops"] == 1
    assert mint_mock.await_args_list[1].kwargs["num_hops"] == 2

    # Primary's r_hash was cancelled (orphan cleanup).
    assert "11" * 32 in cancel_calls

    # The offer-less invreq persisted (offer_id=None) — the
    # invoice signed and returned must carry the ALT r_hash.
    invoice = Invoice.parse(Bolt12String(hrp="lni", records=tlv_decode_stream(out)))
    assert invoice.payment_hash is not None
    assert invoice.payment_hash.hex() == "22" * 32

    breaker.reset_for_tests()


@pytest.mark.asyncio
async def test_responder_skips_adaptive_when_1hop_fallback_fired(
    session_factory_for,
    db_session,
    monkeypatch,
) -> None:
    """When the existing 1-hop fallback fires (primary depth=2
    returned 0 paths → re-mint at depth=1), the adaptive helper
    must NOT also run — it would compute alt_depth=1 (same as
    the fallback's actual depth) and waste an LND round-trip
    with no real chance of helping."""
    from unittest.mock import AsyncMock

    from app.core.config import settings as cfg
    from app.services.bolt12 import responder as resp_mod
    from app.services.bolt12.path_postprocess import get_path_breaker

    monkeypatch.setattr(cfg, "bolt12_blinded_path_min_real_hops", 2)
    monkeypatch.setattr(cfg, "bolt12_adaptive_depth_fallback_enabled", True)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_enabled", True)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_failures_to_open", 1)

    breaker = get_path_breaker()
    breaker.reset_for_tests()
    # Pre-open the intro that the depth-1 fallback mint will surface.
    # If the helper were not gated, it would fire here and try depth=1
    # again (alt_depth = 1 when primary_num_hops==2 post-fallback).
    breaker.record_failure("02" + "aa" * 32)

    fallback_path = {
        "_intro_pubkey_hex": "02" + "aa" * 32,
        "blinded_path": {
            "introduction_node": "02" + "aa" * 32,
            "blinding_point": "03" + "11" * 32,
            "blinded_hops": [
                {"blinded_node": "02" + "55" * 32, "encrypted_data": "de" * 16},
            ],
        },
        "base_fee_msat": 1000,
        "proportional_fee_rate": 100,
        "total_cltv_delta": 40,
        "htlc_min_msat": "1",
        "htlc_max_msat": "100000000",
        "features": "",
    }

    # Mint sequence: depth=2 returns 0 paths → fallback to depth=1
    # → returns one path with an open intro.
    depth2_empty = {
        "r_hash": "33" * 32,
        "payment_request": "lnbc...",
        "add_index": "1",
        "payment_addr": "ab" * 32,
        "blinded_paths": [],
    }
    depth1_result = {
        "r_hash": "44" * 32,
        "payment_request": "lnbc...",
        "add_index": "2",
        "payment_addr": "cd" * 32,
        "blinded_paths": [fallback_path],
    }
    mint_mock = AsyncMock(
        side_effect=[
            (depth2_empty, None),
            (depth1_result, None),
        ]
    )
    monkeypatch.setattr(
        resp_mod.lnd_service,
        "add_blinded_invoice",
        mint_mock,
    )

    cancel_mock = AsyncMock(return_value=(True, None))
    monkeypatch.setattr(
        resp_mod.lnd_service,
        "cancel_invoice",
        cancel_mock,
    )

    async def _passthrough_postprocess(raw_paths, *, amount_msat):
        return raw_paths, {"paths": [{"intro_pubkey": p["_intro_pubkey_hex"]} for p in raw_paths]}

    monkeypatch.setattr(resp_mod, "_postprocess_paths", _passthrough_postprocess)

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None

    # Exactly TWO mint calls: depth=2 (empty) + depth=1 fallback.
    # No third call from the adaptive helper.
    assert mint_mock.await_count == 2
    assert mint_mock.await_args_list[0].kwargs["num_hops"] == 2
    assert mint_mock.await_args_list[1].kwargs["num_hops"] == 1
    # No cancel calls — the helper never ran, so neither path got
    # cancelled.
    assert cancel_mock.await_count == 0

    breaker.reset_for_tests()


@pytest.mark.asyncio
async def test_responder_adaptive_aborts_on_malformed_alt_r_hash(
    session_factory_for,
    db_session,
    monkeypatch,
) -> None:
    """Validate-first discipline: if the alt mint returns a
    malformed r_hash (e.g. wrong length), the helper must abort
    the flip WITHOUT cancelling the primary or swapping any state.
    Pins the validate-first fix that prevents producing an
    unpayable invoice (alt's blinded_paths + primary's r_hash
    after primary was already cancelled)."""
    from unittest.mock import AsyncMock

    from app.core.config import settings as cfg
    from app.services.bolt12 import responder as resp_mod
    from app.services.bolt12.path_postprocess import get_path_breaker

    monkeypatch.setattr(cfg, "bolt12_blinded_path_min_real_hops", 1)
    monkeypatch.setattr(cfg, "bolt12_adaptive_depth_fallback_enabled", True)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_enabled", True)
    monkeypatch.setattr(cfg, "bolt12_path_breaker_failures_to_open", 1)

    breaker = get_path_breaker()
    breaker.reset_for_tests()
    breaker.record_failure("02" + "aa" * 32)

    primary_path = {
        "_intro_pubkey_hex": "02" + "aa" * 32,
        "blinded_path": {
            "introduction_node": "02" + "aa" * 32,
            "blinding_point": "03" + "11" * 32,
            "blinded_hops": [
                {"blinded_node": "02" + "55" * 32, "encrypted_data": "de" * 16},
            ],
        },
        "base_fee_msat": 1000,
        "proportional_fee_rate": 100,
        "total_cltv_delta": 40,
        "htlc_min_msat": "1",
        "htlc_max_msat": "100000000",
        "features": "",
    }
    alt_path = {
        "_intro_pubkey_hex": "02" + "bb" * 32,  # healthy intro
        "blinded_path": {
            "introduction_node": "02" + "bb" * 32,
            "blinding_point": "03" + "22" * 32,
            "blinded_hops": [
                {"blinded_node": "02" + "77" * 32, "encrypted_data": "ff" * 16},
                {"blinded_node": "02" + "88" * 32, "encrypted_data": "aa" * 16},
            ],
        },
        "base_fee_msat": 2000,
        "proportional_fee_rate": 200,
        "total_cltv_delta": 80,
        "htlc_min_msat": "1",
        "htlc_max_msat": "100000000",
        "features": "",
    }
    primary_result = {
        "r_hash": "11" * 32,
        "payment_request": "lnbc...",
        "add_index": "1",
        "payment_addr": "ab" * 32,
        "blinded_paths": [primary_path],
    }
    # Alt returns a malformed r_hash (16 bytes instead of 32).
    # The helper must catch the length check and abort without
    # cancelling primary.
    alt_result = {
        "r_hash": "ab" * 16,
        "payment_request": "lnbc...",
        "add_index": "2",
        "payment_addr": "cd" * 32,
        "blinded_paths": [alt_path],
    }
    mint_mock = AsyncMock(
        side_effect=[
            (primary_result, None),
            (alt_result, None),
        ]
    )
    monkeypatch.setattr(
        resp_mod.lnd_service,
        "add_blinded_invoice",
        mint_mock,
    )

    cancel_calls: list[str] = []

    async def _spy_cancel(h):
        cancel_calls.append(h)
        return True, None

    monkeypatch.setattr(
        resp_mod.lnd_service,
        "cancel_invoice",
        _spy_cancel,
    )

    async def _passthrough_postprocess(raw_paths, *, amount_msat):
        return raw_paths, {"paths": [{"intro_pubkey": p["_intro_pubkey_hex"]} for p in raw_paths]}

    monkeypatch.setattr(resp_mod, "_postprocess_paths", _passthrough_postprocess)

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None

    # Both mints happened (primary + the alt attempt).
    assert mint_mock.await_count == 2
    # The primary's r_hash was NOT cancelled (helper aborted before
    # any side effects). The alt's r_hash WAS cancelled as orphan
    # cleanup.
    assert "11" * 32 not in cancel_calls
    assert "ab" * 16 in cancel_calls

    # The persisted invoice has the PRIMARY r_hash (no flip).
    persisted = (
        await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.api_key_id == offer_row.api_key_id))
    ).scalar_one()
    assert persisted.payment_hash_hex == "11" * 32

    breaker.reset_for_tests()


# ── Fix #3 (2026-06-06): per-offer min_real_hops_override ────────


@pytest.mark.asyncio
async def test_responder_uses_per_offer_min_real_hops_override(
    session_factory_for,
    db_session,
    mock_lnd,
    monkeypatch,
) -> None:
    """When an offer has ``min_real_hops_override=1`` (set by the
    Ocean auto-detection at offer-issuance time), the responder
    calls ``add_blinded_invoice`` with ``num_hops=1`` regardless
    of the global ``BOLT12_BLINDED_PATH_MIN_REAL_HOPS`` setting.
    Pins the override path that eliminates the intermediate hop
    for non-privacy-sensitive payers (Ocean)."""
    from app.core.config import settings as cfg

    # Global setting says 2-real-hop default…
    monkeypatch.setattr(cfg, "bolt12_blinded_path_min_real_hops", 2)

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    # …but THIS offer is marked for 1-real-hop paths.
    offer_row.min_real_hops_override = 1
    await db_session.commit()

    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None

    # The mocked add_blinded_invoice should have been called with
    # ``num_hops=1`` (the override) rather than 2 (the global).
    mock_lnd.assert_awaited()
    kwargs = mock_lnd.await_args.kwargs
    assert kwargs.get("num_hops") == 1


@pytest.mark.asyncio
async def test_responder_falls_back_to_global_when_no_override(
    session_factory_for,
    db_session,
    mock_lnd,
    monkeypatch,
) -> None:
    """When an offer has no override (most offers), the global
    ``BOLT12_BLINDED_PATH_MIN_REAL_HOPS`` setting is honoured."""
    from app.core.config import settings as cfg

    monkeypatch.setattr(cfg, "bolt12_blinded_path_min_real_hops", 2)

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    # No override stamped → uses global default of 2.
    assert offer_row.min_real_hops_override is None

    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None

    kwargs = mock_lnd.await_args.kwargs
    assert kwargs.get("num_hops") == 2


# ── Item 5: outbound invoice envelope size cap ────────────────────


@pytest.mark.asyncio
async def test_responder_drops_invoice_exceeding_outbound_size_cap(
    session_factory_for, db_session, mock_lnd, monkeypatch
) -> None:
    """Per Item 5: when the encoded invoice exceeds
    ``BOLT12_MAX_OUTBOUND_INVOICE_BYTES``, responder must return
    ``None`` and write a ``bolt12_invreq_invoice_too_large`` audit
    row — no garbled wire reply."""
    from app.core.config import settings
    from app.models.audit_log import AuditLog

    # Force the cap to a value the encoded invoice will exceed.
    # The minimum bound is 4096; pick that since a single-path
    # invoice with our fixture is ~3-4 KB. Wrap in a bypass since
    # the Field has ge=4096 — set the value directly on the
    # singleton.
    monkeypatch.setattr(settings, "bolt12_max_outbound_invoice_bytes", 200)

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer)
    payload, _, _ = _build_signed_invreq_bytes(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is None  # silent drop

    # Audit row was emitted with the structured details.
    audit_row = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "bolt12_invreq_invoice_too_large"))
    ).scalar_one()
    assert audit_row.success is False
    assert audit_row.error_message == "invoice_envelope_exceeded"
    assert audit_row.details["cap"] == 200
    assert audit_row.details["invoice_bytes_len"] > 200


# ── amount caps: operator cap + hard ceiling (offer-bound + offer-less) ──


@pytest.mark.asyncio
async def test_responder_rejects_offer_bound_amount_over_operator_cap(
    session_factory_for, db_session, mock_lnd, monkeypatch
) -> None:
    """An open-amount offer whose invreq names an amount above the
    operator cap is declined before any LND mint, with a structured
    audit row."""
    from app.models.audit_log import AuditLog

    monkeypatch.setattr(settings, "bolt12_inbound_max_amount_msat", 100_000_000)
    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer, amount=None)
    payload, _, _ = _build_signed_invreq_bytes(offer_row, amount_msat=200_000_000)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))

    assert out is None
    mock_lnd.assert_not_awaited()
    audit_row = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "bolt12_invreq_amount_cap"))
    ).scalar_one()
    assert audit_row.success is False
    assert audit_row.error_message == "amount_cap_exceeded"
    assert audit_row.details["cap_msat"] == 100_000_000
    assert audit_row.details["offer_id"] == str(offer_row.id)
    # No invoice persisted on a capped reject.
    invoices = (await db_session.execute(select(Bolt12Invoice))).scalars().all()
    assert invoices == []


@pytest.mark.asyncio
async def test_responder_rejects_offer_bound_amount_over_hard_ceiling(
    session_factory_for, db_session, mock_lnd, monkeypatch
) -> None:
    """With the operator cap disabled (0), an amount above the hard
    ceiling is still declined unconditionally."""
    from app.models.audit_log import AuditLog

    monkeypatch.setattr(settings, "bolt12_inbound_max_amount_msat", 0)
    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer_signer=issuer, amount=None)
    payload, _, _ = _build_signed_invreq_bytes(offer_row, amount_msat=200_000_000_000)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))

    assert out is None
    mock_lnd.assert_not_awaited()
    audit_row = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "bolt12_invreq_amount_cap"))
    ).scalar_one()
    assert audit_row.success is False
    assert audit_row.error_message == "amount_hard_cap_exceeded"
    assert audit_row.details["ceiling_msat"] == 100_000_000_000


@pytest.mark.asyncio
async def test_responder_rejects_offerless_amount_over_operator_cap(
    session_factory_for, db_session, mock_lnd, monkeypatch
) -> None:
    """An offer-less invreq above the operator cap is declined before
    minting, with an audit row flagged ``offerless``."""
    from app.models.audit_log import AuditLog

    monkeypatch.setattr(settings, "bolt12_accept_offerless_invreqs", True)
    monkeypatch.setattr(settings, "bolt12_inbound_max_amount_msat", 100_000_000)
    payload, _, _ = _build_signed_offerless_invreq_bytes(amount_msat=200_000_000)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))

    assert out is None
    mock_lnd.assert_not_awaited()
    audit_row = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "bolt12_invreq_amount_cap"))
    ).scalar_one()
    assert audit_row.success is False
    assert audit_row.error_message == "amount_cap_exceeded"
    assert audit_row.details["offerless"] is True


@pytest.mark.asyncio
async def test_responder_rejects_offerless_amount_over_hard_ceiling(
    session_factory_for, db_session, mock_lnd, monkeypatch
) -> None:
    """Offer-less mints enforce the hard ceiling even with the operator
    cap disabled."""
    from app.models.audit_log import AuditLog

    monkeypatch.setattr(settings, "bolt12_accept_offerless_invreqs", True)
    monkeypatch.setattr(settings, "bolt12_inbound_max_amount_msat", 0)
    payload, _, _ = _build_signed_offerless_invreq_bytes(amount_msat=200_000_000_000)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))

    assert out is None
    mock_lnd.assert_not_awaited()
    audit_row = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "bolt12_invreq_amount_cap"))
    ).scalar_one()
    assert audit_row.success is False
    assert audit_row.error_message == "amount_hard_cap_exceeded"
    assert audit_row.details["offerless"] is True
