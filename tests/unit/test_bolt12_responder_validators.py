# SPDX-License-Identifier: MIT
"""
Table tests for the BOLT 12 responder's pure amount/quantity validators.

``_resolve_amount`` pins the price from the trusted DB offer row so a payer
can't override a fixed price or underpay; ``_validate_quantity`` bounds the
mint so a peer can't drive an unbounded issuance via quantity even when the
amount cap is disabled. Both are pure functions of (invoice-request, offer)
and are exercised here over their full branch set with lightweight stubs —
they read only ``amount``/``quantity`` and ``amount_msat``/``quantity_max``.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.models.bolt12_invoice import Bolt12InvoiceStatus
from app.services.bolt12.responder import (
    _HARD_QUANTITY_MAX,
    _invoice_expired,
    _invreq_idempotency_key,
    _resolve_amount,
    _validate_quantity,
)


def _invreq(*, amount=None, quantity=None):
    return SimpleNamespace(amount=amount, quantity=quantity)


def _offer(*, amount_msat=None, quantity_max=None):
    return SimpleNamespace(amount_msat=amount_msat, quantity_max=quantity_max)


class TestResolveAmount:
    @pytest.mark.parametrize(
        "invreq, offer, expected",
        [
            # Fixed-price offer, no invreq amount → pinned × default qty(1).
            (_invreq(), _offer(amount_msat=1000), 1000),
            # Fixed-price, explicit quantity multiplies the pinned price.
            (_invreq(quantity=3), _offer(amount_msat=1000), 3000),
            # Fixed-price, invreq amount equal to the total is accepted.
            (_invreq(amount=2000, quantity=2), _offer(amount_msat=1000), 2000),
            # Fixed-price, invreq amount that disagrees with the total → reject.
            (_invreq(amount=999, quantity=2), _offer(amount_msat=1000), None),
            # Quantity below 1 on a fixed-price offer → reject.
            (_invreq(quantity=0), _offer(amount_msat=1000), None),
            # Open-amount offer: invreq must carry a positive total.
            (_invreq(amount=4321), _offer(amount_msat=None), 4321),
            (_invreq(amount=None), _offer(amount_msat=None), None),
            (_invreq(amount=0), _offer(amount_msat=None), None),
            (_invreq(amount=-5), _offer(amount_msat=None), None),
        ],
    )
    def test_cases(self, invreq, offer, expected):
        assert _resolve_amount(invreq, offer) == expected

    def test_payer_cannot_underpay_fixed_price(self):
        # A fixed-price offer with a lower invreq amount must be refused.
        assert _resolve_amount(_invreq(amount=500), _offer(amount_msat=1000)) is None


class TestValidateQuantity:
    @pytest.mark.parametrize(
        "invreq, offer, expected",
        [
            (_invreq(quantity=None), _offer(), True),  # unset → allowed
            (_invreq(quantity=0), _offer(), False),  # zero never valid
            (_invreq(quantity=-1), _offer(), False),  # negative never valid
            (_invreq(quantity=1), _offer(quantity_max=None), True),  # no cap → ok
            (_invreq(quantity=5), _offer(quantity_max=5), True),  # at cap → ok
            (_invreq(quantity=6), _offer(quantity_max=5), False),  # over cap → reject
        ],
    )
    def test_cases(self, invreq, offer, expected):
        assert _validate_quantity(invreq, offer) is expected

    def test_hard_ceiling_blocks_unbounded_mint_without_offer_cap(self):
        # Even with no offer quantity_max, the hard ceiling bounds the mint.
        assert _validate_quantity(_invreq(quantity=_HARD_QUANTITY_MAX), _offer(quantity_max=None)) is True
        assert _validate_quantity(_invreq(quantity=_HARD_QUANTITY_MAX + 1), _offer(quantity_max=None)) is False


def _invoice_row(*, status, expiry=None):
    """Lightweight stand-in for a ``Bolt12Invoice`` row — ``_invoice_expired``
    reads only ``status`` and ``expiry``."""
    return SimpleNamespace(status=status, expiry=expiry)


class TestInvoiceExpired:
    """``_invoice_expired`` decides whether a stored inbound invoice may
    be replayed on a metadata-dedup hit. PAID rows are always replayed
    (BOLT 12 idempotency MUST); FAILED / EXPIRED always mint fresh; OPEN
    rows fall through to a wall-clock expiry check."""

    def test_paid_row_is_never_expired(self):
        # Even a paid row whose stored expiry is in the past must replay
        # verbatim so the payer's node sees the settle-already condition.
        row = _invoice_row(
            status=Bolt12InvoiceStatus.PAID,
            expiry=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert _invoice_expired(row) is False

    @pytest.mark.parametrize("status", [Bolt12InvoiceStatus.FAILED, Bolt12InvoiceStatus.EXPIRED])
    def test_failed_or_expired_rows_mint_fresh(self, status):
        assert _invoice_expired(_invoice_row(status=status)) is True

    def test_open_row_without_expiry_is_conservatively_replayable(self):
        # A legacy / NULL expiry is treated as not-expired — replay an old
        # invoice rather than risk minting a duplicate payment_hash.
        assert _invoice_expired(_invoice_row(status=Bolt12InvoiceStatus.OPEN, expiry=None)) is False

    def test_open_row_past_wall_clock_expiry_is_expired(self):
        row = _invoice_row(
            status=Bolt12InvoiceStatus.OPEN,
            expiry=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        assert _invoice_expired(row) is True

    def test_open_row_future_expiry_is_not_expired(self):
        row = _invoice_row(
            status=Bolt12InvoiceStatus.OPEN,
            expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert _invoice_expired(row) is False

    def test_naive_expiry_is_coerced_to_utc(self):
        # SQLite drops tzinfo on round-trips; a naive past timestamp must
        # still compare as expired (treated as UTC).
        naive_past = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(tzinfo=None)
        row = _invoice_row(status=Bolt12InvoiceStatus.OPEN, expiry=naive_past)
        assert _invoice_expired(row) is True


class TestInvreqIdempotencyKey:
    """``_invreq_idempotency_key`` prefers the payer-supplied
    ``invreq_metadata`` (so a retried fetch dedups), and falls back to the
    signature digest — namespaced ``sd:`` — when the payer omits metadata,
    so dedup is never silently skipped."""

    def test_prefers_metadata_hex(self):
        invreq = SimpleNamespace(
            metadata=b"\x42" * 16,
            signature_digest=lambda: b"\xff" * 32,
        )
        assert _invreq_idempotency_key(invreq) == ("42" * 16)

    def test_falls_back_to_namespaced_signature_digest(self):
        invreq = SimpleNamespace(
            metadata=None,
            signature_digest=lambda: b"\xab" * 32,
        )
        key = _invreq_idempotency_key(invreq)
        assert key == "sd:" + ("ab" * 32)
        # The ``sd:`` prefix can never collide with a real metadata hex.
        assert key.startswith("sd:")


# ── responder early-reject paths (drive ``make_invreq_responder``) ─────


@pytest.fixture
def session_factory_for(db_engine):
    """A SessionFactory bound to the conftest test engine."""
    sm = async_sessionmaker(db_engine, expire_on_commit=False)

    @asynccontextmanager
    async def _factory():
        async with sm() as session:
            try:
                yield session
            finally:
                await session.close()

    return _factory


def _signed_invreq_payload(*, amount_msat=1500, chain=None, offerless=False):
    """Build a real, validly-signed invreq TLV stream.

    ``offerless`` builds an empty-offer invreq (no ``offer_issuer_id``);
    otherwise it targets a throwaway issuer that is never persisted (so
    the offer lookup misses)."""
    from app.services.bolt12 import (
        CoincurveSigner,
        InvoiceRequest,
        Offer,
        sign_invoice_request,
    )
    from app.services.bolt12.chain_hash import REGTEST_CHAIN_HASH
    from app.services.bolt12.tlv import encode_stream as tlv_encode_stream

    chain = chain or REGTEST_CHAIN_HASH
    payer = CoincurveSigner.generate()
    if offerless:
        offer = Offer(chains=(REGTEST_CHAIN_HASH,))
    else:
        issuer = CoincurveSigner.generate()
        offer = Offer(
            chains=(REGTEST_CHAIN_HASH,),
            description="ghost-offer",
            amount=amount_msat,
            issuer_id=issuer.public_key,
            metadata=b"\x00" * 16,
        )
    invreq = InvoiceRequest.from_offer(
        offer,
        metadata=b"\x42" * 16,
        payer_id=payer.public_key,
        amount=amount_msat,
        chain=chain,
    )
    signed = sign_invoice_request(invreq, payer)
    return tlv_encode_stream(signed.to_records())


def _make_ctx(payload, *, recv_id="validators-recv"):
    from app.services.bolt12 import InboundInvreqContext

    return InboundInvreqContext(
        invreq_payload=payload,
        reply_path=b"\xaa" * 32,
        inbound_context=b"\xbb" * 16,
        recv_id=recv_id,
    )


@pytest.fixture
def _mock_lnd(monkeypatch):
    """Stub ``lnd_service.add_blinded_invoice`` so no LND call escapes.
    These tests assert the responder drops *before* minting, so the stub
    doubles as a 'was the mint path reached?' probe."""
    from app.services.bolt12 import responder as responder_mod

    mock = AsyncMock(return_value=({"r_hash": "11" * 32, "blinded_paths": []}, None))
    monkeypatch.setattr(responder_mod.lnd_service, "add_blinded_invoice", mock)
    return mock


# A realistic single-path / single-hop LND blinded-paths fixture so the
# mint flow can encode spec-compliant BOLT 12 invoice_paths.
_LND_BLINDED_PATHS_FIXTURE = [
    {
        "blinded_path": {
            "introduction_node": "02" + "33" * 32,
            "blinding_point": "03" + "44" * 32,
            "blinded_hops": [{"blinded_node": "02" + "55" * 32, "encrypted_data": "de" * 16}],
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
def _mock_lnd_mints(monkeypatch):
    """Stub ``add_blinded_invoice`` with a mintable result (one blinded
    path) so the responder can complete a full mint."""
    from app.services.bolt12 import responder as responder_mod

    mock = AsyncMock(
        return_value=(
            {"r_hash": "11" * 32, "blinded_paths": _LND_BLINDED_PATHS_FIXTURE},
            None,
        )
    )
    monkeypatch.setattr(responder_mod.lnd_service, "add_blinded_invoice", mock)
    return mock


@pytest.mark.asyncio
async def test_responder_mints_and_persists_for_active_offer(session_factory_for, db_session, _mock_lnd_mints):
    """The happy path: an invreq for an active offer mints a signed
    invoice, returns its TLV bytes, and persists INBOUND invreq +
    invoice rows."""
    from app.models.bolt12_invoice import (
        Bolt12Direction,
        Bolt12Invoice,
        Bolt12InvoiceRequest,
        Bolt12InvoiceRequestStatus,
    )
    from app.services.bolt12 import CoincurveSigner
    from app.services.bolt12.responder import make_invreq_responder

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer=issuer, amount=1500)
    payload = _invreq_payload_for_offer(offer_row, amount_msat=1500)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None and isinstance(out, bytes)
    _mock_lnd_mints.assert_awaited_once()

    invreq_row = (
        await db_session.execute(select(Bolt12InvoiceRequest).where(Bolt12InvoiceRequest.offer_id == offer_row.id))
    ).scalar_one()
    assert invreq_row.direction == Bolt12Direction.INBOUND
    assert invreq_row.status == Bolt12InvoiceRequestStatus.INVOICE_SENT
    assert invreq_row.amount_msat == 1500
    invoice_row = (
        await db_session.execute(select(Bolt12Invoice).where(Bolt12Invoice.invoice_request_id == invreq_row.id))
    ).scalar_one()
    assert invoice_row.payment_hash_hex == "11" * 32


@pytest.mark.asyncio
async def test_responder_replays_same_invoice_for_repeated_invreq(session_factory_for, db_session, _mock_lnd_mints):
    """Re-sending the same signed invreq replays the first invoice
    verbatim with no second LND mint (BOLT 12 idempotency MUST)."""
    from app.services.bolt12 import CoincurveSigner
    from app.services.bolt12.responder import make_invreq_responder

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer=issuer, amount=1500)
    payload = _invreq_payload_for_offer(offer_row, amount_msat=1500)

    responder = make_invreq_responder(session_factory=session_factory_for)
    first = await responder(_make_ctx(payload))
    second = await responder(_make_ctx(payload))
    assert first is not None and second is not None
    assert first == second
    assert _mock_lnd_mints.await_count == 1


@pytest.mark.asyncio
async def test_responder_mints_offerless_invreq_when_enabled(
    session_factory_for, db_session, _mock_lnd_mints, monkeypatch
):
    """With the policy flag on, an offer-less invreq mints a fresh-key
    invoice attributed to the dashboard sentinel with ``offer_id=None``."""
    from app.core.config import settings
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.bolt12_invoice import Bolt12InvoiceRequest
    from app.services.bolt12.responder import make_invreq_responder

    monkeypatch.setattr(settings, "bolt12_accept_offerless_invreqs", True)
    payload = _signed_invreq_payload(amount_msat=4242, offerless=True)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is not None and isinstance(out, bytes)

    invreq_row = (
        await db_session.execute(select(Bolt12InvoiceRequest).where(Bolt12InvoiceRequest.offer_id.is_(None)))
    ).scalar_one()
    assert invreq_row.api_key_id == DASHBOARD_KEY_ID
    assert invreq_row.amount_msat == 4242


@pytest.mark.asyncio
async def test_responder_drops_oversized_payload(session_factory_for, _mock_lnd, monkeypatch):
    """A payload over ``bolt12_max_payload_bytes`` is dropped before the
    parser runs, fail-closing against an OOM-spray from an unauthenticated
    onion-message peer."""
    from app.core.config import settings
    from app.services.bolt12.responder import make_invreq_responder

    monkeypatch.setattr(settings, "bolt12_max_payload_bytes", 8)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(b"x" * 4096))
    assert out is None
    _mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_rate_limited_invreq(session_factory_for, _mock_lnd, monkeypatch):
    """When the sliding-window rate-limiter declines, the responder drops
    the invreq before any offer lookup or LND mint."""
    from app.services.bolt12 import responder as responder_mod
    from app.services.bolt12.responder import make_invreq_responder

    async def _deny(_peer_key, _offer_key):
        return False, "global_cap", 5

    monkeypatch.setattr(responder_mod, "check_inbound_invreq_rate", _deny)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(_signed_invreq_payload()))
    assert out is None
    _mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_offerless_invreq_when_disabled(session_factory_for, _mock_lnd, monkeypatch):
    """Default policy: an invreq with no ``offer_issuer_id`` is dropped
    when ``bolt12_accept_offerless_invreqs`` is off."""
    from app.core.config import settings
    from app.services.bolt12.responder import make_invreq_responder

    monkeypatch.setattr(settings, "bolt12_accept_offerless_invreqs", False)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(_signed_invreq_payload(offerless=True)))
    assert out is None
    _mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_invreq_for_wrong_chain(session_factory_for, _mock_lnd):
    """An invreq pinned to mainnet while the wallet runs on regtest is
    dropped before any LND mint (network-confusion guard)."""
    from app.services.bolt12.chain_hash import MAINNET_CHAIN_HASH
    from app.services.bolt12.responder import make_invreq_responder

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(_signed_invreq_payload(chain=MAINNET_CHAIN_HASH)))
    assert out is None
    _mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_audits_unknown_offer_drop(session_factory_for, db_session, _mock_lnd):
    """An invreq for an issuer with no active offer row is dropped and an
    ``bolt12_invreq_unknown_offer`` audit row is written so post-mortems
    can reconstruct the drop from the DB."""
    from app.models.audit_log import AuditLog
    from app.services.bolt12.responder import make_invreq_responder

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(_signed_invreq_payload()))
    assert out is None
    _mock_lnd.assert_not_awaited()

    audit = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "bolt12_invreq_unknown_offer"))
    ).scalar_one()
    assert audit.success is False
    assert audit.error_message == "no_active_offer_matches_issuer_id"


@pytest.mark.asyncio
async def test_responder_drops_malformed_payload(session_factory_for, _mock_lnd):
    """A payload that isn't a parseable TLV stream is dropped silently."""
    from app.services.bolt12.responder import make_invreq_responder

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(b"not-a-tlv-stream"))
    assert out is None
    _mock_lnd.assert_not_awaited()


async def _seed_offer(db_session, *, issuer, amount=1500, status=None, absolute_expiry=None, quantity_max=None):
    """Insert a wallet-issued offer row + return it."""
    from app.core.encryption import encrypt_field
    from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferStatus
    from app.services.bolt12 import Bolt12Codec, Offer
    from app.services.bolt12.chain_hash import REGTEST_CHAIN_HASH

    offer_obj = Offer(
        chains=(REGTEST_CHAIN_HASH,),
        description="seeded-offer",
        amount=amount,
        issuer_id=issuer.public_key,
        metadata=b"\x01" * 16,
        quantity_max=quantity_max,
        absolute_expiry=int(absolute_expiry.timestamp()) if absolute_expiry is not None else None,
    )
    row = Bolt12Offer(
        api_key_id=uuid4(),
        bolt12=Bolt12Codec.encode(offer_obj.to_bolt12_string()),
        description="seeded-offer",
        amount_msat=amount,
        issuer_id_hex=issuer.public_key.hex(),
        status=status or Bolt12OfferStatus.ACTIVE,
        quantity_max=quantity_max,
        absolute_expiry=absolute_expiry,
        encrypted_metadata=encrypt_field(issuer.secret.hex()),
    )
    db_session.add(row)
    await db_session.commit()
    await db_session.refresh(row)
    return row


def _invreq_payload_for_offer(offer_row, *, amount_msat=1500, quantity=None):
    """Build a signed invreq targeting a seeded offer row."""
    from app.services.bolt12 import (
        CoincurveSigner,
        InvoiceRequest,
        Offer,
    )
    from app.services.bolt12 import decode as decode_bolt12
    from app.services.bolt12.chain_hash import REGTEST_CHAIN_HASH
    from app.services.bolt12.tlv import encode_stream as tlv_encode_stream

    offer = Offer.parse(decode_bolt12(offer_row.bolt12))
    payer = CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(
        offer,
        metadata=b"\x42" * 16,
        payer_id=payer.public_key,
        amount=amount_msat,
        quantity=quantity,
        chain=REGTEST_CHAIN_HASH,
    )
    from app.services.bolt12 import sign_invoice_request

    signed = sign_invoice_request(invreq, payer)
    return tlv_encode_stream(signed.to_records())


@pytest.mark.asyncio
async def test_responder_drops_invreq_for_disabled_offer(session_factory_for, db_session, _mock_lnd):
    """An invreq matching a DISABLED offer is dropped before minting —
    only ACTIVE offers may mint."""
    from app.models.bolt12_offer import Bolt12OfferStatus
    from app.services.bolt12 import CoincurveSigner
    from app.services.bolt12.responder import make_invreq_responder

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer=issuer, status=Bolt12OfferStatus.DISABLED)
    payload = _invreq_payload_for_offer(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is None
    _mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_invreq_for_expired_offer(session_factory_for, db_session, _mock_lnd):
    """An invreq matching an offer past its ``absolute_expiry`` is
    declined before minting."""
    from app.services.bolt12 import CoincurveSigner
    from app.services.bolt12.responder import make_invreq_responder

    issuer = CoincurveSigner.generate()
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    offer_row = await _seed_offer(db_session, issuer=issuer, absolute_expiry=past)
    payload = _invreq_payload_for_offer(offer_row)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is None
    _mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_invreq_amount_below_fixed_price(session_factory_for, db_session, _mock_lnd):
    """A fixed-price offer rejects an invreq amount that disagrees with
    the pinned total — the payer can't underpay."""
    from app.services.bolt12 import CoincurveSigner
    from app.services.bolt12.responder import make_invreq_responder

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer=issuer, amount=2000)
    payload = _invreq_payload_for_offer(offer_row, amount_msat=999)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is None
    _mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_invreq_quantity_over_offer_max(session_factory_for, db_session, _mock_lnd):
    """An invreq quantity above the offer's ``quantity_max`` is rejected
    before minting."""
    from app.services.bolt12 import CoincurveSigner
    from app.services.bolt12.responder import make_invreq_responder

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer=issuer, quantity_max=3)
    payload = _invreq_payload_for_offer(offer_row, quantity=4, amount_msat=None)

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is None
    _mock_lnd.assert_not_awaited()


@pytest.mark.asyncio
async def test_responder_drops_when_lnd_mint_fails(session_factory_for, db_session, monkeypatch):
    """When ``add_blinded_invoice`` returns a non-Tor error, the responder
    audits the failure and drops without retrying (a 4xx won't improve),
    and persists no invoice row."""
    from app.models.audit_log import AuditLog
    from app.services.bolt12 import CoincurveSigner
    from app.services.bolt12 import responder as responder_mod
    from app.services.bolt12.responder import make_invreq_responder

    issuer = CoincurveSigner.generate()
    offer_row = await _seed_offer(db_session, issuer=issuer)
    payload = _invreq_payload_for_offer(offer_row)

    monkeypatch.setattr(
        responder_mod.lnd_service,
        "add_blinded_invoice",
        AsyncMock(return_value=(None, "lnd auth error")),
    )

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is None

    audit = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "bolt12_invreq_lnd_mint_failed"))
    ).scalar_one()
    assert audit.success is False


@pytest.mark.asyncio
async def test_responder_drops_invreq_with_invalid_signature(session_factory_for, _mock_lnd):
    """A structurally-valid invreq whose signature doesn't verify is
    dropped before any offer lookup."""
    from dataclasses import replace as _replace

    from app.services.bolt12 import (
        CoincurveSigner,
        InvoiceRequest,
        Offer,
    )
    from app.services.bolt12.chain_hash import REGTEST_CHAIN_HASH
    from app.services.bolt12.responder import make_invreq_responder
    from app.services.bolt12.tlv import encode_stream as tlv_encode_stream

    issuer = CoincurveSigner.generate()
    payer = CoincurveSigner.generate()
    offer = Offer(
        chains=(REGTEST_CHAIN_HASH,),
        description="ghost",
        amount=1500,
        issuer_id=issuer.public_key,
        metadata=b"\x00" * 16,
    )
    unsigned = InvoiceRequest.from_offer(
        offer,
        metadata=b"\x99" * 16,
        payer_id=payer.public_key,
        amount=1500,
        chain=REGTEST_CHAIN_HASH,
    )
    tampered = _replace(unsigned, signature=b"\x00" * 64)
    payload = tlv_encode_stream(tampered.to_records())

    responder = make_invreq_responder(session_factory=session_factory_for)
    out = await responder(_make_ctx(payload))
    assert out is None
    _mock_lnd.assert_not_awaited()
