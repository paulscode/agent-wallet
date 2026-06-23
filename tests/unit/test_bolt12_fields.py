# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.fields`` (field-level codec)."""

from __future__ import annotations

import pytest

from app.services.bolt12 import (
    Bolt12Codec,
    Bolt12FormatError,
    Bolt12String,
    Invoice,
    InvoiceRequest,
    Offer,
    TLVRecord,
    decode_tu32,
    decode_tu64,
    encode_tu32,
    encode_tu64,
)
from app.services.bolt12.fields import (
    INVOICE_AMOUNT,
    INVOICE_PAYMENT_HASH,
    INVREQ_METADATA,
    INVREQ_PAYER_ID,
    OFFER_AMOUNT,
    OFFER_DESCRIPTION,
    OFFER_ISSUER_ID,
    SIGNATURE,
)

# ── canonical 33-byte points (need valid 0x02/0x03 prefix) ────────

ISSUER_ID = bytes.fromhex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619")
PAYER_ID = bytes.fromhex("032405cbd0f41225d5f203fe4adac8401321a9e05767c5f8af97d51d2e81fbb206")


# ── tu64/tu32 ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("n", "encoded"),
    [
        (0, b""),
        (1, b"\x01"),
        (255, b"\xff"),
        (256, b"\x01\x00"),
        (1024, b"\x04\x00"),
        (0x10000000000000, b"\x10\x00\x00\x00\x00\x00\x00"),
    ],
)
def test_tu64_round_trip(n: int, encoded: bytes) -> None:
    assert encode_tu64(n) == encoded
    assert decode_tu64(encoded) == n


def test_tu64_rejects_leading_zero() -> None:
    with pytest.raises(Bolt12FormatError):
        decode_tu64(b"\x00\x01")


def test_tu64_accepts_eight_bytes() -> None:
    assert decode_tu64(b"\xff" * 8) == 0xFFFFFFFFFFFFFFFF


def test_tu64_rejects_oversized() -> None:
    with pytest.raises(Bolt12FormatError):
        decode_tu64(b"\x01" * 9)


def test_tu64_negative_rejected() -> None:
    with pytest.raises(ValueError):
        encode_tu64(-1)


def test_tu32_bounds() -> None:
    assert encode_tu32(0xFFFFFFFF) == b"\xff\xff\xff\xff"
    with pytest.raises(ValueError):
        encode_tu32(0x100000000)
    with pytest.raises(Bolt12FormatError):
        decode_tu32(b"\x01\x00\x00\x00\x00")  # 5 bytes


# ── Offer round-trip ──────────────────────────────────────────────


def test_offer_minimal_round_trip() -> None:
    o = Offer(issuer_id=ISSUER_ID)
    s = Bolt12Codec.encode(o.to_bolt12_string())
    parsed = Offer.parse(Bolt12Codec.decode(s))
    assert parsed == o


def test_offer_full_round_trip() -> None:
    chains = (b"\x11" * 32, b"\x22" * 32)
    o = Offer(
        chains=chains,
        metadata=b"opaque",
        currency="USD",
        amount=12345,
        description="coffee",
        features=b"\x01\x80",
        absolute_expiry=1_700_000_000,
        paths=b"path-blob",
        issuer="alice@example.com",
        quantity_max=10,
        issuer_id=ISSUER_ID,
    )
    rt = Offer.parse(Bolt12Codec.decode(Bolt12Codec.encode(o.to_bolt12_string())))
    assert rt == o


def test_offer_preserves_unknown_records() -> None:
    extra = TLVRecord(type=78, value=b"future-extension")
    o = Offer(
        amount=1,
        description="x",
        issuer_id=ISSUER_ID,
        unknown_records=(extra,),
    )
    rt = Offer.parse(Bolt12Codec.decode(Bolt12Codec.encode(o.to_bolt12_string())))
    assert extra in rt.unknown_records
    assert rt == o


def test_offer_records_are_sorted_canonically() -> None:
    o = Offer(amount=1, description="x", issuer_id=ISSUER_ID)
    types = [r.type for r in o.to_records()]
    assert types == sorted(types)


def test_offer_rejects_wrong_hrp() -> None:
    s = Bolt12String(hrp="lnr", records=[])
    with pytest.raises(Bolt12FormatError, match="expected hrp 'lno'"):
        Offer.parse(s)


def test_offer_rejects_invalid_pubkey_prefix() -> None:
    bad = b"\x04" + b"\x00" * 32
    with pytest.raises(Bolt12FormatError, match="invalid compressed-pubkey"):
        Offer(issuer_id=bad).to_records()


def test_offer_rejects_chains_with_bad_length() -> None:
    s = Bolt12String(hrp="lno", records=[TLVRecord(2, b"\x01" * 31)])
    with pytest.raises(Bolt12FormatError, match="multiple of 32"):
        Offer.parse(s)


def test_offer_rejects_unexpected_tlv() -> None:
    # Type 1000000000 is in the experimental range, well past offer scope.
    s = Bolt12String(hrp="lno", records=[TLVRecord(1_000_000_000, b"\x00")])
    with pytest.raises(Bolt12FormatError, match="unexpected TLV type"):
        Offer.parse(s)


# ── InvoiceRequest round-trip ─────────────────────────────────────


def test_invreq_from_offer_mirrors_all_offer_tlvs() -> None:
    extra = TLVRecord(type=78, value=b"future")
    o = Offer(
        amount=1000,
        description="x",
        issuer_id=ISSUER_ID,
        unknown_records=(extra,),
    )
    ir = InvoiceRequest.from_offer(
        o,
        metadata=b"\xaa" * 16,
        payer_id=PAYER_ID,
        amount=1500,
        payer_note="thanks",
    )
    rt = InvoiceRequest.parse(Bolt12Codec.decode(Bolt12Codec.encode(ir.to_bolt12_string())))
    assert rt.offer == o
    assert rt.metadata == b"\xaa" * 16
    assert rt.payer_id == PAYER_ID
    assert rt.amount == 1500
    assert rt.payer_note == "thanks"
    assert rt.signature is None


def test_invreq_with_signature_round_trip() -> None:
    o = Offer(amount=1, description="d", issuer_id=ISSUER_ID)
    ir = InvoiceRequest.from_offer(o, metadata=b"m", payer_id=PAYER_ID)
    sig = b"\x55" * 64
    signed = ir.with_signature(sig)
    rt = InvoiceRequest.parse(Bolt12Codec.decode(Bolt12Codec.encode(signed.to_bolt12_string())))
    assert rt.signature == sig


def test_invreq_signature_must_be_64_bytes() -> None:
    o = Offer(issuer_id=ISSUER_ID)
    ir = InvoiceRequest.from_offer(o, metadata=b"m", payer_id=PAYER_ID)
    with pytest.raises(ValueError):
        ir.with_signature(b"\x00" * 63)


def test_invreq_signature_digest_excludes_signature_record() -> None:
    o = Offer(amount=1, description="d", issuer_id=ISSUER_ID)
    ir = InvoiceRequest.from_offer(o, metadata=b"m", payer_id=PAYER_ID)
    digest_unsigned = ir.signature_digest()
    digest_signed = ir.with_signature(b"\x55" * 64).signature_digest()
    # Digest must be invariant w.r.t. presence of the signature TLV.
    assert digest_unsigned == digest_signed
    assert len(digest_unsigned) == 32


def test_invreq_payer_id_must_be_valid_point() -> None:
    o = Offer(issuer_id=ISSUER_ID)
    with pytest.raises(Bolt12FormatError, match="33-byte"):
        InvoiceRequest.from_offer(o, metadata=b"m", payer_id=b"\x02" * 32)


def test_invreq_rejects_signature_length_in_wire() -> None:
    s = Bolt12String(
        hrp="lnr",
        records=[
            TLVRecord(INVREQ_METADATA, b"m"),
            TLVRecord(INVREQ_PAYER_ID, PAYER_ID),
            TLVRecord(SIGNATURE, b"\x00" * 63),
        ],
    )
    with pytest.raises(Bolt12FormatError, match="signature"):
        InvoiceRequest.parse(s)


# ── Invoice round-trip ────────────────────────────────────────────


def _sample_invreq() -> InvoiceRequest:
    o = Offer(amount=1000, description="coffee", issuer_id=ISSUER_ID)
    return InvoiceRequest.from_offer(o, metadata=b"m" * 16, payer_id=PAYER_ID)


def test_invoice_round_trip() -> None:
    inv = Invoice(
        invreq=_sample_invreq(),
        paths=b"\x01\x02",
        blindedpay=b"\x03\x04",
        created_at=1_700_000_000,
        relative_expiry=7200,
        payment_hash=b"\xbb" * 32,
        amount=1000,
        features=b"\x00",
        node_id=ISSUER_ID,
    )
    rt = Invoice.parse(Bolt12Codec.decode(Bolt12Codec.encode(inv.to_bolt12_string())))
    assert rt == inv


def test_invoice_signature_round_trip() -> None:
    inv = Invoice(
        invreq=_sample_invreq(),
        payment_hash=b"\xbb" * 32,
        amount=1000,
        node_id=ISSUER_ID,
    )
    sig = b"\xee" * 64
    signed = inv.with_signature(sig)
    rt = Invoice.parse(Bolt12Codec.decode(Bolt12Codec.encode(signed.to_bolt12_string())))
    assert rt.signature == sig


def test_invoice_signature_digest_stable() -> None:
    inv = Invoice(
        invreq=_sample_invreq(),
        payment_hash=b"\xbb" * 32,
        amount=1000,
        node_id=ISSUER_ID,
    )
    d1 = inv.signature_digest()
    d2 = inv.with_signature(b"\xff" * 64).signature_digest()
    assert d1 == d2
    assert len(d1) == 32


def test_invoice_payment_hash_must_be_32_bytes() -> None:
    s = Bolt12String(
        hrp="lni",
        records=[TLVRecord(INVOICE_PAYMENT_HASH, b"\x00" * 31)],
    )
    with pytest.raises(Bolt12FormatError, match="32 bytes"):
        Invoice.parse(s)


def test_invoice_rejects_wrong_hrp() -> None:
    with pytest.raises(Bolt12FormatError, match="expected hrp 'lni'"):
        Invoice.parse(Bolt12String(hrp="lno", records=[]))


# ── codec interop / canonical ordering ────────────────────────────


def test_records_ascend_no_duplicates() -> None:
    o = Offer(
        amount=1,
        description="x",
        issuer_id=ISSUER_ID,
        unknown_records=(TLVRecord(78, b""),),
    )
    types = [r.type for r in o.to_records()]
    assert types == [
        OFFER_AMOUNT,
        OFFER_DESCRIPTION,
        OFFER_ISSUER_ID,
        78,
    ]


def test_duplicate_unknown_record_rejected_at_build() -> None:
    o = Offer(
        amount=1,
        issuer_id=ISSUER_ID,
        # An "unknown" record colliding with a typed field.
        unknown_records=(TLVRecord(OFFER_AMOUNT, b"\x02"),),
    )
    with pytest.raises(Bolt12FormatError, match="duplicate"):
        o.to_records()


def test_invoice_amount_zero_encodes_empty_value() -> None:
    inv = Invoice(invreq=_sample_invreq(), amount=0)
    recs = {r.type: r for r in inv.to_records()}
    assert recs[INVOICE_AMOUNT].value == b""
