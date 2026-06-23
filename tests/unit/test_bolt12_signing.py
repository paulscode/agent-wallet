# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.signing`` (BIP-340 signing/verification)."""

from __future__ import annotations

import pytest

from app.services.bolt12 import (
    Bolt12Codec,
    CoincurveSigner,
    Invoice,
    InvoiceRequest,
    Offer,
    sign_invoice,
    sign_invoice_request,
    verify_bip340,
    verify_invoice,
    verify_invoice_request,
)

# ── coincurve signer ─────────────────────────────────────────────


def test_signer_generate_produces_unique_keys() -> None:
    a = CoincurveSigner.generate()
    b = CoincurveSigner.generate()
    assert a.secret != b.secret
    assert a.public_key != b.public_key
    assert len(a.public_key) == 33
    assert a.public_key[0] in (0x02, 0x03)
    assert len(a.secret) == 32


def test_signer_round_trip_from_secret() -> None:
    s1 = CoincurveSigner.generate()
    s2 = CoincurveSigner(s1.secret)
    assert s2.public_key == s1.public_key


def test_signer_rejects_bad_secret() -> None:
    with pytest.raises(ValueError):
        CoincurveSigner(b"\x00" * 31)


def test_signer_rejects_bad_digest() -> None:
    s = CoincurveSigner.generate()
    with pytest.raises(ValueError):
        s.sign(b"\x00" * 31)


def test_signer_sign_then_verify_directly() -> None:
    s = CoincurveSigner.generate()
    msg = b"\xaa" * 32
    sig = s.sign(msg)
    assert len(sig) == 64
    assert verify_bip340(pubkey33=s.public_key, message32=msg, signature64=sig)


# ── verify_bip340 — defensive paths ──────────────────────────────


def test_verify_returns_false_on_bad_message_length() -> None:
    s = CoincurveSigner.generate()
    sig = s.sign(b"\x00" * 32)
    assert not verify_bip340(pubkey33=s.public_key, message32=b"\x00" * 31, signature64=sig)


def test_verify_returns_false_on_bad_sig_length() -> None:
    s = CoincurveSigner.generate()
    assert not verify_bip340(pubkey33=s.public_key, message32=b"\x00" * 32, signature64=b"\x00" * 63)


def test_verify_returns_false_on_bad_pubkey() -> None:
    s = CoincurveSigner.generate()
    sig = s.sign(b"\x00" * 32)
    assert not verify_bip340(pubkey33=b"\x04" + b"\x00" * 32, message32=b"\x00" * 32, signature64=sig)
    assert not verify_bip340(pubkey33=b"\x02" * 32, message32=b"\x00" * 32, signature64=sig)


def test_verify_returns_false_on_wrong_signer() -> None:
    a = CoincurveSigner.generate()
    b = CoincurveSigner.generate()
    sig = a.sign(b"\x77" * 32)
    assert not verify_bip340(pubkey33=b.public_key, message32=b"\x77" * 32, signature64=sig)


def test_verify_ignores_y_parity_byte() -> None:
    """BIP-340 is x-only — flipping the y-parity prefix must still verify."""
    s = CoincurveSigner.generate()
    sig = s.sign(b"\xff" * 32)
    pub = s.public_key
    flipped = bytes([0x05 - pub[0]]) + pub[1:]  # 0x02 ↔ 0x03
    assert verify_bip340(pubkey33=flipped, message32=b"\xff" * 32, signature64=sig)


# ── invoice_request signing ──────────────────────────────────────


ISSUER_ID = bytes.fromhex("02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619")


def _offer() -> Offer:
    return Offer(amount=1000, description="coffee", issuer_id=ISSUER_ID)


def test_sign_invoice_request_round_trip() -> None:
    payer = CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(_offer(), metadata=b"\x42" * 16, payer_id=payer.public_key)
    signed = sign_invoice_request(invreq, payer)
    assert signed.signature is not None
    assert len(signed.signature) == 64
    assert verify_invoice_request(signed)

    # And the signature survives a wire round-trip.
    s = Bolt12Codec.encode(signed.to_bolt12_string())
    rt = InvoiceRequest.parse(Bolt12Codec.decode(s))
    assert verify_invoice_request(rt)


def test_sign_invoice_request_rejects_mismatched_payer_id() -> None:
    payer = CoincurveSigner.generate()
    other = CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(_offer(), metadata=b"x", payer_id=other.public_key)
    with pytest.raises(ValueError, match="x-only"):
        sign_invoice_request(invreq, payer)


def test_sign_invoice_request_requires_payer_id() -> None:
    payer = CoincurveSigner.generate()
    invreq = InvoiceRequest(offer=_offer(), metadata=b"x")
    with pytest.raises(ValueError, match="payer_id"):
        sign_invoice_request(invreq, payer)


def test_verify_invoice_request_handles_missing_fields() -> None:
    invreq = InvoiceRequest(offer=_offer())
    assert not verify_invoice_request(invreq)


def test_verify_invoice_request_rejects_tampered_payload() -> None:
    payer = CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(_offer(), metadata=b"orig", payer_id=payer.public_key)
    signed = sign_invoice_request(invreq, payer)
    # Replace metadata after signing; signature must no longer verify.
    tampered = InvoiceRequest(
        offer=signed.offer,
        metadata=b"tampered",
        payer_id=signed.payer_id,
        signature=signed.signature,
    )
    assert not verify_invoice_request(tampered)


# ── invoice signing ──────────────────────────────────────────────


def test_sign_invoice_round_trip() -> None:
    payer = CoincurveSigner.generate()
    node = CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(_offer(), metadata=b"m", payer_id=payer.public_key)
    invreq = sign_invoice_request(invreq, payer)

    inv = Invoice(
        invreq=invreq,
        payment_hash=b"\xaa" * 32,
        amount=1000,
        node_id=node.public_key,
    )
    signed = sign_invoice(inv, node)
    assert signed.signature is not None and len(signed.signature) == 64
    assert verify_invoice(signed)

    s = Bolt12Codec.encode(signed.to_bolt12_string())
    rt = Invoice.parse(Bolt12Codec.decode(s))
    assert verify_invoice(rt)


def test_sign_invoice_requires_node_id() -> None:
    payer = CoincurveSigner.generate()
    node = CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(_offer(), metadata=b"m", payer_id=payer.public_key)
    inv = Invoice(invreq=invreq, payment_hash=b"\xbb" * 32, amount=1000)
    with pytest.raises(ValueError, match="node_id"):
        sign_invoice(inv, node)


def test_sign_invoice_rejects_mismatched_node_id() -> None:
    payer = CoincurveSigner.generate()
    node = CoincurveSigner.generate()
    other = CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(_offer(), metadata=b"m", payer_id=payer.public_key)
    inv = Invoice(invreq=invreq, node_id=other.public_key, payment_hash=b"\xcc" * 32)
    with pytest.raises(ValueError, match="x-only"):
        sign_invoice(inv, node)


def test_verify_invoice_handles_missing_fields() -> None:
    payer = CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(_offer(), metadata=b"m", payer_id=payer.public_key)
    assert not verify_invoice(Invoice(invreq=invreq))


def test_verify_invoice_rejects_tampered_amount() -> None:
    payer = CoincurveSigner.generate()
    node = CoincurveSigner.generate()
    invreq = sign_invoice_request(
        InvoiceRequest.from_offer(_offer(), metadata=b"m", payer_id=payer.public_key),
        payer,
    )
    inv = Invoice(
        invreq=invreq,
        payment_hash=b"\xdd" * 32,
        amount=1000,
        node_id=node.public_key,
    )
    signed = sign_invoice(inv, node)
    tampered = Invoice(
        invreq=signed.invreq,
        payment_hash=signed.payment_hash,
        amount=2000,  # changed
        node_id=signed.node_id,
        signature=signed.signature,
    )
    assert not verify_invoice(tampered)
