# SPDX-License-Identifier: MIT
"""Tests for ``app.services.bolt12.selective_disclosure``."""

from __future__ import annotations

from app.services.bolt12 import (
    CoincurveSigner,
    Offer,
    SelectiveDisclosureProof,
    build_proof,
    sign_invoice_request,
    verify_proof,
)
from app.services.bolt12.fields import InvoiceRequest


def _signed_invreq() -> tuple[CoincurveSigner, InvoiceRequest]:
    """Build a real signed invreq with a wide TLV set so we can redact."""
    issuer = CoincurveSigner.generate()
    offer = Offer(
        description="proof-test",
        amount=2500,
        issuer_id=issuer.public_key,
        metadata=b"\x07" * 16,
        currency="USD",
        issuer="Alice",
    )
    payer = CoincurveSigner.generate()
    invreq = InvoiceRequest.from_offer(
        offer,
        metadata=b"\xab" * 16,
        payer_id=payer.public_key,
        amount=2500,
        payer_note="lunch on Tuesday",
    )
    signed = sign_invoice_request(invreq, payer)
    return payer, signed


def test_proof_round_trip_full_reveal() -> None:
    """Revealing every TLV reproduces the original root + signature."""
    payer, invreq = _signed_invreq()
    records = invreq.to_records()
    types_in_order = [
        r.type
        for r in records
        if r.type < 240 or r.type > 1000  # exclude signature
    ]

    proof = build_proof(
        records,
        reveal_types=set(types_in_order),
        message_name="invoice_request",
    )
    sig = invreq.signature
    assert sig is not None

    assert verify_proof(
        proof,
        full_stream_record_types_in_order=types_in_order,
        pubkey33=payer.public_key,
        signature64=sig,
    )


def test_proof_round_trip_partial_reveal() -> None:
    """Revealing only a subset still verifies (typical receipt use-case)."""
    payer, invreq = _signed_invreq()
    records = invreq.to_records()
    types_in_order = [r.type for r in records if r.type < 240 or r.type > 1000]

    # Reveal only amount, payer_id, metadata — hide the rest.
    proof = build_proof(
        records,
        reveal_types={0, 82, 88},  # invreq_metadata, invreq_amount, invreq_payer_id
        message_name="invoice_request",
    )
    sig = invreq.signature
    assert sig is not None

    assert verify_proof(
        proof,
        full_stream_record_types_in_order=types_in_order,
        pubkey33=payer.public_key,
        signature64=sig,
    )

    # Round-trip through JSON.
    rehydrated = SelectiveDisclosureProof.from_json(proof.to_json())
    assert verify_proof(
        rehydrated,
        full_stream_record_types_in_order=types_in_order,
        pubkey33=payer.public_key,
        signature64=sig,
    )


def test_proof_with_zero_revealed_still_verifies() -> None:
    """All-redacted proof is degenerate but valid — proves *something* was signed."""
    payer, invreq = _signed_invreq()
    records = invreq.to_records()
    types_in_order = [r.type for r in records if r.type < 240 or r.type > 1000]

    proof = build_proof(
        records,
        reveal_types=set(),
        message_name="invoice_request",
    )
    sig = invreq.signature
    assert sig is not None

    assert verify_proof(
        proof,
        full_stream_record_types_in_order=types_in_order,
        pubkey33=payer.public_key,
        signature64=sig,
    )


def test_proof_rejects_tampered_revealed_value() -> None:
    """If the prover modifies a revealed value, root reconstruction fails."""
    payer, invreq = _signed_invreq()
    records = invreq.to_records()
    types_in_order = [r.type for r in records if r.type < 240 or r.type > 1000]

    proof = build_proof(
        records,
        reveal_types={82},  # invreq_amount
        message_name="invoice_request",
    )
    # Mutate the revealed amount.
    revealed = list(proof.revealed)
    bad_value = bytes.fromhex(revealed[0].value_hex)
    bad_value = bytes((bad_value[0] ^ 0x01,)) + bad_value[1:]
    revealed[0] = revealed[0].__class__(type=revealed[0].type, value_hex=bad_value.hex())
    bad_proof = SelectiveDisclosureProof(
        revealed=tuple(revealed),
        omitted_paired_hashes=proof.omitted_paired_hashes,
        first_tlv_encoding_hex=proof.first_tlv_encoding_hex,
        message_name=proof.message_name,
        field_name=proof.field_name,
    )

    sig = invreq.signature
    assert sig is not None

    assert not verify_proof(
        bad_proof,
        full_stream_record_types_in_order=types_in_order,
        pubkey33=payer.public_key,
        signature64=sig,
    )


def test_proof_rejects_wrong_signature() -> None:
    payer, invreq = _signed_invreq()
    records = invreq.to_records()
    types_in_order = [r.type for r in records if r.type < 240 or r.type > 1000]

    proof = build_proof(
        records,
        reveal_types={82},
        message_name="invoice_request",
    )
    # 64 bytes of garbage masquerading as a signature.
    assert not verify_proof(
        proof,
        full_stream_record_types_in_order=types_in_order,
        pubkey33=payer.public_key,
        signature64=b"\x00" * 64,
    )


def test_proof_rejects_pubkey_mismatch() -> None:
    payer, invreq = _signed_invreq()
    records = invreq.to_records()
    types_in_order = [r.type for r in records if r.type < 240 or r.type > 1000]

    proof = build_proof(
        records,
        reveal_types={82},
        message_name="invoice_request",
    )
    sig = invreq.signature
    assert sig is not None

    other = CoincurveSigner.generate()
    assert not verify_proof(
        proof,
        full_stream_record_types_in_order=types_in_order,
        pubkey33=other.public_key,
        signature64=sig,
    )


def test_proof_rejects_duplicate_revealed_type() -> None:
    payer, invreq = _signed_invreq()
    records = invreq.to_records()
    types_in_order = [r.type for r in records if r.type < 240 or r.type > 1000]

    proof = build_proof(
        records,
        reveal_types={82},
        message_name="invoice_request",
    )
    duplicated = SelectiveDisclosureProof(
        revealed=proof.revealed + proof.revealed,
        omitted_paired_hashes=proof.omitted_paired_hashes,
        first_tlv_encoding_hex=proof.first_tlv_encoding_hex,
        message_name=proof.message_name,
        field_name=proof.field_name,
    )
    sig = invreq.signature
    assert sig is not None
    assert not verify_proof(
        duplicated,
        full_stream_record_types_in_order=types_in_order,
        pubkey33=payer.public_key,
        signature64=sig,
    )


def test_proof_rejects_wrong_schema() -> None:
    """Verifier-side schema mismatch (extra type) → fail without crashing."""
    payer, invreq = _signed_invreq()
    records = invreq.to_records()
    types_in_order = [r.type for r in records if r.type < 240 or r.type > 1000]

    proof = build_proof(
        records,
        reveal_types={82},
        message_name="invoice_request",
    )
    sig = invreq.signature
    assert sig is not None

    # Extra phantom type at the end → omitted iter exhausted early or
    # omitted-iter remainder check fires.
    bogus_schema = types_in_order + [777]
    assert not verify_proof(
        proof,
        full_stream_record_types_in_order=bogus_schema,
        pubkey33=payer.public_key,
        signature64=sig,
    )


def test_proof_is_canonical_under_json_roundtrip() -> None:
    payer, invreq = _signed_invreq()
    records = invreq.to_records()
    proof = build_proof(
        records,
        reveal_types={0, 82, 88},
        message_name="invoice_request",
    )
    j = proof.to_json()
    rehydrated = SelectiveDisclosureProof.from_json(j)
    assert rehydrated.to_json() == j
