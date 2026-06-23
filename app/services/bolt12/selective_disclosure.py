# SPDX-License-Identifier: MIT
"""BOLT 12 selective-disclosure Merkle proofs.

The signature attached to an offer / invoice_request / invoice covers
the *root* of a Merkle tree built over the TLV stream, with each TLV
record contributing two leaves (`LnLeaf` + `LnNonce`). That structure
gives the receiver an interesting capability: they can reveal a *subset*
of the TLV records — plus a small number of sibling hashes — and a
verifier can reconstruct the root and check the signature without ever
seeing the redacted fields.

This module provides

* :func:`build_proof` — given the full TLV stream and a set of "reveal"
  record indexes, compute the sibling hashes the holder must send
  alongside the revealed records.
* :func:`verify_proof` — given the revealed records, the proof's
  sibling hashes, the original signed-stream's metadata (message name,
  field name, signature pubkey, signature bytes) plus the
  *full-stream's* first-tlv encoding (to derive the nonce tag),
  recompute the root and verify the BIP-340 signature against it.

The proof format is a flat list of ``ProofStep`` records ordered as the
verifier needs to consume them. There is no standard for BOLT 12
selective-disclosure on the wire as of spec PR #798; we use a JSON
representation suitable for receipts / dispute evidence.

Threat model: the prover can omit fields, but cannot forge them — any
field they include is bound to the original signature root, so the
verifier sees exactly what the signer signed for those fields. The
prover *can* choose which fields to reveal, so verifiers MUST validate
that the revealed set contains the fields they care about (e.g. that an
invoice receipt actually contains ``invoice_payment_hash`` and
``invoice_amount``).

The omitted-fields-are-still-bound property comes from the nonce leaf:
a redacted record's nonce is derived from its TLV type, so the verifier
can detect that *some* record of that type was present in the original
stream, even when the value is hidden.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from app.services.bolt12.merkle import (
    _branch,
    _pair_with_nonce,
    signature_message_hash,
    tagged_hash,
)
from app.services.bolt12.signing import verify_bip340
from app.services.bolt12.tlv import TLVRecord, is_signature_type


@dataclass(frozen=True, slots=True)
class ProofStep:
    """One sibling hash combined into the running root.

    ``side`` is "L" if the running hash should sit on the left, "R" if
    on the right. The combine is always min/max-tagged via
    ``LnBranch`` per BOLT 12 spec, so ``side`` is informational only —
    needed if a future spec extension drops the min/max ordering.
    """

    side: str  # "L" or "R"
    hash_hex: str  # 32-byte sibling hash, hex-encoded


@dataclass(frozen=True, slots=True)
class RevealedRecord:
    """A TLV record disclosed in the proof, encoded for transport."""

    type: int
    value_hex: str

    def to_record(self) -> TLVRecord:
        return TLVRecord(self.type, bytes.fromhex(self.value_hex))


@dataclass(frozen=True, slots=True)
class SelectiveDisclosureProof:
    """Self-contained proof of a subset of a signed BOLT 12 TLV stream.

    The verifier additionally needs the message-stream metadata
    (``message_name``, ``field_name``, signing pubkey, signature
    bytes) which travel out-of-band as part of the original BOLT 12
    object.
    """

    revealed: tuple[RevealedRecord, ...]
    """Records disclosed by the prover (in original-stream order)."""

    omitted_paired_hashes: tuple[ProofStep, ...]
    """Sibling paired-hashes for the omitted records, in
    original-stream order. One entry per omitted record."""

    first_tlv_encoding_hex: str
    """The full encoding (type+length+value) of the lowest-type
    non-signature TLV in the original stream. Required to derive
    `LnNonce`-tag for hashing."""

    message_name: str
    """e.g. "offer", "invoice", "invoice_request"."""

    field_name: str
    """Almost always "signature"."""

    def to_json(self) -> str:
        d = asdict(self)
        d["revealed"] = [{"type": r.type, "value_hex": r.value_hex} for r in self.revealed]
        d["omitted_paired_hashes"] = [{"side": s.side, "hash_hex": s.hash_hex} for s in self.omitted_paired_hashes]
        return json.dumps(d, sort_keys=True)

    @classmethod
    def from_json(cls, payload: str) -> "SelectiveDisclosureProof":
        d = json.loads(payload)
        return cls(
            revealed=tuple(RevealedRecord(**r) for r in d["revealed"]),
            omitted_paired_hashes=tuple(ProofStep(**s) for s in d["omitted_paired_hashes"]),
            first_tlv_encoding_hex=d["first_tlv_encoding_hex"],
            message_name=d["message_name"],
            field_name=d["field_name"],
        )


def build_proof(
    records: list[TLVRecord],
    *,
    reveal_types: set[int],
    message_name: str,
    field_name: str = "signature",
) -> SelectiveDisclosureProof:
    """Construct a proof revealing the records whose type ∈ ``reveal_types``.

    Signature records (types 240..1000) are *never* revealed — their
    omission is what makes selective disclosure useful.

    Returns a self-contained :class:`SelectiveDisclosureProof`.
    """
    non_sig = [r for r in records if not is_signature_type(r.type)]
    if not non_sig:
        raise ValueError("selective disclosure: no non-signature records")

    first_encoding = non_sig[0].encode()
    nonce_tag = b"LnNonce" + first_encoding

    revealed: list[RevealedRecord] = []
    omitted_steps: list[ProofStep] = []
    for r in non_sig:
        if r.type in reveal_types:
            revealed.append(RevealedRecord(type=r.type, value_hex=r.value.hex()))
            continue
        leaf = tagged_hash(b"LnLeaf", r.encode())
        nonce = tagged_hash(nonce_tag, r.type_bytes)
        paired = _pair_with_nonce(leaf, nonce)
        # Side is informational since LnBranch always sorts; we record
        # "R" because, conceptually, the omitted record's paired-hash
        # is being merged in at its original position, not as a left
        # sibling of an in-flight running hash. Verifiers do not rely
        # on this field today.
        omitted_steps.append(ProofStep(side="R", hash_hex=paired.hex()))

    return SelectiveDisclosureProof(
        revealed=tuple(revealed),
        omitted_paired_hashes=tuple(omitted_steps),
        first_tlv_encoding_hex=first_encoding.hex(),
        message_name=message_name,
        field_name=field_name,
    )


def verify_proof(
    proof: SelectiveDisclosureProof,
    *,
    full_stream_record_types_in_order: list[int],
    pubkey33: bytes,
    signature64: bytes,
) -> bool:
    """Verify a selective-disclosure proof.

    Args:
        proof: the proof shipped by the prover.
        full_stream_record_types_in_order: the *complete* sequence of
          non-signature TLV types in the original signed stream. The
          verifier needs this to know where to splice the revealed
          records back into the omitted-paired-hashes sequence so the
          tree shape matches. This is typically derived from a
          well-known schema for a given ``message_name``.
        pubkey33: 33-byte compressed pubkey bound to the signature TLV
          (e.g. ``offer_issuer_id`` for offers, ``invoice_node_id`` for
          invoices).
        signature64: BIP-340 signature bytes from the original
          signature TLV.

    Returns ``True`` if the proof reconstructs to a root that the
    signature validates against; ``False`` otherwise.
    """
    if len(pubkey33) != 33:
        return False
    if len(signature64) != 64:
        return False

    first_encoding = bytes.fromhex(proof.first_tlv_encoding_hex)
    if not first_encoding:
        return False
    nonce_tag = b"LnNonce" + first_encoding

    # Splice revealed records and omitted paired-hashes back together
    # in the original stream order.
    revealed_by_type: dict[int, RevealedRecord] = {}
    for rev in proof.revealed:
        if rev.type in revealed_by_type:
            return False  # duplicate reveal
        revealed_by_type[rev.type] = rev

    omitted_iter = iter(proof.omitted_paired_hashes)

    paired: list[bytes] = []
    for t in full_stream_record_types_in_order:
        if is_signature_type(t):
            return False  # caller passed a sig record in the schema
        rev_for_type = revealed_by_type.get(t)
        if rev_for_type is not None:
            rec = rev_for_type.to_record()
            leaf = tagged_hash(b"LnLeaf", rec.encode())
            nonce = tagged_hash(nonce_tag, rec.type_bytes)
            paired.append(_pair_with_nonce(leaf, nonce))
        else:
            try:
                step = next(omitted_iter)
            except StopIteration:
                return False
            try:
                paired.append(bytes.fromhex(step.hash_hex))
            except ValueError:
                return False

    # The omitted-iter must be fully consumed if revealed accounts
    # for the rest of the stream — otherwise the schema is wrong.
    if next(omitted_iter, None) is not None:
        return False

    # Sanity: every revealed type must appear in the schema.
    schema_types = set(full_stream_record_types_in_order)
    for rev in proof.revealed:
        if rev.type not in schema_types:
            return False

    if not paired:
        return False

    # Fold paired hashes into the root via LnBranch.
    root = _fold(paired)

    digest = signature_message_hash(
        message_name=proof.message_name,
        field_name=proof.field_name,
        merkle_root_bytes=root,
    )

    return verify_bip340(pubkey33=pubkey33, message32=digest, signature64=signature64)


def _fold(nodes: list[bytes]) -> bytes:
    """Local copy of :func:`merkle._fold`; identical semantics.

    Importing the private helper would couple us to internal API; we
    keep an exact-mirror here so refactors of ``merkle._fold`` only
    touch one module if behaviour stays identical.
    """
    n = len(nodes)
    if n == 0:
        raise ValueError("selective disclosure: empty node list")
    if n == 1:
        return nodes[0]
    pow2 = 1
    while pow2 * 2 <= n:
        pow2 *= 2
    split = n // 2 if pow2 == n else pow2
    left = _fold(nodes[:split])
    right = _fold(nodes[split:])
    return _branch(left, right)


__all__ = [
    "ProofStep",
    "RevealedRecord",
    "SelectiveDisclosureProof",
    "build_proof",
    "verify_proof",
]
