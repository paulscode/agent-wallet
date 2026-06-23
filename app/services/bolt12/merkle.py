# SPDX-License-Identifier: MIT
"""BOLT 12 Merkle-tree construction and signature digest.

Per BOLT 12 §Signature Calculation:

* Tagged-hash primitive (BIP-340 style):

      H(tag, msg) = SHA256( SHA256(tag) || SHA256(tag) || msg )

* For each non-signature TLV record `R` in ascending-type order, two
  leaves are emitted:

      leaf  = H( "LnLeaf", R_full_encoding )
      nonce = H( "LnNonce" || first_tlv_full_encoding, R_type_bigsize )

  where `first_tlv_full_encoding` is the entire (type+length+value)
  encoding of the **lowest-type non-signature** TLV in the stream.

  Each pair `(leaf, nonce)` is combined into a *paired* node:

      paired = H( "LnBranch", min(leaf, nonce) || max(leaf, nonce) )

* The list of paired nodes is then folded into a tree by repeatedly
  combining adjacent nodes with `H("LnBranch", min || max)`. When the
  count is not a power of two the deeper subtree always sits on the
  lower-index side (per spec).

* The signature for a record `S` of type T (240..1000) is BIP-340
  Schnorr over

      m = H( "lightning" || message_name || field_name, merkle_root )

  where `message_name` is the stream's name ("offer", "invoice_request",
  "invoice", "invoice_error") and `field_name` is the human-readable
  name of `S`'s containing field (almost always "signature").

This module implements only the construction up to `m`. Actual
schnorr verification is delegated to `app.services.bolt12.schnorr`.
"""

from __future__ import annotations

import hashlib

from .tlv import TLVRecord, is_signature_type


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    """BIP-340 tagged hash: SHA256(SHA256(tag)||SHA256(tag)||msg)."""
    th = _sha256(tag)
    return _sha256(th + th + msg)


def _branch(a: bytes, b: bytes) -> bytes:
    """LnBranch combine — lexicographically orders inputs first."""
    lo, hi = (a, b) if a <= b else (b, a)
    return tagged_hash(b"LnBranch", lo + hi)


def _pair_with_nonce(leaf: bytes, nonce: bytes) -> bytes:
    """Combine a TLV leaf with its nonce leaf via LnBranch.

    The order is min/max — same as every other LnBranch combination.
    """
    return _branch(leaf, nonce)


def _fold(nodes: list[bytes]) -> bytes:
    """Fold a list of paired nodes into a single root via LnBranch.

    Per BOLT 12: when the count is not a power of two, the *deepest*
    subtree sits on the lowest-order leaves. Concretely: split at the
    largest power of two strictly less than `n` (or `n // 2` when
    `n` is itself a power of two), recurse on each half, combine via
    LnBranch (min / max ordering).
    """
    n = len(nodes)
    if n == 0:
        raise ValueError("merkle: empty node list")
    if n == 1:
        return nodes[0]
    # Largest power of two ≤ n.
    pow2 = 1
    while pow2 * 2 <= n:
        pow2 *= 2
    # If n is itself a power of two, split in half; else split at pow2
    # so the left subtree is fully balanced.
    split = n // 2 if pow2 == n else pow2
    left = _fold(nodes[:split])
    right = _fold(nodes[split:])
    return _branch(left, right)


def merkle_root(records: list[TLVRecord]) -> bytes:
    """Compute the BOLT 12 merkle root of a TLV stream.

    Signature records (types 240..1000) are excluded from the root —
    they sign the root, so they cannot be part of it.
    """
    non_sig = [r for r in records if not is_signature_type(r.type)]
    if not non_sig:
        raise ValueError("merkle: no non-signature TLV records")

    first_tlv_encoding = non_sig[0].encode()
    nonce_tag = b"LnNonce" + first_tlv_encoding

    paired: list[bytes] = []
    for r in non_sig:
        leaf = tagged_hash(b"LnLeaf", r.encode())
        nonce = tagged_hash(nonce_tag, r.type_bytes)
        paired.append(_pair_with_nonce(leaf, nonce))

    return _fold(paired)


def signature_message_hash(
    *,
    message_name: str,
    field_name: str,
    merkle_root_bytes: bytes,
) -> bytes:
    """Compute the BIP-340 message digest that a signature TLV signs.

    Returns the 32-byte value `m = H(tag, merkle_root)` where the tag
    is `"lightning" || message_name || field_name`.
    """
    if len(merkle_root_bytes) != 32:
        raise ValueError("merkle root must be 32 bytes")
    tag = b"lightning" + message_name.encode("ascii") + field_name.encode("ascii")
    return tagged_hash(tag, merkle_root_bytes)
