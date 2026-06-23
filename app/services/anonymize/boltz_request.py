# SPDX-License-Identifier: MIT
"""Pinned Boltz request shape.

Every Boltz API request the anonymize stack issues goes through one
of the builders in this module. The pinned shape is asserted by the
companion CI lint test
(`tests/unit/test_anonymize_boltz_request_shape.py`); a regression
that adds a new field would let an operator-side analyst see a wallet
fingerprint distinct from organic Boltz traffic.

This module ships two builders covering the reverse swap and a
``make_submarine_create_request()`` for the on-chain submarine swap.
"""

from __future__ import annotations

from typing import Any

# Payload-size padding. HTTP request bodies emitted by the
# anonymize stack are padded to fixed-size buckets so a passive
# observer can't infer the request kind from its byte count.
_PAD_BUCKETS_BYTES: tuple[int, ...] = (512, 1024, 2048, 4096, 8192, 16384)


_REVERSE_CREATE_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "from",
        "to",
        "preimageHash",
        "claimPublicKey",
        "invoiceAmount",
        "claimAddress",
        # payload-size padding — the request body carries an
        # opaque ``_pad`` field of variable length so the serialized
        # body is rounded up to the smallest containing bucket from
        # :data:`_PAD_BUCKETS_BYTES`. Receiving Boltz operators ignore
        # unknown fields per HTTP convention; the field is purely a
        # fingerprinting countermeasure.
        "_pad",
    }
)


_SUPPORTED_CHAINS: frozenset[str] = frozenset({"BTC", "L-BTC"})


def make_reverse_create_request(
    *,
    preimage_hash_hex: str,
    claim_public_key_hex: str,
    invoice_amount_sats: int,
    destination_address: str | None = None,
    from_chain: str = "BTC",
    to_chain: str = "BTC",
    pad: bool = True,
) -> dict[str, Any]:
    """The only request shape the anonymize stack POSTs to
    Boltz ``/swap/reverse``.

    Every kwarg corresponds to one of the fields in
    :data:`_REVERSE_CREATE_ALLOWED_FIELDS`. The builder refuses to
    return a dict containing any other key; the CI lint enforces
    that the request body emitted is a subset of the pinned set so
    a stray ``pairHash`` / ``preferredCurrency`` (Boltz feature
    flags the wallet's general-purpose swap path sometimes sets)
    can't slip in via the anonymize stack and fingerprint us.

    The default ``from_chain`` / ``to_chain`` of ``BTC`` produces the
    original BTC reverse-swap body. Liquid reverse swaps (LN→L-BTC)
    pass ``to_chain="L-BTC"`` and omit ``destination_address``: Boltz
    generates the Liquid lockup address itself (returned in the swap
    response) so the wallet does not pre-supply a claim address.

    ``pad=True`` (default) adds the ``_pad`` field rounding
    the serialized body up to the next bucket from
    :data:`_PAD_BUCKETS_BYTES`. Tests pass ``pad=False`` to keep
    fixture sizes deterministic.
    """
    if from_chain not in _SUPPORTED_CHAINS:
        raise ValueError(f"unsupported from_chain: {from_chain!r}")
    if to_chain not in _SUPPORTED_CHAINS:
        raise ValueError(f"unsupported to_chain: {to_chain!r}")
    out: dict[str, Any] = {
        "from": from_chain,
        "to": to_chain,
        "preimageHash": preimage_hash_hex,
        "claimPublicKey": claim_public_key_hex,
        "invoiceAmount": int(invoice_amount_sats),
    }
    if destination_address is not None:
        out["claimAddress"] = destination_address
    if pad:
        # Compute padding length so the JSON-serialized body
        # rounds up to the smallest bucket. ``json.dumps`` is run
        # twice: once to measure the un-padded size, once to produce
        # the final body. The pad string is opaque (printable ASCII)
        # so the request still round-trips through ``json.loads``.
        import json as _json

        unpadded = _json.dumps(out, separators=(",", ":")).encode("utf-8")
        n = len(unpadded)
        # Reserve space for the ``,"_pad":""`` overhead (~10 bytes).
        overhead = len(b',"_pad":""')
        target = _next_bucket_size(n + overhead)
        pad_len = max(0, target - n - overhead)
        out["_pad"] = "x" * pad_len
    # Guard rail — refuse to ship a request with unknown keys.
    bad = set(out.keys()) - _REVERSE_CREATE_ALLOWED_FIELDS
    if bad:
        raise ValueError(f"make_reverse_create_request produced unknown fields: {sorted(bad)}")
    return out


# Pinned submarine-swap request shape.
_SUBMARINE_CREATE_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "from",
        "to",
        "invoice",
        "refundPublicKey",
        "pairHash",
        # payload-size padding (same bucket policy as reverse).
        "_pad",
    }
)


def make_submarine_create_request(
    *,
    invoice: str,
    refund_public_key_hex: str,
    pair_hash: str | None = None,
    from_chain: str = "BTC",
    to_chain: str = "BTC",
    pad: bool = True,
) -> dict[str, Any]:
    """The only request shape the anonymize stack POSTs to
    Boltz ``/swap/submarine``.

    Mirrors :func:`make_reverse_create_request`: every kwarg maps to
    a single field in :data:`_SUBMARINE_CREATE_ALLOWED_FIELDS`. The
    request body carries no preimage hash — Boltz derives it from
    the BOLT11 ``invoice`` itself. The wallet's invoice generation
    happens upstream (e.g., via LND ``add_invoice``); this builder
    is purely the request-shape pinner.

    ``pair_hash`` is the operator-supplied freshness token from the
    pair-info response; on-chain submarine swaps include it when
    present so the operator can refuse on a stale fee quote.

    ``pad=True`` (default) adds the ``_pad`` field rounding
    the serialized body up to the next bucket from
    :data:`_PAD_BUCKETS_BYTES`. Tests pass ``pad=False`` to keep
    fixture sizes deterministic.
    """
    if from_chain not in _SUPPORTED_CHAINS:
        raise ValueError(f"unsupported from_chain: {from_chain!r}")
    if to_chain not in _SUPPORTED_CHAINS:
        raise ValueError(f"unsupported to_chain: {to_chain!r}")
    out: dict[str, Any] = {
        "from": from_chain,
        "to": to_chain,
        "invoice": invoice,
        "refundPublicKey": refund_public_key_hex,
    }
    if pair_hash:
        out["pairHash"] = pair_hash
    if pad:
        import json as _json

        unpadded = _json.dumps(out, separators=(",", ":")).encode("utf-8")
        n = len(unpadded)
        overhead = len(b',"_pad":""')
        target = _next_bucket_size(n + overhead)
        pad_len = max(0, target - n - overhead)
        out["_pad"] = "x" * pad_len
    bad = set(out.keys()) - _SUBMARINE_CREATE_ALLOWED_FIELDS
    if bad:
        raise ValueError(f"make_submarine_create_request produced unknown fields: {sorted(bad)}")
    return out


def assert_submarine_request_shape(body: dict[str, Any]) -> None:
    """Refuse to admit a submarine-create body that carries extra keys."""
    extras = set(body.keys()) - _SUBMARINE_CREATE_ALLOWED_FIELDS
    if extras:
        raise ValueError(f"submarine-swap request body has non-pinned fields: {sorted(extras)}")


def _next_bucket_size(n: int) -> int:
    """Return the smallest pad bucket that fits ``n`` bytes."""
    for cap in _PAD_BUCKETS_BYTES:
        if n <= cap:
            return cap
    return _PAD_BUCKETS_BYTES[-1]


def assert_reverse_request_shape(body: dict[str, Any]) -> None:
    """Refuse to admit a request body that carries extra keys.

    Used in tests + a hot-path runtime assertion when the wallet
    routes a non-builder-derived body through the anonymize HTTP
    client.
    """
    extras = set(body.keys()) - _REVERSE_CREATE_ALLOWED_FIELDS
    if extras:
        raise ValueError(f"reverse-swap request body has non-pinned fields: {sorted(extras)}")


def pad_request_body(serialized: bytes) -> bytes:
    """Pad ``serialized`` to the smallest fitting bucket.

    The padding goes into a JSON-comment-style trailer separated by
    a single ``\\x00`` byte so the HTTP client can strip it before
    posting (or the receiving operator can ignore trailing nulls).
    Bodies larger than the largest bucket pass through unpadded
    with a single-byte sentinel so the lint can still detect
    the pad operation.
    """
    n = len(serialized)
    for cap in _PAD_BUCKETS_BYTES:
        if n <= cap - 1:  # leave 1 byte for the sentinel
            return serialized + b"\x00" * (cap - n)
    return serialized + b"\x00"  # over-cap; mark with single null


__all__ = [
    "make_reverse_create_request",
    "make_submarine_create_request",
    "assert_reverse_request_shape",
    "assert_submarine_request_shape",
    "pad_request_body",
]
