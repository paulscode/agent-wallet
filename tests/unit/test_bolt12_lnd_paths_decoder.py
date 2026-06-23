# SPDX-License-Identifier: MIT
"""Tests for :func:`app.services.bolt12.lnd_paths.decode_invoice_paths`.

The decoder is the J2 inverse of ``encode_invoice_paths`` — it
takes the BOLT 12 wire blobs (``invoice_paths`` + ``invoice_blindedpay``)
and produces LND-shape :class:`BlindedPaymentPath` dicts ready to
splice into a ``QueryRoutesRequest``. Tested:

* Round-trip with the existing encoder (single + multi-path).
* Length-mismatch + truncation rejections.
* Zero-hop / num_hops=0 rejection per the BOLT 12 spec.
* Empty-features path (the common LND output shape).
"""

from __future__ import annotations

import base64

import pytest

from app.services.bolt12.lnd_paths import (
    decode_invoice_paths,
    encode_invoice_paths,
)


def _b64_33(byte: int) -> str:
    """Build a 33-byte compressed-pubkey-shape base64 string."""
    return base64.b64encode(bytes([byte]) + bytes([byte ^ 0xFF]) * 32).decode()


def _sample_path(*, num_hops: int = 1, base_fee: int = 1000) -> dict:
    """Build a synthetic LND-shape BlindedPaymentPath entry."""
    return {
        "blinded_path": {
            "introduction_node": _b64_33(0x02),
            "blinding_point": _b64_33(0x03),
            "blinded_hops": [
                {
                    "blinded_node": _b64_33(0x04 + i),
                    "encrypted_data": base64.b64encode(bytes([0x10 + i, 0x20 + i, 0x30 + i])).decode(),
                }
                for i in range(num_hops)
            ],
        },
        "base_fee_msat": base_fee,
        "proportional_fee_rate": 50,
        "total_cltv_delta": 144,
        "htlc_min_msat": "1",
        "htlc_max_msat": "1000000000",
        "features": "",
    }


# ── Round-trip ─────────────────────────────────────────────────────


def test_round_trip_single_path() -> None:
    """encode → decode preserves every field."""
    paths = [_sample_path(num_hops=2, base_fee=1000)]
    paths_b, pay_b = encode_invoice_paths(paths)
    decoded = decode_invoice_paths(paths_b, pay_b)
    assert len(decoded) == 1
    d = decoded[0]
    assert d["blinded_path"]["introduction_node"] == _b64_33(0x02)
    assert d["blinded_path"]["blinding_point"] == _b64_33(0x03)
    assert len(d["blinded_path"]["blinded_hops"]) == 2
    assert d["base_fee_msat"] == "1000"
    assert d["proportional_fee_rate"] == 50
    assert d["total_cltv_delta"] == 144
    assert d["htlc_min_msat"] == "1"
    assert d["htlc_max_msat"] == "1000000000"


def test_round_trip_multi_path() -> None:
    """Two paths in, two out, in the same order."""
    paths = [
        _sample_path(num_hops=1, base_fee=500),
        _sample_path(num_hops=3, base_fee=2500),
    ]
    paths_b, pay_b = encode_invoice_paths(paths)
    decoded = decode_invoice_paths(paths_b, pay_b)
    assert len(decoded) == 2
    assert decoded[0]["base_fee_msat"] == "500"
    assert decoded[1]["base_fee_msat"] == "2500"
    assert len(decoded[0]["blinded_path"]["blinded_hops"]) == 1
    assert len(decoded[1]["blinded_path"]["blinded_hops"]) == 3


def test_features_empty_omitted_in_output() -> None:
    """LND emits ``features: ""`` in the JSON; the decoder treats
    a zero-length feature bytestring as "no features" and omits
    the raw key from the output dict."""
    paths_b, pay_b = encode_invoice_paths([_sample_path()])
    decoded = decode_invoice_paths(paths_b, pay_b)
    assert "features_raw_b64" not in decoded[0]


def test_features_non_empty_round_trips_as_base64() -> None:
    spec = _sample_path()
    spec["features"] = base64.b64encode(b"\x80\x00").decode()
    paths_b, pay_b = encode_invoice_paths([spec])
    decoded = decode_invoice_paths(paths_b, pay_b)
    assert decoded[0]["features_raw_b64"] == base64.b64encode(b"\x80\x00").decode()


# ── Rejection paths ───────────────────────────────────────────────


def test_rejects_path_count_mismatch() -> None:
    """invoice_paths has 2 entries; invoice_blindedpay has 1 → reject."""
    paths_b, _ = encode_invoice_paths([_sample_path(), _sample_path()])
    _, pay_b = encode_invoice_paths([_sample_path()])
    with pytest.raises(ValueError, match="subtype-count"):
        decode_invoice_paths(paths_b, pay_b)


def test_rejects_truncated_path_blob() -> None:
    """A blob that ends mid-subtype must surface a clear error."""
    paths_b, pay_b = encode_invoice_paths([_sample_path()])
    with pytest.raises(ValueError, match="truncated"):
        decode_invoice_paths(paths_b[:-3], pay_b)


def test_rejects_truncated_payinfo_blob() -> None:
    paths_b, pay_b = encode_invoice_paths([_sample_path()])
    with pytest.raises(ValueError, match="truncated"):
        decode_invoice_paths(paths_b, pay_b[:-2])


def test_rejects_zero_hops() -> None:
    """num_hops=0 is forbidden by BOLT 12; the decoder must reject
    a path whose hop count is zero."""
    # Build a path blob manually: 33 + 33 + 1 (num_hops=0).
    path_bytes = b"\x02" + b"\x11" * 32 + b"\x03" + b"\x22" * 32 + b"\x00"
    # Build a minimal valid payinfo (count must match).
    _, pay_b = encode_invoice_paths([_sample_path()])
    with pytest.raises(ValueError, match="num_hops MUST be > 0"):
        decode_invoice_paths(path_bytes, pay_b)


# ── Empty input ────────────────────────────────────────────────────


def test_empty_input_returns_empty_list() -> None:
    assert decode_invoice_paths(b"", b"") == []
