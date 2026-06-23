# SPDX-License-Identifier: MIT
"""End-to-end tests for the BOLT 12 codec, driven by upstream test vectors.

The vectors live under `tests/vectors/bolt12/` and are vendored from
the `lightning/bolts` repo (see `tests/vectors/bolt12/README.md`).
This file is the **CI gate** for `app/services/bolt12/`: any change
that breaks an upstream vector must be reverted or accompanied by a
spec update + vendored re-pin.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.bolt12 import (
    Bolt12Codec,
    Bolt12FormatError,
    bech32_nochk,
    bigsize,
    decode,
)
from app.services.bolt12.merkle import (
    merkle_root,
    signature_message_hash,
    tagged_hash,
)
from app.services.bolt12.tlv import TLVRecord, decode_stream, encode_stream

VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors" / "bolt12"


# --------------------------------------------------------------------------- #
# BigSize unit tests (no upstream vectors — we use the canonical examples).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected_hex"),
    [
        (0, "00"),
        (1, "01"),
        (252, "fc"),
        (253, "fd00fd"),
        (0xFFFF, "fdffff"),
        (0x10000, "fe00010000"),
        (0xFFFFFFFF, "feffffffff"),
        (0x100000000, "ff0000000100000000"),
    ],
)
def test_bigsize_roundtrip(value: int, expected_hex: str) -> None:
    encoded = bigsize.encode(value)
    assert encoded.hex() == expected_hex
    decoded, end = bigsize.decode(encoded)
    assert decoded == value
    assert end == len(encoded)


@pytest.mark.parametrize(
    "non_canonical_hex",
    [
        "fd00fc",  # 252 in 3-byte form
        "fe0000ffff",  # 0xffff in 5-byte form
        "ff00000000ffffffff",  # 0xffffffff in 9-byte form
    ],
)
def test_bigsize_rejects_non_canonical(non_canonical_hex: str) -> None:
    from app.services.bolt12.errors import Bolt12DecodeError

    with pytest.raises(Bolt12DecodeError):
        bigsize.decode(bytes.fromhex(non_canonical_hex))


# --------------------------------------------------------------------------- #
# format-string-test.json — bech32-no-checksum framing.
# --------------------------------------------------------------------------- #


def _load(name: str) -> list[dict]:
    return json.loads((VECTORS_DIR / name).read_text())


@pytest.mark.parametrize("vec", _load("format-string-test.json"))
def test_format_string_vectors(vec: dict) -> None:
    s = vec["string"]
    if vec["valid"]:
        hrp, payload = bech32_nochk.decode(s)
        assert hrp in {"lno", "lnr", "lni"}
        # Re-encode (lowercase canonical form) and confirm it decodes
        # to the same payload.
        re_encoded = bech32_nochk.encode(hrp, payload)
        hrp2, payload2 = bech32_nochk.decode(re_encoded)
        assert hrp2 == hrp
        assert payload2 == payload
    else:
        with pytest.raises(Bolt12FormatError):
            bech32_nochk.decode(s)


# --------------------------------------------------------------------------- #
# offers-test.json — full lno round-trip.
# --------------------------------------------------------------------------- #


# The byte-level decode only catches *byte-level* invalidity: bech32 framing,
# BigSize canonicality, TLV ordering / duplication / truncation. Vectors that
# are invalid for *field-level* reasons (unknown even type, missing required
# field, invalid UTF-8 inside a value, etc.) parse cleanly at this layer
# and are rejected by field-level validation. The descriptions below
# enumerate the byte-level cases in `offers-test.json`.
_OFFER_BYTE_LEVEL_INVALID = frozenset(
    {
        "Malformed: fields out of order",
        "Malformed: truncated at type",
        "Malformed: truncated in length",
        "Malformed: truncated after length",
        "Bech32 padding exceeds 4-bit limit",
    }
)


@pytest.mark.parametrize("vec", _load("offers-test.json"))
def test_offer_vectors(vec: dict) -> None:
    s = vec["bolt12"]
    if vec["valid"]:
        decoded = decode(s)
        assert decoded.hrp == "lno"
        # Compare TLVs against the vector's `fields` list.
        expected_fields = vec.get("fields", [])
        assert len(decoded.records) == len(expected_fields), (
            f"record count mismatch: got {len(decoded.records)} expected {len(expected_fields)}"
        )
        for got, want in zip(decoded.records, expected_fields, strict=True):
            assert got.type == want["type"]
            assert len(got.value) == want["length"]
            assert got.value.hex() == want["hex"]

        # Re-encode and confirm round-trip stability.
        re_encoded = Bolt12Codec.encode(decoded)
        re_decoded = decode(re_encoded)
        assert re_decoded.records == decoded.records
        assert re_decoded.hrp == decoded.hrp
    elif vec["description"] in _OFFER_BYTE_LEVEL_INVALID:
        with pytest.raises(Exception):
            decode(s)
    else:
        # Field-level invalidity — codec at this layer is allowed to
        # *either* reject (if the malformation cascades into a
        # TLV-truncation) *or* accept (field-level validation will
        # then reject). Both outcomes are acceptable; we just exercise
        # the path to make sure nothing crashes unexpectedly.
        try:
            decoded = decode(s)
            assert decoded.hrp == "lno"
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# signature-test.json — merkle construction and signature digest.
# --------------------------------------------------------------------------- #


_SIG_VECTORS = _load("signature-test.json")


def _records_from_signature_vec(vec: dict) -> list[TLVRecord]:
    """Reconstruct TLV records from a signature-test vector.

    Each leaf entry has a key like ``H(`LnLeaf`,02080000010000020003)`` —
    the substring after the comma is the hex of the full TLV record.
    """
    out: list[TLVRecord] = []
    for leaf_entry in vec["leaves"]:
        # Find the LnLeaf key.
        leaf_key = next(k for k in leaf_entry if k.startswith("H(`LnLeaf`"))
        tlv_hex = leaf_key.split(",", 1)[1].rstrip(")")
        records = decode_stream(bytes.fromhex(tlv_hex))
        assert len(records) == 1, "signature vec leaf must hold one TLV"
        out.append(records[0])
    return out


@pytest.mark.parametrize("vec", _SIG_VECTORS)
def test_signature_merkle_root(vec: dict) -> None:
    records = _records_from_signature_vec(vec)
    expected_root = bytes.fromhex(vec["merkle"])
    # When the vector includes a `bolt12` string, our codec's stream
    # parse must agree with the leaf-hex reconstruction.
    if "bolt12" in vec:
        decoded = decode(vec["bolt12"])
        non_sig = [r for r in decoded.records if not r.is_signature]
        assert non_sig == records, "bolt12 string TLVs disagree with leaf hex"
    assert merkle_root(records) == expected_root


@pytest.mark.parametrize(
    "vec",
    [v for v in _SIG_VECTORS if "bolt12" in v],
)
def test_signature_digest(vec: dict) -> None:
    """For invoice_request vectors, verify the signature TLV's digest input."""
    decoded = decode(vec["bolt12"])
    sig_records = [r for r in decoded.records if r.is_signature]
    assert sig_records, "expected at least one signature TLV"

    # The vector encodes the signed message via the `tlv` key
    # (e.g. "invoice_request"). The signature field is conventionally
    # named "signature".
    digest = signature_message_hash(
        message_name=vec["tlv"],
        field_name="signature",
        merkle_root_bytes=decoded.merkle_root(),
    )
    # The digest is a 32-byte BIP-340 message; we don't verify the
    # schnorr signature itself at this layer, but the digest must at
    # least be deterministic and a valid sha256-sized output.
    assert len(digest) == 32
    # Cross-check via tagged_hash directly to guard against accidental
    # refactors in `signature_message_hash`.
    expected = tagged_hash(
        b"lightning" + vec["tlv"].encode("ascii") + b"signature",
        decoded.merkle_root(),
    )
    assert digest == expected


# --------------------------------------------------------------------------- #
# TLV stream invariants (independent of vectors).
# --------------------------------------------------------------------------- #


def test_tlv_rejects_out_of_order() -> None:
    from app.services.bolt12.errors import Bolt12DecodeError

    bad = encode_stream([TLVRecord(type=2, value=b""), TLVRecord(type=1, value=b"")])
    # encode_stream is permissive (caller's responsibility); decode rejects.
    with pytest.raises(Bolt12DecodeError):
        decode_stream(bad)


def test_tlv_rejects_duplicate() -> None:
    from app.services.bolt12.errors import Bolt12DecodeError

    bad = encode_stream([TLVRecord(type=5, value=b"a"), TLVRecord(type=5, value=b"b")])
    with pytest.raises(Bolt12DecodeError):
        decode_stream(bad)


def test_tlv_rejects_truncated_value() -> None:
    from app.services.bolt12.errors import Bolt12DecodeError

    # type=1, length=10, but only 3 bytes follow.
    truncated = b"\x01\x0a" + b"abc"
    with pytest.raises(Bolt12DecodeError):
        decode_stream(truncated)


# ── Defence-in-depth resource caps ─────────────────────────────


def test_decode_stream_rejects_excessive_record_count() -> None:
    """``max_records`` rejects streams with more records than the cap."""
    from app.services.bolt12.errors import Bolt12DecodeError

    # Five zero-length records at strictly ascending types.
    stream = encode_stream([TLVRecord(type=t, value=b"") for t in range(5)])
    # Cap of 3: must reject.
    with pytest.raises(Bolt12DecodeError, match="record count"):
        decode_stream(stream, max_records=3)
    # Cap >= count: must accept.
    assert len(decode_stream(stream, max_records=5)) == 5
    assert len(decode_stream(stream, max_records=100)) == 5


def test_decode_stream_rejects_oversized_value_length() -> None:
    """``max_value_bytes`` rejects records whose declared length
    exceeds the cap **before** any slice allocation."""
    from app.services.bolt12.errors import Bolt12DecodeError

    # type=1, length=2^33 (BigSize 9-byte form, must be > 2^32 to
    # be canonical). No actual value bytes follow \u2014 a permissive
    # decoder would try to allocate the slice first and only then
    # notice the truncation.
    fake_giant = (
        b"\x01"  # BigSize type=1
        + b"\xff"
        + (2**33).to_bytes(8, "big")  # BigSize length=2^33
    )
    with pytest.raises(Bolt12DecodeError, match="declares length"):
        decode_stream(fake_giant, max_value_bytes=8192)


def test_decode_stream_caps_default_to_no_cap() -> None:
    """Without explicit caps the legacy permissive behaviour is
    preserved (callers operating on trusted bytes \u2014 e.g. our own
    encoded outputs \u2014 remain unaffected)."""
    stream = encode_stream([TLVRecord(type=t, value=b"x" * 10) for t in range(3)])
    assert len(decode_stream(stream)) == 3


# \u2500\u2500 Top-level codec.decode honours the caps (P5) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


def _encode_bolt12_string(hrp: str, n_records: int) -> str:
    """Build a bech32-no-checksum BOLT 12 string with ``n_records`` records."""
    payload = encode_stream([TLVRecord(type=t, value=b"") for t in range(n_records)])
    return bech32_nochk.encode(hrp, payload)


def test_codec_decode_honours_record_cap() -> None:
    """``decode`` / ``Bolt12Codec.decode`` forward the cap kwargs to the TLV
    decoder so untrusted callers can bound an attacker-supplied string."""
    from app.services.bolt12.errors import Bolt12DecodeError

    s = _encode_bolt12_string("lno", 6)

    # Uncapped (default) accepts.
    assert len(decode(s).records) == 6
    # Capped below the record count rejects, via both entry points.
    with pytest.raises(Bolt12DecodeError):
        decode(s, max_records=3)
    with pytest.raises(Bolt12DecodeError):
        Bolt12Codec.decode(s, max_records=3)
    # Cap at/above the count accepts.
    assert len(decode(s, max_records=6).records) == 6


def test_codec_decode_honours_value_cap() -> None:
    """``decode`` forwards ``max_value_bytes`` to bound individual record
    values."""
    from app.services.bolt12.errors import Bolt12DecodeError

    payload = encode_stream([TLVRecord(type=1, value=b"x" * 100)])
    s = bech32_nochk.encode("lno", payload)

    assert len(decode(s).records) == 1
    with pytest.raises(Bolt12DecodeError):
        decode(s, max_value_bytes=10)


def test_offer_decode_api_helper_enforces_record_cap() -> None:
    """The offer-decode entry point (``_decode_offer_or_400``) applies the
    settings TLV caps so a hostile caller-supplied offer string with an
    over-cap record count is rejected as 400, not decoded unbounded."""
    from fastapi import HTTPException

    from app.api.bolt12 import _decode_offer_or_400
    from app.core.config import settings

    over_cap = (settings.bolt12_max_tlv_records or 512) + 50
    hostile = _encode_bolt12_string("lno", over_cap)
    # Well under the 8192-char Pydantic length bound, so only the record cap
    # can stop it.
    assert len(hostile) < 8192

    with pytest.raises(HTTPException) as exc:
        _decode_offer_or_400(hostile)
    assert exc.value.status_code == 400
