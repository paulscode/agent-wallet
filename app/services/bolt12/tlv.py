# SPDX-License-Identifier: MIT
"""TLV record encoding for BOLT 12 streams.

A BOLT 12 message is a *TLV stream*: a sequence of records, each
laid out as

    BigSize(type) || BigSize(length) || value[length]

with records strictly ordered by ascending type and **no duplicates**
(BOLT 1, BOLT 12 §Encoding).

Records of type 240..1000 are *signature TLV records* — they're never
included in the Merkle root calculation; their value is a 64-byte
BIP-340 signature over the merkle root of all *other* records.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import bigsize
from .errors import Bolt12DecodeError

# Inclusive range of TLV types reserved for signatures (BOLT 12).
SIG_TYPE_MIN = 240
SIG_TYPE_MAX = 1000


def is_signature_type(tlv_type: int) -> bool:
    """Return True iff `tlv_type` is in the signature-record range."""
    return SIG_TYPE_MIN <= tlv_type <= SIG_TYPE_MAX


@dataclass(frozen=True, slots=True)
class TLVRecord:
    """One TLV record from a BOLT 12 stream."""

    type: int
    value: bytes

    def encode(self) -> bytes:
        """Serialize this record (type + length + value) canonically."""
        if self.type < 0:
            raise ValueError("TLV type must be non-negative")
        return bigsize.encode(self.type) + bigsize.encode(len(self.value)) + self.value

    @property
    def is_signature(self) -> bool:
        return is_signature_type(self.type)

    @property
    def type_bytes(self) -> bytes:
        """The BigSize-encoded type, used as the LnNonce leaf message."""
        return bigsize.encode(self.type)


def decode_stream(
    data: bytes,
    *,
    max_records: int | None = None,
    max_value_bytes: int | None = None,
) -> list[TLVRecord]:
    """Decode `data` as a TLV stream. Validates ordering and uniqueness.

    Optional defence-in-depth caps:

    * ``max_records`` \u2014 reject streams that declare more records
      than the cap (default: no cap; legacy behaviour).
    * ``max_value_bytes`` \u2014 reject streams whose individual record
      length declarations exceed the cap **before** any slice
      allocation. This prevents a single ``length=2^31`` record
      from forcing the interpreter to allocate gigabytes of memory
      before truncation rejects it.

    Callers operating on untrusted bytes (the inbound onion-message
    path) should pass both caps from ``settings``.

    Raises ``Bolt12DecodeError`` on truncation, type-collision,
    out-of-order records, or cap violations.
    """
    out: list[TLVRecord] = []
    offset = 0
    last_type: int | None = None
    n = len(data)

    while offset < n:
        tlv_type, offset = bigsize.decode(data, offset)
        length, offset = bigsize.decode(data, offset)
        if max_value_bytes is not None and length > max_value_bytes:
            raise Bolt12DecodeError(
                f"TLV: record of type {tlv_type} declares length {length} \u003e cap {max_value_bytes}"
            )
        if offset + length > n:
            raise Bolt12DecodeError(f"TLV: value of type {tlv_type} truncated (need {length} bytes, have {n - offset})")
        value = data[offset : offset + length]
        offset += length

        if last_type is not None:
            if tlv_type == last_type:
                raise Bolt12DecodeError(f"TLV: duplicate type {tlv_type}")
            if tlv_type < last_type:
                raise Bolt12DecodeError(f"TLV: type {tlv_type} out of order after {last_type}")
        last_type = tlv_type
        if max_records is not None and len(out) >= max_records:
            raise Bolt12DecodeError(f"TLV: record count exceeds cap {max_records}")
        out.append(TLVRecord(type=tlv_type, value=value))

    return out


def encode_stream(records: list[TLVRecord]) -> bytes:
    """Concatenate `records` into a TLV stream.

    Caller is responsible for supplying records in ascending type
    order with no duplicates.
    """
    return b"".join(r.encode() for r in records)
