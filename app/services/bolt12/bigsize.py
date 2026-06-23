# SPDX-License-Identifier: MIT
"""BigSize integer encoding (BOLT 1).

BigSize is a variable-length unsigned-integer encoding that uses 1, 3,
5, or 9 bytes depending on the value. Encodings must be canonical
(shortest possible), and decoders MUST reject non-canonical forms.
"""

from __future__ import annotations

from .errors import Bolt12DecodeError


def encode(n: int) -> bytes:
    """Encode an unsigned integer as a canonical BigSize value."""
    if n < 0:
        raise ValueError("BigSize values must be non-negative")
    if n < 0xFD:
        return bytes([n])
    if n < 0x10000:
        return b"\xfd" + n.to_bytes(2, "big")
    if n < 0x100000000:
        return b"\xfe" + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return b"\xff" + n.to_bytes(8, "big")
    raise ValueError("BigSize value exceeds 64 bits")


def decode(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode one BigSize at `offset`. Returns `(value, new_offset)`.

    Rejects non-canonical encodings (e.g. 0xfd-prefixed values < 0xfd).
    """
    if offset >= len(data):
        raise Bolt12DecodeError("BigSize: unexpected end of stream")
    head = data[offset]
    if head < 0xFD:
        return head, offset + 1
    if head == 0xFD:
        if offset + 3 > len(data):
            raise Bolt12DecodeError("BigSize: truncated 3-byte form")
        v = int.from_bytes(data[offset + 1 : offset + 3], "big")
        if v < 0xFD:
            raise Bolt12DecodeError("BigSize: non-canonical 3-byte encoding")
        return v, offset + 3
    if head == 0xFE:
        if offset + 5 > len(data):
            raise Bolt12DecodeError("BigSize: truncated 5-byte form")
        v = int.from_bytes(data[offset + 1 : offset + 5], "big")
        if v < 0x10000:
            raise Bolt12DecodeError("BigSize: non-canonical 5-byte encoding")
        return v, offset + 5
    # head == 0xff
    if offset + 9 > len(data):
        raise Bolt12DecodeError("BigSize: truncated 9-byte form")
    v = int.from_bytes(data[offset + 1 : offset + 9], "big")
    if v < 0x100000000:
        raise Bolt12DecodeError("BigSize: non-canonical 9-byte encoding")
    return v, offset + 9


def encoded_length(n: int) -> int:
    """Return the canonical encoded length in bytes for `n`."""
    if n < 0xFD:
        return 1
    if n < 0x10000:
        return 3
    if n < 0x100000000:
        return 5
    return 9
