# SPDX-License-Identifier: MIT
"""bech32-without-checksum framing for BOLT 12 (`lno` / `lnr` / `lni`).

BOLT 12 reuses the bech32 alphabet to ASCII-encode TLV byte streams
but **omits** the six-character checksum (the reasoning: QR codes
already carry their own error correction, and a bad parse can never
cause loss of funds).

Allowed framing:

    <hrp>1<data>

…optionally interspersed with `+` (followed by zero or more whitespace
characters) between two bech32 data characters. The `+`/whitespace is
elided before decoding. Strings must be either entirely lowercase or
entirely uppercase; mixed case is rejected.
"""

from __future__ import annotations

from .errors import Bolt12FormatError

# bech32 alphabet (BIP-173). Index of each character is its 5-bit value.
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_REV: dict[str, int] = {c: i for i, c in enumerate(_CHARSET)}

# HRPs supported by BOLT 12.
KNOWN_HRPS = frozenset({"lno", "lnr", "lni"})

_WHITESPACE = frozenset(" \t\r\n")

# Hard input cap for the no-checksum decoder. Matches
# the BOLT 12 API-model bound (``_MAX_BOLT12_LEN = 8192``); a longer
# offer/invoice string is rejected outright before the O(n) scan.
_MAX_INPUT_LEN = 8192


def _strip_continuations(s: str) -> str:
    """Remove `+` (and any trailing whitespace) when sandwiched between non-whitespace chars.

    Per BOLT 12 §Encoding: a `+` followed by zero or more whitespace
    characters between two bech32 characters MUST be removed before
    decoding. We treat the rule slightly more permissively than the
    literal spec wording — the surrounding chars need only be
    non-`+`-non-whitespace; subsequent bech32 / HRP validation will
    reject anything else.
    """
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "+":
            if not out:
                raise Bolt12FormatError("bech32: leading '+'")
            # Skip the optional whitespace run after `+`.
            j = i + 1
            while j < n and s[j] in _WHITESPACE:
                j += 1
            if j >= n:
                raise Bolt12FormatError("bech32: trailing '+'")
            if s[j] in ("+",) or s[j] in _WHITESPACE:
                raise Bolt12FormatError("bech32: '+' not followed by data char")
            i = j
            continue
        if c in _WHITESPACE:
            # Whitespace is only valid immediately after a `+` (handled
            # above). Stand-alone whitespace is a hard error.
            raise Bolt12FormatError("bech32: stray whitespace")
        out.append(c)
        i += 1
    return "".join(out)


def _convert_5_to_8(data5: list[int]) -> bytes:
    """Convert a sequence of 5-bit groups into a byte string (BIP-173 style)."""
    acc = 0
    bits = 0
    out = bytearray()
    for v in data5:
        if v < 0 or v >= 32:
            raise Bolt12FormatError("bech32: 5-bit value out of range")
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    # Per BIP-173 we permit up to 4 leftover bits IF they are zero. BOLT 12
    # additionally requires the trailing bits be zero (no padding shenanigans).
    if bits >= 5:
        raise Bolt12FormatError("bech32: excess bits after decoding")
    if bits > 0 and (acc & ((1 << bits) - 1)) != 0:
        raise Bolt12FormatError("bech32: non-zero padding bits")
    return bytes(out)


def _convert_8_to_5(data: bytes) -> list[int]:
    """Pack bytes into 5-bit groups (BIP-173 style)."""
    acc = 0
    bits = 0
    out: list[int] = []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append((acc >> bits) & 0x1F)
    if bits > 0:
        out.append((acc << (5 - bits)) & 0x1F)
    return out


def decode(s: str) -> tuple[str, bytes]:
    """Decode a BOLT 12 bech32-no-checksum string.

    Returns `(hrp, payload_bytes)`. Raises `Bolt12FormatError` on any
    framing violation (mixed case, unknown HRP, missing separator,
    invalid characters, dangling `+`, non-zero padding).
    """
    if not s:
        raise Bolt12FormatError("bech32: empty string")

    # Cap the input length so this O(n)
    # primitive is safe regardless of call site. Every reachable caller
    # is already bounded upstream (the API models cap at 8192 chars), but
    # bounding it here too makes the decoder defensively self-contained
    # against a future caller that forgets the outer limit.
    if len(s) > _MAX_INPUT_LEN:
        raise Bolt12FormatError(f"bech32: input too long ({len(s)} > {_MAX_INPUT_LEN})")

    # Whole-string case rule (applies *before* `+`/whitespace removal).
    has_lower = any("a" <= c <= "z" for c in s)
    has_upper = any("A" <= c <= "Z" for c in s)
    if has_lower and has_upper:
        raise Bolt12FormatError("bech32: mixed case")

    normalised = s.lower()
    normalised = _strip_continuations(normalised)

    sep = normalised.rfind("1")
    if sep < 1:
        raise Bolt12FormatError("bech32: missing or misplaced separator '1'")

    hrp = normalised[:sep]
    data_part = normalised[sep + 1 :]

    if hrp not in KNOWN_HRPS:
        raise Bolt12FormatError(f"bech32: unknown HRP {hrp!r}")
    if not data_part:
        raise Bolt12FormatError("bech32: empty data part")

    data5: list[int] = []
    for c in data_part:
        v = _CHARSET_REV.get(c)
        if v is None:
            raise Bolt12FormatError(f"bech32: invalid data char {c!r}")
        data5.append(v)

    payload = _convert_5_to_8(data5)
    return hrp, payload


def encode(hrp: str, payload: bytes) -> str:
    """Encode `(hrp, payload_bytes)` as a BOLT 12 bech32-no-checksum string."""
    if hrp not in KNOWN_HRPS:
        raise Bolt12FormatError(f"bech32: unknown HRP {hrp!r}")
    data5 = _convert_8_to_5(payload)
    return hrp + "1" + "".join(_CHARSET[v] for v in data5)
