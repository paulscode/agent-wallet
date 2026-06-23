# SPDX-License-Identifier: MIT
"""Bech32 decoder tailored for LNURL strings (LUD-01).

LNURL strings are bech32-encoded URLs with HRP ``lnurl``. Unlike
Bitcoin segwit addresses they are not limited to 90 characters; LUD-01
explicitly relaxes that cap. We therefore cannot reuse the segwit
decoder in :mod:`app.core.validation` directly.

The implementation here is small (≈40 LOC) and only does what we need:
decode an ``lnurl1...`` string into the original URL string. Encoding is
not implemented — we never need to produce LNURL strings.
"""

from __future__ import annotations

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1

# Hard cap on input length. LNURL strings in the wild are typically
# 90–250 characters; an attacker-supplied 4 KB string would explode
# polymod and waste CPU. 2048 chars is generous (~1.5 KB URL).
_MAX_LNURL_LEN = 2048


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: list[int], frombits: int, tobits: int, pad: bool) -> list[int] | None:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def decode_lnurl(s: str) -> str | None:
    """Decode a bech32 LNURL string into its original URL.

    Returns the decoded URL on success, or ``None`` on any decode
    error (mixed case, bad charset, bad checksum, wrong HRP, length
    out of bounds, non-UTF-8 payload).

    The function does **not** validate that the resulting string is
    a usable URL; that is the caller's responsibility.
    """
    if not isinstance(s, str) or not s:
        return None
    if len(s) > _MAX_LNURL_LEN:
        return None
    # Mixed case is forbidden by bech32.
    if s.lower() != s and s.upper() != s:
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return None
    hrp = s[:pos]
    if hrp != "lnurl":
        return None
    data: list[int] = []
    for c in s[pos + 1 :]:
        idx = _BECH32_CHARSET.find(c)
        if idx == -1:
            return None
        data.append(idx)
    if _polymod(_hrp_expand(hrp) + data) != _BECH32_CONST:
        return None
    payload = data[:-6]
    decoded_bytes = _convertbits(payload, 5, 8, pad=False)
    if decoded_bytes is None:
        return None
    try:
        url = bytes(decoded_bytes).decode("utf-8")
    except UnicodeDecodeError:
        return None
    return url
