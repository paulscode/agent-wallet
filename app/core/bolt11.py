# SPDX-License-Identifier: MIT
"""Minimal BOLT11 utilities.

The wallet normally decodes invoices via LND's ``/v1/payreq/{invoice}``
endpoint (see ``lnd_service.decode_payment_request``). That requires
LND to be reachable, which is exactly the precondition that fails on
the recovery code paths this module is built for — a swap whose
``pay_invoice`` call dropped mid-stream because the Tor circuit to
LND went away. To recover that swap we need the BOLT11 payment_hash
so we can track / reconcile the in-flight HTLC, and we need it
without taking another dependency on the very thing that just
failed.

The implementation is intentionally minimal:

* Only ``payment_hash_from_bolt11`` is exposed.
* No checksum validation, no HRP / amount / signature handling, no
  third-party dependency. A malformed input returns ``None`` rather
  than raising — recovery paths must not crash on garbage.
* Word-tagged BOLT11 is straightforward bech32; the payment_hash is
  the 32-byte payload of the ``p`` tag.

Reference: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
"""

from __future__ import annotations

import re
from typing import Optional

# Bech32 charset — index of each character is its 5-bit value.
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# BOLT11 HRP amount = <digits><multiplier?>. The multiplier scales the
# value (in BTC) by the power of ten below; absence means whole BTC.
# Expressed as millisatoshi-per-unit-digit to keep the arithmetic
# integer-exact: 1 BTC = 100_000_000_000 msat.
_HRP_MULTIPLIER_MSAT_PER_DIGIT = {
    "": 100_000_000_000,  # BTC
    "m": 100_000_000,  # milli-BTC
    "u": 100_000,  # micro-BTC
    "n": 100,  # nano-BTC
    "p": None,  # pico-BTC — 0.1 msat per digit; handled specially
}

# ``ln`` prefix, a lowercase currency prefix, then an optional amount
# (digits + optional multiplier). Amountless invoices have no digit run.
# The digit run is bounded so an absurdly long HRP cannot drive unbounded
# bigint work; the protocol maximum needs far fewer than 14 digits, and a
# longer run simply fails to match (parsed as malformed → ``None``).
_HRP_AMOUNT_RE = re.compile(r"^ln[a-z]+?(\d{1,14})([munp]?)$")


def _to_5bit(s: str) -> list[int]:
    out: list[int] = []
    for c in s:
        idx = _BECH32_CHARSET.find(c)
        if idx < 0:
            return []
        out.append(idx)
    return out


def _from_5bit_bytes(values: list[int]) -> bytes:
    """Pack a sequence of 5-bit values into bytes (big-endian)."""
    acc = 0
    bits = 0
    out = bytearray()
    for v in values:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


def payment_hash_from_bolt11(invoice: str) -> Optional[str]:
    """Extract the payment_hash from a BOLT11 invoice as a 64-char hex
    string. Returns ``None`` for any malformed input.

    Operates on the invoice text alone — no network calls, no LND
    dependency, no third-party libraries. Designed for use from
    recovery paths where the normal LND-backed decoder isn't
    available.
    """
    if not isinstance(invoice, str) or not invoice:
        return None
    inv = invoice.strip().lower()
    if not inv.startswith("ln"):
        return None
    # BOLT11 separates the HRP from the data with the LAST '1'
    # (because the bech32 charset itself has no '1').
    _, sep, data_part = inv.rpartition("1")
    if not sep or not data_part:
        return None
    # Trailing 6-char bech32 checksum, then a 104-group (65-byte)
    # signature suffix. Both are excluded before walking tagged fields so
    # a ``p``-valued group inside the signature can't be mis-parsed as a
    # payment-hash tag.
    if len(data_part) < 6 + 7 + 104:
        return None
    data_chars = data_part[:-6]
    # First 7 5-bit groups encode the timestamp; the last 104 are the sig.
    tagged = data_chars[7:-104]
    i = 0
    while i + 3 <= len(tagged):
        tag_char = tagged[i]
        length_high_c = tagged[i + 1]
        length_low_c = tagged[i + 2]
        try:
            length_high = _BECH32_CHARSET.index(length_high_c)
            length_low = _BECH32_CHARSET.index(length_low_c)
        except ValueError:
            return None
        # Tagged-field length is encoded in 5-bit groups (NOT bytes).
        field_5bit_count = length_high * 32 + length_low
        data_start = i + 3
        data_end = data_start + field_5bit_count
        if data_end > len(tagged):
            return None
        # 'p' = payment_hash, exactly 52 5-bit groups → 260 bits → 32 bytes
        # plus 4 padding bits. A field of any other length is not a
        # payment_hash; skip it rather than mis-reading the payload.
        if tag_char == "p" and field_5bit_count == 52:
            payload = _from_5bit_bytes(_to_5bit(tagged[data_start:data_end]))
            if len(payload) < 32:
                return None
            return payload[:32].hex()
        i = data_end
    return None


def principal_sats_from_bolt11(invoice: str) -> Optional[int]:
    """Return the invoice's principal amount in whole satoshis.

    Parses the amount encoded in the BOLT11 human-readable part
    (``lnbc<amount><multiplier>``) with integer-exact arithmetic. Returns
    ``None`` for an amountless invoice or any malformed input, and for a
    sub-satoshi principal that is not a whole number of sats (so a caller
    comparing against an expected whole-sat amount fails closed rather
    than rounding).

    Operates on the invoice text alone — no network calls, no LND
    dependency — so it is usable from the swap egress paths that must
    verify an operator-supplied hold invoice before paying it.
    """
    if not isinstance(invoice, str) or not invoice:
        return None
    inv = invoice.strip().lower()
    hrp, sep, _data = inv.rpartition("1")
    if not sep or not hrp:
        return None
    m = _HRP_AMOUNT_RE.match(hrp)
    if m is None:
        return None
    digits, multiplier = m.group(1), m.group(2)
    try:
        value = int(digits)
    except ValueError:
        return None
    if multiplier == "p":
        # 0.1 msat per digit; a sub-msat amount is invalid per spec.
        if value % 10 != 0:
            return None
        msat = value // 10
    else:
        per_digit = _HRP_MULTIPLIER_MSAT_PER_DIGIT[multiplier]
        assert per_digit is not None  # only "p" maps to None
        msat = value * per_digit
    if msat % 1000 != 0:
        return None
    return msat // 1000


__all__ = ["payment_hash_from_bolt11", "principal_sats_from_bolt11"]
