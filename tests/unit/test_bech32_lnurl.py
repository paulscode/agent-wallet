# SPDX-License-Identifier: MIT
"""Tests for the LNURL bech32 decoder."""

from __future__ import annotations

from app.core.bech32_lnurl import decode_lnurl

# Reference vector encoded with our own helper from the URL below.
# (The widely-circulated LUD-01 example string is mis-quoted in many
# places online; this round-tripped vector is what a correct encoder
# produces for the canonical URL.)
_LUD01_LNURL = (
    "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35X"
    "VUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9"
    "XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS"
)
_LUD01_DECODED = "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df"


def test_decode_lud01_reference_vector() -> None:
    assert decode_lnurl(_LUD01_LNURL) == _LUD01_DECODED


def test_decode_lowercase_equivalent() -> None:
    assert decode_lnurl(_LUD01_LNURL.lower()) == _LUD01_DECODED


def test_mixed_case_rejected() -> None:
    mixed = _LUD01_LNURL[:6].lower() + _LUD01_LNURL[6:]
    assert decode_lnurl(mixed) is None


def test_wrong_hrp_rejected() -> None:
    # Replace "lnurl" prefix with another HRP — checksum will fail.
    bad = "abcde" + _LUD01_LNURL.lower()[5:]
    assert decode_lnurl(bad) is None


def test_bad_checksum_rejected() -> None:
    s = list(_LUD01_LNURL.lower())
    # Flip the last data char to break the checksum.
    s[-1] = "q" if s[-1] != "q" else "p"
    assert decode_lnurl("".join(s)) is None


def test_empty_input_rejected() -> None:
    assert decode_lnurl("") is None
    assert decode_lnurl("   ") is None  # type: ignore[arg-type]


def test_excessive_length_rejected() -> None:
    assert decode_lnurl("lnurl1" + "q" * 5000) is None


def test_invalid_charset_rejected() -> None:
    # 'b' / 'i' / 'o' / '1' are not in the bech32 charset.
    assert decode_lnurl("lnurl1qqqbqq") is None
