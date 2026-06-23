# SPDX-License-Identifier: MIT
"""Input-length cap on the BOLT 12 no-checksum bech32 decoder.

The decoder is O(n) in the input length. Every reachable caller is
bounded upstream (the API models cap at 8192 chars), but the primitive
itself enforces a hard cap so it stays safe regardless of call site.
"""

from __future__ import annotations

import pytest

from app.services.bolt12.bech32_nochk import _MAX_INPUT_LEN, decode
from app.services.bolt12.errors import Bolt12FormatError


def test_oversized_input_is_rejected():
    giant = "lno1" + ("q" * (_MAX_INPUT_LEN + 10))
    with pytest.raises(Bolt12FormatError, match="too long"):
        decode(giant)


def test_at_cap_is_not_rejected_for_length():
    # A string exactly at the cap must not be rejected *for length* — it
    # may still fail later framing checks, but not with "too long".
    s = "lno1" + ("q" * (_MAX_INPUT_LEN - len("lno1")))
    assert len(s) == _MAX_INPUT_LEN
    try:
        decode(s)
    except Bolt12FormatError as exc:
        assert "too long" not in str(exc)
