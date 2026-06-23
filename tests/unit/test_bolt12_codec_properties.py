# SPDX-License-Identifier: MIT
"""
Property-based round-trip tests for the BOLT 12 BigSize + TLV codecs.

Encode-then-decode must be the identity over arbitrary valid inputs, and
the decoder must reject the malformedness the BOLT 12 spec forbids
(out-of-order / duplicate TLV types). The existing codec tests pin
specific spec vectors; these generalize over generated inputs.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.services.bolt12 import bigsize
from app.services.bolt12.errors import Bolt12DecodeError
from app.services.bolt12.tlv import TLVRecord, decode_stream, encode_stream

# BigSize covers a u64; cover the whole range including the encoding-width
# boundaries (0xFC, 0xFFFF, 0xFFFFFFFF).
_U64 = st.integers(min_value=0, max_value=2**64 - 1)


class TestBigSizeRoundTrip:
    @given(_U64)
    def test_encode_decode_identity(self, n):
        value, offset = bigsize.decode(bigsize.encode(n), 0)
        assert value == n
        assert offset == bigsize.encoded_length(n) == len(bigsize.encode(n))

    @given(st.sampled_from([0, 0xFC, 0xFD, 0xFFFF, 0x1_0000, 0xFFFF_FFFF, 0x1_0000_0000, 2**64 - 1]))
    def test_width_boundaries(self, n):
        assert bigsize.decode(bigsize.encode(n))[0] == n


def _records_from_pairs(pairs):
    """Build a canonical (ascending types, unique) record list."""
    by_type = {t: v for t, v in pairs}
    return [TLVRecord(type=t, value=by_type[t]) for t in sorted(by_type)]


class TestTLVStreamRoundTrip:
    @given(st.lists(st.tuples(st.integers(min_value=0, max_value=2**32), st.binary(max_size=48)), max_size=8))
    def test_encode_decode_identity(self, pairs):
        records = _records_from_pairs(pairs)
        assert decode_stream(encode_stream(records)) == records

    @given(st.lists(st.tuples(st.integers(min_value=0, max_value=2**32), st.binary(max_size=48)), max_size=8))
    def test_reencode_is_canonical(self, pairs):
        records = _records_from_pairs(pairs)
        encoded = encode_stream(records)
        # Decoding then re-encoding yields byte-identical output.
        assert encode_stream(decode_stream(encoded)) == encoded


class TestTLVDecoderRejectsMalformed:
    def test_rejects_out_of_order(self):
        stream = encode_stream([TLVRecord(5, b"a")]) + encode_stream([TLVRecord(3, b"b")])
        with pytest.raises(Bolt12DecodeError, match="out of order"):
            decode_stream(stream)

    def test_rejects_duplicate_type(self):
        stream = TLVRecord(7, b"a").encode() + TLVRecord(7, b"b").encode()
        with pytest.raises(Bolt12DecodeError, match="duplicate"):
            decode_stream(stream)

    def test_rejects_truncated_value(self):
        # Declares a 10-byte value but supplies none.
        stream = bigsize.encode(1) + bigsize.encode(10)
        with pytest.raises(Bolt12DecodeError, match="truncated"):
            decode_stream(stream)

    def test_value_length_cap_enforced_before_alloc(self):
        stream = bigsize.encode(1) + bigsize.encode(1_000_000)
        with pytest.raises(Bolt12DecodeError, match="cap"):
            decode_stream(stream, max_value_bytes=1024)
