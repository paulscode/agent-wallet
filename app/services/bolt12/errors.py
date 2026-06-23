# SPDX-License-Identifier: MIT
"""Exception types raised by the BOLT 12 codec."""

from __future__ import annotations


class Bolt12Error(Exception):
    """Base class for all BOLT 12 codec errors."""


class Bolt12FormatError(Bolt12Error):
    """The outer bech32-no-checksum framing is malformed.

    Raised for: mixed case, missing `1` separator, unknown HRP,
    non-bech32 characters, isolated `+` continuation marker.
    """


class Bolt12DecodeError(Bolt12Error):
    """The inner byte stream cannot be decoded as TLV records.

    Raised for: truncated BigSize, truncated value, non-canonical
    BigSize encoding, out-of-order or duplicate TLV types.
    """


class Bolt12TLVError(Bolt12Error):
    """A specific TLV record violates BOLT 12 invariants.

    Reserved for higher-level field-level validation; not
    raised by the byte-level decoder.
    """
