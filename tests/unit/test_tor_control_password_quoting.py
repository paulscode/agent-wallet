# SPDX-License-Identifier: MIT
"""Tor control-protocol QuotedString escaping for AUTHENTICATE.

The control protocol requires backslash and double-quote to be
backslash-escaped inside a quoted string. The auto-generated password
never contains these, but a hand-set ``TOR_CONTROL_PASSWORD`` might —
without escaping, a ``"`` would break the quoting and could be misread
as additional control-protocol tokens.
"""

from __future__ import annotations

from app.services.anonymize.tor import _quote_control_password


def test_plain_password_is_quoted():
    assert _quote_control_password("abc123") == '"abc123"'


def test_double_quote_is_escaped():
    assert _quote_control_password('a"b') == '"a\\"b"'


def test_backslash_is_escaped():
    assert _quote_control_password("a\\b") == '"a\\\\b"'


def test_backslash_and_quote_combined():
    # Backslash must be escaped first so the escape of the quote isn't
    # itself doubled incorrectly.
    assert _quote_control_password('a\\"b') == '"a\\\\\\"b"'


def test_empty_password():
    assert _quote_control_password("") == '""'
