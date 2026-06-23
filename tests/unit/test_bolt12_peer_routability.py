# SPDX-License-Identifier: MIT
"""Unit tests for ``_is_publicly_routable_peer_address``.

The helper gates which gateway peers are eligible as BOLT 12
introduction nodes. It must:

* Treat empty / missing addresses as non-routable (we have no way to
  reach a peer whose address we never recorded).
* Treat ``.onion`` hidden services as non-routable (public CLN/LDK
  payers without Tor egress can't connect).
* Treat clearnet IPv4 / IPv6 / DNS addresses as routable.
* Strip the port from LDK's ``host:port`` Display format correctly
  for every variant (including bracketed IPv6).
"""

from __future__ import annotations

import pytest

from app.api.bolt12 import _is_publicly_routable_peer_address


class TestRoutable:
    """Addresses that public-network payers can reach."""

    @pytest.mark.parametrize(
        "addr",
        [
            "1.2.3.4:9735",
            "10.0.0.1:9735",  # RFC1918 — not actually public, but our
            # filter is a heuristic; flagging private
            # IPs is out of scope.
            "203.0.113.42:9735",
            "[2001:db8::1]:9735",
            "[::1]:9735",
            "example.com:9735",
            "node.example.com:9735",
            # A DNS name that contains "onion" as a substring but is
            # NOT a Tor hidden service — only ``.onion`` TLD matches.
            "gateway.onion-router.example.com:9735",
        ],
    )
    def test_clearnet_address_is_routable(self, addr: str) -> None:
        assert _is_publicly_routable_peer_address(addr) is True


class TestNotRoutable:
    """Addresses that should fail the routability check."""

    def test_empty_string_is_not_routable(self) -> None:
        assert _is_publicly_routable_peer_address("") is False

    @pytest.mark.parametrize(
        "addr",
        [
            "voibgcjsapdylerigku4gdpmu6sdb5x32b4p3bddtzr52endivdacoad.onion:9735",
            # OnionV2 (deprecated, 16-char base32) shouldn't pass either.
            "abcdefghijklmnop.onion:9735",
            # Case-insensitive: capitalised .onion still excluded.
            "FOOBARBAZ.ONION:9735",
            # Even without a port, ``.onion`` should be flagged. (LDK
            # always emits port, but defence in depth.)
            "abc.onion",
        ],
    )
    def test_onion_address_is_not_routable(self, addr: str) -> None:
        assert _is_publicly_routable_peer_address(addr) is False
