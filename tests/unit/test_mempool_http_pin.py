# SPDX-License-Identifier: MIT
"""The Mempool HTTP backend pins the resolved IP for clearnet hosts.

Validating the hostname and then connecting by hostname would leave a
DNS-rebind window between check and use. The backend resolves once to a
validated IP literal and connects to that, carrying the original host for
SNI / cert verification — the same posture every other clearnet egress
path uses.
"""

from __future__ import annotations

from unittest.mock import patch

from app.core.config import settings
from app.services.chain.mempool_http import MempoolHttpBackend


def _with_mempool_url(url: str):
    return patch.object(settings, "lnd_mempool_url", url)


def test_clearnet_host_is_pinned_to_resolved_ip():
    backend = MempoolHttpBackend()
    with _with_mempool_url("https://mempool.example.com/api/"), patch(
        "app.core.net_guard.resolve_pinned_ip", return_value="203.0.113.7"
    ):
        base_url, headers, sni = backend._resolve_pinned_target(needs_proxy=False)
    assert base_url == "https://203.0.113.7:443/api"
    assert headers == {"Host": "mempool.example.com"}
    assert sni == "mempool.example.com"


def test_resolution_refusal_propagates():
    """If the host resolves only to a non-routable address, the pin
    helper raises (the connection is never attempted)."""
    from app.core.net_guard import BlockedHostError

    backend = MempoolHttpBackend()
    with _with_mempool_url("https://rebind.example.com/"), patch(
        "app.core.net_guard.resolve_pinned_ip",
        side_effect=BlockedHostError("host resolves to a non-routable address"),
    ):
        try:
            backend._resolve_pinned_target(needs_proxy=False)
        except BlockedHostError:
            return
        raise AssertionError("expected BlockedHostError")


def test_proxied_host_is_not_pinned():
    backend = MempoolHttpBackend()
    with _with_mempool_url("https://mempool.example.com/"):
        base_url, headers, sni = backend._resolve_pinned_target(needs_proxy=True)
    assert base_url == "https://mempool.example.com"
    assert headers == {}
    assert sni is None


def test_onion_host_is_not_pinned():
    backend = MempoolHttpBackend()
    with _with_mempool_url("http://abcd.onion/api"):
        base_url, headers, sni = backend._resolve_pinned_target(needs_proxy=False)
    assert "abcd.onion" in base_url
    assert sni is None


def test_bare_ip_literal_is_not_re_resolved():
    backend = MempoolHttpBackend()
    with _with_mempool_url("https://203.0.113.7:8332/"):
        base_url, headers, sni = backend._resolve_pinned_target(needs_proxy=False)
    assert base_url == "https://203.0.113.7:8332"
    assert sni is None
