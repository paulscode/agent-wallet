# SPDX-License-Identifier: MIT
"""Unit tests for ``app.core.net_guard``.

Covers the egress guard's verdicts on routable vs. non-routable
addresses, the resolve-and-pin behaviour (including refusal when a host
resolves — or re-resolves — to an internal range), and the request
argument builder that keeps the original hostname for TLS/Host while
connecting to the pinned IP.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from app.core import net_guard
from app.core.net_guard import (
    BlockedHostError,
    host_resolves_to_blocked,
    is_blocked_ip,
    pin_request_args,
    resolve_pinned_ip,
)


def _addrinfo(*ips: str) -> list:
    """Build a getaddrinfo-shaped return for the given IP strings."""
    out = []
    for ip in ips:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        out.append((fam, socket.SOCK_STREAM, 6, "", (ip, 0)))
    return out


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "0.0.0.0",
        "224.0.0.1",
        # CGNAT (RFC 6598) — was previously NOT blocked.
        "100.64.0.1",
        "100.127.255.254",
        # Benchmarking / documentation ranges (non-global).
        "198.18.0.1",
        "192.0.2.1",
        # 6to4-encapsulated internal targets — embedded v4 decoded.
        "2002:7f00:0001::1",  # embeds 127.0.0.1
        "2002:a9fe:a9fe::1",  # embeds 169.254.169.254 (metadata)
        "2002:0a00:0001::1",  # embeds 10.0.0.1
    ],
)
def test_blocked_ranges_are_blocked(ip: str) -> None:
    assert is_blocked_ip(ipaddress.ip_address(ip)) is True


@pytest.mark.parametrize(
    "ip",
    [
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "8.8.8.8",
        # 6to4 wrapping a *global* v4 must still be allowed.
        "2002:0808:0808::1",  # embeds 8.8.8.8
    ],
)
def test_routable_addresses_are_allowed(ip: str) -> None:
    assert is_blocked_ip(ipaddress.ip_address(ip)) is False


def test_onion_host_is_not_resolved_or_blocked() -> None:
    assert host_resolves_to_blocked("abc.onion") is False


def test_unresolvable_host_treated_as_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a, **_k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(net_guard.socket, "getaddrinfo", _boom)
    assert host_resolves_to_blocked("does-not-exist.example") is True


def test_literal_private_ip_blocked_without_dns() -> None:
    assert host_resolves_to_blocked("10.1.2.3") is True


def test_resolve_pinned_ip_returns_validated_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(net_guard.socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    assert resolve_pinned_ip("example.com", 443) == "93.184.216.34"


def test_resolve_pinned_ip_refuses_when_any_answer_is_private(monkeypatch: pytest.MonkeyPatch) -> None:
    # A round-robin record mixing a public and a private answer must be
    # refused outright, not filtered down to the public one.
    monkeypatch.setattr(
        net_guard.socket,
        "getaddrinfo",
        lambda *a, **k: _addrinfo("93.184.216.34", "169.254.169.254"),
    )
    with pytest.raises(BlockedHostError):
        resolve_pinned_ip("rebind.example", 443)


def test_pin_request_args_rewrites_host_keeps_sni_and_host_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(net_guard.socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    url, headers, extensions = pin_request_args("https://pay.example.com/lnurlp/alice?x=1")
    assert url == "https://93.184.216.34:443/lnurlp/alice?x=1"
    assert headers["Host"] == "pay.example.com"
    assert extensions["sni_hostname"] == "pay.example.com"


def test_pin_request_args_preserves_explicit_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(net_guard.socket, "getaddrinfo", lambda *a, **k: _addrinfo("93.184.216.34"))
    url, headers, _ext = pin_request_args("https://pay.example.com:8443/cb")
    assert url == "https://93.184.216.34:8443/cb"
    assert headers["Host"] == "pay.example.com:8443"


def test_pin_request_args_ipv6_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(net_guard.socket, "getaddrinfo", lambda *a, **k: _addrinfo("2606:4700:4700::1111"))
    url, _h, _e = pin_request_args("https://pay.example.com/cb")
    assert url == "https://[2606:4700:4700::1111]:443/cb"


def test_pin_request_args_refuses_rebind_to_private(monkeypatch: pytest.MonkeyPatch) -> None:
    # The validated host resolves to a private address at connection time:
    # pinning must refuse rather than hand back a usable request.
    monkeypatch.setattr(net_guard.socket, "getaddrinfo", lambda *a, **k: _addrinfo("127.0.0.1"))
    with pytest.raises(BlockedHostError):
        pin_request_args("https://rebind.example.com/cb")


def test_pin_request_args_rejects_onion() -> None:
    with pytest.raises(ValueError):
        pin_request_args("http://abc.onion/cb")


def test_cross_host_resolve_and_callback_each_pinned_independently(monkeypatch: pytest.MonkeyPatch) -> None:
    # A Lightning Address on one domain whose callback lives on another
    # (the "static .well-known file pointing at a provider" pattern) must
    # work: each host is resolved and pinned on its own.
    resolved = {"pay.example.com": "93.184.216.34", "relay.provider.test": "1.1.1.1"}

    def _resolve(host, *_a, **_k):
        return _addrinfo(resolved[host])

    monkeypatch.setattr(net_guard.socket, "getaddrinfo", _resolve)

    u1, h1, _ = pin_request_args("https://pay.example.com/.well-known/lnurlp/alice")
    u2, h2, _ = pin_request_args("https://relay.provider.test/cb")
    assert u1.startswith("https://93.184.216.34:443/")
    assert h1["Host"] == "pay.example.com"
    assert u2.startswith("https://1.1.1.1:443/")
    assert h2["Host"] == "relay.provider.test"
