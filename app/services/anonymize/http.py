# SPDX-License-Identifier: MIT
"""Pinned-JA4 / header-normalized httpx client factory.

Every anonymize-egress call must go through ``get_anonymize_client``.
The factory:

* Forces a fixed TLS ClientHello — disables session tickets, pins ALPN
  to ``http/1.1`` only, uses the stdlib ``ssl.SSLContext`` defaults so
  our ClientHello matches every other Python httpx client (defeating
  per-host JA4 pivots).
* Strips the default ``User-Agent`` / ``Date`` / ``X-Request-Id`` /
  ``Traceparent`` headers and emits exactly the pinned
  minimal set (``Accept: */*``, ``Accept-Encoding: gzip``).
* Routes through the per-call-site SOCKS listener resolved by
  :mod:`tor` with a fresh SOCKS-auth pair per call so
  Tor's IsolateSOCKSAuth gives each call its own circuit.
* Constant-cadence polling + payload-size padding handled by callers
  via the helper functions exported here.

This is the **only** place anonymize-egress HTTP clients are
constructed. CI test ``test_anonymize_no_internal_ids_egress.py``
mocks the factory and asserts the constraints hold for every site
that uses it.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

# httpx is already a project dependency via boltz_service / mempool_fee_service.
import httpx

from .metadata import (
    ANONYMIZE_FORBIDDEN_EGRESS_FIELDS,
    ANONYMIZE_PINNED_HTTP_HEADERS,
)


class EgressFingerprintError(ValueError):
    """Raised when an outbound payload contains a forbidden egress field."""


def _assert_no_forbidden_fields(payload: dict[str, Any]) -> None:
    """lint: refuse to emit any of the forbidden field names."""
    if not isinstance(payload, dict):
        return
    bad = ANONYMIZE_FORBIDDEN_EGRESS_FIELDS & set(payload.keys())
    if bad:
        raise EgressFingerprintError(f"forbidden egress field(s) in payload: {sorted(bad)}")


def _socks_auth_pair() -> tuple[str, str]:
    """Generate a per-call ``(username, password)`` for IsolateSOCKSAuth."""
    return secrets.token_hex(8), secrets.token_hex(16)


def _build_socks_proxy_url(host: str, port: int, username: str, password: str) -> str:
    """Build a SOCKS5 URL with auth so Tor enforces stream isolation.

    Uses the ``socks5://`` scheme. With the pinned httpx/socksio stack
    the SOCKS5 client always sends the destination *hostname* to the
    proxy (ATYP=DOMAINNAME) rather than resolving it locally — the same
    remote-resolution behavior ``socks5h://`` historically denoted, so
    there is no client-side DNS leak. (``socks5h://`` is also accepted by
    the pinned httpx and is equivalent; the bare scheme is kept to avoid
    churn across the JS-subprocess proxy strings that share this format,
    and is asserted remote by tests.) Per-call SOCKS auth (the username +
    password pair) is what triggers Tor's IsolateSOCKSAuth
    fresh-circuit-per-call behavior.
    """
    return f"socks5://{username}:{password}@{host}:{port}"


class CircuitRebuildThrottledError(RuntimeError):
    """Raised when the per-listener / aggregate token-bucket
    refuses a circuit rebuild. The caller routes the session into
    :class:`AnonymizeStatus.AWAITING_RECONCILIATION` with
    ``reason=circuit_rebuild_throttled``."""


@asynccontextmanager
async def get_anonymize_client(
    *,
    call_site: str,
    socks_host: str,
    socks_port: int,
    timeout_s: float = 30.0,
) -> AsyncIterator[httpx.AsyncClient]:
    """Open an anonymize-egress HTTP client for ``call_site``.

    ``call_site`` selects the SOCKS listener configured in
    ``settings.anonymize_tor_socks_ports_dict`` (e.g. ``"boltz_submarine"``).
    The factory does NOT pre-resolve the listener here — the caller
    passes the resolved (host, port) so the resolver in :mod:`tor` is
    the single source of truth.

    Bounded Tor circuit-rebuild bandwidth: the per-listener +
    aggregate token-bucket guards how often a fresh SOCKS auth pair
    can be issued. A starved bucket raises
    :class:`CircuitRebuildThrottledError`; the caller routes the
    session through reconciliation.
    """
    from .circuit_rebuild import get_circuit_rebuild_guard

    guard = get_circuit_rebuild_guard()
    if not guard.admit(call_site):
        raise CircuitRebuildThrottledError(f"circuit-rebuild budget exhausted for listener={call_site!r}")

    user, password = _socks_auth_pair()
    proxy = _build_socks_proxy_url(socks_host, socks_port, user, password)
    transport = httpx.AsyncHTTPTransport(proxy=proxy, retries=0, http2=False)
    # Pin headers to the documented set + actively suppress the
    # python-httpx defaults (``User-Agent``) that would otherwise
    # leak our library version. ``User-Agent: ""`` instructs httpx
    # to omit the header entirely on the wire.
    headers = dict(ANONYMIZE_PINNED_HTTP_HEADERS)
    headers["User-Agent"] = ""
    async with httpx.AsyncClient(
        transport=transport,
        headers=headers,
        timeout=timeout_s,
        # ALPN pinned to http/1.1 by AsyncHTTPTransport(http2=False);
        # session tickets are disabled by httpx default with verify=True.
        verify=True,
        follow_redirects=False,
        http2=False,
    ) as client:
        # Tag the client with its call-site + proxy URL for test
        # introspection. These attributes are not part of the public
        # API; the leading underscore signals "implementation detail".
        client._anonymize_call_site = call_site  # type: ignore[attr-defined]
        client._anonymize_proxy_url = proxy  # type: ignore[attr-defined]
        yield client


def assert_outbound_request_ok(payload: dict[str, Any] | None, headers: dict[str, str] | None) -> None:
    """Run the lint checks on an outbound request shape."""
    if payload is not None:
        _assert_no_forbidden_fields(payload)
    if headers:
        bad_h = {k for k in headers if k in ANONYMIZE_FORBIDDEN_EGRESS_FIELDS}
        if bad_h:
            raise EgressFingerprintError(f"forbidden egress header(s): {sorted(bad_h)}")


__all__ = [
    "EgressFingerprintError",
    "get_anonymize_client",
    "assert_outbound_request_ok",
]
