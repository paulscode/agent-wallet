# SPDX-License-Identifier: MIT
"""DNS-leak / Tor-routing verification at startup.

The wallet relies on httpx's SOCKS5 transport to route every onion
+ clearnet HTTP request through Tor when ``LND_TOR_PROXY`` is set.
If the SOCKS transport ever silently falls back to direct connect
(scheme parsing bug, library upgrade, etc.), we'd leak the wallet's
clearnet identity AND the destination hostname.

This module runs ONCE at lifespan startup. It calls
``https://check.torproject.org/api/ip`` through the configured
proxy and checks the JSON ``IsTor`` field. ``True`` confirms the
round-trip actually traversed Tor.

Outcome:
  - ok        — IsTor=true; we're routing through Tor as expected.
  - skipped   — no proxy configured (clearnet-only deploy).
  - warning   — IsTor=false; LOG LOUDLY but don't refuse to start
                (dual-stack networks can produce ambiguous results;
                the operator decides).
  - failed    — could not reach the endpoint at all; informational.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# torproject.org's own service. Returns JSON of the form
# ``{"IsTor": true, "IP": "10.20.30.40"}``. Cheap (<1 KB body).
_PROBE_URL = "https://check.torproject.org/api/ip"
_PROBE_TIMEOUT_S = 15.0


@dataclass
class DNSLeakResult:
    """Outcome of the startup DNS-leak / Tor-routing check."""

    ok: bool
    skipped: bool
    is_tor: Optional[bool] = None
    observed_ip: Optional[str] = None
    error: Optional[str] = None


async def check_for_dns_leak() -> DNSLeakResult:
    """Confirm Tor routing actually works via the configured proxy.

    Loud-warns on a confirmed leak (``IsTor=false``); silent on a
    successful round-trip; informational on a network failure.
    """
    from app.core.config import settings

    proxy = (settings.lnd_tor_proxy or "").strip()
    if not proxy:
        return DNSLeakResult(ok=True, skipped=True)

    import httpx

    try:
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=_PROBE_TIMEOUT_S,
            verify=True,
        ) as client:
            resp = await client.get(_PROBE_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:  # noqa: BLE001
        # Tor unreachable / endpoint down / clock skew on cert —
        # information only. The proxy-reach check is the
        # canonical "proxy works at all" gate.
        msg = str(exc)[:200]
        logger.info(
            "tor dns leak check: could not probe %s (%s). Skipping verification — this is informational only.",
            _PROBE_URL,
            msg,
        )
        return DNSLeakResult(
            ok=True,
            skipped=False,
            error=msg,
        )

    is_tor = bool(data.get("IsTor"))
    observed_ip = data.get("IP")
    if not is_tor:
        # DNS leak / SOCKS routing failure. Surface loudly so the
        # operator notices BEFORE any onion traffic flows.
        logger.error(
            "tor dns leak check: ROUTE NOT VIA TOR — check.torproject.org "
            "reports IsTor=false (observed source IP %s). The wallet "
            "is configured for Tor via LND_TOR_PROXY=%s but the SOCKS5 "
            "transport is not actually routing traffic through Tor. "
            "Fix this before processing any onion-routed payment. "
            "See docs/operator_tor_runbook.md.",
            observed_ip,
            proxy,
        )
        return DNSLeakResult(
            ok=False,
            skipped=False,
            is_tor=False,
            observed_ip=observed_ip,
        )

    logger.info(
        "tor dns leak check: ok — check.torproject.org confirms IsTor=true.",
    )
    return DNSLeakResult(
        ok=True,
        skipped=False,
        is_tor=True,
        observed_ip=observed_ip,
    )


__all__ = ["DNSLeakResult", "check_for_dns_leak"]
