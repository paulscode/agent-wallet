# SPDX-License-Identifier: MIT
"""Operator-supplied Tor reachability check at startup.

Operators running their own Tor (host Tor, Whonix, Tails) point
``LND_TOR_PROXY`` somewhere other than ``tor-proxy:9050`` and skip
the bundled service. The current code silently tolerates a
misconfigured proxy — the wallet boots, then every onion request
fails with an unhelpful "Connection refused" later.

This module runs ONCE at lifespan startup: a single SOCKS5 round-
trip via the configured proxy to a known clearnet target. Outcome:
  - ok       — proxy reachable + round-trip succeeded.
  - skipped  — no proxy configured (clearnet-only deploy).
  - failed   — log a clear error so the operator sees it on first
               boot. We don't refuse to start (clearnet endpoints
               still work); the log + audit row are the signal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# Probe URL is settings.tor_probe_url (env: ``TOR_PROBE_URL``);
# read inside the probe function so an operator's override takes
# effect without code edits. Default is Cloudflare's ``cdn-cgi/trace``
# — see config.py for the rationale.
_PROBE_TIMEOUT_S = 10.0


@dataclass
class ProxyReachResult:
    """Outcome of the one-shot proxy reachability probe."""

    ok: bool
    skipped: bool
    proxy: Optional[str]
    error: Optional[str] = None


async def check_tor_proxy_reachable() -> ProxyReachResult:
    """Probe the configured ``lnd_tor_proxy`` once. Returns the
    result; logging + audit are the operator-facing signals.

    No-op when ``LND_TOR_PROXY`` is empty — operators on clearnet
    deploys don't get a spurious error.
    """
    from app.core.config import settings

    proxy = (settings.lnd_tor_proxy or "").strip()
    if not proxy:
        return ProxyReachResult(ok=True, skipped=True, proxy=None)

    probe_url = settings.tor_probe_url

    import httpx

    try:
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=_PROBE_TIMEOUT_S,
            verify=True,
        ) as client:
            resp = await client.get(probe_url)
            resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)[:200]
        logger.error(
            "tor proxy reach check: %s did NOT respond to a SOCKS5 "
            "round-trip (%s). The wallet will still start, but any "
            "onion request will fail until the proxy is reachable. "
            "If you're running your own Tor outside docker, see "
            "docs/operator_tor_runbook.md.",
            proxy,
            msg,
        )
        return ProxyReachResult(ok=False, skipped=False, proxy=proxy, error=msg)

    logger.info(
        "tor proxy reach check: %s OK (one SOCKS5 round-trip succeeded).",
        proxy,
    )
    return ProxyReachResult(ok=True, skipped=False, proxy=proxy)


__all__ = ["ProxyReachResult", "check_tor_proxy_reachable"]
