# SPDX-License-Identifier: MIT
"""Per-listener SOCKS5 health probe.

The Dockerfile's circuit-validating healthcheck only round-trips via
port 9050 (``boltz_submarine``). A wedge on a different listener (e.g.
``chain_backend``) leaves the rest of the wallet stuck while Docker
still reports the container healthy. This module probes EACH SOCKS5
listener individually so the wallet has a per-listener signal.

Strategy
========

8 listeners × ~8 s per round-trip = ~64 s total. Probing them all on
every watchdog tick (30 s) would overlap and saturate the control
port + outbound network. Instead, the watchdog probes ONE listener
per tick (round-robin), so the full cycle completes every 8 ticks
(~4 minutes). Operators get a fresh probe per listener every cycle;
the result is cached between cycles for the dashboard.

Probe target
============

We use the same clearnet target the Dockerfile healthcheck uses
(``mempool.space``) so the probe's network behaviour is identical
across the two surfaces. A failure here means: the SOCKS5 listener
either won't accept connections at all (port not bound) OR can't
establish a working circuit through Tor. Both are situations the
watchdog should know about.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# Probe URL is settings.tor_probe_url (env: ``TOR_PROBE_URL``);
# read inside the probe function so an operator's override takes
# effect without code edits. Default is Cloudflare's ``cdn-cgi/trace``
# — small clearnet text response, anycast-backed, no Bitcoin-
# project association. See config.py for the rationale.
_PROBE_TIMEOUT_S = 8.0


@dataclass
class ListenerHealth:
    """Health snapshot for one SOCKS5 listener.

    ``ok`` is ``None`` until the first probe completes. A
    ``False`` value is informational, not fatal — the watchdog
    doesn't tear anything down based on this; it just surfaces
    the signal to the operator via the dashboard and audit log.
    """

    name: str
    port: int
    ok: Optional[bool] = None
    last_probe_ts: float = 0.0
    last_ok_ts: float = 0.0
    last_error: Optional[str] = None


# Module state: one entry per listener. Populated lazily on first
# probe of each port (so reconfiguration doesn't strand stale
# entries from old ports).
_listener_health: dict[str, ListenerHealth] = {}
# Index into the rotating probe schedule. Stored as a list so the
# rotation is stable even if the ports dict's iteration order
# varies across reloads.
_probe_cursor: int = 0


def _listener_names_sorted() -> list[str]:
    """Snapshot the configured listeners in deterministic order so
    the round-robin cursor lines up across reloads."""
    from app.core.config import settings

    return sorted(settings.anonymize_tor_socks_ports_dict.keys())


async def probe_one_listener(
    name: str,
    port: int,
    *,
    timeout_s: float = _PROBE_TIMEOUT_S,
) -> ListenerHealth:
    """Run one SOCKS5 round-trip via the named listener.

    Returns the updated :class:`ListenerHealth` regardless of
    outcome; the caller is responsible for surfacing the result.
    """
    import httpx

    health = _listener_health.setdefault(
        name,
        ListenerHealth(name=name, port=port),
    )
    # Keep the port up-to-date if the operator changed it via
    # ``anonymize_tor_socks_ports`` between probes.
    health.port = port
    health.last_probe_ts = time.monotonic()

    # Read the anonymize-pool SOCKS host from settings so
    # split-mode (``tor-anonymize``) and single-mode (``tor-proxy``)
    # work without touching this module.
    from app.core.config import settings

    socks_host = settings.anonymize_tor_socks_host or "tor-proxy"
    proxy = f"socks5h://{socks_host}:{port}"
    probe_url = settings.tor_probe_url
    try:
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=timeout_s,
            verify=True,
        ) as client:
            resp = await client.get(probe_url)
            resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        # Truncate the error so we don't blow up the in-memory state
        # if Tor returns a long ProxyError chain.
        health.ok = False
        health.last_error = str(exc)[:200]
        logger.info(
            "tor per-listener probe failed: %s (port=%d): %s",
            name,
            port,
            health.last_error,
        )
        return health

    health.ok = True
    health.last_error = None
    health.last_ok_ts = health.last_probe_ts
    return health


async def probe_next_listener() -> Optional[ListenerHealth]:
    """Probe the next listener in the round-robin. Returns the
    updated :class:`ListenerHealth`, or ``None`` if no listeners
    are configured.

    Called from the watchdog tick — one listener per tick keeps
    the network footprint flat while still cycling through all 8
    listeners every ~4 minutes (8 listeners × 30 s tick interval).
    """
    global _probe_cursor
    from app.core.config import settings

    names = _listener_names_sorted()
    if not names:
        return None
    ports_map = settings.anonymize_tor_socks_ports_dict
    # Wrap the cursor; tolerate the listener set shrinking.
    _probe_cursor %= len(names)
    name = names[_probe_cursor]
    _probe_cursor = (_probe_cursor + 1) % len(names)
    port = ports_map.get(name)
    if not port:
        return None
    return await probe_one_listener(name, port)


def get_snapshot() -> dict[str, dict]:
    """Snapshot all listener health entries as a JSON-serialisable
    dict keyed by listener name. The dashboard panel renders this
    as a per-listener status table."""
    now = time.monotonic()
    out: dict[str, dict] = {}
    for name, h in _listener_health.items():
        out[name] = {
            "port": h.port,
            "ok": h.ok,  # None until first probe
            "last_probe_age_s": ((now - h.last_probe_ts) if h.last_probe_ts else None),
            "last_ok_age_s": ((now - h.last_ok_ts) if h.last_ok_ts else None),
            "last_error": h.last_error,
        }
    return out


def _reset_for_tests() -> None:
    """Drop all listener state. Test-only."""
    global _probe_cursor
    _listener_health.clear()
    _probe_cursor = 0


__all__ = [
    "ListenerHealth",
    "get_snapshot",
    "probe_next_listener",
    "probe_one_listener",
]
