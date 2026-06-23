# SPDX-License-Identifier: MIT
"""Startup exit-relay diversity smoke test.

The 8 SOCKS listeners are supposed to use distinct circuits via Tor's
per-SocksPort stream-isolation domain plus the ``IsolateDestAddr`` /
``IsolateDestPort`` flags. If a torrc typo or version-skew
breaks isolation, the threat-model collapses silently — every
anonymize session would use the same exit.

The existing :func:`assert_exit_relay_diversity` runs PER-SESSION at
admission time. It would catch a collision, but only for the specific
submarine + reverse pair being admitted. This smoke test is a
STRUCTURAL boot check: open one concurrent SOCKS5 probe per listener,
then read ``GETINFO circuit-status`` and assert each probe got a
distinct circuit id.

Behaviour
=========

* Run after Tor reports ``circuit_established`` so we don't trip
  on cold-start. The check is skipped (not failed) if Tor isn't ready.
* Probes run concurrently, with a short whole-batch timeout.
* HARD-fail (raise :class:`DiversitySmokeFailureError`) only when probes
  succeed but observably collide on the same circuit. That's a real
  isolation regression and refusing to start is the right response.
* SOFT-fail (log + audit; do not raise) when probes can't complete
  — a network blip at startup shouldn't refuse to serve traffic.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# Probe URL is settings.tor_probe_url (env: ``TOR_PROBE_URL``);
# read inside ``_hold_one_probe`` so an operator's override takes
# effect without code edits. Default is Cloudflare's ``cdn-cgi/trace``
# — see config.py for the rationale.
_PROBE_TIMEOUT_S = 8.0
_OVERALL_TIMEOUT_S = 15.0
# How long to keep the probe sockets open after the HTTP request
# completes, so Tor still has the corresponding circuit in
# ``circuit-status`` when we query it.
_CIRCUIT_INSPECT_HOLD_S = 2.0


class DiversitySmokeFailureError(RuntimeError):
    """Raised when probes succeed but observably share a circuit."""


@dataclass
class SmokeResult:
    """Outcome of the smoke test.

    ``ok`` is ``True`` only when every probe succeeded AND each
    probe used a distinct circuit. ``skipped`` is ``True`` when Tor
    wasn't ready and the check was bypassed.
    """

    ok: bool
    skipped: bool
    listeners_probed: int
    listeners_ok: int
    distinct_circuits: int
    error: Optional[str] = None


async def _hold_one_probe(port: int, hold_s: float) -> bool:
    """One probe: open a SOCKS5 connection via ``port``, make a
    HEAD/GET request, then hold the connection for ``hold_s``
    seconds so the circuit stays visible in circuit-status when we
    query it. Returns True on success."""
    import httpx

    # Anonymize-pool SOCKS host comes from settings.
    from app.core.config import settings

    socks_host = settings.anonymize_tor_socks_host or "tor-proxy"
    proxy = f"socks5h://{socks_host}:{port}"
    probe_url = settings.tor_probe_url
    try:
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=_PROBE_TIMEOUT_S,
            verify=True,
        ) as client:
            resp = await client.get(probe_url)
            resp.raise_for_status()
        # The client is now closed, but Tor's circuit-status keeps
        # the circuit for ~MaxCircuitDirtiness; the hold is just to
        # avoid a race where the inspect query is faster than the
        # close-and-cleanup path.
        await asyncio.sleep(hold_s)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "tor diversity smoke: probe on port %d failed: %s",
            port,
            exc,
        )
        return False


async def run_diversity_smoke() -> SmokeResult:
    """Public entrypoint — run the smoke test once.

    Behaviour matches the module docstring: skip on cold Tor, soft-
    fail on probe timeouts, hard-fail (raise) only on observed
    circuit collision."""
    from app.core.config import settings
    from app.services.anonymize.tor import (
        probe_tor_bootstrap_status,
        probe_tor_circuit_status,
    )

    # Skip when no Tor proxy is configured — there's nothing to
    # smoke-test. Keeps test/CI environments quiet.
    if not getattr(settings, "lnd_tor_proxy", None):
        return SmokeResult(
            ok=True,
            skipped=True,
            listeners_probed=0,
            listeners_ok=0,
            distinct_circuits=0,
            error="no Tor proxy configured",
        )

    ports_map = settings.anonymize_tor_socks_ports_dict
    if not ports_map:
        return SmokeResult(
            ok=True,
            skipped=True,
            listeners_probed=0,
            listeners_ok=0,
            distinct_circuits=0,
            error="no SOCKS listeners configured",
        )

    # Skip if Tor isn't ready — the smoke test isn't a bootstrap
    # check; let the watchdog drive recovery there.
    try:
        boot = await probe_tor_bootstrap_status()
    except Exception as exc:  # noqa: BLE001
        boot = None
        logger.info("tor diversity smoke: bootstrap probe raised %s", exc)
    if boot is None or not getattr(boot, "circuit_established", False):
        return SmokeResult(
            ok=True,
            skipped=True,
            listeners_probed=0,
            listeners_ok=0,
            distinct_circuits=0,
            error="tor not ready (circuit_established=False)",
        )

    # Snapshot the circuit-status BEFORE probing so we can identify
    # the new circuits the probes created (vs. circuits that existed
    # before we ran).
    before_circuits, _ = await probe_tor_circuit_status()
    before_ids = {c.circuit_id for c in before_circuits}

    ports = sorted(ports_map.items())  # stable order: (name, port)
    tasks = [asyncio.create_task(_hold_one_probe(port, _CIRCUIT_INSPECT_HOLD_S)) for _, port in ports]
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=_OVERALL_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        for t in tasks:
            t.cancel()
        return SmokeResult(
            ok=False,
            skipped=False,
            listeners_probed=len(ports),
            listeners_ok=0,
            distinct_circuits=0,
            error="overall timeout",
        )

    listeners_ok = sum(1 for r in results if r is True)
    after_circuits, _ = await probe_tor_circuit_status()
    after_ids = {c.circuit_id for c in after_circuits}
    new_ids = after_ids - before_ids
    distinct_circuits = len(new_ids)

    # HARD-fail: probes succeeded but isolation collapsed.
    if listeners_ok >= 2 and distinct_circuits < listeners_ok:
        # listeners_ok succeeded but they share circuits — broken
        # isolation. Refuse to start.
        msg = (
            f"exit-relay diversity smoke FAILED: "
            f"{listeners_ok} listeners succeeded but only "
            f"{distinct_circuits} distinct circuits were observed. "
            "Check that torrc applies IsolateDestAddr+IsolateDestPort "
            "(or IsolateSOCKSAuth) per SocksPort."
        )
        raise DiversitySmokeFailureError(msg)

    # SOFT-fail: some probes didn't complete (network, cold start);
    # log + audit but don't raise.
    ok = (listeners_ok == len(ports)) and (distinct_circuits >= listeners_ok)
    return SmokeResult(
        ok=ok,
        skipped=False,
        listeners_probed=len(ports),
        listeners_ok=listeners_ok,
        distinct_circuits=distinct_circuits,
        error=None if ok else "partial — some probes did not complete",
    )


__all__ = [
    "DiversitySmokeFailureError",
    "SmokeResult",
    "run_diversity_smoke",
]
