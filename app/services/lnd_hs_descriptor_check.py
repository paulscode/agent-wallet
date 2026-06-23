# SPDX-License-Identifier: MIT
"""LND-side HS descriptor freshness check.

If LND's onion service descriptor stops being republished by LND
(LND process down, LND-side Tor stuck, descriptor key issue), no
amount of wallet-side recovery helps: every onion call to LND will
fail because the HSDir copies expire. Currently undetectable from
the wallet — the operator sees "connection refused" forever.

This module issues ``HSFETCH <onion>`` on the wallet's Tor control
port at a periodic cadence (Celery beat task). HSFETCH is async —
Tor returns immediately, then emits an ``HS_DESC`` event with the
outcome:
  - ``RECEIVED`` — descriptor was fetched. LND is republishing.
  - ``FAILED``   — could not retrieve. LND's descriptor is stale
                   or LND-side Tor isn't publishing.

A consecutive-failure threshold guards against transient HSDir
flap. Crossing the threshold emits an audit-log warning the
dashboard surfaces.

Auto-remediation: the
:mod:`app.services.lnd_tor_supervisor` consumes this state +
corroborating signals to decide whether to fire HSFETCH / NEWNYM /
SIGHUP. The supervisor's escalation ladder is the
remediation path; this module is the *detection* surface. The
design was driven by the 2026-06-01 stale-descriptor incident.

(An earlier docstring here said *"we don't auto-remediate (only
LND can republish)"*. That assumption was based on stale-
descriptor failures being exclusively on the publisher side. The
2026-06-01 incident proved they can also originate in the
wallet's local Tor cache — refreshing via ``HSFETCH`` resolves
those, which is the supervisor's step 1.)
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


_HSFETCH_TIMEOUT_S = 60.0


@dataclass
class _State:
    """Module-level state. Persisted in-memory; a worker restart
    resets it (which is fine — the alarm is for *sustained* drift,
    not a single tick)."""

    last_fetch_attempt_ts: float = 0.0
    last_fetch_ok_ts: float = 0.0
    consecutive_failures: int = 0
    last_error: Optional[str] = None


_STATE = _State()


def get_state() -> _State:
    """Return the live freshness-check state (read-only — the
    dashboard panel reads this)."""
    return _STATE


def _extract_onion_hostname(url: str) -> Optional[str]:
    """Return the bare ``...onion`` hostname from ``url`` or None
    if the URL doesn't point at a hidden service. We DON'T include
    the port in the HSFETCH argument — Tor wants just the
    address-without-tld."""
    if not url or ".onion" not in url:
        return None
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return None
    host = (parsed.hostname or "").lower()
    if not host.endswith(".onion"):
        return None
    # HSFETCH wants the v3 address with the .onion suffix.
    return host


async def _hsfetch_and_wait(
    hostname: str,
    *,
    host: Optional[str] = None,
    port: Optional[int] = None,
    password: Optional[str] = None,
    timeout_s: float = _HSFETCH_TIMEOUT_S,
) -> tuple[bool, Optional[str]]:
    """Issue ``HSFETCH <hostname>`` and read events until we see a
    matching ``HS_DESC RECEIVED`` or ``HS_DESC FAILED``. Returns
    ``(ok, error)``.

    A timeout is not an outright failure — HSDirs can be slow.
    Caller decides whether timeout-counts-as-stale via
    consecutive-failure tracking.
    """
    from app.core.config import settings

    resolved_host = host or settings.anonymize_tor_control_host or "127.0.0.1"
    resolved_port = int(
        port if port is not None else settings.anonymize_tor_control_port,
    )
    resolved_pw = password if password is not None else settings.resolved_tor_control_password
    if not resolved_host or resolved_port <= 0:
        return False, "control port not configured"

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(resolved_host, resolved_port),
            timeout=10.0,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"control connect failed: {exc}"

    async def _send(cmd: str) -> str:
        writer.write((cmd + "\r\n").encode("ascii"))
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not line:
                break
            chunks.append(line)
            text = line.decode("ascii", errors="replace")
            if re.match(r"^[2-5]\d{2} ", text):
                break
        return b"".join(chunks).decode("ascii", errors="replace")

    try:
        if resolved_pw:
            auth_resp = await _send(f'AUTHENTICATE "{resolved_pw}"')
        else:
            auth_resp = await _send("AUTHENTICATE")
        if not auth_resp.startswith("250"):
            return False, f"AUTHENTICATE rejected: {auth_resp.strip()[:120]}"

        # Subscribe to HS_DESC so we can read the async result.
        sub_resp = await _send("SETEVENTS HS_DESC")
        if not sub_resp.startswith("250"):
            return False, f"SETEVENTS rejected: {sub_resp.strip()[:120]}"

        # Strip the .onion suffix — HSFETCH takes the bare base32
        # address only.
        bare = hostname[: -len(".onion")] if hostname.endswith(".onion") else hostname
        fetch_resp = await _send(f"HSFETCH {bare}")
        if not fetch_resp.startswith("250"):
            return False, f"HSFETCH rejected: {fetch_resp.strip()[:120]}"

        # Read async HS_DESC events until we see one for our address.
        # Tor emits multiple per HSDir queried — RECEIVED means at
        # least one HSDir served the descriptor.
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                return False, "HSFETCH timed out"
            if not line:
                return False, "control port EOF"
            text = line.decode("ascii", errors="replace").strip()
            if not text.startswith("650 HS_DESC "):
                continue
            # Lines look like:
            #   650 HS_DESC RECEIVED <addr> NO_AUTH <hsdir> <descid>
            #   650 HS_DESC FAILED <addr> NO_AUTH <hsdir> REASON=NOT_FOUND
            parts = text.split()
            if len(parts) < 4:
                continue
            action = parts[2]
            addr = parts[3].lower()
            if addr != bare.lower():
                continue
            if action == "RECEIVED":
                return True, None
            if action == "FAILED":
                # Capture the reason if present.
                reason = ""
                for p in parts:
                    if p.upper().startswith("REASON="):
                        reason = p[len("REASON=") :]
                        break
                return False, f"HSFETCH FAILED reason={reason or 'unknown'}"
        return False, "HSFETCH timed out (no matching HS_DESC event)"
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def check_lnd_hs_descriptor_freshness() -> dict:
    """Public entrypoint — issue HSFETCH against LND's onion and
    record the outcome. Returns a small dict the Celery wrapper
    forwards into its task-tracking result."""
    from app.core.config import settings
    from app.services.tor_watchdog import _emit_audit

    lnd_url = settings.lnd_rest_url or ""
    hostname = _extract_onion_hostname(lnd_url)
    if not hostname:
        # Clearnet LND deploy — no descriptor to check. Not an
        # error.
        return {"status": "skipped", "reason": "lnd_url_not_onion"}

    _STATE.last_fetch_attempt_ts = time.monotonic()
    ok, err = await _hsfetch_and_wait(hostname)
    if ok:
        _STATE.last_fetch_ok_ts = _STATE.last_fetch_attempt_ts
        _STATE.consecutive_failures = 0
        _STATE.last_error = None
        logger.info(
            "lnd hs descriptor: fetch ok for %s",
            hostname,
        )
        return {"status": "fresh", "hostname": hostname}

    _STATE.consecutive_failures += 1
    _STATE.last_error = err
    logger.warning(
        "lnd hs descriptor: fetch failed for %s (#%d consecutive): %s",
        hostname,
        _STATE.consecutive_failures,
        err,
    )
    # Emit an audit row once we've crossed the alarm threshold.
    # Threshold of 2 means: a one-tick blip is silent; sustained
    # failure (12h with default 6h cadence) emits.
    if _STATE.consecutive_failures >= 2:
        await _emit_audit(
            "lnd_hs_descriptor_stale",
            details={
                "hostname": hostname,
                "consecutive_failures": _STATE.consecutive_failures,
                "last_error": err,
            },
        )
    return {
        "status": "stale",
        "hostname": hostname,
        "consecutive_failures": _STATE.consecutive_failures,
        "error": err,
    }


# Public alias of ``_hsfetch_and_wait``. The implementation was
# originally private (underscore prefix) when this module's only
# caller was its own freshness-check task. The LND Tor
# supervisor later needed to reuse the same helper from another module;
# rather than have the supervisor reach into a leading-underscore
# symbol, we expose ``hsfetch_and_wait`` as the public name + keep
# the underscore alias so existing tests + the in-module call site
# at :func:`check_lnd_hs_descriptor_freshness` don't have to change.
hsfetch_and_wait = _hsfetch_and_wait


__all__ = [
    "check_lnd_hs_descriptor_freshness",
    "get_state",
    "hsfetch_and_wait",
]
