# SPDX-License-Identifier: MIT
"""Liveness endpoint for the Docker healthcheck.

``GET /livez`` returns 200 when the API container is internally
healthy and 503 when it is wedged. Wired to the api service's
``HEALTHCHECK`` in ``docker-compose.yml``; three consecutive 503s
(after the start-period grace window) cause Docker to restart the
container under ``restart: unless-stopped``.

The endpoint is intentionally **unauthenticated** — Docker
healthchecks can't carry credentials — and is intentionally
**minimal** in what it returns. The response body is a short JSON
diagnostic shape for an operator who curls it directly; the
Docker probe only cares about the HTTP status code.

Drives:

* LND reachability via the keepalive's most recent success
  timestamp. If the keepalive hasn't seen a successful
  ``getinfo`` within ``_LIVENESS_KEEPALIVE_MAX_AGE_S`` AND the
  process has been running long enough that warm-up doesn't
  apply, mark unhealthy.
* DB session viability via a ``SELECT 1`` round-trip. Catches the
  SQLAlchemy connection-pool exhaustion mode we saw during the
  2026-06-02 wedge (every probe raising ISCE → watchdog deferred
  forever → no path to self-heal).

The check deliberately does NOT call ``lnd_service.get_info()``
directly — the keepalive task already does that on a steady
cadence with its own timeout, retry, and active-recovery logic.
Reading the keepalive's cached state keeps the healthcheck cheap
(O(1)) AND independent of the same connection pool that may be
wedged.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Response
from sqlalchemy import text

logger = logging.getLogger(__name__)

# ``/livez`` is intentionally unauthenticated (Docker healthchecks can't
# carry credentials), so its body must not leak host-identifying strings.
# Upstream connection errors (httpx / httpx-socks) routinely embed the
# target URL — i.e. the LND ``.onion`` address:port — inside the exception
# text. Redact any onion host, ``host:port`` pair, or IP literal from the
# diagnostic ``last_error`` / ``error`` fields before returning them.
_ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion(?::\d+)?\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
_HOSTPORT_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?\b", re.IGNORECASE)


def _redact_sensitive(text_value: str) -> str:
    """Strip host/onion/IP identifiers from an upstream error string."""
    if not text_value:
        return text_value
    out = _ONION_RE.sub("[redacted-onion]", text_value)
    out = _IPV4_RE.sub("[redacted-ip]", out)
    out = _HOSTPORT_RE.sub("[redacted-host]", out)
    return out

# Maximum age of the keepalive's last successful probe before we
# call the container unhealthy. Tuned to comfortably exceed the
# default ``LND_KEEPALIVE_INTERVAL_S=60`` plus the
# ``_KEEPALIVE_TIMEOUT_S=20`` worst-case round, plus headroom for
# one active-recovery cycle. Going lower (e.g. 2 × interval) would
# flap the healthcheck on transient blips that the keepalive
# itself absorbs without operator action.
_LIVENESS_KEEPALIVE_MAX_AGE_S = 300

# Grace period after the keepalive started before its absence of a
# successful probe counts as unhealthy. Covers the cold-start case
# where the first ``getinfo`` legitimately takes 10–15 s over Tor
# and we're still waiting for it. Docker's own ``start_period`` (a
# longer grace at the container level) covers the period BEFORE
# the keepalive task even starts — this knob covers the window
# AFTER it starts but before the first success lands.
_LIVENESS_KEEPALIVE_GRACE_S = 90

# Wall-clock cap on the DB ping. Anything longer means SQLAlchemy
# is provisioning a new connection (the ISCE-cascade symptom from
# the 2026-06-02 wedge) or the database itself is unreachable;
# either way the API can't serve traffic, so report unhealthy
# rather than letting the healthcheck hang.
_LIVENESS_DB_PROBE_TIMEOUT_S = 5.0


router = APIRouter(tags=["health"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def _check_keepalive() -> tuple[bool, dict[str, Any]]:
    """Return ``(ok, diag)``. ``ok=False`` only when the keepalive
    task is enabled AND past its warm-up grace AND has no recent
    success."""
    from app.core.config import settings
    from app.services.lnd_keepalive import get_state

    interval = float(getattr(settings, "lnd_keepalive_interval_s", 60.0))
    if interval <= 0:
        return True, {"status": "skipped", "reason": "keepalive_disabled"}

    state = get_state()
    # ``/livez`` is unauthenticated, so its body carries only a coarse
    # liveness verdict. Host-identifying strings (channel peer pubkeys
    # / aliases) and fine-grained Tor/HS timing telemetry — which a
    # remote observer could use to fingerprint the host or time a
    # correlation/availability attack against the hidden service — are
    # served exclusively from the admin-gated ``/v1/status/tor``
    # snapshot.
    diag: dict[str, Any] = {}

    if state.last_success_at is None:
        # Warming up — has the task been running long enough that
        # we'd expect a first success by now?
        if state.started_at is None:
            return True, {**diag, "status": "warming", "reason": "not_started"}
        age = (_utcnow() - state.started_at).total_seconds()
        if age < _LIVENESS_KEEPALIVE_GRACE_S:
            return True, {**diag, "status": "warming", "reason": "grace_period"}
        return False, {
            **diag,
            "status": "unhealthy",
            "reason": "no_first_success",
            "last_error": _redact_sensitive((state.last_error or "")[:200]),
        }

    age = (_utcnow() - state.last_success_at).total_seconds()
    diag["last_success_age_s"] = round(age, 1)
    if age > _LIVENESS_KEEPALIVE_MAX_AGE_S:
        return False, {
            **diag,
            "status": "unhealthy",
            "reason": "last_success_stale",
            "last_error": _redact_sensitive((state.last_error or "")[:200]),
        }
    return True, {**diag, "status": "ok"}


async def _check_db() -> tuple[bool, dict[str, Any]]:
    """``SELECT 1`` round-trip. Fails fast on ISCE / pool
    exhaustion."""
    import asyncio

    from app.core.database import get_db_context

    try:
        async with get_db_context() as db:
            await asyncio.wait_for(
                db.execute(text("SELECT 1")),
                timeout=_LIVENESS_DB_PROBE_TIMEOUT_S,
            )
        return True, {"status": "ok"}
    except asyncio.TimeoutError:
        return False, {
            "status": "unhealthy",
            "reason": "db_probe_timeout",
            "timeout_s": _LIVENESS_DB_PROBE_TIMEOUT_S,
        }
    except Exception as exc:  # noqa: BLE001
        return False, {
            "status": "unhealthy",
            "reason": "db_probe_raised",
            "error": _redact_sensitive(f"{type(exc).__name__}: {str(exc)[:200]}"),
        }


@router.get("/livez")
async def livez(response: Response) -> dict[str, Any]:
    """Container-level liveness. 200 = healthy, 503 = restart-worthy.

    Each check failure is fail-safe (mark unhealthy) — when in
    doubt, prefer Docker bouncing the container over a silent
    wedge.
    """
    keepalive_ok, keepalive_diag = await _check_keepalive()
    db_ok, db_diag = await _check_db()

    overall_ok = keepalive_ok and db_ok
    if not overall_ok:
        response.status_code = 503
        logger.warning(
            "livez: unhealthy (keepalive_ok=%s db_ok=%s)",
            keepalive_ok,
            db_ok,
        )

    return {
        "status": "ok" if overall_ok else "unhealthy",
        "checks": {
            "keepalive": keepalive_diag,
            "db": db_diag,
        },
    }


__all__ = ["router"]
