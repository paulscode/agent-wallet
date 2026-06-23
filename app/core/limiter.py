# SPDX-License-Identifier: MIT
"""
Shared SlowAPI rate limiter instance.

Extracted from main.py so dashboard routes can apply per-endpoint
rate limits (e.g., login brute-force protection) without circular imports.

Storage: prefers Redis (DB 2) so limits are shared across uvicorn
workers and replicas. Falls back to in-memory storage when Redis is
unreachable at startup with a loud warning — multi-worker deployments
must have Redis available for limits to be enforced correctly.
"""

import logging

from fastapi import Request
from slowapi import Limiter

from app.core.config import settings
from app.core.rate_limit import _redis_url_for_db

logger = logging.getLogger(__name__)

# Set when the limiter falls back to per-process in-memory storage, so
# the startup sequence can raise a security alert. In-memory storage is
# not shared across workers/replicas, so the effective limit becomes
# ``N × configured`` — operators must know when this is in effect.
storage_degraded_reason: str | None = None


def _get_client_ip(request: Request) -> str:
    """Extract client IP for rate limiting.

    Uses request.client.host which is set correctly by ProxyHeadersMiddleware
    when TRUSTED_PROXIES is configured. Never trusts X-Forwarded-For directly.
    """
    return request.client.host if request.client else "unknown"


def _build_limiter() -> Limiter:
    """Build the shared SlowAPI limiter with Redis storage when available."""
    global storage_degraded_reason
    if settings.redis_url:
        storage_uri = _redis_url_for_db(settings.redis_url, 2)
        # Probe Redis synchronously before binding it as the limiter
        # backend. SlowAPI's swallow_errors only wraps a subset of the
        # storage code-path; a hard ConnectionError on EVALSHA still
        # surfaces as a 500 to the request. Falling back to in-memory
        # storage on an unreachable Redis keeps single-worker
        # deployments functional and lets multi-worker deployments
        # surface the misconfiguration loudly via this warning.
        try:
            import redis as _redis_sync

            client = _redis_sync.Redis.from_url(storage_uri, socket_connect_timeout=2)
            client.ping()
            client.close()
            return Limiter(
                key_func=_get_client_ip,
                default_limits=[settings.slowapi_default_limit],
                storage_uri=storage_uri,
                # Defence-in-depth: if Redis goes down mid-flight,
                # log and pass requests rather than 500. The custom
                # rate-limiters in app/core/security.py and
                # app/core/rate_limit.py enforce stricter fail-closed
                # behaviour for high-value operations.
                swallow_errors=True,
            )
        except Exception as exc:
            global storage_degraded_reason
            storage_degraded_reason = f"Redis storage unavailable ({exc})"
            logger.warning(
                "SlowAPI Redis storage unavailable (%s) — falling back "
                "to in-memory storage. Multi-worker deployments will "
                "not share rate-limit state.",
                exc,
            )
    else:
        storage_degraded_reason = "REDIS_URL not configured"
        logger.warning(
            "REDIS_URL is not configured — SlowAPI is using in-memory "
            "rate-limit storage. Multi-worker deployments will not share "
            "rate-limit state."
        )
    return Limiter(key_func=_get_client_ip, default_limits=[settings.slowapi_default_limit])


limiter = _build_limiter()
