# SPDX-License-Identifier: MIT
"""
Redis-backed rate limiting for payment safety guards.

Implements two sliding-window checks:
1. Cumulative spend limit — total sats sent in a rolling time window
2. Velocity limit — max number of send transactions in a rolling window

Both use Redis sorted sets for efficient windowed counting.
Limits are configured via LND_RATE_LIMIT_* and LND_VELOCITY_* env vars.
Set any limit to 0 to disable it.
NOTE: These rate limits apply ONLY to the API layer (AI agent callers).
The dashboard (human operator) bypasses these intentionally — the node
owner should have unrestricted control. See app/dashboard/api.py docstring."""

import asyncio
import logging
import time
import uuid
from typing import Optional
from urllib.parse import urlparse, urlunparse

import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger(__name__)

_redis_client: Optional[aioredis.Redis] = None
_redis_lock = asyncio.Lock()


def _redis_url_for_db(url: str, db: int) -> str:
    """Return ``url`` with its path replaced by ``/<db>``.

    Preserves scheme, userinfo, host, port, query string, and fragment
    so TLS parameters (e.g. ``?ssl_cert_reqs=required`` on ``rediss://``)
    on the configured Redis URL are not silently stripped when the
    rate-limit client points at a different logical DB index.
    """
    parsed = urlparse(url)
    return urlunparse(parsed._replace(path=f"/{db}"))


_SPEND_CHECK_SCRIPT = """
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local amount = tonumber(ARGV[3])
local limit = tonumber(ARGV[4])
local member = ARGV[5]
local ttl = tonumber(ARGV[6])

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

local members = redis.call('ZRANGE', key, window_start, '+inf', 'BYSCORE')
local total = 0
for _, m in ipairs(members) do
    local amt = string.match(m, '^(%d+):')
    if amt then total = total + tonumber(amt) end
end

if total + amount > limit then
    return {0, tostring(total)}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl)
return {1, tostring(total + amount)}
"""

_VELOCITY_CHECK_SCRIPT = """
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local max_txns = tonumber(ARGV[3])
local member = ARGV[4]
local ttl = tonumber(ARGV[5])

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

local count = redis.call('ZCARD', key)
if count >= max_txns then
    return {0, tostring(count)}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl)
return {1, tostring(count + 1)}
"""


async def get_redis() -> aioredis.Redis:
    """Get or create the Redis client for rate limiting."""
    global _redis_client
    if _redis_client is None:
        async with _redis_lock:
            if _redis_client is None:
                _redis_client = aioredis.from_url(
                    _redis_url_for_db(settings.redis_url, 1),
                    decode_responses=True,
                    socket_connect_timeout=5,
                    # Bound every command read. Without this, a pooled
                    # connection that went half-open while idle (Redis
                    # server timeout / NAT drop) makes the next command
                    # block on a reply that never arrives — forever. That
                    # hang surfaces on the dashboard page route via
                    # verify_session(), so a refresh-after-idle spins
                    # indefinitely. A bounded read instead raises, which
                    # verify_session()'s Redis-unavailable fallback
                    # already handles gracefully.
                    socket_timeout=5,
                    # Proactively PING any connection idle longer than
                    # this before reusing it, transparently reconnecting
                    # if it's dead — the actual antidote to the
                    # stale-after-idle case (mirrors the DB engine's
                    # pool_pre_ping). 30s comfortably beats typical
                    # idle-connection reaping windows.
                    health_check_interval=30,
                    # Ride out a single transient blip rather than
                    # bouncing the user to /login on one dropped packet.
                    retry_on_timeout=True,
                )
    return _redis_client


async def close_redis() -> None:
    """Close the Redis client."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None


async def check_spend_limit(amount_sats: int, api_key_id: str) -> tuple[bool, Optional[str], Optional[str]]:
    """Check if a payment would exceed the cumulative spend limit.

    Uses an atomic Lua script to check and record in one round-trip.
    Returns (allowed, error_message, member_id). The member_id can be
    used with rollback_spend_limit() if the payment fails.
    """
    limit = settings.lnd_rate_limit_sats
    if limit <= 0:
        return True, None, None

    try:
        r = await get_redis()
        now = time.time()
        window_start = now - settings.lnd_rate_limit_window_seconds
        key = f"lwa:spend:{api_key_id}"
        member = f"{amount_sats}:{uuid.uuid4().hex}"
        ttl = settings.lnd_rate_limit_window_seconds + 60

        result = await r.eval(  # type: ignore[misc]
            _SPEND_CHECK_SCRIPT,
            1,
            key,
            str(window_start),
            str(now),
            str(amount_sats),
            str(limit),
            member,
            str(ttl),
        )

        allowed = int(result[0]) == 1
        current = result[1]

        if not allowed:
            window_mins = settings.lnd_rate_limit_window_seconds // 60
            return (
                False,
                (
                    f"Cumulative spend limit reached. "
                    f"Current window total: {current} sats, "
                    f"requested: {amount_sats:,} sats, "
                    f"limit: {limit:,} sats per {window_mins} min window."
                ),
                None,
            )
        return True, None, member

    except Exception as e:
        logger.error("Spend rate limit check failed: %s", e)
        if settings.rate_limit_fail_policy == "open":
            logger.warning("Rate limit fail-open: allowing payment without spend limit check")
            try:
                import asyncio

                from app.services.alert_service import send_alert

                asyncio.ensure_future(
                    send_alert(
                        "rate_limit_bypass",
                        f"Spend rate limit check failed, policy=open — payment allowed without rate limiting: {e}",
                    )
                )
            except Exception:
                pass
            return True, None, None
        return False, "Rate limiting unavailable — payments temporarily blocked for safety.", None


async def check_velocity_limit(api_key_id: str) -> tuple[bool, Optional[str], Optional[str]]:
    """Check if transaction count would exceed the velocity limit.

    Uses an atomic Lua script to check and record in one round-trip.
    Returns (allowed, error_message, member_id). The member_id can be
    used with rollback_velocity_limit() if the payment fails.
    """
    max_txns = settings.lnd_velocity_max_txns
    if max_txns <= 0:
        return True, None, None

    try:
        r = await get_redis()
        now = time.time()
        window_start = now - settings.lnd_velocity_window_seconds
        key = f"lwa:velocity:{api_key_id}"
        member = f"{now}:{uuid.uuid4().hex}"
        ttl = settings.lnd_velocity_window_seconds + 60

        result = await r.eval(  # type: ignore[misc]
            _VELOCITY_CHECK_SCRIPT,
            1,
            key,
            str(window_start),
            str(now),
            str(max_txns),
            member,
            str(ttl),
        )

        allowed = int(result[0]) == 1
        current = result[1]

        if not allowed:
            window_mins = settings.lnd_velocity_window_seconds // 60
            return (
                False,
                (
                    f"Transaction velocity limit reached. "
                    f"{current} transactions in the last {window_mins} min "
                    f"(limit: {max_txns})."
                ),
                None,
            )
        return True, None, member

    except Exception as e:
        logger.error("Velocity rate limit check failed: %s", e)
        if settings.rate_limit_fail_policy == "open":
            logger.warning("Rate limit fail-open: allowing payment without velocity limit check")
            try:
                import asyncio

                from app.services.alert_service import send_alert

                asyncio.ensure_future(
                    send_alert(
                        "rate_limit_bypass",
                        f"Velocity rate limit check failed, policy=open — payment allowed without rate limiting: {e}",
                    )
                )
            except Exception:
                pass
            return True, None, None
        return False, "Rate limiting unavailable — payments temporarily blocked for safety.", None


async def check_payment_limits(amount_sats: int, api_key_id: str) -> tuple[bool, Optional[str], Optional[dict]]:
    """Run all payment safety checks (spend + velocity).

    Returns (allowed, error_message, reservation). The reservation dict
    contains member IDs that should be rolled back via
    rollback_payment_limits() if the payment subsequently fails.
    """
    allowed, error, spend_member = await check_spend_limit(amount_sats, api_key_id)
    if not allowed:
        return False, error, None

    allowed, error, velocity_member = await check_velocity_limit(api_key_id)
    if not allowed:
        # Roll back the spend reservation since the velocity check failed
        if spend_member:
            await _rollback_member(f"lwa:spend:{api_key_id}", spend_member)
        return False, error, None

    return (
        True,
        None,
        {
            "api_key_id": api_key_id,
            "spend_member": spend_member,
            "velocity_member": velocity_member,
            "amount_sats": amount_sats,
        },
    )


async def _rollback_member(key: str, member: str) -> None:
    """Remove a single member from a rate-limit sorted set (best-effort)."""
    try:
        r = await get_redis()
        await r.zrem(key, member)
    except Exception as e:
        logger.warning("Rate limit rollback failed for %s: %s", key, e)


_RECONCILE_SPEND_SCRIPT = """
local key = KEYS[1]
local old_member = ARGV[1]
local new_member = ARGV[2]
local score = redis.call('ZSCORE', key, old_member)
if not score then
    return 0
end
redis.call('ZREM', key, old_member)
redis.call('ZADD', key, score, new_member)
return 1
"""


async def reconcile_spend_limit(reservation: Optional[dict], actual_sats: int) -> None:
    """Replace a worst-case spend reservation with the settled amount.

    A payment reserves the requested amount plus a fee budget before it
    leaves; the real routing fee is only known once it settles. Swapping
    the reserved member for one carrying the actual outflow keeps the
    rolling-window total aligned with what really left the wallet — both
    when the real fee came in under budget (freeing headroom) and when it
    ran over (consuming it). Best-effort; the reserved worst case stands
    if reconciliation can't complete.
    """
    if not reservation:
        return
    api_key_id = reservation.get("api_key_id", "")
    spend_member = reservation.get("spend_member")
    if not spend_member:
        return
    try:
        new_member = f"{max(0, int(actual_sats))}:{uuid.uuid4().hex}"
        r = await get_redis()
        await r.eval(  # type: ignore[misc]
            _RECONCILE_SPEND_SCRIPT,
            1,
            f"lwa:spend:{api_key_id}",
            spend_member,
            new_member,
        )
        # Keep the reservation pointing at the live member so any later
        # rollback targets the right entry.
        reservation["spend_member"] = new_member
    except Exception as e:
        logger.warning("Spend reconciliation failed for %s: %s", api_key_id, e)


async def rollback_payment_limits(reservation: Optional[dict]) -> None:
    """Roll back rate-limit reservations after a failed payment.

    This prevents failed payments from consuming rate-limit budget.
    Best-effort — failures are logged but don't propagate.
    """
    if not reservation:
        return

    api_key_id = reservation.get("api_key_id", "")
    spend_member = reservation.get("spend_member")
    velocity_member = reservation.get("velocity_member")

    if spend_member:
        await _rollback_member(f"lwa:spend:{api_key_id}", spend_member)
    if velocity_member:
        await _rollback_member(f"lwa:velocity:{api_key_id}", velocity_member)


# ─── Sign-message rate limit ────────────────────────────────────────────
#
# Sign operations are cheap on the LND side but every successful sign
# creates a permanent, public attestation. We cap them per identity per
# rolling hour using the same sorted-set pattern as the velocity check.

_SIGN_CHECK_SCRIPT = """
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local max_ops = tonumber(ARGV[3])
local member = ARGV[4]
local ttl = tonumber(ARGV[5])

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

local count = redis.call('ZCARD', key)
if count >= max_ops then
    return {0, tostring(count)}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl)
return {1, tostring(count + 1)}
"""

_SIGN_WINDOW_SECONDS = 3600


async def check_sign_rate_limit(identity: str, max_per_hour: int) -> tuple[bool, Optional[str]]:
    """Per-identity sliding-hour rate limit for sign operations.

    `identity` is a stable key (API key UUID, or the dashboard sentinel).
    Returns `(allowed, error_message)`. `max_per_hour <= 0` disables the
    check.

    Fails CLOSED on Redis errors regardless of `RATE_LIMIT_FAIL_POLICY`
    — sign caps protect against accidental over-issuance of public
    attestations and we'd rather refuse than silently un-cap.
    """
    if max_per_hour <= 0:
        return True, None
    try:
        r = await get_redis()
        now = time.time()
        window_start = now - _SIGN_WINDOW_SECONDS
        key = f"lwa:sign:{identity}"
        member = f"{now}:{uuid.uuid4().hex}"
        result = await r.eval(  # type: ignore[misc]
            _SIGN_CHECK_SCRIPT,
            1,
            key,
            str(window_start),
            str(now),
            str(max_per_hour),
            member,
            str(_SIGN_WINDOW_SECONDS + 60),
        )
        allowed = int(result[0]) == 1
        current = result[1]
        if not allowed:
            return False, (
                f"Sign rate limit reached: {current} sign operations in the last hour (limit: {max_per_hour})."
            )
        return True, None
    except Exception as e:
        logger.error("Sign rate limit check failed: %s", e)
        return False, "Rate limiting unavailable — sign operations temporarily blocked."
