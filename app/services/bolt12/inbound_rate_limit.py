# SPDX-License-Identifier: MIT
"""Per-payer + per-offer + global rate limiter for inbound BOLT 12 invreqs.

The receiver-side responder is reachable by *any* onion-message
peer, with no API-key boundary. Without a rate limit, a hostile
peer could fire millions of invreqs at the wallet and force LND to
mint just as many invoices (each consuming a ``r_hash`` slot and
a small amount of state). This module enforces THREE sliding-window
caps, configurable via:

* ``bolt12_inbound_rate_limit_count`` — max accepted invreqs per
  peer key per window (``0`` disables the per-peer limit).
* ``bolt12_inbound_rate_limit_per_offer_count`` — max accepted
  invreqs per *offer* (keyed on the offer ``issuer_id``) per window
  (``0`` disables it).
* ``bolt12_inbound_rate_limit_global_count`` — max accepted invreqs
  aggregated across ALL peers per window (``0`` disables the
  global cap).
* ``bolt12_inbound_rate_limit_window_seconds`` — shared window.

Onion-message senders are *anonymous*: BOLT 12 carries no
authenticated peer identity, and the per-peer key is the hex of
``invreq_payer_id`` (a fresh BIP-340 transient pubkey the sender
picks per call — CLN's ``fetchinvoice`` rotates it every request),
or the gateway's ``recv_id`` when absent. The per-peer bucket is
therefore only a courtesy bound against a naive repeat sender; a
deliberate attacker rotates the key for free. The **per-offer** and
**global** caps — which cannot be rotated away — are the effective
bounds: the per-offer cap stops one offer being milked for unbounded
mints, and the global cap stops cross-offer flooding.

All caps are checked + recorded in a single Redis ``EVAL`` so the
admission decision is atomic. Without atomicity one bucket's check
could pass while another invreq consumes a different bucket, and the
original invreq would commit to a slot it can't back out of.

Rate-limit failures default to **closed** — overly conservative,
but the alternative on a Redis outage is to silently expose the
LND mint endpoint. Operators who want fail-open behaviour can set
``rate_limit_fail_policy=open`` in env (the same knob the API-side
limiter honours).
"""

from __future__ import annotations

import logging
import time
import uuid

from app.core.config import settings
from app.core.rate_limit import get_redis

logger = logging.getLogger(__name__)


_GLOBAL_KEY = "lwa:bolt12:inbound:_global_"
# Sentinel offer key used when an invreq names no offer (offer-less). All
# offer-less invreqs share one per-offer bucket — they cannot be tied to a
# specific issued offer, so the per-offer cap degrades to a single shared
# allowance for them while the global cap remains the real bound.
_OFFERLESS_OFFER_KEY = "_offerless_"


# Three-key atomic admission script. Returns:
#   {1, peer_after, offer_after, global_after, ""}                  — allowed
#   {0, peer, offer, global, "per_peer"|"per_offer"|"global"}      — denied
# The script peels stale entries from all three ZSETs, checks each count
# against its cap, then atomically adds to all three iff every check passes.
# Single Redis EVAL = atomic decision across all buckets.
_THREE_TIER_SCRIPT = """
local peer_key = KEYS[1]
local offer_key = KEYS[2]
local global_key = KEYS[3]
local window_start = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local peer_max = tonumber(ARGV[3])
local offer_max = tonumber(ARGV[4])
local global_max = tonumber(ARGV[5])
local member = ARGV[6]
local ttl = tonumber(ARGV[7])

redis.call('ZREMRANGEBYSCORE', peer_key, '-inf', window_start)
redis.call('ZREMRANGEBYSCORE', offer_key, '-inf', window_start)
redis.call('ZREMRANGEBYSCORE', global_key, '-inf', window_start)

local peer_count = redis.call('ZCARD', peer_key)
local offer_count = redis.call('ZCARD', offer_key)
local global_count = redis.call('ZCARD', global_key)

if peer_max > 0 and peer_count >= peer_max then
    return {0, tostring(peer_count), tostring(offer_count), tostring(global_count), 'per_peer'}
end
if offer_max > 0 and offer_count >= offer_max then
    return {0, tostring(peer_count), tostring(offer_count), tostring(global_count), 'per_offer'}
end
if global_max > 0 and global_count >= global_max then
    return {0, tostring(peer_count), tostring(offer_count), tostring(global_count), 'global'}
end

redis.call('ZADD', peer_key, now, member)
redis.call('ZADD', offer_key, now, member)
redis.call('ZADD', global_key, now, member)
redis.call('EXPIRE', peer_key, ttl)
redis.call('EXPIRE', offer_key, ttl)
redis.call('EXPIRE', global_key, ttl)
return {1, tostring(peer_count + 1), tostring(offer_count + 1), tostring(global_count + 1), ''}
"""


async def check_inbound_invreq_rate(
    peer_key: str,
    offer_key: str | None = None,
) -> tuple[bool, str | None, str | None]:
    """Atomically check + record a new invreq under the per-peer,
    per-offer, and global buckets.

    ``offer_key`` is the offer's ``issuer_id`` hex (or ``None`` for an
    offer-less invreq, which shares a single offer bucket). Returns
    ``(allowed, reason, cap)``. ``cap`` is one of ``"per_peer"``,
    ``"per_offer"``, ``"global"``, or ``"backend"`` (the latter when Redis
    was unreachable under fail-closed policy). Both are ``None`` on success.
    """
    peer_limit = settings.bolt12_inbound_rate_limit_count
    offer_limit = settings.bolt12_inbound_rate_limit_per_offer_count
    global_limit = settings.bolt12_inbound_rate_limit_global_count
    if peer_limit <= 0 and offer_limit <= 0 and global_limit <= 0:
        return True, None, None

    try:
        r = await get_redis()
        now = time.time()
        window = settings.bolt12_inbound_rate_limit_window_seconds
        window_start = now - window
        per_peer_key = f"lwa:bolt12:inbound:{peer_key}"
        per_offer_key = f"lwa:bolt12:inbound:offer:{offer_key or _OFFERLESS_OFFER_KEY}"
        member = f"{now}:{uuid.uuid4().hex}"
        ttl = window + 60

        result = await r.eval(  # type: ignore[misc]
            _THREE_TIER_SCRIPT,
            3,
            per_peer_key,
            per_offer_key,
            _GLOBAL_KEY,
            str(window_start),
            str(now),
            str(peer_limit),
            str(offer_limit),
            str(global_limit),
            member,
            str(ttl),
        )
        allowed = int(result[0]) == 1
        peer_count = result[1]
        offer_count = result[2]
        global_count = result[3]
        cap = result[4]
        if not allowed:
            cap_str = cap.decode() if isinstance(cap, bytes) else cap
            return (
                False,
                (
                    f"BOLT 12 inbound rate limit hit ({cap_str}): "
                    f"peer={peer_count} offer={offer_count} global={global_count} "
                    f"window={window}s (peer_limit={peer_limit} "
                    f"offer_limit={offer_limit} global_limit={global_limit})"
                ),
                cap_str,
            )
        return True, None, None
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "BOLT 12 inbound rate limit check failed (%s); fail-policy=%s",
            exc,
            settings.rate_limit_fail_policy,
        )
        if settings.rate_limit_fail_policy == "open":
            return True, None, None
        return False, "rate-limit backend unavailable", "backend"


__all__ = ["check_inbound_invreq_rate"]
