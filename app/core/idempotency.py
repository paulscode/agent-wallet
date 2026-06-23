# SPDX-License-Identifier: MIT
"""Idempotency-key support for mutating endpoints.

Clients may include an ``Idempotency-Key: <uuid>`` header on
``POST /v1/payments/pay``, ``POST /v1/payments/send-onchain``, and
similar money-moving endpoints. The first successful response is
cached in Redis for 24 h; subsequent requests with the same
(api_key_id, idempotency_key) tuple short-circuit and return the
stored response instead of re-executing the operation.

Design notes
------------

* Scope: cache key is ``api_key_id || idempotency_key`` so two
  different agents cannot collide on the same UUID.
* Conflict detection: if the *same* key is replayed but the request
  body hash differs from the stored fingerprint, we return 409 —
  the spec for Stripe/IETF idempotency-key drafts.
* Storage: Redis ``SETNX`` for the in-flight marker, ``SET ... EX``
  for the result. If Redis is unreachable while an ``Idempotency-Key``
  is in play, behaviour follows ``RATE_LIMIT_FAIL_POLICY``: ``closed``
  (the default) returns ``503`` so a retry cannot double-execute the
  operation the key was meant to protect; ``open`` degrades to
  pass-through. This mirrors the spend limiter's fail-closed posture.
* In-flight: a sentinel value distinguishes "request started but
  not yet completed" from "no record". Concurrent retries against
  an in-flight key get 409 instead of executing twice.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any, Optional, cast

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

_KEY_PREFIX = "agent_wallet:idem:"
_TTL_SECONDS = 60 * 60 * 24  # 24 h
# The in-flight marker must outlive the slowest operation the key
# protects. A Lightning payment may run up to its ``timeout_seconds``
# ceiling (300 s), so the default covers that worst case plus margin;
# callers performing a bounded operation may pass a tighter ``inflight_ttl``.
# If the marker expired while the operation was still running, a retry
# with the same key would be granted a fresh reservation and execute the
# money-moving operation a second time.
_INFLIGHT_TTL = 360  # seconds
_INFLIGHT_SENTINEL = "__inflight__"

# The reservation
# must be atomic. The previous SETNX-then-GET-then-SETNX-fallback
# had a TTL-fired-between-SETNX-and-GET race in which two concurrent
# retries could both reach the fallback ``return None`` branch and
# both execute the underlying money-moving operation. The Lua
# script below collapses "get-or-claim" into a single, atomic
# Redis operation:
#   * If the slot already exists, return the stored value.
#   * Otherwise install the in-flight marker and return ``nil``.
# Both branches run inside the same Redis EVAL invocation so no
# concurrent SETNX/GET can interleave.
_RESERVE_LUA = """
local existing = redis.call('GET', KEYS[1])
if existing then
    return existing
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
return false
"""

# Compare-and-set for the completed result. ARGV[3] is the in-flight
# sentinel substring. The write proceeds only when the slot is absent or
# still holds an in-flight marker; a slot that already holds a completed
# result is left untouched, so a slow finisher whose reservation was
# reclaimed cannot overwrite a newer cached response.
_STORE_LUA = """
local existing = redis.call('GET', KEYS[1])
if existing == false or string.find(existing, ARGV[3], 1, true) then
    redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
    return 1
end
return 0
"""


def _redis_client() -> Any | None:
    try:
        import redis  # type: ignore[import-untyped]

        from app.core.config import settings

        return redis.Redis.from_url(settings.redis_url, socket_timeout=2.0)
    except Exception:  # noqa: BLE001
        return None


def _fail_closed() -> bool:
    """True when an unavailable Redis should block rather than pass through."""
    from app.core.config import settings

    return (settings.rate_limit_fail_policy or "").strip().lower() != "open"


def _redis_unavailable() -> Optional[dict[str, Any]]:
    """Decide what to do when the idempotency store cannot be reached.

    With the default fail-closed policy this raises ``503`` so a client
    retrying after a timeout cannot slip past the missing idempotency
    guard and execute a money-moving operation twice. With ``open`` it
    returns ``None`` (pass-through, no idempotency protection).
    """
    if _fail_closed():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Idempotency store unavailable; retry shortly.",
        )
    return None


def _validate_key(raw: str) -> str:
    """Validate the idempotency key. Reject anything that isn't a UUID."""
    try:
        uuid.UUID(raw)
    except (ValueError, AttributeError, TypeError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Idempotency-Key must be a valid UUID",
        ) from e
    return raw


def _fingerprint(body: Any) -> str:
    """Stable hash of the request body for replay-conflict detection."""
    try:
        canon = json.dumps(body, sort_keys=True, default=str)
    except Exception:  # noqa: BLE001
        canon = repr(body)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _redis_key(api_key_id: str, idem_key: str) -> str:
    return f"{_KEY_PREFIX}{api_key_id}:{idem_key}"


def get_idempotency_key(request: Request) -> Optional[str]:
    """Read and validate the ``Idempotency-Key`` header. Returns ``None``
    if not provided. Raises 400 if malformed.
    """
    raw = request.headers.get("Idempotency-Key") or request.headers.get("idempotency-key")
    if not raw:
        return None
    return _validate_key(raw.strip())


def lookup_or_reserve(
    *,
    api_key_id: str,
    idem_key: str,
    request_body: Any,
    inflight_ttl: int = _INFLIGHT_TTL,
) -> Optional[dict[str, Any]]:
    """Return a cached response if one exists for this key.

    Behaviour:

    * Returns ``None`` and reserves the slot (in-flight) when the
      key is fresh — caller should execute and then call
      :func:`store_result`.
    * Returns the cached response dict when the key already has a
      successful prior result with a *matching* body fingerprint.
    * Raises HTTP 409 if either (a) the key is currently in flight
      or (b) the stored fingerprint does not match the new body
      (replay-conflict).
    * Returns ``None`` (no caching) if Redis is unavailable —
      idempotency degrades open rather than blocking traffic.
    """
    client = _redis_client()
    if client is None:
        return _redis_unavailable()
    try:
        key = _redis_key(api_key_id, idem_key)
        fp = _fingerprint(request_body)

        # Atomic get-or-claim. ``eval`` returns either the
        # existing stored payload (str/bytes) or a falsy value
        # (None / False / 0) when we successfully installed the
        # in-flight marker. There is no SETNX/GET interleaving
        # window for a concurrent retry to slip through.
        marker = json.dumps({"state": "inflight", "sentinel": _INFLIGHT_SENTINEL, "fp": fp, "ts": time.time()})
        try:
            raw = client.eval(_RESERVE_LUA, 1, key, marker, inflight_ttl)
        except Exception as e:  # noqa: BLE001
            # The atomic reserve-or-return is the only safe primitive for a
            # money-moving idempotency check: the non-atomic SETNX+GET+SETNX
            # fallback has a double-execute window when the in-flight marker
            # expires mid-operation. Modern Redis always ships EVAL, so a
            # failure here means a scripting-disabled / misconfigured
            # backend. Fail closed rather than degrade to the racy path.
            logger.error(
                "idempotency: EVAL unavailable (%s); refusing the request "
                "rather than degrading to a non-atomic claim. Enable Redis "
                "scripting (EVAL) for idempotent endpoints.",
                e,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Idempotency backend unavailable — please retry.",
            ) from e

        if not raw:
            # Atomic EVAL claimed the slot for us.
            return None
        # Slot existed — decode and decide.
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        try:
            stored = json.loads(raw)
        except Exception:  # noqa: BLE001
            return None  # corrupt cache; fall through to re-execute

        if not hmac.compare_digest(stored.get("fp") or "", fp):
            # Same key, different body — IETF idempotency draft 409.
            # Constant-time compare avoids leaking the stored
            # fingerprint via response-timing on repeated probes.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=("Idempotency-Key reused with a different request body. Use a fresh UUID for a new request."),
            )
        if stored.get("state") in ("inflight", "pending"):
            # ``pending`` means a prior attempt's outcome is still unknown
            # (e.g. a Lightning HTLC that may yet settle). Reject the retry
            # rather than re-execute; reconciliation resolves the slot to a
            # completed result or releases it for a fresh attempt.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "A request with this Idempotency-Key is still in flight; "
                    "wait for the prior response or retry later."
                ),
            )
        if stored.get("state") == "completed":
            return cast(Optional[dict[str, Any]], stored.get("response"))
        return None
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        # The store became unreachable mid-operation (connection drop,
        # timeout). Treat it the same as an unavailable store at entry.
        logger.warning("idempotency lookup failed: %s", e)
        return _redis_unavailable()


def store_result(
    *,
    api_key_id: str,
    idem_key: str,
    request_body: Any,
    response: Any,
    status_code: int = 200,
) -> None:
    """Persist the successful response for 24 h. Best-effort.

    Only call on successful (2xx) responses; failures are NOT
    cached so a transient error does not poison the slot.
    """
    client = _redis_client()
    if client is None:
        return
    try:
        key = _redis_key(api_key_id, idem_key)
        fp = _fingerprint(request_body)
        # Serialise carefully: pydantic models become dicts via .model_dump()
        # but most call sites pass already-jsonifiable structures.
        try:
            payload = json.dumps(
                {
                    "state": "completed",
                    "fp": fp,
                    "ts": time.time(),
                    "status_code": status_code,
                    "response": response,
                },
                default=str,
            )
        except Exception:  # noqa: BLE001
            return
        try:
            client.eval(_STORE_LUA, 1, key, payload, _TTL_SECONDS, _INFLIGHT_SENTINEL)
        except Exception:  # noqa: BLE001
            # Older Redis or eval disabled — write unconditionally.
            client.set(key, payload, ex=_TTL_SECONDS)
    except Exception as e:  # noqa: BLE001
        logger.debug("idempotency store failed: %s", e)


def release_inflight(*, api_key_id: str, idem_key: str) -> None:
    """Drop the in-flight marker on a terminal failure so the client can retry.

    Called from a try/except wrapper around the operation. If the
    marker has already been replaced by ``store_result`` (success),
    this is a no-op because we only delete keys whose value is the
    sentinel-prefixed in-flight marker.

    A ``pending`` slot is left untouched: it records an operation whose
    outcome is not yet known and must be resolved by reconciliation
    (see :func:`mark_pending` / :func:`peek`), not dropped — dropping it
    would let a retry re-execute a money-moving operation that may still
    settle.
    """
    client = _redis_client()
    if client is None:
        return
    try:
        key = _redis_key(api_key_id, idem_key)
        raw = client.get(key)
        if not raw:
            return
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        try:
            stored = json.loads(raw)
        except Exception:  # noqa: BLE001
            return
        if stored.get("state") == "inflight":
            client.delete(key)
    except Exception as e:  # noqa: BLE001
        logger.debug("idempotency release failed: %s", e)


def peek(*, api_key_id: str, idem_key: str) -> Optional[dict[str, Any]]:
    """Return the decoded slot record without mutating it, or ``None``.

    Used by reconciliation to read a ``pending`` slot's recorded
    ``payment_hash`` and body fingerprint.
    """
    client = _redis_client()
    if client is None:
        return None
    try:
        raw = client.get(_redis_key(api_key_id, idem_key))
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        return cast(dict[str, Any], json.loads(raw))
    except Exception:  # noqa: BLE001
        return None


def mark_pending(
    *,
    api_key_id: str,
    idem_key: str,
    request_body: Any,
    payment_hash: str,
    ttl: int = _TTL_SECONDS,
) -> None:
    """Convert a reservation into a ``pending`` record for an operation
    whose outcome is unknown (e.g. a Lightning send whose transport timed
    out while the HTLC may still be in flight).

    A pending slot keeps the key reserved — a same-key retry is rejected
    with 409 until the outcome resolves — and records the ``payment_hash``
    so the outcome can be looked up against the node and the slot either
    converted to a completed result (:func:`store_result`) or released
    (:func:`release_pending`). The compare-and-set only writes over a slot
    that is still a reservation, never over a completed result.
    """
    client = _redis_client()
    if client is None:
        return
    try:
        key = _redis_key(api_key_id, idem_key)
        fp = _fingerprint(request_body)
        payload = json.dumps(
            {
                "state": "pending",
                # Carry the sentinel substring so the ``store_result`` /
                # CAS guard recognises this slot as a reservation it may
                # overwrite once the outcome is known.
                "sentinel": _INFLIGHT_SENTINEL,
                "fp": fp,
                "ts": time.time(),
                "payment_hash": payment_hash,
            }
        )
        client.eval(_STORE_LUA, 1, key, payload, ttl, _INFLIGHT_SENTINEL)
    except Exception as e:  # noqa: BLE001
        logger.debug("idempotency mark_pending failed: %s", e)


def release_pending(*, api_key_id: str, idem_key: str) -> None:
    """Drop a ``pending`` marker once its operation is known to have
    failed, so the client can retry. No-op on any other slot state.
    """
    client = _redis_client()
    if client is None:
        return
    try:
        key = _redis_key(api_key_id, idem_key)
        raw = client.get(key)
        if not raw:
            return
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        try:
            stored = json.loads(raw)
        except Exception:  # noqa: BLE001
            return
        if stored.get("state") == "pending":
            client.delete(key)
    except Exception as e:  # noqa: BLE001
        logger.debug("idempotency release_pending failed: %s", e)
