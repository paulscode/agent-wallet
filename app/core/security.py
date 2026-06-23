# SPDX-License-Identifier: MIT
"""
API Key authentication for AI agent access.

Security model:
- API keys are HMAC-SHA-256 hashed before storage (never stored in plaintext)
- Keys are passed via Authorization: Bearer <key> header
- Each key has a name, optional expiry, and enabled/disabled status
- All operations are logged with the key ID for audit trail
"""

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models.api_key import APIKey

logger = logging.getLogger(__name__)
security_scheme = HTTPBearer()

_AUTH_FAIL_LIMIT = 20
_AUTH_FAIL_WINDOW = 900  # 15 minutes
_AUTH_FAIL_PREFIX = "lwa:auth_fail:"
_GLOBAL_AUTH_FAIL_KEY = "lwa:auth_fail:global"
_GLOBAL_AUTH_FAIL_ALERT_THRESHOLD = 50  # Alert after this many total failures in window

# In-process throttle for fail-open alerts. The alert fires when Redis
# is unreachable AND RATE_LIMIT_FAIL_POLICY=open, so it cannot use
# Redis itself for de-duplication. ``time.monotonic()`` is sufficient
# here because the throttle is per-process and bounded by the worker
# lifetime.
_FAIL_OPEN_ALERT_INTERVAL_SECONDS = 60.0
_last_fail_open_alert_at: float = 0.0


def _maybe_alert_fail_open(client_ip: str, reason: str) -> None:
    """Fire a one-shot rate-limited alert when auth rate-limiter fails open.

    Only emits when ``RATE_LIMIT_FAIL_POLICY=open``; under the
    fail-closed default the request is rejected so no alert is needed.
    """
    if settings.rate_limit_fail_policy != "open":
        return
    import time as _time

    global _last_fail_open_alert_at
    now = _time.monotonic()
    if now - _last_fail_open_alert_at < _FAIL_OPEN_ALERT_INTERVAL_SECONDS:
        return
    _last_fail_open_alert_at = now
    try:
        import asyncio

        from app.services.alert_service import send_alert

        asyncio.ensure_future(
            send_alert(
                "rate_limit_bypass",
                f"Auth rate-limit backend unavailable ({reason}); "
                f"requests are passing through (fail-open). Latest IP: {client_ip}",
            )
        )
    except Exception:
        pass


# Domain-separation context so the API-key hashing key is independent of
# every other SECRET_KEY-derived MAC (audit chain, session cookie). Same
# pattern as ``audit_chain_hmac``.
_API_KEY_CONTEXT = b"agent-wallet/api-key/v1"


def hash_api_key_with(secret: str, key: str) -> str:
    """HMAC-SHA-256 hash an API key under an arbitrary secret.

    The MAC key is a domain-separated subkey of ``secret`` (not ``secret``
    directly) so the API-key digest can never collide with a session
    cookie or audit-chain MAC derived from the same SECRET_KEY.
    """
    subkey = hmac.new(secret.encode("utf-8"), _API_KEY_CONTEXT, hashlib.sha256).digest()
    return hmac.new(
        subkey,
        key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hash_api_key(key: str) -> str:
    """HMAC-SHA-256 hash an API key for storage (keyed with SECRET_KEY)."""
    return hash_api_key_with(settings.secret_key, key)


def generate_api_key() -> str:
    """Generate a cryptographically secure API key.

    Format: lwk_{48 random hex chars} (52 chars total)
    Prefix makes keys easily identifiable in logs.
    """
    return f"lwk_{secrets.token_hex(24)}"


# Distinct derivation context so the audit-chain MAC key is independent of
# the API-key hashing key even though both come from SECRET_KEY.
_AUDIT_CHAIN_CONTEXT = b"agent-wallet/audit-chain/v1"


def audit_chain_hmac(payload: str, *, secret: str | None = None) -> str:
    """Keyed hash of an audit entry's canonical payload.

    The audit hash chain is a *keyed* MAC, not a bare digest: the key is
    derived from SECRET_KEY, so the chain is forgeable only by a party
    that holds SECRET_KEY. Someone who can write the ``audit_logs`` table
    but does not hold the key cannot recompute valid hashes, so any
    post-write tamper is detectable by the chain verifier.

    Rotating SECRET_KEY changes this key; the chain must be re-anchored
    after a rotation (see the admin re-anchor action).
    """
    chain_key = hmac.new(
        (secret or settings.secret_key).encode("utf-8"),
        _AUDIT_CHAIN_CONTEXT,
        hashlib.sha256,
    ).digest()
    return hmac.new(chain_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


async def _check_auth_rate_limit(client_ip: str) -> None:
    """Block the request if the IP has exceeded the failed-auth threshold.

    Uses a Redis counter with a sliding expiry. Respects RATE_LIMIT_FAIL_POLICY
    when Redis is unavailable (default 'closed' = reject requests).
    """
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        key = f"{_AUTH_FAIL_PREFIX}{client_ip}"
        count = await r.get(key)
        if count is not None and int(count) >= _AUTH_FAIL_LIMIT:
            logger.warning("Auth rate limit exceeded for IP %s", client_ip)
            raise HTTPException(
                status_code=429,
                detail="Too many failed authentication attempts. Try again later.",
            )
    except HTTPException:
        raise
    except Exception:
        if settings.rate_limit_fail_policy == "closed":
            raise HTTPException(
                status_code=503,
                detail="Authentication service temporarily unavailable.",
            )
        _maybe_alert_fail_open(client_ip, "redis_unavailable")
        pass  # fail-open; global SlowAPI limit still applies


async def _record_auth_failure(client_ip: str) -> None:
    """Increment the failed-auth counter for an IP and check global alert threshold."""
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        key = f"{_AUTH_FAIL_PREFIX}{client_ip}"
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, _AUTH_FAIL_WINDOW)
        await pipe.execute()

        # Track global failure count and alert on threshold
        global_pipe = r.pipeline()
        global_pipe.incr(_GLOBAL_AUTH_FAIL_KEY)
        global_pipe.expire(_GLOBAL_AUTH_FAIL_KEY, _AUTH_FAIL_WINDOW)
        results = await global_pipe.execute()
        global_count = int(results[0])
        if global_count == _GLOBAL_AUTH_FAIL_ALERT_THRESHOLD:
            try:
                import asyncio

                from app.services.alert_service import send_alert

                asyncio.ensure_future(
                    send_alert(
                        "auth_brute_force",
                        f"Global auth failure threshold reached: {global_count} failures "
                        f"in {_AUTH_FAIL_WINDOW}s window. Latest IP: {client_ip}",
                    )
                )
            except Exception:
                pass
    except Exception:
        pass  # Best-effort


async def _clear_auth_failures(client_ip: str) -> None:
    """Reset the failed-auth counter on successful authentication."""
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        await r.delete(f"{_AUTH_FAIL_PREFIX}{client_ip}")
    except Exception:
        pass  # Best-effort


async def get_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    """FastAPI dependency: validate API key and return the key record.

    Raises 401 if key is invalid, disabled, or expired.
    Raises 429 if the client IP has exceeded failed-auth threshold.
    """
    client_ip = request.client.host if request.client else "unknown"
    await _check_auth_rate_limit(client_ip)

    new_hash = hash_api_key(credentials.credentials)
    candidate_hashes = [new_hash]
    if settings.secret_key_previous:
        old_hash = hash_api_key_with(settings.secret_key_previous, credentials.credentials)
        if old_hash != new_hash:
            candidate_hashes.append(old_hash)

    result = await db.execute(select(APIKey).where(APIKey.key_hash.in_(candidate_hashes)))
    api_key = result.scalar_one_or_none()

    if not api_key:
        # Equalise
        # timing between the "row not found" and "row found" paths
        # with a dummy constant-time compare. Without this, an
        # attacker can measure the slight difference between a
        # bare DB miss and a DB hit + Python-level digest compare.
        hmac.compare_digest(new_hash, new_hash)
        await _record_auth_failure(client_ip)
        logger.warning("Authentication failed: invalid API key")
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Use ``hmac.compare_digest`` for the post-fetch digest
    # comparison so the rotation path cannot be probed via response
    # timing. Walk all candidate hashes (current SECRET_KEY plus, if
    # configured, the previous one) and demand a constant-time match
    # against the row's stored ``key_hash``. The ``SELECT ... WHERE
    # IN (...)`` already guarantees this in practice; the explicit
    # post-check is defence-in-depth against future schema changes
    # or hash collisions.
    stored_hash = api_key.key_hash or ""
    matched = False
    for candidate in candidate_hashes:
        if hmac.compare_digest(stored_hash, candidate):
            matched = True
            break
    if not matched:
        await _record_auth_failure(client_ip)
        logger.warning("Authentication failed: hash mismatch after lookup")
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not api_key.is_active:
        await _record_auth_failure(client_ip)
        logger.warning("Authentication failed: disabled API key '%s'", api_key.name)
        raise HTTPException(status_code=401, detail="API key is disabled")

    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        await _record_auth_failure(client_ip)
        logger.warning("Authentication failed: expired API key '%s'", api_key.name)
        raise HTTPException(status_code=401, detail="API key has expired")

    # Successful auth — clear failure counter and update timestamp
    await _clear_auth_failures(client_ip)
    api_key.last_used_at = datetime.now(timezone.utc)
    # If this key authenticated under the previous SECRET_KEY, rewrite
    # the digest under the current secret so it survives removal of
    # SECRET_KEY_PREVIOUS. The rewrite of ``key_hash`` is what provides
    # continuity; the old digest is copied to ``key_hash_prev`` only as
    # an audit record (it is never a lookup source — see the column doc).
    # Use compare_digest consistently here too — the timing
    # difference is otherwise negligible but the rule is "no naked
    # `!=` on cryptographic material in authentication paths".
    if not hmac.compare_digest(api_key.key_hash or "", new_hash):
        api_key.key_hash_prev = api_key.key_hash
        api_key.key_hash = new_hash
        logger.info("Rewrote API key '%s' digest under current SECRET_KEY", api_key.name)
    await db.commit()

    return api_key


async def get_admin_key(
    api_key: APIKey = Depends(get_api_key),
) -> APIKey:
    """FastAPI dependency: require an admin API key.

    Admin keys have full control — channel management, message signing,
    and operator endpoints.
    """
    if not api_key.is_admin:
        raise HTTPException(status_code=403, detail="Admin API key required for this operation")
    return api_key


async def request_has_admin_key(request: Request, db: AsyncSession) -> bool:
    """Non-raising admin check for endpoints with OPTIONAL detail gating.

    Returns ``True`` only when the request carries a ``Bearer`` token
    that resolves to an active admin API key. Never raises and never
    records an auth-failure / rate-limit side effect — it is a soft
    "should I include the sensitive detail?" gate, not an auth boundary.
    """
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return False
    token = auth[7:].strip()
    if not token:
        return False
    new_hash = hash_api_key(token)
    candidate_hashes = [new_hash]
    if settings.secret_key_previous:
        old_hash = hash_api_key_with(settings.secret_key_previous, token)
        if old_hash != new_hash:
            candidate_hashes.append(old_hash)
    try:
        result = await db.execute(select(APIKey).where(APIKey.key_hash.in_(candidate_hashes)))
        api_key = result.scalar_one_or_none()
    except Exception:  # noqa: BLE001
        return False
    if api_key is None or not api_key.is_active or not api_key.is_admin:
        return False
    stored_hash = api_key.key_hash or ""
    if not any(hmac.compare_digest(stored_hash, c) for c in candidate_hashes):
        return False
    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        return False
    return True


async def get_spend_key(
    api_key: APIKey = Depends(get_api_key),
) -> APIKey:
    """FastAPI dependency: require a key that may move funds.

    Satisfied by a ``spend`` key (agents) or an ``admin`` key; read-only
    keys are rejected. Spending stays bounded by the configured payment
    caps and per-key rate limits regardless of scope.
    """
    if not api_key.can_spend:
        raise HTTPException(
            status_code=403,
            detail="A spend or admin API key is required for this operation",
        )
    return api_key
