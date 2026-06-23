# SPDX-License-Identifier: MIT
"""
Dashboard auth — token validation, cookie signing, auto-generation.

The dashboard uses a separate authentication flow from the API:
- DASHBOARD_TOKEN env var (auto-generated if not set)
- HttpOnly session cookie for browser auth
- Server-side session tracking via Redis for revocation support
- Session duration configurable via DASHBOARD_SESSION_HOURS (default: 4)
- Cookie Secure flag controlled by COOKIE_SECURE (default True; disable
  only for local plain-HTTP development)
"""

import hashlib
import hmac
import logging
import os
import secrets
import stat
import time
from collections import OrderedDict

from fastapi import Request, Response

from app.core.config import settings

logger = logging.getLogger(__name__)

# Session cookie config
COOKIE_NAME = "dashboard_session"
SESSION_MAX_AGE = settings.dashboard_session_hours * 3600
_IDLE_TIMEOUT = min(SESSION_MAX_AGE, settings.dashboard_idle_timeout_minutes * 60)
_SESSION_REDIS_PREFIX = "lwa:dash_session:"

# ──: process-local revocation cache ───────────────────────────
#
# When Redis is unavailable, ``RATE_LIMIT_FAIL_POLICY=closed`` (the
# default and the only policy allowed in production by the
# ``_validate_rate_limit_fail_policy`` model validator) refuses every
# session — safe but disruptive during a brief Redis blip. To keep
# revocation working through short outages we keep a small in-process
# TTL'd set of session IDs that this worker has explicitly revoked.
# When Redis is down ``verify_session`` consults this cache: a hit
# means "definitively revoked, reject regardless of policy". A miss
# falls through to the existing fail-policy branch.
#
# Bounded LRU semantics so a malicious flood of forged session IDs
# cannot exhaust memory: ``_REVOCATION_CACHE_MAX_ENTRIES`` is the
# hard cap; on overflow the oldest entry is evicted.
_REVOCATION_CACHE_TTL_SECONDS = 300  # 5 min
_REVOCATION_CACHE_MAX_ENTRIES = 4096
_revocation_cache: "OrderedDict[str, float]" = OrderedDict()


def _revocation_cache_add(session_id: str) -> None:
    """Mark ``session_id`` as locally revoked. Idempotent."""
    now = time.time()
    if session_id in _revocation_cache:
        del _revocation_cache[session_id]
    _revocation_cache[session_id] = now + _REVOCATION_CACHE_TTL_SECONDS
    # Evict the oldest entry on overflow.
    while len(_revocation_cache) > _REVOCATION_CACHE_MAX_ENTRIES:
        _revocation_cache.popitem(last=False)


def _revocation_cache_contains(session_id: str) -> bool:
    """Return True iff ``session_id`` is in the local cache and not
    yet expired. Expired entries are evicted opportunistically."""
    expires = _revocation_cache.get(session_id)
    if expires is None:
        return False
    if time.time() >= expires:
        _revocation_cache.pop(session_id, None)
        return False
    return True


# Dashboard login lockout
_LOGIN_FAIL_PREFIX = "lwa:dash_login_fail:"
_LOGIN_FAIL_LIMIT = 10  # Lock out after this many failures
_LOGIN_FAIL_WINDOW = 900  # 15-minute window

# Cross-IP global brute-force counter — does not block (would self-DoS)
# but emits an `auth_brute_force` alert above the threshold so an
# operator can rotate DASHBOARD_TOKEN.
_LOGIN_FAIL_GLOBAL_KEY = "lwa:dash_login_fail:_global"
_LOGIN_FAIL_GLOBAL_THRESHOLD = 50
_LOGIN_FAIL_GLOBAL_ALERT_COOLDOWN_KEY = "lwa:dash_login_fail:_global:alerted"
_LOGIN_FAIL_GLOBAL_ALERT_COOLDOWN_SECONDS = 900


async def check_login_lockout(client_ip: str) -> bool:
    """Return True if the IP is locked out due to too many failed login attempts.

    When Redis is unavailable, respects RATE_LIMIT_FAIL_POLICY:
    'closed' (default) = treat as locked out; 'open' = allow through.
    """
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        key = f"{_LOGIN_FAIL_PREFIX}{client_ip}"
        count = await r.get(key)
        if count is not None and int(count) >= _LOGIN_FAIL_LIMIT:
            return True
    except Exception:
        if settings.rate_limit_fail_policy == "closed":
            logger.warning("Redis unavailable — dashboard login blocked (rate_limit_fail_policy=closed)")
            return True  # Fail closed — treat as locked out
    return False


async def record_login_failure(client_ip: str) -> None:
    """Increment the failed login counter for an IP and the global counter.

    The per-IP counter blocks brute force from a single source. The
    global counter doesn't block (a global block would be a trivial
    self-DoS) but fires an ``auth_brute_force`` alert when a coordinated
    cross-IP attack crosses the threshold, with a cooldown to avoid
    alert spam.
    """
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        key = f"{_LOGIN_FAIL_PREFIX}{client_ip}"
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, _LOGIN_FAIL_WINDOW)
        pipe.incr(_LOGIN_FAIL_GLOBAL_KEY)
        pipe.expire(_LOGIN_FAIL_GLOBAL_KEY, _LOGIN_FAIL_WINDOW)
        results = await pipe.execute()
        try:
            global_count = int(results[2])
        except (IndexError, TypeError, ValueError):
            return
        if global_count >= _LOGIN_FAIL_GLOBAL_THRESHOLD:
            # Set alert cooldown atomically — only the first racer fires.
            already_alerted = await r.set(
                _LOGIN_FAIL_GLOBAL_ALERT_COOLDOWN_KEY,
                "1",
                ex=_LOGIN_FAIL_GLOBAL_ALERT_COOLDOWN_SECONDS,
                nx=True,
            )
            if already_alerted:
                try:
                    from app.services.alert_service import send_alert

                    await send_alert(
                        "auth_brute_force",
                        f"Dashboard login: {global_count} failures across all IPs "
                        f"in the last {_LOGIN_FAIL_WINDOW // 60} minutes",
                        details={
                            "global_count": global_count,
                            "window_seconds": _LOGIN_FAIL_WINDOW,
                            "threshold": _LOGIN_FAIL_GLOBAL_THRESHOLD,
                        },
                    )
                except Exception:
                    logger.exception("Failed to emit auth_brute_force alert")
    except Exception:
        pass  # Best-effort


async def clear_login_failures(client_ip: str) -> None:
    """Reset the failed login counter on successful login."""
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        await r.delete(f"{_LOGIN_FAIL_PREFIX}{client_ip}")
    except Exception:
        pass  # Best-effort


_MIN_DASHBOARD_TOKEN_LENGTH = 32
_MIN_DASHBOARD_TOKEN_DISTINCT_CHARS = 8


def _validate_token_strength(token: str) -> None:
    """Refuse to boot with a weak operator-supplied DASHBOARD_TOKEN.

    The token is a shared secret compared in constant time, so its only
    brute-force defense is its own entropy plus the per-IP login lockout
    — and an attacker rotating source IPs is not hard-blocked by that
    lockout (it alerts on the cross-IP threshold rather than blocking, to
    avoid letting a spoofed source lock the operator out). The strength
    floor therefore has to carry the weight on its own.

    Auto-generated tokens (``secrets.token_urlsafe(32)``) are 43 chars of
    URL-safe base64 and clear both checks comfortably. The length floor
    and the distinct-character floor together reject a short or
    pathologically low-entropy operator-chosen passphrase (e.g. a long
    run of one repeated character) while leaving any real random token or
    diceware-style passphrase untouched.
    """
    if len(token) < _MIN_DASHBOARD_TOKEN_LENGTH:
        raise RuntimeError(
            f"DASHBOARD_TOKEN is too short ({len(token)} chars); "
            f"minimum is {_MIN_DASHBOARD_TOKEN_LENGTH}. Generate one "
            f"with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )
    if len(set(token)) < _MIN_DASHBOARD_TOKEN_DISTINCT_CHARS:
        raise RuntimeError(
            f"DASHBOARD_TOKEN has too few distinct characters "
            f"({len(set(token))}); it must contain at least "
            f"{_MIN_DASHBOARD_TOKEN_DISTINCT_CHARS}. Generate a high-entropy "
            f"token with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )


def _append_env_line_0600(env_path: str, line: str) -> None:
    """Append ``line`` to ``env_path`` with mode 0o600 enforced *before* write.

    Uses ``os.fchmod`` on the open descriptor so there is no window in
    which the file exists with the default umask.
    """
    if os.path.exists(env_path):
        fd = os.open(env_path, os.O_WRONLY | os.O_APPEND)
    else:
        # O_EXCL is safe here because we just checked exists(); if a
        # concurrent process won the race we'll see EEXIST and fall
        # back to the append branch on the next call. Better than
        # silently overwriting.
        fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, line.encode())
    finally:
        os.close(fd)


def _get_token() -> str:
    """Get or auto-generate the dashboard token.

    Token strength is validated at startup by :func:`ensure_token_ready`,
    not here, so per-request calls don't repeat the check. Outside
    Docker, when auto-generating, we persist via an
    ``O_CREAT|O_EXCL`` + ``fchmod(0o600)`` sequence so the file never
    exists at the default umask, and we abort startup if persistence
    fails rather than silently downgrading to an ephemeral token
    (which on the next restart would lock the operator out).
    """
    if settings.dashboard_token:
        return settings.dashboard_token

    # Auto-generate
    token = secrets.token_urlsafe(32)
    settings.dashboard_token = token

    # Skip file write inside Docker containers — require explicit DASHBOARD_TOKEN env var
    if os.path.exists("/.dockerenv"):
        logger.warning(
            "DASHBOARD_TOKEN not set. An ephemeral token was auto-generated "
            "(32 bytes URL-safe). Set DASHBOARD_TOKEN in your environment "
            "for persistent access."
        )
        return token

    env_path = os.path.join(os.getcwd(), ".env")
    line = f"\nDASHBOARD_TOKEN={token}\n"
    try:
        # Don't append a duplicate if the line is already present.
        already_present = False
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                already_present = "DASHBOARD_TOKEN=" in f.read()
        if not already_present:
            _append_env_line_0600(env_path, line)
        # Tighten existing permissions even when we didn't write.
        try:
            current_mode = stat.S_IMODE(os.stat(env_path).st_mode)
            if current_mode & 0o077:
                os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        logger.warning(
            "─" * 64 + "\n"
            "  SECURITY: DASHBOARD_TOKEN was auto-generated and written to\n"
            "  %s with mode 0600. For production deployments set\n"
            "  DASHBOARD_TOKEN explicitly in the environment instead of\n"
            "  relying on auto-generation, and ensure the .env file is not\n"
            "  bind-mounted into other containers or backed up unencrypted.\n" + "─" * 64,
            env_path,
        )
    except OSError as e:
        # Refuse to continue: an ephemeral token would lock the
        # operator out on the next restart, and a 0o644 file would
        # leak the token to anything that can read the cwd.
        raise RuntimeError(
            f"Could not persist DASHBOARD_TOKEN to {env_path} with secure "
            f"permissions ({e}). Set DASHBOARD_TOKEN explicitly in the "
            f"environment and restart."
        ) from e

    return token


# Domain-separation context so the cookie/nonce signing key is
# independent of every other SECRET_KEY-derived MAC (API-key hash, audit
# chain). Mirrors ``audit_chain_hmac``.
_SESSION_COOKIE_CONTEXT = b"agent-wallet/session-cookie/v1"


def _sign(data: str, *, purpose: str = "session") -> str:
    """HMAC-sign data with a domain-separated subkey of SECRET_KEY.

    ``purpose`` labels the token class and is folded into the signed
    bytes so distinct token types are cryptographically
    non-interchangeable: a login nonce (``purpose="login-nonce"``) and a
    session cookie (``purpose="session"``) share the same payload shape
    (``"{random}:{expires}"``) but produce disjoint signatures, so one
    can never be presented as the other regardless of any side-channel
    state.
    """
    subkey = hmac.new(
        settings.secret_key.encode(),
        _SESSION_COOKIE_CONTEXT,
        hashlib.sha256,
    ).digest()
    return hmac.new(
        subkey,
        f"{purpose}\x00{data}".encode(),
        hashlib.sha256,
    ).hexdigest()


def verify_token(token: str) -> bool:
    """Check if the provided token matches the dashboard token."""
    expected = _get_token()
    # Compare as UTF-8 bytes: hmac.compare_digest rejects str inputs containing
    # non-ASCII characters, so a submission with any non-ASCII byte must compare
    # unequal rather than raise.
    return hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8"))


async def create_session_cookie(response: Response, request: Request | None = None) -> str:
    """Set the signed session cookie on a response with server-side tracking.

    Returns the CSRF token associated with the session.
    When request is provided, the client IP is stored for session binding.
    """
    session_id = secrets.token_urlsafe(24)
    expires = int(time.time()) + SESSION_MAX_AGE
    payload = f"{session_id}:{expires}"
    signature = _sign(payload)
    value = f"{payload}.{signature}"

    # Track session server-side in Redis (best-effort — falls back to signature-only)
    csrf_token = secrets.token_urlsafe(32)
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        await r.setex(f"{_SESSION_REDIS_PREFIX}{session_id}", SESSION_MAX_AGE, "1")
        await r.setex(f"{_SESSION_REDIS_PREFIX}{session_id}:csrf", SESSION_MAX_AGE, csrf_token)
        await r.setex(f"{_SESSION_REDIS_PREFIX}{session_id}:active", _IDLE_TIMEOUT, "1")
        if request and request.client:
            await r.setex(f"{_SESSION_REDIS_PREFIX}{session_id}:ip", SESSION_MAX_AGE, request.client.host)
    except Exception:
        logger.debug("Could not store session in Redis (non-critical)")

    response.set_cookie(
        key=COOKIE_NAME,
        value=value,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="strict",
        path="/dashboard",
        secure=settings.cookie_secure,
    )
    return csrf_token


async def verify_session(request: Request) -> bool:
    """Verify the session cookie is valid, not expired, and not revoked."""
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return False

    parts = cookie.rsplit(".", 1)
    if len(parts) != 2:
        return False

    payload, signature = parts
    expected_sig = _sign(payload)
    if not hmac.compare_digest(signature, expected_sig):
        return False

    # Parse payload: "session_id:expires".
    # The legacy id-less format ("expires" only) is no longer accepted.
    # ``create_session_cookie`` has always minted ``session_id:expires``,
    # so an id-less payload can only be a stale/forged cookie — and
    # accepting it would skip server-side revocation, idle-timeout, and
    # IP-binding entirely. Reject it; the user simply re-authenticates.
    payload_parts = payload.split(":", 1)
    if len(payload_parts) != 2:
        return False
    session_id, expires_str = payload_parts
    if not session_id:
        return False

    try:
        expires = int(expires_str)
    except ValueError:
        return False

    if time.time() >= expires:
        return False

    # Check server-side revocation and idle timeout (best-effort — allow if Redis unavailable)
    if session_id:
        try:
            from app.core.rate_limit import get_redis

            r = await get_redis()
            if not await r.exists(f"{_SESSION_REDIS_PREFIX}{session_id}"):
                return False
            # Check idle timeout
            idle_key = f"{_SESSION_REDIS_PREFIX}{session_id}:active"
            if not await r.exists(idle_key):
                return False  # Idle timeout exceeded
            # Refresh idle timer on activity
            await r.expire(idle_key, _IDLE_TIMEOUT)
            # Verify session IP binding (best-effort). When a session was
            # bound to an IP, a request that cannot present a matching
            # client IP — including one with no client IP at all — is
            # refused rather than silently skipping the check, so the
            # binding does not fail open on an absent ``request.client``.
            stored_ip = await r.get(f"{_SESSION_REDIS_PREFIX}{session_id}:ip")
            current_ip = request.client.host if request.client else None
            if stored_ip and stored_ip != (current_ip or ""):
                logger.warning("Session IP mismatch: stored=%s, current=%s", stored_ip, current_ip)
                return False
        except Exception:
            # Redis is unreachable. First consult the process-local
            # revocation cache: if this session ID was revoked
            # by this worker within the cache TTL, reject regardless
            # of fail policy.
            if session_id and _revocation_cache_contains(session_id):
                logger.warning("Redis unavailable — refusing dashboard session via local revocation cache")
                return False
            # Otherwise honour the same fail policy used for
            # rate-limiting: when ``RATE_LIMIT_FAIL_POLICY=closed`` we
            # refuse the request rather than degrade silently to
            # signature-only validation (which would leak session
            # revocation, idle timeout, and IP binding guarantees).
            # Default policy is "closed" in production.
            if settings.rate_limit_fail_policy == "closed":
                logger.warning("Redis unavailable — refusing dashboard session (RATE_LIMIT_FAIL_POLICY=closed)")
                return False
            logger.warning(
                "Redis unavailable — dashboard session validated by signature only "
                "(revocation, idle timeout, and IP binding not enforced)"
            )

    return True


def clear_session_cookie(response: Response) -> None:
    """Delete the session cookie and revoke the session server-side."""
    response.delete_cookie(
        key=COOKIE_NAME,
        path="/dashboard",
    )


async def revoke_session(request: Request) -> None:
    """Revoke the current session in Redis so the cookie can't be reused."""
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return

    parts = cookie.rsplit(".", 1)
    if len(parts) != 2:
        return

    payload, signature = parts
    expected_sig = _sign(payload)
    if not hmac.compare_digest(signature, expected_sig):
        return

    payload_parts = payload.split(":", 1)
    if len(payload_parts) == 2:
        session_id = payload_parts[0]
        # Record the revocation in the process-local cache so
        # ``verify_session`` keeps rejecting this session even if
        # Redis is unreachable when the cookie is reused.
        _revocation_cache_add(session_id)
        try:
            from app.core.rate_limit import get_redis

            r = await get_redis()
            await r.delete(f"{_SESSION_REDIS_PREFIX}{session_id}")
        except Exception:
            logger.debug("Could not revoke session in Redis (non-critical)")


def ensure_token_ready() -> str:
    """Called at startup to ensure the token exists. Returns the token.

    This is the boundary at which token strength is enforced; tests
    and per-request calls go through :func:`_get_token` directly and
    are not subject to the length floor. An operator-supplied token
    shorter than the minimum aborts startup with a clear error.
    """
    if settings.dashboard_token:
        _validate_token_strength(settings.dashboard_token)
    return _get_token()


def _extract_session_id(request: Request) -> str | None:
    """Extract the session ID from the cookie after verifying its HMAC.

    Returns ``None`` if the cookie is missing, malformed, has an
    invalid signature, is in the legacy (no-session-id) format, or has
    expired. Callers can therefore safely use the returned id as a
    Redis lookup key without further validation.
    """
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    parts = cookie.rsplit(".", 1)
    if len(parts) != 2:
        return None
    payload, signature = parts
    if not hmac.compare_digest(signature, _sign(payload)):
        return None
    payload_parts = payload.split(":", 1)
    if len(payload_parts) != 2:
        return None
    session_id, expires_str = payload_parts
    try:
        expires = int(expires_str)
    except ValueError:
        return None
    if time.time() >= expires:
        return None
    return session_id


async def get_csrf_token(request: Request) -> str | None:
    """Retrieve the CSRF token for the current session from Redis."""
    session_id = _extract_session_id(request)
    if not session_id:
        return None
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        token = await r.get(f"{_SESSION_REDIS_PREFIX}{session_id}:csrf")
        return token if isinstance(token, str) else None
    except Exception:
        return None


async def rotate_csrf_token(request: Request) -> str | None:
    """Mint a fresh CSRF token for the active session and persist it.

    Returns the new token or ``None`` if there is no active session
    (e.g. anonymous request) or Redis is unreachable. The rotation
    is "rotate-on-use": callers (see
    ``app.dashboard.api._require_auth_csrf``) invoke this after a
    successful CSRF check on a state-changing request and surface
    the new token via the ``X-CSRF-Token-Next`` response header.

    Rotating the CSRF token on every successful state-changing
    request limits exposure: leaking a single CSRF header should
    not give the attacker a full ``dashboard_session_hours``-long
    window.
    """
    session_id = _extract_session_id(request)
    if not session_id:
        return None
    new_token = secrets.token_urlsafe(32)
    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        await r.setex(
            f"{_SESSION_REDIS_PREFIX}{session_id}:csrf",
            SESSION_MAX_AGE,
            new_token,
        )
        return new_token
    except Exception:
        return None


# CSRF verification result codes (used by dashboard API to differentiate
# infrastructure problems from security violations).
CSRF_OK = "ok"
CSRF_MISSING_HEADER = "missing_header"
CSRF_NO_SESSION_TOKEN = "no_session_token"
CSRF_MISMATCH = "mismatch"
CSRF_BACKEND_UNAVAILABLE = "backend_unavailable"


async def check_csrf_token(request: Request) -> str:
    """Granular CSRF check used by dashboard endpoints.

    Returns one of the ``CSRF_*`` constants so callers can map to
    different HTTP status codes (403 for violations, 503 for backend
    outages) and emit alerts on real mismatches.
    """
    header_token = request.headers.get("X-CSRF-Token")
    if not header_token:
        return CSRF_MISSING_HEADER

    session_id = _extract_session_id(request)
    if not session_id:
        return CSRF_NO_SESSION_TOKEN

    try:
        from app.core.rate_limit import get_redis

        r = await get_redis()
        stored_token = await r.get(f"{_SESSION_REDIS_PREFIX}{session_id}:csrf")
    except Exception:
        return CSRF_BACKEND_UNAVAILABLE

    if not stored_token:
        return CSRF_NO_SESSION_TOKEN
    if not hmac.compare_digest(header_token, stored_token):
        return CSRF_MISMATCH
    return CSRF_OK


async def verify_csrf_token(request: Request) -> bool:
    """Verify the X-CSRF-Token header matches the session's CSRF token.

    Legacy boolean wrapper around :func:`check_csrf_token`. New code
    should call :func:`check_csrf_token` to distinguish backend outages
    from genuine violations.
    """
    return (await check_csrf_token(request)) == CSRF_OK


# ── Login CSRF nonce ────────────────────────────────────────────────
#
# Stateless signed nonce used to defeat "login CSRF" — a third-party
# site cannot forge a valid nonce because it lacks the SECRET_KEY and
# cannot read the cookie set on the dashboard origin. The nonce is
# also checked against an Origin/Referer host allow-list when those
# headers are present on the POST.

_LOGIN_NONCE_TTL_SECONDS = 600  # 10 minutes


def generate_login_nonce() -> str:
    """Mint a signed, time-bounded nonce for the login form."""
    nonce = secrets.token_urlsafe(16)
    expires = int(time.time()) + _LOGIN_NONCE_TTL_SECONDS
    payload = f"{nonce}:{expires}"
    return f"{payload}.{_sign(payload, purpose='login-nonce')}"


def verify_login_nonce(value: str) -> bool:
    """Validate a login nonce: signature must match and not be expired."""
    if not value:
        return False
    parts = value.rsplit(".", 1)
    if len(parts) != 2:
        return False
    payload, signature = parts
    if not hmac.compare_digest(signature, _sign(payload, purpose="login-nonce")):
        return False
    payload_parts = payload.split(":", 1)
    if len(payload_parts) != 2:
        return False
    try:
        expires = int(payload_parts[1])
    except ValueError:
        return False
    return time.time() < expires


def verify_login_origin(request: Request) -> bool:
    """Reject form submissions whose Origin/Referer points off-host.

    Returns True when no Origin/Referer header is present (some
    privacy-focused clients strip both) so the nonce remains the
    primary line of defence; returns False only on an *explicit*
    cross-origin signal.

    The set of accepted hosts covers the request's own host and the
    hosts of any configured CORS origins. A reverse proxy that
    terminates TLS under a public host the application does not bind to
    must have that host listed in ``CORS_ORIGINS`` — the canonical
    public-host source. The accepted set is never derived from a
    request header (``X-Forwarded-Host`` is client-suppliable and would
    let an attacker enrol an arbitrary origin into the allow-list).
    """
    from urllib.parse import urlparse

    accepted: set[str] = {request.url.netloc}
    for origin in settings.cors_origins_list:
        netloc = urlparse(origin).netloc
        if netloc:
            accepted.add(netloc)

    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if not value:
            continue
        try:
            parsed = urlparse(value)
        except ValueError:
            return False
        if parsed.netloc and parsed.netloc not in accepted:
            return False
    return True
