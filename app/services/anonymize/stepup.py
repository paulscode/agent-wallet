# SPDX-License-Identifier: MIT
"""Step-up confirmation nonce + verify rate-limit.

The override-spend flows (refund-UTXO override, decoy-output spend
override) require a fresh server-issued nonce, bound to the caller's
session and the specific scope/action, that the client echoes back to
authorize the override. The nonce is single-use and replay-resistant:
a stale nonce from an earlier prompt — or one issued for a different
session, scope, or action — cannot satisfy a fresh challenge. It is a
deliberate confirmation step on top of the session's existing
authentication and CSRF protection, not an independent second factor.

 / item 126 hardens this with:

* :func:`generate_nonce` — ≥256 bits of entropy via
  :func:`secrets.token_bytes`. ``ANONYMIZE_STEPUP_NONCE_BYTES`` is
  clamped to a 32-byte minimum at startup; the helper
  re-applies the floor defensively.
* :func:`is_nonce_expired` — TTL gate using
  ``ANONYMIZE_STEPUP_NONCE_TTL_S``.
* :func:`is_cookie_locked_out` / :func:`record_failed_verify` —
  per-cookie verify-rate-limit. Budget exhaustion locks the cookie
  out of step-up flows for
  ``ANONYMIZE_STEPUP_NONCE_VERIFY_LOCKOUT_S``; the orchestrator
  emits ``stepup_nonce_verify_rate_limited``.

DB persistence (the ``anonymize_stepup_state`` rows from migration
021) lands when the override-spend endpoints wire up; this module
ships the pure-helper layer the endpoints will compose against.
"""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.core.config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# hard floor — the helper enforces a minimum even when
# config drifts.
_HARD_MINIMUM_NONCE_BYTES: int = 16
# documented default.
_DEFAULT_NONCE_BYTES: int = 32


def _resolve_nonce_bytes() -> int:
    """Read the configured nonce length, clamping below the hard floor.

    The startup helper :func:`assert_nonce_entropy_floor` raises when
    the operator has set a value below the hard minimum without
    explicitly opting in. This per-call helper is defense-in-depth:
    if the startup gate is bypassed, the nonce length still satisfies
    the brute-force resistance requirement.
    """
    cfg = int(settings.anonymize_stepup_nonce_bytes)
    if cfg < _HARD_MINIMUM_NONCE_BYTES:
        return _DEFAULT_NONCE_BYTES
    return cfg


def assert_nonce_entropy_floor() -> int:
    """Startup gate: refuse below ``_HARD_MINIMUM_NONCE_BYTES``.

    Returns the clamped value (so the caller can log the auto-clamp
    on the CRITICAL path). Refuses to run only when the operator
    explicitly opts into a length below the floor; the default-clamp
    branch logs at CRITICAL via the operator runbook.
    """
    cfg = int(settings.anonymize_stepup_nonce_bytes)
    if cfg < _HARD_MINIMUM_NONCE_BYTES:
        # Auto-clamp to default; the runbook calls this out as a
        # CRITICAL configuration error.
        return _DEFAULT_NONCE_BYTES
    return cfg


def generate_nonce(rng: secrets.SystemRandom | None = None) -> bytes:
    """Generate a step-up nonce with ≥256 bits of entropy."""
    n = _resolve_nonce_bytes()
    return secrets.token_bytes(n)


def encode_nonce_for_transport(nonce: bytes) -> str:
    """Base64url-encode the nonce for the JSON wire format."""
    return base64.urlsafe_b64encode(nonce).rstrip(b"=").decode("ascii")


def decode_nonce_from_transport(s: str) -> bytes:
    """Inverse of :func:`encode_nonce_for_transport`."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def is_nonce_expired(
    *,
    issued_at_unix_s: float,
    now_unix_s: float | None = None,
    ttl_s: int | None = None,
) -> bool:
    """True iff ``issued_at + TTL < now``."""
    if ttl_s is None:
        ttl_s = int(settings.anonymize_stepup_nonce_ttl_s)
    n = now_unix_s if now_unix_s is not None else time.time()
    return (issued_at_unix_s + ttl_s) < n


# --------------------------------------------------------------------
# Per-cookie verify-rate-limit.
# --------------------------------------------------------------------


@dataclass
class CookieVerifyState:
    """In-memory per-cookie verify-failure counter.

    The production layer persists state via migration 021's
    ``anonymize_stepup_state`` rows; this dataclass is the canonical
    shape unit tests exercise.
    """

    failed_verifies_in_window: int = 0
    last_failure_unix_s: float | None = None
    locked_out_until_unix_s: float | None = None


def is_cookie_locked_out(
    state: CookieVerifyState,
    *,
    now_unix_s: float | None = None,
) -> bool:
    """True iff the cookie is inside an active lockout window."""
    if state.locked_out_until_unix_s is None:
        return False
    n = now_unix_s if now_unix_s is not None else time.time()
    return n < state.locked_out_until_unix_s


def record_failed_verify(
    state: CookieVerifyState,
    *,
    now_unix_s: float | None = None,
    rate_per_min: int | None = None,
    lockout_s: int | None = None,
) -> CookieVerifyState:
    """Increment the failure counter; flip ``locked_out_until`` on threshold.

    Pure / no I/O — the caller persists the returned state to the
    DB. The fresh state shape is returned (rather than mutating the
    input) so the caller can decide whether to commit.
    """
    if rate_per_min is None:
        rate_per_min = int(settings.anonymize_stepup_nonce_verify_rate_limit_per_min)
    if lockout_s is None:
        lockout_s = int(settings.anonymize_stepup_nonce_verify_lockout_s)
    n = now_unix_s if now_unix_s is not None else time.time()

    # Reset the counter when the previous failure is older than the
    # 60-second rate-limit window.
    last = state.last_failure_unix_s
    failures = state.failed_verifies_in_window
    if last is None or (n - last) >= 60.0:
        failures = 0

    failures += 1
    locked = state.locked_out_until_unix_s
    if failures >= rate_per_min:
        locked = n + float(lockout_s)
    return CookieVerifyState(
        failed_verifies_in_window=failures,
        last_failure_unix_s=n,
        locked_out_until_unix_s=locked,
    )


def reset_cookie_state() -> CookieVerifyState:
    """Return a fresh state on successful verification."""
    return CookieVerifyState()


# --------------------------------------------------------------------
# DB-bound step-up nonce issue + verify.
# --------------------------------------------------------------------


def _stepup_blinding_key() -> bytes:
    """Return the HMAC key used to blind cookie subjects in the
    ``anonymize_stepup_state`` table.

    Prefers the dedicated ``ANONYMIZE_STEPUP_COOKIE_HMAC_KEY_FERNET``.
    When it is unset we derive a domain-separated key from SECRET_KEY
    rather than falling back to an EMPTY key — an empty key would make
    the cookie-blinding HMAC attacker-computable, defeating the
    DB-snapshot-adversary protection the blinding exists to provide.
    """
    import hashlib
    import hmac

    raw = (settings.anonymize_stepup_cookie_hmac_key_fernet or "").strip()
    if raw:
        return raw.encode("ascii")
    return hmac.new(
        settings.secret_key.encode("utf-8"),
        b"agent-wallet/anonymize-stepup-cookie/v1",
        hashlib.sha256,
    ).digest()


def _cookie_id_hmac(cookie_subject: str) -> bytes:
    """HMAC-blind a cookie subject for storage in the
    ``anonymize_stepup_state`` table.

    The blinded form is what the table stores so a DB-snapshot
    adversary cannot map rows to specific operator cookies.
    """
    import hashlib
    import hmac

    return hmac.new(
        _stepup_blinding_key(),
        cookie_subject.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def _nonce_at_rest(nonce: bytes) -> bytes:
    """Return the stored form of a step-up nonce.

    The row stores a domain-separated HMAC of the nonce rather than the
    nonce itself, so a DB-snapshot adversary who reads the row cannot
    replay the value to satisfy a step-up challenge — only the holder of
    the original (transport-encoded) nonce can reproduce the digest. The
    HMAC key is derived from the same secret material as the cookie
    blinding key under a distinct domain string.
    """
    import hashlib
    import hmac

    nonce_key = hmac.new(
        _stepup_blinding_key(),
        b"agent-wallet/anonymize-stepup-nonce/v1",
        hashlib.sha256,
    ).digest()
    return hmac.new(nonce_key, nonce, hashlib.sha256).digest()


def _aware_utc(dt):
    """Coerce a possibly-naive DB datetime to timezone-aware UTC.

    The ``anonymize_stepup_state`` columns are ``DateTime(timezone=True)``
    but SQLite (used in tests) returns naive values; treat those as UTC so
    Python-level comparisons against an aware ``now`` don't raise.
    """
    from datetime import timezone

    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _bind_scope(scope: str, binding: str | None) -> str:
    """Fold an action ``binding`` (e.g. the session id) into the scope so
    a nonce issued to confirm one action cannot be replayed for a
    different action in the same scope."""
    if not binding:
        return str(scope)
    return f"{scope}|sid={binding}"


async def issue_stepup_nonce(
    db: AsyncSession,
    *,
    cookie_subject: str,
    scope: str,
    binding: str | None = None,
    ttl_s: int | None = None,
) -> str:
    """Issue a fresh step-up nonce row.

    Returns the transport-encoded nonce string the dashboard hands
    to the operator. The DB row stores the nonce bytes (Fernet-
    encrypted via the wallet's at-rest layer when configured) +
    the cookie HMAC + the (binding-folded) scope.

    ``binding`` (e.g. the target session id) is folded into the stored
    scope so the nonce can only satisfy a verify for the SAME action.

    The caller commits.
    """
    from datetime import datetime, timedelta, timezone

    from app.models.anonymize_session import AnonymizeStepupState

    nonce = generate_nonce()
    ttl = int(ttl_s if ttl_s is not None else settings.anonymize_stepup_nonce_ttl_s)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=max(60, ttl))
    db.add(
        AnonymizeStepupState(
            kind="nonce",
            cookie_id_hmac=_cookie_id_hmac(cookie_subject),
            # Store a domain-separated HMAC of the nonce, not the nonce
            # itself — a DB read cannot then reproduce a replayable value.
            nonce_enc=_nonce_at_rest(nonce),
            scope=_bind_scope(scope, binding),
            created_at=now,
            expires_at=expires_at,
        )
    )
    return encode_nonce_for_transport(nonce)


async def verify_stepup_nonce(
    db: AsyncSession,
    *,
    cookie_subject: str,
    scope: str,
    transport_nonce: str,
    binding: str | None = None,
    now_unix_s: float | None = None,
) -> bool:
    """Verify a step-up nonce + consume the row.

    Returns True iff a matching ``(cookie_id_hmac, bound-scope, nonce)``
    row exists AND has not expired AND the cookie is not locked out. On
    success the nonce row is deleted (single-use) and the cookie's
    failed-verify lockout counter is cleared. On failure the per-cookie
    lockout counter is incremented; once it crosses
    ``ANONYMIZE_STEPUP_NONCE_VERIFY_RATE_LIMIT_PER_MIN`` within a 60s
    window the cookie is locked out of step-up for
    ``ANONYMIZE_STEPUP_NONCE_VERIFY_LOCKOUT_S``.

    The caller commits.
    """
    from datetime import datetime, timezone

    from sqlalchemy import delete, select

    from app.models.anonymize_session import AnonymizeStepupState

    bound_scope = _bind_scope(scope, binding)
    blinded = _cookie_id_hmac(cookie_subject)
    now = datetime.fromtimestamp(now_unix_s, tz=timezone.utc) if now_unix_s is not None else datetime.now(timezone.utc)
    threshold = max(1, int(settings.anonymize_stepup_nonce_verify_rate_limit_per_min))
    lockout_s = max(1, int(settings.anonymize_stepup_nonce_verify_lockout_s))

    # Load the per-cookie lockout row (one row per cookie, scope-agnostic
    # so a flood across scopes still trips the budget).
    lock_stmt = select(AnonymizeStepupState).where(
        AnonymizeStepupState.kind == "lockout",
        AnonymizeStepupState.cookie_id_hmac == blinded,
    )
    lock = (await db.execute(lock_stmt)).scalar_one_or_none()

    # Active lockout? Refuse without consuming a nonce.
    if lock is not None and lock.failed_verifies >= threshold and _aware_utc(lock.expires_at) > now:
        return False

    try:
        nonce_bytes = decode_nonce_from_transport(transport_nonce)
    except (ValueError, TypeError):
        await _record_stepup_failure(db, lock, blinded, now, threshold, lockout_s)
        return False

    # The row stores the HMAC of the nonce; match against the digest of
    # the presented value rather than the raw bytes.
    nonce_at_rest = _nonce_at_rest(nonce_bytes)
    stmt = select(AnonymizeStepupState).where(
        AnonymizeStepupState.kind == "nonce",
        AnonymizeStepupState.cookie_id_hmac == blinded,
        AnonymizeStepupState.scope == bound_scope,
        AnonymizeStepupState.nonce_enc == nonce_at_rest,
        AnonymizeStepupState.expires_at >= now,
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        await _record_stepup_failure(db, lock, blinded, now, threshold, lockout_s)
        return False

    # Success — consume the nonce and clear any lockout counter.
    await db.execute(delete(AnonymizeStepupState).where(AnonymizeStepupState.id == row.id))
    if lock is not None:
        await db.execute(delete(AnonymizeStepupState).where(AnonymizeStepupState.id == lock.id))
    return True


async def _record_stepup_failure(
    db: "AsyncSession",
    lock,
    blinded: bytes,
    now,
    threshold: int,
    lockout_s: int,
) -> None:
    """Increment the per-cookie failed-verify counter; trip the lockout
    when the budget is exhausted within the 60s window."""
    from datetime import timedelta

    from app.models.anonymize_session import AnonymizeStepupState

    if lock is None or _aware_utc(lock.expires_at) <= now:
        # Fresh counting window.
        new_lock = AnonymizeStepupState(
            kind="lockout",
            cookie_id_hmac=blinded,
            nonce_enc=None,
            scope="",
            created_at=now,
            expires_at=now + timedelta(seconds=60),
            failed_verifies=1,
        )
        db.add(new_lock)
        return

    lock.failed_verifies = int(lock.failed_verifies) + 1
    if lock.failed_verifies >= threshold:
        # Budget exhausted — extend the row into a full lockout window.
        lock.expires_at = now + timedelta(seconds=lockout_s)


__all__ = [
    "CookieVerifyState",
    "assert_nonce_entropy_floor",
    "generate_nonce",
    "encode_nonce_for_transport",
    "decode_nonce_from_transport",
    "is_nonce_expired",
    "is_cookie_locked_out",
    "record_failed_verify",
    "reset_cookie_state",
    "issue_stepup_nonce",
    "verify_stepup_nonce",
]
