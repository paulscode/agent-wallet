# SPDX-License-Identifier: MIT
"""Recurring key-rotation framework (/ items 60 + 73).

Three independent secrets in the anonymize stack rotate on bounded
retention horizons:

* ``ANONYMIZE_REUSE_DETECTION_KEY_FERNET`` — keyed-BLAKE2b
  destination-reuse hashing. Rotation cadence
  ``ANONYMIZE_REUSE_DETECTION_KEY_ROTATION_DAYS`` (default 30); past
  the retention horizon the rotated-out key is purged and affected
  hash columns are sentinel-overwritten.
* ``ANONYMIZE_HOP_IDEMPOTENCY_KEY_FERNET`` — HMAC key for
  ``hop_idempotency_key``. Rotation cadence
  ``ANONYMIZE_HOP_IDEMPOTENCY_KEY_ROTATION_DAYS`` (default 7); past
  the retention horizon ``anonymize_session_event.hop_idempotency_key``
  is nulled.
* ``ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET`` — HMAC key for
  the quote tokens. Rotation cadence 1 day; retention 7 days.

This module ships the *framework* — a recurring task that runs on a
1-hour cadence (advisory-locked, mirroring), reads the
last-rotation timestamp from ``anonymize_runtime_state``, decides
whether a rotation is due, and emits the appropriate rotation event.
The actual key-material reads / writes / sentinel-overwrites land in
the per-key purge passes (`reuse_detection.py`, `hop_idempotency.py`,
`crypto.py` quote-token signing).

The horizon invariant is enforced separately at startup:
``RETENTION_DAYS >= DESTINATION_RETENTION_DAYS + ROTATION_DAYS`` for
the reuse-detection key, and the equivalent for hop-idempotency-key.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

from app.core.config import settings

KeySetName = Literal[
    "reuse_detection",
    "hop_idempotency",
    "quote_token_hmac",
    "quote_cache_signing",
]


@dataclass(frozen=True)
class RotationPolicy:
    """Per-key rotation + retention bounds."""

    name: KeySetName
    rotation_days: int
    retention_days: int
    runtime_state_key: str  # last-rotation timestamp lookup


def reuse_detection_policy() -> RotationPolicy:
    return RotationPolicy(
        name="reuse_detection",
        rotation_days=int(settings.anonymize_reuse_detection_key_rotation_days),
        retention_days=int(settings.anonymize_reuse_detection_key_retention_days),
        runtime_state_key="reuse_detection_key_rotation_last_at",
    )


def hop_idempotency_policy() -> RotationPolicy:
    return RotationPolicy(
        name="hop_idempotency",
        rotation_days=int(settings.anonymize_hop_idempotency_key_rotation_days),
        retention_days=int(settings.anonymize_hop_idempotency_key_retention_days),
        runtime_state_key="hop_idempotency_key_rotation_last_at",
    )


def quote_token_policy() -> RotationPolicy:
    return RotationPolicy(
        name="quote_token_hmac",
        rotation_days=int(settings.anonymize_quote_token_hmac_key_rotation_days),
        retention_days=int(settings.anonymize_quote_token_hmac_key_retention_days),
        runtime_state_key="quote_token_hmac_key_rotation_last_at",
    )


def quote_cache_signing_policy() -> RotationPolicy:
    """The quote-cache signing key shares the quote-token cadence."""
    return RotationPolicy(
        name="quote_cache_signing",
        rotation_days=int(settings.anonymize_quote_token_hmac_key_rotation_days),
        retention_days=int(settings.anonymize_quote_token_hmac_key_retention_days),
        runtime_state_key="quote_cache_signing_key_rotation_last_at",
    )


def all_policies() -> tuple[RotationPolicy, ...]:
    """Return every rotation policy the framework manages."""
    return (
        reuse_detection_policy(),
        hop_idempotency_policy(),
        quote_token_policy(),
        quote_cache_signing_policy(),
    )


# ────────────────────────────────────────────────────────────────────
# Decision helpers — pure / no I/O so the orchestrator can wrap them
# in its own DB / advisory-lock primitives.
# ────────────────────────────────────────────────────────────────────


def is_rotation_due(
    policy: RotationPolicy,
    *,
    last_rotation_unix_s: float | None,
    now_unix_s: float | None = None,
    min_interval_s: int | None = None,
) -> bool:
    """Decide whether ``policy`` is due for rotation.

    * If we have never rotated (``last_rotation_unix_s is None``),
      due immediately so a fresh deployment writes its first
      generation.
    * Otherwise, due when the elapsed time exceeds
      ``rotation_days * 86400`` AND at least
      ``min_interval_s`` (default
      ``ANONYMIZE_REUSE_DETECTION_KEY_ROTATION_MIN_INTERVAL_S``,
       idempotency floor) has passed.
    """
    if policy.rotation_days <= 0:
        # Rotation disabled — never due.
        return False
    now = now_unix_s if now_unix_s is not None else time.time()
    if last_rotation_unix_s is None:
        return True
    elapsed = now - float(last_rotation_unix_s)
    if elapsed < 0:
        # Clock went backwards; treat as not-yet-due so a clock blip
        # doesn't double-rotate.
        return False
    threshold = float(policy.rotation_days) * 86400.0
    floor = (
        min_interval_s
        if min_interval_s is not None
        else int(settings.anonymize_reuse_detection_key_rotation_min_interval_s)
    )
    return elapsed >= threshold and elapsed >= float(floor)


def is_purge_due(
    policy: RotationPolicy,
    *,
    rotated_out_at_unix_s: float,
    now_unix_s: float | None = None,
) -> bool:
    """Past the retention horizon, the rotated-out key is purged.

    The purge sentinel-overwrites every column whose generating key
    has been retired (the actual sentinel write lives in the per-key
    purge pass; this helper just decides *when*).
    """
    if policy.retention_days <= 0:
        return True
    now = now_unix_s if now_unix_s is not None else time.time()
    elapsed = now - float(rotated_out_at_unix_s)
    return elapsed >= float(policy.retention_days) * 86400.0


def horizon_invariant_satisfied(
    policy: RotationPolicy,
    *,
    destination_retention_days: int,
) -> bool:
    """Startup horizon invariant.

    The retention window must be ≥ destination_retention_days +
    rotation_days, otherwise a leaked key + a recent backup could
    re-derive nonces for sessions that were event-collapsed under
    the assumption that the key was already gone.
    """
    return policy.retention_days >= destination_retention_days + policy.rotation_days


def quote_token_horizon_invariant_satisfied(
    policy: RotationPolicy,
    *,
    quote_ttl_s: int,
) -> bool:
    """Quote-token-specific horizon.

    For the quote-token HMAC key the relevant lower bound is the
    *quote token's TTL*, not the destination-retention horizon:

        ``RETENTION_DAYS >= ceil(QUOTE_TTL_S / 86400) + ROTATION_DAYS``

    A token signed under a key rotated out one minute ago must still
    verify until its issued_at + TTL elapses; the retention window
    must therefore exceed the TTL plus the worst-case rotation slack.
    """
    if policy.name != "quote_token_hmac":
        raise ValueError("quote_token_horizon_invariant_satisfied is for quote_token_hmac only")
    ttl_days = (int(quote_ttl_s) + 86400 - 1) // 86400  # ceil
    return policy.retention_days >= ttl_days + policy.rotation_days


__all__ = [
    "KeySetName",
    "RotationPolicy",
    "reuse_detection_policy",
    "hop_idempotency_policy",
    "quote_token_policy",
    "quote_cache_signing_policy",
    "all_policies",
    "is_rotation_due",
    "is_purge_due",
    "horizon_invariant_satisfied",
    "quote_token_horizon_invariant_satisfied",
]
