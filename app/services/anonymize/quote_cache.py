# SPDX-License-Identifier: MIT
"""Background pair-info / fee cache.

The ``POST /quote`` endpoint reads only from this cache (quote
network silence). Refreshes happen on a randomized cadence
(``Uniform(450, 750)`` s by default) and round-robin across the full
registry so no single operator sees us at a fixed cadence.

The cache is keyed on ``(operator_id, pair, asset)`` — never on
``(pair, asset)`` alone — so a malicious operator can poison only its
own namespace.

Post-rotation reads under a rotated-out signing key block
until refresh completes; on timeout, return 503 quote_cache_stale.

This module ships:
*:func:`sample_refresh_interval_s` — the randomized cadence.
* :class:`CacheKey` / :class:`CacheEntry` — the per-operator
  namespacing data shape.
* :func:`is_entry_fresh` — predicate the quote-handler uses on read.

The actual refresh task + signature verification land alongside the
HTTP client wrapper for live Boltz traffic.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.core.config import settings


def sample_refresh_interval_s(rng: secrets.SystemRandom | None = None) -> int:
    """Sample the next refresh interval uniformly.

    Defaults to ``Uniform(ANONYMIZE_QUOTE_CACHE_REFRESH_MIN_S,
    ANONYMIZE_QUOTE_CACHE_REFRESH_MAX_S)``. The randomized cadence
    denies a fixed-cadence beacon to any single operator.
    """
    rng = rng or secrets.SystemRandom()
    lo = int(settings.anonymize_quote_cache_refresh_min_s)
    hi = int(settings.anonymize_quote_cache_refresh_max_s)
    if hi < lo:
        # Mis-config — fall back to using the minimum.
        return lo
    return rng.randint(lo, hi)


@dataclass(frozen=True)
class CacheKey:
    """per-operator namespacing key.

    The cache is keyed on ``(operator_id, pair, asset)`` so a
    malicious operator can poison only its own namespace.
    """

    operator_id: str
    pair: str
    asset: str

    def __post_init__(self) -> None:
        for k in ("operator_id", "pair", "asset"):
            v = getattr(self, k)
            if not isinstance(v, str) or not v:
                raise ValueError(f"CacheKey.{k} must be a non-empty string")


@dataclass(frozen=True)
class CacheEntry:
    """One operator's cached pair-info response."""

    key: CacheKey
    payload: dict[str, Any]
    fetched_at_unix_s: float
    operator_signature: bytes | None = None  # sig per read
    signing_key_generation: int | None = None  #


def is_entry_fresh(
    entry: CacheEntry,
    *,
    max_age_s: int | None = None,
    now_unix_s: float | None = None,
) -> bool:
    """True iff ``entry`` is within ``max_age_s`` of now."""
    if max_age_s is None:
        max_age_s = int(settings.anonymize_quote_cache_max_age_s)
    if max_age_s <= 0:
        return False
    now = now_unix_s if now_unix_s is not None else time.time()
    return (now - entry.fetched_at_unix_s) <= max_age_s


def is_entry_eligible_for_soft_stale_read(
    entry: CacheEntry,
    *,
    active_signing_key_generation: int,
) -> bool:
    """Return True iff the cache line was signed under the
    *active* signing-key generation.

    A line signed under a rotated-out key MUST NOT be returned via
    the soft-stale path; the read blocks until refresh completes
    (or returns 503 quote_cache_stale on timeout).
    """
    if entry.signing_key_generation is None:
        return False
    return entry.signing_key_generation == active_signing_key_generation


# --------------------------------------------------------------------
# items 94 + 125 — soft-stale read decisions.
# --------------------------------------------------------------------


from typing import Literal

SoftStaleDecision = Literal[
    "serve",  # entry is fresh + active-key-signed → serve.
    "block_for_refresh",  # rotated-out signing key → block until refresh.
    "stale_503",  # entry is past max age (or refresh exceeded its budget) → 503.
]


def soft_stale_block_should_503(
    *,
    block_started_unix_s: float,
    now_unix_s: float | None = None,
    timeout_s: int | None = None,
) -> bool:
    """Soft-stale block deadline.

    The orchestrator's blocking-refresh path waits up to
    ``ANONYMIZE_QUOTE_CACHE_SOFT_STALE_REFRESH_TIMEOUT_S`` (default 5s)
    for the refresh task to land a new entry. Past the deadline, the
    read returns the byte-pinned ``503 quote_cache_stale`` body
    (identical to the cache-stale path so the post-rotation
    timing channel does not leak).
    """
    now = now_unix_s if now_unix_s is not None else time.time()
    tmo = int(timeout_s) if timeout_s is not None else int(settings.anonymize_quote_cache_soft_stale_refresh_timeout_s)
    if tmo <= 0:
        return True
    return (now - block_started_unix_s) >= float(tmo)


def soft_stale_read_decision(
    entry: CacheEntry,
    *,
    active_signing_key_generation: int,
    now_unix_s: float | None = None,
    max_age_s: int | None = None,
) -> SoftStaleDecision:
    """Decide what the read path does for ``entry``.

    Three outcomes:

    * ``serve`` — the entry is fresh AND its signature is under the
      currently-active signing key.
    * ``block_for_refresh`` — the entry's signature was generated
      under a *rotated-out* key. The contract: the read
      path blocks until a refresh under the active key completes
      (or its `ANONYMIZE_QUOTE_CACHE_SOFT_STALE_REFRESH_TIMEOUT_S`
      budget elapses, in which case it returns 503).
    * ``stale_503`` — the entry is past its max-age threshold
      independent of signing key. The orchestrator emits a byte-
      pinned 503 ``quote_cache_stale`` (/.py).
    """
    if not is_entry_fresh(entry, max_age_s=max_age_s, now_unix_s=now_unix_s):
        return "stale_503"
    if not is_entry_eligible_for_soft_stale_read(entry, active_signing_key_generation=active_signing_key_generation):
        return "block_for_refresh"
    return "serve"


def sample_reverify_jitter_s(rng: secrets.SystemRandom | None = None) -> float:
    """Per-entry verification-deadline jitter.

    Spreads the thundering-herd impact of a legitimate operator-key
    rotation: each cache line's next-verify deadline lies somewhere
    in ``[0, ANONYMIZE_QUOTE_CACHE_REVERIFY_JITTER_S)``.
    """
    rng = rng or secrets.SystemRandom()
    cap = max(0, int(settings.anonymize_quote_cache_reverify_jitter_s))
    if cap <= 0:
        return 0.0
    return rng.uniform(0.0, float(cap))


# --------------------------------------------------------------------
# Rotation pre-warm (resign) pass.
# --------------------------------------------------------------------


@dataclass(frozen=True)
class ResignResult:
    """Outcome of one :func:`run_resign_pass` invocation."""

    resign_count: int
    duration_s: float
    skipped_count: int  # already on the active generation


def run_resign_pass(
    entries: list[CacheEntry],
    *,
    active_signing_key_generation: int,
    sign_fn: Callable[[CacheEntry, int], bytes],
    rate_per_s: int | None = None,
    now_fn: Callable[[], float] = time.time,
    sleep_fn: Callable[[float], object] = time.sleep,
) -> tuple[list[CacheEntry], ResignResult]:
    """Rotation pre-warm pass.

    Walks ``entries`` and re-signs each cache line whose signature was
    generated under a rotated-out key under the *new* active signing
    key, **without** re-fetching the payload from the operator. The
    rate is bounded by ``ANONYMIZE_QUOTE_CACHE_RESIGN_RATE_PER_S``
    (default 50/s) to keep CPU spikes off the wallet-host budget.

    ``sign_fn`` is ``Callable[[CacheEntry, int], bytes]`` — the caller
    plugs in the active HMAC key. The function is pure for the cache
    layer; the only side effect is the throttle sleep.

    Returns the rebuilt entry list (in input order) and a result
    record consumed by the metric emitter the orchestrator runs
    when the pass completes.
    """
    rate = int(rate_per_s) if rate_per_s is not None else int(settings.anonymize_quote_cache_resign_rate_per_s)
    if rate <= 0:
        raise ValueError("resign rate must be positive")
    interval_s = 1.0 / float(rate)

    start = float(now_fn())
    rebuilt: list[CacheEntry] = []
    resign_count = 0
    skipped_count = 0

    for idx, entry in enumerate(entries):
        if entry.signing_key_generation == active_signing_key_generation:
            rebuilt.append(entry)
            skipped_count += 1
            continue
        new_sig = sign_fn(entry, active_signing_key_generation)
        rebuilt.append(
            CacheEntry(
                key=entry.key,
                payload=entry.payload,
                fetched_at_unix_s=entry.fetched_at_unix_s,
                operator_signature=new_sig,
                signing_key_generation=active_signing_key_generation,
            )
        )
        resign_count += 1
        # Throttle: skip the sleep on the very last entry so the
        # caller's metric timing reflects actual work, not idle wait.
        if idx < len(entries) - 1 and interval_s > 0:
            sleep_fn(interval_s)

    duration_s = max(0.0, float(now_fn()) - start)
    return rebuilt, ResignResult(
        resign_count=resign_count,
        duration_s=duration_s,
        skipped_count=skipped_count,
    )


@dataclass
class QuoteCacheInstance:
    """Per-operator-namespaced in-memory quote cache.

    Stores entries indexed by :class:`CacheKey` ``(operator_id,
    pair, asset)``. The recurring refresh task populates
    entries with fresh pair-info from Boltz; the quote endpoint
    reads via :meth:`get`. A poisoned response from operator A
    cannot affect a session that selected operator B.
    """

    entries: dict[CacheKey, CacheEntry] = field(default_factory=dict)

    def put(self, entry: CacheEntry) -> None:
        self.entries[entry.key] = entry

    def get(self, key: CacheKey) -> CacheEntry | None:
        return self.entries.get(key)

    def remove(self, key: CacheKey) -> None:
        self.entries.pop(key, None)

    def all(self) -> list[CacheEntry]:
        return list(self.entries.values())

    def size(self) -> int:
        return len(self.entries)


_QUOTE_CACHE: QuoteCacheInstance | None = None


def get_quote_cache() -> QuoteCacheInstance:
    """Return the module-level singleton cache instance."""
    global _QUOTE_CACHE
    if _QUOTE_CACHE is None:
        _QUOTE_CACHE = QuoteCacheInstance()
    return _QUOTE_CACHE


def reset_quote_cache() -> None:
    """Test helper — clear the singleton between cases."""
    global _QUOTE_CACHE
    _QUOTE_CACHE = None


def invalidate_quote_cache_for_operator(operator_id: str) -> None:
    """Evict every
    quote-cache entry whose key references ``operator_id``.

    Called from :func:`operator_health.record_operator_outlier` when
    an operator transitions to degraded, so a stale-but-validated
    quote that priced through that operator cannot be returned by
    the quote endpoint.
    """
    cache = get_quote_cache()
    to_evict = [k for k in cache.entries if k.operator_id == operator_id]
    for k in to_evict:
        cache.remove(k)


# --------------------------------------------------------------------
# Operator-bound HMAC signing + verify-on-read.
# --------------------------------------------------------------------


import hashlib
import hmac
import json


def _signing_key_bytes() -> bytes | None:
    """Resolve the active HMAC key for cache-entry signatures.

    The persisted key is a Fernet-encrypted string under
    ``ANONYMIZE_QUOTE_CACHE_SIGNING_KEY_FERNET``. When the operator
    has not configured one we fall back to ``None``; the read path
    then skips verification (logged-only WARNING) so a fresh
    deployment without the key still serves quotes.
    """
    raw = (settings.anonymize_quote_cache_signing_key_fernet or "").strip()
    if not raw:
        return None
    # Use the Fernet-formatted bytes themselves as the key material.
    # Fernet keys are url-safe base64 with a fixed length (32 bytes
    # after decode); the HMAC accepts arbitrary-length keys, so the
    # straightforward path is to use the raw token as a stable secret
    # rather than introducing a separate KDF.
    return raw.encode("ascii")


def _canonical_entry_bytes(
    *,
    key: "CacheKey",
    payload: dict[str, Any],
    fetched_at_unix_s: float,
    signing_key_generation: int,
) -> bytes:
    """Canonicalize the entry fields into bytes for HMAC input.

    The canonicalization sorts dict keys + uses compact JSON separators
    so a tampered payload that *adds* a field changes the digest.
    """
    canonical = {
        "k": [key.operator_id, key.pair, key.asset],
        "p": payload,
        "t": int(fetched_at_unix_s),
        "g": int(signing_key_generation),
    }
    return json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_cache_entry(
    *,
    key: "CacheKey",
    payload: dict[str, Any],
    fetched_at_unix_s: float,
    signing_key_generation: int,
) -> bytes | None:
    """Return the HMAC-SHA256 over a canonicalized cache entry, or
    ``None`` when no signing key is configured.

    Callers store the result on the :class:`CacheEntry` row; the read
    path verifies it via :func:`verify_cache_entry`.
    """
    key_bytes = _signing_key_bytes()
    if key_bytes is None:
        return None
    message = _canonical_entry_bytes(
        key=key,
        payload=payload,
        fetched_at_unix_s=fetched_at_unix_s,
        signing_key_generation=signing_key_generation,
    )
    return hmac.new(key_bytes, message, hashlib.sha256).digest()


def verify_cache_entry(entry: "CacheEntry") -> bool:
    """Verify the HMAC signature on a cache entry.

    Returns ``True`` when the signature matches under the configured
    key, and ``False`` on mismatch or on a configured-key-but-unsigned
    entry — the caller routes a ``False`` as "treat as cache miss +
    refresh". The no-key branch returns ``True`` only as a defensive
    default; an enabled anonymize service always has a signing key
    because :func:`startup.assert_quote_cache_signing_key_loadable`
    refuses to start without one, so the cache is never consulted in
    that state.
    """
    key_bytes = _signing_key_bytes()
    if key_bytes is None:
        return True
    if entry.operator_signature is None:
        # A configured key + unsigned entry is an integrity gap; the
        # read path must refuse it.
        return False
    expected = sign_cache_entry(
        key=entry.key,
        payload=entry.payload,
        fetched_at_unix_s=entry.fetched_at_unix_s,
        signing_key_generation=(entry.signing_key_generation or 0),
    )
    if expected is None:  # configuration race — fail closed
        return False
    return hmac.compare_digest(expected, entry.operator_signature)


__all__ = [
    "CacheKey",
    "CacheEntry",
    "QuoteCacheInstance",
    "ResignResult",
    "SoftStaleDecision",
    "sample_refresh_interval_s",
    "is_entry_fresh",
    "is_entry_eligible_for_soft_stale_read",
    "soft_stale_read_decision",
    "soft_stale_block_should_503",
    "sample_reverify_jitter_s",
    "run_resign_pass",
    "sign_cache_entry",
    "verify_cache_entry",
    "get_quote_cache",
    "reset_quote_cache",
]
