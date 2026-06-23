# SPDX-License-Identifier: MIT
"""Liquid fee oracle.

The Liquid hop must commit to a fee bound at quote time so the
operator's egress fingerprint at quote-creation is independent of
the per-session swap rate. The pattern: a **recurring
refresh task** polls the backend on a cadence (constant traffic
shape), updates an in-memory cache; quote-time reads are
**cache-only / synchronous** with no egress, defeating per-session
timing-correlation between quote creation and chain-side fee query.

Defense-in-depth clamps:

* **Floor** — never report below ``ANONYMIZE_LIQUID_FEE_RATE_FLOOR_SAT_PER_VB``
  so a backend returning ``0`` doesn't yield an unminable quote.
* **Ceiling** — never report above
  ``ANONYMIZE_LIQUID_FEE_RATE_CEILING_SAT_PER_VB`` so a backend
  returning an absurd rate doesn't drain the operator's budget.

Stale-cache fallback: when ``refresh()`` fails AND the cache is
older than the TTL, ``get_fee_sat_per_vb()`` returns the ceiling
(conservative) + a ``"stale"`` error so the caller can decide
whether to refuse the quote. When the cache is still fresh, ``refresh()``
failures are transparent.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

from app.core.config import settings

from .liquid_backend import LiquidBackend
from .metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


class LiquidFeeOracleError(RuntimeError):
    """Raised on a configuration error at oracle construction."""


@dataclass(frozen=True)
class CachedFeeRate:
    """One snapshot of the oracle's cache."""

    rate_sat_per_vb: float
    fetched_at_unix_s: float


class LiquidFeeOracle:
    """Cached + clamped Liquid fee oracle.

    Typical usage:

    .. code-block:: python

        oracle = LiquidFeeOracle(backend)
        # Recurring task:
        await oracle.refresh()
        # Quote-time:
        rate, err = oracle.get_fee_sat_per_vb()
    """

    def __init__(
        self,
        backend: LiquidBackend,
        *,
        floor_sat_per_vb: Optional[float] = None,
        ceiling_sat_per_vb: Optional[float] = None,
        cache_ttl_s: Optional[int] = None,
        default_target_blocks: Optional[int] = None,
    ) -> None:
        self._backend = backend
        self._floor = float(
            floor_sat_per_vb if floor_sat_per_vb is not None else settings.anonymize_liquid_fee_rate_floor_sat_per_vb
        )
        self._ceiling = float(
            ceiling_sat_per_vb
            if ceiling_sat_per_vb is not None
            else settings.anonymize_liquid_fee_rate_ceiling_sat_per_vb
        )
        if self._floor <= 0:
            raise LiquidFeeOracleError("floor_sat_per_vb must be positive")
        if self._ceiling < self._floor:
            raise LiquidFeeOracleError("ceiling_sat_per_vb must be >= floor_sat_per_vb")
        self._cache_ttl_s = int(
            cache_ttl_s if cache_ttl_s is not None else settings.anonymize_liquid_fee_rate_cache_ttl_s
        )
        if self._cache_ttl_s <= 0:
            raise LiquidFeeOracleError("cache_ttl_s must be positive")
        self._default_target_blocks = int(
            default_target_blocks
            if default_target_blocks is not None
            else settings.anonymize_liquid_fee_rate_default_target_blocks
        )
        if self._default_target_blocks <= 0:
            raise LiquidFeeOracleError("default_target_blocks must be positive")
        self._cached: Optional[CachedFeeRate] = None

        # Refresh-log throttling. When the Liquid backend
        # (electrs-liquid → elementsd) is unreachable for an
        # extended period (e.g. during Liquid IBD which can take
        # days), ``refresh()`` is called every cache_ttl_s and
        # would otherwise emit a WARNING every call indefinitely.
        # We log the first error of a streak + a periodic summary
        # at WARNING, identical repeats at DEBUG, and an INFO line
        # on recovery so operators see what they need without log
        # spam burying other diagnostics.
        self._consecutive_failures: int = 0
        self._last_failure_sig: Optional[str] = None
        self._failure_log_every: int = 20

    # ── Properties ─────────────────────────────────────────────────

    @property
    def floor_sat_per_vb(self) -> float:
        return self._floor

    @property
    def ceiling_sat_per_vb(self) -> float:
        return self._ceiling

    @property
    def cache_ttl_s(self) -> int:
        return self._cache_ttl_s

    @property
    def cached(self) -> Optional[CachedFeeRate]:
        return self._cached

    def is_cache_fresh(self, *, now_unix_s: Optional[float] = None) -> bool:
        if self._cached is None:
            return False
        now = now_unix_s if now_unix_s is not None else time.time()
        return (now - self._cached.fetched_at_unix_s) < self._cache_ttl_s

    # ── Clamping ───────────────────────────────────────────────────

    def _clamp(self, rate: float) -> float:
        """Clip ``rate`` into ``[floor, ceiling]``."""
        if rate < self._floor:
            return self._floor
        if rate > self._ceiling:
            return self._ceiling
        return rate

    # ── Refresh + read ─────────────────────────────────────────────

    async def refresh(
        self,
        *,
        now_unix_s: Optional[float] = None,
    ) -> Optional[str]:
        """Query the backend + update the cache. Returns ``None`` on
        success or an error string.

        On error, the cache is **not** updated — a stale value sticks
        around for ``get_fee_sat_per_vb`` to surface with a "stale"
        marker.
        """
        rate, err = await self._backend.estimate_fee_sat_per_vb(
            target_blocks=self._default_target_blocks,
        )
        if err is not None:
            sig = err
            self._consecutive_failures += 1
            is_new_streak = self._last_failure_sig != sig
            is_periodic_summary = self._consecutive_failures % self._failure_log_every == 0
            if is_new_streak:
                logger.warning(
                    "anonymize liquid fee oracle: backend refresh failed: %s",
                    err,
                )
            elif is_periodic_summary:
                logger.warning(
                    "anonymize liquid fee oracle: backend still unavailable after %d attempts: %s",
                    self._consecutive_failures,
                    err,
                )
            else:
                logger.debug(
                    "anonymize liquid fee oracle: backend refresh failed (attempt %d): %s",
                    self._consecutive_failures,
                    err,
                )
            self._last_failure_sig = sig
            return err
        if rate is None:
            return "backend returned no fee rate"
        if self._consecutive_failures > 0:
            logger.info(
                "anonymize liquid fee oracle: backend recovered after %d failed attempt(s)",
                self._consecutive_failures,
            )
        self._consecutive_failures = 0
        self._last_failure_sig = None
        now = now_unix_s if now_unix_s is not None else time.time()
        clamped = self._clamp(float(rate))
        self._cached = CachedFeeRate(
            rate_sat_per_vb=clamped,
            fetched_at_unix_s=float(now),
        )
        return None

    def get_fee_sat_per_vb(
        self,
        *,
        now_unix_s: Optional[float] = None,
    ) -> tuple[float, Optional[str]]:
        """Synchronous cache read.

        Returns:

        * ``(rate, None)`` — cache is fresh.
        * ``(rate, "stale")`` — cache is older than TTL but a prior
          value exists; the caller may use it or refuse based on
          its policy.
        * ``(ceiling, "no_cache")`` — no value has ever been
          successfully refreshed. The ceiling is returned as the
          maximally-conservative bound.
        """
        if self._cached is None:
            return self._ceiling, "no_cache"
        if not self.is_cache_fresh(now_unix_s=now_unix_s):
            return self._cached.rate_sat_per_vb, "stale"
        return self._cached.rate_sat_per_vb, None


# ── Module-level singleton ─────────────────────────────────────────


_INSTANCE: Optional[LiquidFeeOracle] = None


def get_liquid_fee_oracle(
    backend: Optional[LiquidBackend] = None,
) -> LiquidFeeOracle:
    """Return the singleton oracle. The first call must supply a backend."""
    global _INSTANCE
    if _INSTANCE is None:
        if backend is None:
            raise LiquidFeeOracleError("first call to get_liquid_fee_oracle must supply a backend")
        _INSTANCE = LiquidFeeOracle(backend)
    return _INSTANCE


def reset_liquid_fee_oracle() -> None:
    """Reset the singleton; intended for tests + supervisor restarts."""
    global _INSTANCE
    _INSTANCE = None


def is_liquid_indexer_reachable() -> bool:
    """Best-effort liveness signal for the electrs-liquid backend.

    Returns ``True`` when the fee-oracle's most recent refresh
    succeeded within its TTL — a positive signal that the
    underlying electrs-liquid indexer responded to a round-trip
    recently. Returns ``False`` when the oracle has not been
    initialised (Liquid hop disabled), when no refresh has yet
    succeeded, or when the last successful refresh is now stale.

    Used by the dashboard policy endpoint to render a "Liquid
    indexer unreachable" hint without requiring a fresh probe on
    every poll. Never raises; failure is the negative answer.
    """
    if _INSTANCE is None:
        return False
    try:
        return _INSTANCE.is_cache_fresh()
    except Exception:  # noqa: BLE001
        return False


__all__ = [
    "CachedFeeRate",
    "LiquidFeeOracle",
    "LiquidFeeOracleError",
    "get_liquid_fee_oracle",
    "is_liquid_indexer_reachable",
    "reset_liquid_fee_oracle",
]
