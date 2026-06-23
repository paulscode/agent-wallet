# SPDX-License-Identifier: MIT
"""Per-listener + aggregate circuit-rebuild token buckets.

A guard / ISP / cloud-metrics adversary that watches Tor circuits
originating from our wallet host can fingerprint anonymize sessions
by the *burst* of fresh circuit-build requests they generate during
operator outages. The mitigation is a per-listener token
bucket — once a listener exhausts its budget the orchestrator routes
the session to ``awaiting_reconciliation`` rather than continuing the
rebuild burst.

Bucket state (level + last-refill timestamp) is persisted
in ``anonymize_runtime_state`` so an attacker who induces orchestrator
restart cycles cannot recover budget the bucket had already paid out.

This module ships:
* :class:`TokenBucket` — pure leaky-bucket math (level, refill rate,
  burst capacity). Uses :func:`time.monotonic` so wall-clock drift
  doesn't produce phantom budget.
* :func:`tokens_per_second_for_listener` / :func:`aggregate_tokens_per_second`
  — translate the human-friendly ``per_hour`` config into a per-second
  refill rate.

The orchestrator-side persistence wrapper lives in :mod:`gc` /
:mod:`runtime_state` modules (filled in alongside the actual rebuild
call site).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from app.core.config import settings

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def tokens_per_second_for_listener() -> float:
    """Per-listener refill rate (tokens / second)."""
    per_hour = max(0, int(settings.anonymize_circuit_rebuild_tokens_per_hour))
    return per_hour / 3600.0


def aggregate_tokens_per_second() -> float:
    """Aggregate refill rate across every listener (tokens / second)."""
    per_hour = max(0, int(settings.anonymize_circuit_rebuild_aggregate_tokens_per_hour))
    return per_hour / 3600.0


def burst_capacity() -> int:
    """Maximum standing tokens before saturation."""
    return max(1, int(settings.anonymize_circuit_rebuild_burst))


@dataclass
class TokenBucket:
    """Leaky-bucket model for circuit-rebuild rate control.

    The bucket is described by:
    * ``level`` — current standing tokens (float; refilling is
      continuous-time even though consumption is discrete). When
      omitted, the bucket starts saturated at ``capacity``; pass an
      explicit float (including ``0.0``) to start at a specific level.
    * ``capacity`` — maximum standing tokens; saturating refill is
      bounded by this.
    * ``refill_rate_per_s`` — tokens added per second of wall-clock
      time elapsed since the last refill.
    * ``last_refill_monotonic_s`` — monotonic-clock anchor used to
      compute "elapsed since last refill" without trusting the wall
      clock.
    """

    capacity: int
    refill_rate_per_s: float
    level: float | None = None
    last_refill_monotonic_s: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        # When ``level`` was not specified by the caller, saturate the
        # bucket so a fresh deployment doesn't immediately reject its
        # first attempt. Callers that want a specific starting level
        # (including a starved 0.0) pass it explicitly.
        if self.level is None:
            self.level = float(self.capacity)
        else:
            self.level = float(self.level)

    def refill(self, *, now_monotonic_s: float | None = None) -> None:
        """Update ``level`` based on elapsed time since the last refill."""
        now = now_monotonic_s if now_monotonic_s is not None else time.monotonic()
        elapsed = max(0.0, now - self.last_refill_monotonic_s)
        # ``__post_init__`` always coerces ``level`` to a float.
        assert self.level is not None
        if elapsed > 0 and self.refill_rate_per_s > 0:
            self.level = min(
                float(self.capacity),
                self.level + elapsed * self.refill_rate_per_s,
            )
        self.last_refill_monotonic_s = now

    def try_consume(
        self,
        cost: float = 1.0,
        *,
        now_monotonic_s: float | None = None,
    ) -> bool:
        """Attempt to consume ``cost`` tokens; return True on success.

        Refills the bucket against the current monotonic clock first,
        then deducts. The orchestrator's call site tracks the
        return value: True ⇒ proceed with the rebuild;
        False ⇒ park the session in ``awaiting_reconciliation`` with
        ``reason=circuit_rebuild_throttled``.
        """
        self.refill(now_monotonic_s=now_monotonic_s)
        # ``refill`` (via ``__post_init__``) guarantees ``level`` is set.
        assert self.level is not None
        if self.level < cost:
            return False
        self.level -= cost
        return True

    def available(self, *, now_monotonic_s: float | None = None) -> float:
        """Return the *current* level after refill (read-only inspection)."""
        self.refill(now_monotonic_s=now_monotonic_s)
        # ``refill`` (via ``__post_init__``) guarantees ``level`` is set.
        assert self.level is not None
        return self.level


def make_per_listener_bucket() -> TokenBucket:
    """Build a fresh per-listener bucket using config defaults."""
    return TokenBucket(
        capacity=burst_capacity(),
        refill_rate_per_s=tokens_per_second_for_listener(),
    )


def make_aggregate_bucket() -> TokenBucket:
    """Build a fresh aggregate bucket using config defaults.

    Capacity ≈ ``BURST × number_of_listeners``; the aggregate refill
    rate is the documented ``ANONYMIZE_CIRCUIT_REBUILD_AGGREGATE_TOKENS_PER_HOUR``.
    """
    listener_count = max(1, len(settings.anonymize_tor_socks_ports_dict))
    return TokenBucket(
        capacity=burst_capacity() * listener_count,
        refill_rate_per_s=aggregate_tokens_per_second(),
    )


@dataclass
class CircuitRebuildGuard:
    """Process-wide bucket guard for per-listener +
    aggregate circuit-rebuild budgets.

    Every anonymize-egress call that opens a fresh Tor circuit
    must first :meth:`admit`; if either the per-listener bucket or
    the aggregate is starved, the call refuses and the caller
    routes to :func:`http.py`'s circuit-rebuild-throttled handler.
    """

    per_listener: dict[str, TokenBucket] = field(default_factory=dict)
    aggregate: TokenBucket | None = None

    def _ensure(self, listener: str) -> TokenBucket:
        b = self.per_listener.get(listener)
        if b is None:
            b = make_per_listener_bucket()
            self.per_listener[listener] = b
        return b

    def admit(
        self,
        listener: str,
        *,
        now_monotonic_s: float | None = None,
    ) -> bool:
        """True iff the per-listener AND aggregate buckets admit
        one circuit-rebuild call right now. On refusal, no token is
        consumed in either bucket; on admit, exactly one token is
        consumed in each."""
        agg = self.aggregate
        if agg is None:
            agg = make_aggregate_bucket()
            self.aggregate = agg
        local = self._ensure(listener)
        # Peek both before consuming so a refused call leaves both
        # buckets unmodified.
        if local.available(now_monotonic_s=now_monotonic_s) < 1.0:
            return False
        if agg.available(now_monotonic_s=now_monotonic_s) < 1.0:
            return False
        # Both can admit — actually consume.
        local.try_consume(now_monotonic_s=now_monotonic_s)
        agg.try_consume(now_monotonic_s=now_monotonic_s)
        return True


_GUARD: CircuitRebuildGuard | None = None


def get_circuit_rebuild_guard() -> CircuitRebuildGuard:
    """Module-level singleton; the HTTP-client factory calls
    :meth:`admit` before issuing a fresh SOCKS-auth pair."""
    global _GUARD
    if _GUARD is None:
        _GUARD = CircuitRebuildGuard()
    return _GUARD


def reset_circuit_rebuild_guard() -> None:
    """Test helper — clear the singleton."""
    global _GUARD
    _GUARD = None


# --------------------------------------------------------------------
# Runtime-state persistence so a process restart cannot
# silently reset the bucket and refund budget the bucket had already
# paid out.
# --------------------------------------------------------------------


def _runtime_state_key_for_listener(listener: str) -> str:
    return f"circuit_rebuild_bucket:listener={listener}"


_AGGREGATE_RUNTIME_STATE_KEY = "circuit_rebuild_bucket:aggregate"


def _bucket_to_payload(bucket: TokenBucket) -> dict:
    return {
        "capacity": int(bucket.capacity),
        "refill_rate_per_s": float(bucket.refill_rate_per_s),
        "level": float(bucket.level if bucket.level is not None else 0.0),
        "last_refill_monotonic_s": float(bucket.last_refill_monotonic_s),
    }


def _payload_to_bucket(payload: dict) -> TokenBucket | None:
    if not isinstance(payload, dict):
        return None
    try:
        return TokenBucket(
            capacity=int(payload["capacity"]),
            refill_rate_per_s=float(payload["refill_rate_per_s"]),
            level=float(payload["level"]),
            last_refill_monotonic_s=float(payload["last_refill_monotonic_s"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


async def persist_circuit_rebuild_guard(db: AsyncSession, guard: CircuitRebuildGuard) -> None:
    """Write the current bucket state for every per-listener
    bucket + the aggregate bucket into ``anonymize_runtime_state``.

    Called by the orchestrator periodically and on graceful shutdown
    so a restart can't recover already-paid-out budget.
    """
    from .runtime_state import write_runtime_state

    for listener, bucket in guard.per_listener.items():
        await write_runtime_state(
            db,
            key=_runtime_state_key_for_listener(listener),
            payload=_bucket_to_payload(bucket),
        )
    if guard.aggregate is not None:
        await write_runtime_state(
            db,
            key=_AGGREGATE_RUNTIME_STATE_KEY,
            payload=_bucket_to_payload(guard.aggregate),
        )


async def hydrate_circuit_rebuild_guard(
    db: AsyncSession,
    *,
    listeners: tuple[str, ...] = (),
) -> CircuitRebuildGuard:
    """Load persisted bucket state into a fresh guard.

    The caller passes the configured listener keys (typically from
    ``settings.anonymize_tor_socks_ports_dict``); any listener whose
    row is absent gets a fresh saturated bucket.
    """
    from .runtime_state import read_runtime_state

    guard = CircuitRebuildGuard()
    for listener in listeners:
        raw = await read_runtime_state(
            db,
            key=_runtime_state_key_for_listener(listener),
        )
        loaded = _payload_to_bucket(raw) if raw is not None else None
        if loaded is None:
            loaded = make_per_listener_bucket()
        guard.per_listener[listener] = loaded
    agg_raw = await read_runtime_state(db, key=_AGGREGATE_RUNTIME_STATE_KEY)
    guard.aggregate = _payload_to_bucket(agg_raw) if agg_raw else make_aggregate_bucket()
    return guard


__all__ = [
    "TokenBucket",
    "CircuitRebuildGuard",
    "tokens_per_second_for_listener",
    "aggregate_tokens_per_second",
    "burst_capacity",
    "make_per_listener_bucket",
    "make_aggregate_bucket",
    "get_circuit_rebuild_guard",
    "reset_circuit_rebuild_guard",
    "persist_circuit_rebuild_guard",
    "hydrate_circuit_rebuild_guard",
]
