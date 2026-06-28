# SPDX-License-Identifier: MIT
"""Reusable retry + circuit-breaker primitives for upstream service clients.

Every external dependency the wallet talks to (LND, Boltz, mempool,
the BOLT 12 gateway) needs the same anti-fragility properties:

* Retry transient errors a small number of times with bounded
  exponential backoff so a 200 ms blip on the upstream doesn't turn
  into a 5xx on the API.
* Fast-fail when the upstream is sustainedly unhealthy so callers
  don't pile up on a wedged dependency, exhausting connection
  pools and amplifying the outage.
* Expose enough state (last success / consecutive failures /
  breaker state) that operators can answer "is this service
  healthy?" from a single endpoint instead of reading logs.

Implemented as a small composable helper rather than a base class so
each service module keeps full control over its public method
signatures (most of the wallet uses ``tuple[Optional[T], Optional[str]]``
which doesn't fit the base-class-with-decorator pattern cleanly).

Reference implementation: see ``app/services/bolt12/runtime.py`` for
the supervisor pattern this primitive generalises.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable, Iterable, TypeVar

logger = logging.getLogger(__name__)


T = TypeVar("T")


# ─── Defaults ────────────────────────────────────────────────────────────

DEFAULT_BACKOFF_S: tuple[float, ...] = (0.2, 0.5, 1.5)
"""Backoff schedule between retry attempts. Length implies retry count."""

DEFAULT_FAILURE_THRESHOLD: int = 5
"""Consecutive failures before the breaker opens."""

DEFAULT_OPEN_DURATION_S: float = 30.0
"""How long the breaker stays open before half-opening for one probe."""


# ─── Circuit breaker ─────────────────────────────────────────────────────


@dataclass
class CircuitBreaker:
    """Per-upstream circuit breaker.

    Lifecycle:

    * **closed** — calls flow through; failures count up.
    * **open** — calls fast-fail with :class:`BreakerOpenError`
      until ``open_duration_s`` elapses, then transitions to
      half-open on the next call.
    * **half_open** — exactly one call is allowed through; on
      success the breaker closes, on failure it opens again.

    The breaker is created per service instance and shared across
    all calls to that service. Concurrent half-open probes are
    serialised by ``_lock`` so we never let more than one request
    through during the probe.
    """

    name: str
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
    open_duration_s: float = DEFAULT_OPEN_DURATION_S

    state: str = "closed"  # "closed" | "open" | "half_open"
    consecutive_failures: int = 0
    opened_at: datetime | None = None
    last_error: str | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    # The loop ``_lock`` is bound to. A breaker is a process-wide
    # singleton, but Celery runs each task on its own throwaway loop;
    # an ``asyncio.Lock`` binds to the loop it first contends on, and
    # reusing it from another loop raises "bound to a different event
    # loop". We recreate the lock when the running loop changes.
    _lock_loop: "asyncio.AbstractEventLoop | None" = field(default=None, repr=False)

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _rebind_lock_if_needed(self) -> None:
        """Recreate ``_lock`` if the running event loop has changed.

        A loop change means the previous loop is gone (e.g. a finished
        Celery task), so any prior lock state is moot — a fresh lock on
        the current loop is correct and avoids "bound to a different
        event loop". On the long-lived web-server loop this is a no-op
        after the first call. Must be called from within a running loop.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop

    def _maybe_half_open(self) -> None:
        """Transition open → half_open once ``open_duration_s`` has elapsed."""
        if self.state != "open" or self.opened_at is None:
            return
        elapsed = (self._now() - self.opened_at).total_seconds()
        if elapsed >= self.open_duration_s:
            self.state = "half_open"
            logger.info("Circuit breaker [%s] half-opening after %.1fs", self.name, elapsed)

    async def before_call(self) -> None:
        """Raise :class:`BreakerOpenError` if the breaker is currently open.

        Must be awaited before every protected call. Concurrent
        half-open probes are serialised here: only one caller holds
        the lock during a half-open call.
        """
        self._maybe_half_open()
        if self.state == "open":
            raise BreakerOpenError(
                f"Circuit breaker '{self.name}' is open ({self.consecutive_failures} "
                f"consecutive failures, last_error={self.last_error!r})"
            )
        if self.state == "half_open":
            # Block any other coroutine from also slipping through during
            # the probe attempt. The lock is released in
            # record_success / record_failure. Rebind to the current loop
            # first so a probe from a fresh Celery task loop doesn't hit a
            # lock bound to a now-dead loop.
            self._rebind_lock_if_needed()
            await self._lock.acquire()

    def record_success(self) -> None:
        """Mark a successful call; close the breaker."""
        self.last_success_at = self._now()
        self.last_error = None
        if self.state == "half_open":
            logger.info("Circuit breaker [%s] closing after successful probe", self.name)
            if self._lock.locked():
                self._lock.release()
        self.state = "closed"
        self.consecutive_failures = 0
        self.opened_at = None

    def reset(self) -> None:
        """Force-close the breaker, releasing any half-open probe lock.

        Used by liveness-recovery code paths that have side-channel
        evidence the upstream is reachable (e.g. a freshly-rebuilt
        httpx pool just ping'd the LND ``/v1/getinfo`` endpoint
        successfully) but want to clear stale breaker state without
        waiting for the next ``before_call()`` to time-half-open.
        Routine callers should NOT use this — it bypasses the
        breaker's protection. Restricted to the lnd_keepalive active
        recovery path (see 2026-06-02 wedge postmortem).
        """
        # Drop any half-open probe lock by replacing it outright. This is
        # loop-safe (no cross-loop ``release()`` on a lock bound to a
        # now-dead loop) and clears the holder unconditionally, which is
        # exactly reset's intent. The next half-open probe rebinds it.
        self._lock = asyncio.Lock()
        self._lock_loop = None
        if self.state != "closed":
            logger.info(
                "Circuit breaker [%s] force-reset after %d consecutive failure(s)",
                self.name,
                self.consecutive_failures,
            )
        self.state = "closed"
        self.consecutive_failures = 0
        self.opened_at = None
        self.last_error = None

    def record_failure(self, error: str) -> None:
        """Mark a failed call; potentially open the breaker."""
        self.last_failure_at = self._now()
        # Cap ``last_error`` to a reasonable length. ``BreakerOpenError``
        # embeds ``last_error`` via ``!r`` in its message, so if a caller
        # ever feeds that message back in here the escape depth doubles
        # on every pass — left uncapped this OOMs the process. 512 chars
        # is plenty for diagnostics; longer payloads (HTML error pages,
        # deeply-nested JSON) are not actionable in this field.
        if len(error) > 512:
            error = error[:509] + "..."
        self.last_error = error
        self.consecutive_failures += 1
        if self.state == "half_open":
            # Half-open probe failed → re-open immediately.
            self.state = "open"
            self.opened_at = self._now()
            logger.warning(
                "Circuit breaker [%s] re-opened after failed probe (error=%s)",
                self.name,
                error,
            )
            if self._lock.locked():
                self._lock.release()
            return
        if self.state == "closed" and self.consecutive_failures >= self.failure_threshold:
            self.state = "open"
            self.opened_at = self._now()
            logger.warning(
                "Circuit breaker [%s] OPEN after %d consecutive failures (last=%s)",
                self.name,
                self.consecutive_failures,
                error,
            )

    def snapshot(self) -> dict[str, object]:
        """Operator-facing view, suitable for JSON serialisation."""
        return {
            "state": self.state,
            "consecutive_failures": self.consecutive_failures,
            "opened_at": self.opened_at.isoformat() if self.opened_at else None,
            "last_error": self.last_error,
            "last_success_at": (self.last_success_at.isoformat() if self.last_success_at else None),
            "last_failure_at": (self.last_failure_at.isoformat() if self.last_failure_at else None),
        }


class BreakerOpenError(RuntimeError):
    """Raised by :meth:`CircuitBreaker.before_call` when the breaker is open."""


# ─── Retry helper ────────────────────────────────────────────────────────


async def with_retry(
    op: Callable[[], Awaitable[T]],
    *,
    retryable: tuple[type[BaseException], ...],
    backoff_s: Iterable[float] = DEFAULT_BACKOFF_S,
    breaker: CircuitBreaker | None = None,
    op_name: str = "op",
) -> T:
    """Run ``op`` with retry + optional circuit breaker.

    Behaviour:

    * If ``breaker`` is supplied, fast-fails with :class:`BreakerOpenError`
      when the breaker is open.
    * Retries ``op`` on instances of ``retryable`` up to
      ``len(backoff_s)`` extra attempts. Each delay is jittered ±20 %
      to avoid thundering-herd retries from many concurrent callers.
    * On success, records the breaker hit and returns the result.
    * On non-retryable failure, records the breaker miss and re-raises.
    * On retry exhaustion, records the breaker miss and re-raises the
      last exception.
    """
    if breaker is not None:
        await breaker.before_call()

    delays = list(backoff_s)
    last_exc: BaseException | None = None
    attempts = 0
    max_attempts = 1 + len(delays)

    while attempts < max_attempts:
        attempts += 1
        try:
            result = await op()
        except retryable as e:
            last_exc = e
            if attempts >= max_attempts:
                break
            delay = delays[attempts - 1]
            jitter = delay * (0.8 + 0.4 * random.random())
            logger.debug(
                "%s transient failure (attempt %d/%d): %s — retrying in %.2fs",
                op_name,
                attempts,
                max_attempts,
                e,
                jitter,
            )
            await asyncio.sleep(jitter)
            continue
        except BaseException as e:
            # Non-retryable — record miss and re-raise.
            if breaker is not None:
                breaker.record_failure(f"{type(e).__name__}: {e}")
            raise
        else:
            if breaker is not None:
                breaker.record_success()
            return result

    # Retry exhausted.
    assert last_exc is not None
    if breaker is not None:
        breaker.record_failure(f"{type(last_exc).__name__}: {last_exc}")
    raise last_exc
