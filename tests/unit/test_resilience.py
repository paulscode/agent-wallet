# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`app.core.resilience`.

Pins the circuit-breaker state machine and the ``with_retry`` helper
that every upstream-service client shares. The invariants under test:

* The breaker walks closed → open → half_open → closed (and
  half_open → open on a failed probe) on the documented triggers,
  and ``before_call`` fast-fails with :class:`BreakerOpenError`
  while open.
* ``with_retry`` retries only the declared retryable types, records
  the breaker outcome exactly once, and re-raises the original
  exception on non-retryable failure / retry exhaustion.

The breaker reads time through its own ``_now`` seam; tests drive the
open-duration boundary by replacing ``_now`` rather than sleeping for
real wall-clock time, and ``with_retry``'s inter-attempt backoff is
neutralised by stubbing :func:`asyncio.sleep`, so the suite is
deterministic under ``pytest -n auto``.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.core.resilience import (
    BreakerOpenError,
    CircuitBreaker,
    with_retry,
)


def _fixed_clock(start: datetime):
    """Return a ``_now`` replacement whose value the test advances."""
    state = {"now": start}

    def now() -> datetime:
        return state["now"]

    def advance(seconds: float) -> None:
        state["now"] = state["now"] + timedelta(seconds=seconds)

    return now, advance, state


# ── breaker state transitions ──────────────────────────────────────


def test_breaker_opens_after_threshold_consecutive_failures() -> None:
    """A closed breaker opens precisely when ``consecutive_failures``
    reaches ``failure_threshold`` — not before."""
    cb = CircuitBreaker(name="svc", failure_threshold=3)
    cb.record_failure("boom")
    cb.record_failure("boom")
    assert cb.state == "closed"
    cb.record_failure("boom")
    assert cb.state == "open"
    assert cb.opened_at is not None


@pytest.mark.asyncio
async def test_before_call_fast_fails_while_open() -> None:
    """While open and before the open duration elapses, ``before_call``
    raises :class:`BreakerOpenError` instead of admitting the call."""
    cb = CircuitBreaker(name="svc", failure_threshold=1, open_duration_s=30.0)
    now, _advance, _state = _fixed_clock(datetime.now(timezone.utc))
    cb._now = now  # type: ignore[method-assign]
    cb.record_failure("down")
    assert cb.state == "open"
    with pytest.raises(BreakerOpenError):
        await cb.before_call()


@pytest.mark.asyncio
async def test_open_transitions_to_half_open_after_duration() -> None:
    """Once ``open_duration_s`` has elapsed, the next ``before_call``
    half-opens and admits exactly one probe (it does not raise)."""
    cb = CircuitBreaker(name="svc", failure_threshold=1, open_duration_s=30.0)
    now, advance, _state = _fixed_clock(datetime.now(timezone.utc))
    cb._now = now  # type: ignore[method-assign]
    cb.record_failure("down")
    assert cb.state == "open"

    advance(30.0)
    await cb.before_call()
    assert cb.state == "half_open"
    # The half-open probe holds the serialising lock until resolved.
    assert cb._lock.locked()
    cb.record_success()
    assert not cb._lock.locked()


@pytest.mark.asyncio
async def test_half_open_success_closes_breaker() -> None:
    """A successful half-open probe closes the breaker and clears the
    failure counter and opened-at marker."""
    cb = CircuitBreaker(name="svc", failure_threshold=1, open_duration_s=10.0)
    now, advance, _state = _fixed_clock(datetime.now(timezone.utc))
    cb._now = now  # type: ignore[method-assign]
    cb.record_failure("down")
    advance(10.0)
    await cb.before_call()
    assert cb.state == "half_open"

    cb.record_success()
    assert cb.state == "closed"
    assert cb.consecutive_failures == 0
    assert cb.opened_at is None
    assert cb.last_success_at is not None


@pytest.mark.asyncio
async def test_half_open_failure_reopens_breaker() -> None:
    """A failed half-open probe re-opens the breaker immediately,
    releases the probe lock, and refreshes ``opened_at``."""
    cb = CircuitBreaker(name="svc", failure_threshold=1, open_duration_s=10.0)
    now, advance, _state = _fixed_clock(datetime.now(timezone.utc))
    cb._now = now  # type: ignore[method-assign]
    cb.record_failure("down")
    advance(10.0)
    await cb.before_call()
    assert cb.state == "half_open"

    cb.record_failure("probe failed")
    assert cb.state == "open"
    assert not cb._lock.locked()
    # A fresh probe is not admitted until the duration elapses again.
    with pytest.raises(BreakerOpenError):
        await cb.before_call()


@pytest.mark.asyncio
async def test_maybe_half_open_no_transition_before_duration() -> None:
    """Before ``open_duration_s`` elapses the breaker stays open and
    ``before_call`` keeps fast-failing."""
    cb = CircuitBreaker(name="svc", failure_threshold=1, open_duration_s=30.0)
    now, advance, _state = _fixed_clock(datetime.now(timezone.utc))
    cb._now = now  # type: ignore[method-assign]
    cb.record_failure("down")
    advance(29.9)
    with pytest.raises(BreakerOpenError):
        await cb.before_call()
    assert cb.state == "open"


def test_record_success_resets_consecutive_failures_while_closed() -> None:
    """A success below the open threshold clears the running failure
    count so transient blips don't accumulate toward opening."""
    cb = CircuitBreaker(name="svc", failure_threshold=5)
    cb.record_failure("blip")
    cb.record_failure("blip")
    assert cb.consecutive_failures == 2
    cb.record_success()
    assert cb.consecutive_failures == 0
    assert cb.state == "closed"


def test_reset_force_closes_open_breaker_and_releases_lock() -> None:
    """``reset`` force-closes an open breaker and clears all failure
    state, even though it bypasses the normal half-open probe."""
    cb = CircuitBreaker(name="svc", failure_threshold=1)
    cb.record_failure("down")
    assert cb.state == "open"
    cb.reset()
    assert cb.state == "closed"
    assert cb.consecutive_failures == 0
    assert cb.opened_at is None
    assert cb.last_error is None


def test_reset_on_already_closed_breaker_is_idempotent() -> None:
    """``reset`` on a fresh, closed breaker leaves it closed without
    touching the (unheld) probe lock."""
    cb = CircuitBreaker(name="svc")
    assert not cb._lock.locked()
    cb.reset()
    assert cb.state == "closed"
    assert not cb._lock.locked()


def test_record_success_while_closed_does_not_touch_lock() -> None:
    """A success in the closed state takes the no-lock branch (the lock is
    only released on a half-open probe)."""
    cb = CircuitBreaker(name="svc")
    assert not cb._lock.locked()
    cb.record_success()
    assert cb.state == "closed"
    assert not cb._lock.locked()


@pytest.mark.asyncio
async def test_reset_releases_held_half_open_probe_lock() -> None:
    """``reset`` releases the probe lock held by an in-progress half-open
    call so a force-recovery path doesn't leave callers blocked."""
    cb = CircuitBreaker(name="svc", failure_threshold=1, open_duration_s=10.0)
    now, advance, _state = _fixed_clock(datetime.now(timezone.utc))
    cb._now = now  # type: ignore[method-assign]
    cb.record_failure("down")
    advance(10.0)
    await cb.before_call()
    assert cb.state == "half_open"
    assert cb._lock.locked()

    cb.reset()
    assert cb.state == "closed"
    assert not cb._lock.locked()


def test_record_failure_caps_last_error_length() -> None:
    """An oversized error string is truncated so feeding a breaker
    message back through ``record_failure`` cannot grow without bound."""
    cb = CircuitBreaker(name="svc", failure_threshold=100)
    cb.record_failure("x" * 2000)
    assert cb.last_error is not None
    assert len(cb.last_error) == 512
    assert cb.last_error.endswith("...")


def test_snapshot_serialises_breaker_state() -> None:
    """``snapshot`` renders the operator-facing view with ISO timestamps
    and the live state/counter fields."""
    cb = CircuitBreaker(name="svc", failure_threshold=1)
    cb.record_failure("down")
    snap = cb.snapshot()
    assert snap["state"] == "open"
    assert snap["consecutive_failures"] == 1
    assert isinstance(snap["opened_at"], str)
    assert snap["last_error"] == "down"
    assert snap["last_success_at"] is None


# ── with_retry ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_with_retry_returns_first_success_and_records_breaker() -> None:
    """A first-try success returns the value and records the breaker hit,
    closing it from any prior half-open state."""
    cb = CircuitBreaker(name="svc")

    async def op() -> str:
        return "ok"

    out = await with_retry(op, retryable=(ValueError,), breaker=cb)
    assert out == "ok"
    assert cb.state == "closed"
    assert cb.last_success_at is not None


@pytest.mark.asyncio
async def test_with_retry_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """A retryable failure is retried within the backoff budget; a later
    success is returned. Real backoff sleeps are stubbed out."""
    import app.core.resilience as resilience

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(resilience.asyncio, "sleep", _no_sleep)

    calls = {"n": 0}

    async def op() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            raise ValueError("transient")
        return "recovered"

    out = await with_retry(op, retryable=(ValueError,), backoff_s=(0.0, 0.0, 0.0))
    assert out == "recovered"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_with_retry_non_retryable_reraises_and_records_failure() -> None:
    """A non-retryable exception is re-raised unchanged and recorded as a
    breaker failure (it is not retried)."""
    cb = CircuitBreaker(name="svc", failure_threshold=1)
    calls = {"n": 0}

    async def op() -> None:
        calls["n"] += 1
        raise KeyError("not retryable")

    with pytest.raises(KeyError):
        await with_retry(op, retryable=(ValueError,), breaker=cb)
    assert calls["n"] == 1
    assert cb.state == "open"
    assert cb.consecutive_failures == 1


@pytest.mark.asyncio
async def test_with_retry_exhaustion_reraises_last_and_records_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When every attempt raises a retryable error, the last exception is
    re-raised and the breaker records a single failure."""
    import app.core.resilience as resilience

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(resilience.asyncio, "sleep", _no_sleep)

    cb = CircuitBreaker(name="svc", failure_threshold=1)
    attempts = {"n": 0}

    async def op() -> None:
        attempts["n"] += 1
        raise ValueError(f"attempt {attempts['n']}")

    with pytest.raises(ValueError, match="attempt 3"):
        await with_retry(op, retryable=(ValueError,), backoff_s=(0.0, 0.0), breaker=cb)
    assert attempts["n"] == 3
    assert cb.state == "open"
    assert cb.consecutive_failures == 1


@pytest.mark.asyncio
async def test_with_retry_fast_fails_when_breaker_open() -> None:
    """With an open breaker, ``with_retry`` fast-fails via ``before_call``
    and never invokes the operation."""
    cb = CircuitBreaker(name="svc", failure_threshold=1)
    cb.record_failure("down")
    assert cb.state == "open"

    called = {"n": 0}

    async def op() -> None:
        called["n"] += 1

    with pytest.raises(BreakerOpenError):
        await with_retry(op, retryable=(ValueError,), breaker=cb)
    assert called["n"] == 0


@pytest.mark.asyncio
async def test_with_retry_no_breaker_succeeds() -> None:
    """``with_retry`` works without a breaker — the optional breaker
    branches are skipped and the result is returned."""

    async def op() -> int:
        return 42

    assert await with_retry(op, retryable=(ValueError,)) == 42


def test_breaker_lock_rebinds_on_loop_change() -> None:
    """The half-open probe lock must be rebuilt when the running event
    loop changes. A breaker is a process-wide singleton, but Celery runs
    each task on its own throwaway loop, and an ``asyncio.Lock`` bound to
    a now-dead loop raises "bound to a different event loop" when reused.
    """
    cb = CircuitBreaker(name="svc")

    async def grab() -> tuple[asyncio.Lock, asyncio.AbstractEventLoop | None]:
        cb._rebind_lock_if_needed()
        before = cb._lock
        cb._rebind_lock_if_needed()  # same loop → no-op
        assert cb._lock is before
        return cb._lock, cb._lock_loop

    lock1, loop1 = asyncio.run(grab())
    lock2, loop2 = asyncio.run(grab())
    assert loop1 is not loop2
    assert lock1 is not lock2  # recreated on the new loop


def test_breaker_half_open_probe_survives_loop_change() -> None:
    """End-to-end: a half-open probe acquired (and bound) on one loop must
    not wedge the breaker for a probe on a later loop. Without the rebind
    this raises "bound to a different event loop"."""
    cb = CircuitBreaker(name="svc", failure_threshold=1, open_duration_s=0.0)

    async def bind_and_hold_on_this_loop() -> None:
        cb.state = "half_open"
        await cb.before_call()  # probe 1 holds the lock
        cb.state = "half_open"
        waiter = asyncio.create_task(cb.before_call())  # probe 2 contends → binds lock to this loop
        for _ in range(5):
            await asyncio.sleep(0)
        waiter.cancel()
        try:
            await waiter
        except asyncio.CancelledError:
            pass

    asyncio.run(bind_and_hold_on_this_loop())  # loop now closed; lock bound+held on it

    async def probe_on_new_loop() -> None:
        cb.state = "half_open"
        await asyncio.wait_for(cb.before_call(), timeout=1.0)  # must not raise

    asyncio.run(probe_on_new_loop())
