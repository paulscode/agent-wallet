# SPDX-License-Identifier: MIT
"""Recurring-task scheduler for the anonymize orchestrator.

The orchestrator owns a small set of recurring async tasks:

* audit-bucket emission (cadence ``ANONYMIZE_AUDIT_BUCKET_S``)
* garbage-collection sweep (cadence ``ANONYMIZE_GC_TICK_INTERVAL_S``)
* per-key rotation (per-policy cadence in days)
* clock-skew watcher (cadence ``ANONYMIZE_CLOCK_RECHECK_INTERVAL_S``)
* Tor bootstrap recheck (cadence ``ANONYMIZE_TOR_BOOTSTRAP_RECHECK_INTERVAL_S``)
* decoy retention catch-up (cadence ``ANONYMIZE_GC_CATCHUP_INTERVAL_S``)

Running them as N independent ``asyncio.create_task`` loops would
work, but a single supervisor loop is cheaper and easier to reason
about: it picks the next-due task, sleeps until its tick fires, runs
it under a try/except, and re-enters the decision loop.

This module ships the *pure decision helpers* + a thin async runner
so unit tests can exercise the supervisor without standing up the
underlying ticks. The actual run-functions are injected by
:class:`AnonymizeService` so the dispatch path stays narrow.
"""

from __future__ import annotations

import asyncio
import logging
import time as _time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from .metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


RunFn = Callable[[], Awaitable[None]]


@dataclass
class RecurringTask:
    """One scheduled task.

    ``interval_s`` is the desired cadence. ``last_run_at_unix_s`` is
    updated by the supervisor after each run (success or failure);
    on the next decision tick the supervisor computes ``due_at =
    last_run_at + interval_s`` and picks the smallest across the set.
    """

    name: str
    interval_s: float
    run_fn: RunFn
    last_run_at_unix_s: float | None = None
    # Skip-on-failure budget — see :meth:`record_run_outcome`.
    consecutive_failures: int = 0
    # Hard kill switch for one tick; set when the run raises to give
    # the task time to recover before the supervisor retries.
    cooldown_until_unix_s: float | None = None


@dataclass
class SchedulerState:
    """Mutable scheduler state owned by :class:`RecurringScheduler`."""

    tasks: dict[str, RecurringTask] = field(default_factory=dict)
    running: bool = False


def due_at_unix_s(task: RecurringTask) -> float:
    """When is ``task`` next due?

    A task that has never run (``last_run_at_unix_s is None``) is
    due immediately (returns ``-inf``). A task under cooldown waits
    out the cooldown before being eligible.
    """
    base: float
    if task.last_run_at_unix_s is None:
        base = float("-inf")
    else:
        base = float(task.last_run_at_unix_s) + float(task.interval_s)
    if task.cooldown_until_unix_s is not None:
        base = max(base, float(task.cooldown_until_unix_s))
    return base


def pick_next_due_task(
    tasks: list[RecurringTask],
    *,
    now_unix_s: float | None = None,
) -> RecurringTask | None:
    """Return the task with the smallest ``due_at`` that's already
    past, or ``None`` when every task is in the future.

    Tasks tie-break alphabetically by name so the schedule is
    deterministic when two tasks share the same cadence + last_run.
    """
    if not tasks:
        return None
    now = now_unix_s if now_unix_s is not None else _time.time()
    eligible = [t for t in tasks if due_at_unix_s(t) <= now]
    if not eligible:
        return None
    eligible.sort(key=lambda t: (due_at_unix_s(t), t.name))
    return eligible[0]


def sleep_until_next_tick_s(
    tasks: list[RecurringTask],
    *,
    now_unix_s: float | None = None,
    min_floor_s: float = 0.5,
    max_ceiling_s: float = 60.0,
) -> float:
    """Compute how long the supervisor should sleep before its next
    decision pass.

    The supervisor never sleeps longer than ``max_ceiling_s`` so a
    newly-arrived task (registered after sleep started) gets picked
    up reasonably quickly. The minimum sleep is ``min_floor_s`` so a
    tight cadence doesn't tie up the event loop on a busy poll.
    """
    if not tasks:
        return max_ceiling_s
    now = now_unix_s if now_unix_s is not None else _time.time()
    soonest = min(due_at_unix_s(t) for t in tasks)
    if soonest == float("-inf"):
        return min_floor_s
    delta = soonest - now
    if delta < min_floor_s:
        return min_floor_s
    return min(delta, max_ceiling_s)


def record_run_outcome(
    task: RecurringTask,
    *,
    success: bool,
    now_unix_s: float | None = None,
    failure_backoff_base_s: float = 5.0,
    failure_backoff_cap_s: float = 600.0,
) -> None:
    """Update task bookkeeping after a run.

    Failures bump ``consecutive_failures`` and set an exponential
    cooldown so a wedged task can't pin the supervisor loop. The
    cooldown is bounded by ``failure_backoff_cap_s`` so an outage
    that flips a task to broken eventually reaches a steady poll
    interval rather than receding to never-fire.
    """
    now = now_unix_s if now_unix_s is not None else _time.time()
    task.last_run_at_unix_s = now
    if success:
        task.consecutive_failures = 0
        task.cooldown_until_unix_s = None
        return
    task.consecutive_failures += 1
    backoff = min(
        failure_backoff_base_s * (2.0 ** (task.consecutive_failures - 1)),
        failure_backoff_cap_s,
    )
    task.cooldown_until_unix_s = now + backoff


class RecurringScheduler:
    """Owns the task registry + the single supervisor coroutine.

    The supervisor stays alive between ``start()`` and ``stop()``,
    which mirror :class:`AnonymizeService.start` / ``stop``.
    """

    def __init__(self) -> None:
        self._state = SchedulerState()
        self._loop_task: asyncio.Task | None = None
        self._wake_event = asyncio.Event()

    # ── Registration ─────────────────────────────────────────────────

    def register(self, task: RecurringTask) -> None:
        """Add or replace a task by name.

        Replaces in-place so a later registration overrides the
        cadence (useful when the operator changes a setting and the
        scheduler picks the new value on the next reload).
        """
        self._state.tasks[task.name] = task
        # Wake the loop so it can re-evaluate the schedule.
        self._wake_event.set()

    def unregister(self, name: str) -> None:
        self._state.tasks.pop(name, None)
        self._wake_event.set()

    def tasks(self) -> list[RecurringTask]:
        return list(self._state.tasks.values())

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the supervisor coroutine. Idempotent."""
        if self._state.running:
            return
        self._state.running = True
        self._loop_task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        """Cancel the supervisor and wait for it to settle."""
        if not self._state.running:
            return
        self._state.running = False
        self._wake_event.set()
        if self._loop_task is not None:
            self._loop_task.cancel()
            try:
                await self._loop_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._loop_task = None

    # ── Supervisor body ──────────────────────────────────────────────

    async def _run_loop(self) -> None:
        """The single recurring-task supervisor coroutine.

        On each pass:
        1. Pick the next due task.
        2. If one is due, run it under try/except and record outcome.
        3. Otherwise compute the sleep budget and await it; the wake
           event short-circuits the sleep when a registration arrives.
        """
        while self._state.running:
            task = pick_next_due_task(list(self._state.tasks.values()))
            if task is not None:
                await self._run_one(task)
                continue

            sleep_s = sleep_until_next_tick_s(list(self._state.tasks.values()))
            self._wake_event.clear()
            try:
                await asyncio.wait_for(self._wake_event.wait(), timeout=sleep_s)
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                return

    async def _run_one(self, task: RecurringTask) -> None:
        try:
            await task.run_fn()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception(
                "anonymize recurring task %s failed",
                task.name,
            )
            record_run_outcome(task, success=False)
        else:
            record_run_outcome(task, success=True)


__all__ = [
    "RecurringScheduler",
    "RecurringTask",
    "SchedulerState",
    "due_at_unix_s",
    "pick_next_due_task",
    "record_run_outcome",
    "sleep_until_next_tick_s",
]
