# SPDX-License-Identifier: MIT
"""Recurring-task scheduler — pure decision + async supervisor."""

from __future__ import annotations

import asyncio

import pytest

from app.services.anonymize.scheduler import (
    RecurringScheduler,
    RecurringTask,
    due_at_unix_s,
    pick_next_due_task,
    record_run_outcome,
    sleep_until_next_tick_s,
)
from app.services.anonymize.service import (
    AnonymizeService,
    reset_anonymize_service,
)


@pytest.fixture(autouse=True)
def _reset_service():
    reset_anonymize_service()
    yield
    reset_anonymize_service()


# ── due_at_unix_s ────────────────────────────────────────────────────


def test_due_at_never_run_returns_negative_infinity() -> None:
    t = RecurringTask(name="a", interval_s=60, run_fn=_noop)
    assert due_at_unix_s(t) == float("-inf")


def test_due_at_after_run_uses_last_run_plus_interval() -> None:
    t = RecurringTask(
        name="a",
        interval_s=60,
        run_fn=_noop,
        last_run_at_unix_s=1_000.0,
    )
    assert due_at_unix_s(t) == 1_060.0


def test_due_at_respects_cooldown() -> None:
    """A task with an active cooldown waits past it."""
    t = RecurringTask(
        name="a",
        interval_s=60,
        run_fn=_noop,
        last_run_at_unix_s=1_000.0,
        cooldown_until_unix_s=2_000.0,
    )
    assert due_at_unix_s(t) == 2_000.0


async def _noop() -> None:
    return None


# ── pick_next_due_task ───────────────────────────────────────────────


def test_pick_next_due_returns_none_when_no_tasks() -> None:
    assert pick_next_due_task([], now_unix_s=1_000.0) is None


def test_pick_next_due_returns_none_when_nothing_eligible() -> None:
    """A task whose due_at lies in the future is not picked."""
    t = RecurringTask(
        name="a",
        interval_s=60,
        run_fn=_noop,
        last_run_at_unix_s=1_000.0,
    )
    # Due at 1060; now=1010 → not eligible.
    assert pick_next_due_task([t], now_unix_s=1_010.0) is None


def test_pick_next_due_returns_earliest_eligible() -> None:
    """Across multiple eligible tasks, the smallest due_at wins."""
    a = RecurringTask(
        name="a",
        interval_s=60,
        run_fn=_noop,
        last_run_at_unix_s=1_000.0,
    )  # due 1060
    b = RecurringTask(
        name="b",
        interval_s=60,
        run_fn=_noop,
        last_run_at_unix_s=900.0,
    )  # due 960 — earliest
    pick = pick_next_due_task([a, b], now_unix_s=1_100.0)
    assert pick is b


def test_pick_next_due_tiebreaks_alphabetically() -> None:
    """Same due_at → alphabetical name picks deterministically."""
    a = RecurringTask(name="a", interval_s=60, run_fn=_noop)
    b = RecurringTask(name="b", interval_s=60, run_fn=_noop)
    pick = pick_next_due_task([b, a], now_unix_s=1_000.0)
    assert pick is a


# ── sleep_until_next_tick_s ──────────────────────────────────────────


def test_sleep_returns_ceiling_when_no_tasks() -> None:
    assert sleep_until_next_tick_s([], max_ceiling_s=60.0) == 60.0


def test_sleep_returns_floor_for_never_run_task() -> None:
    """A task that's never run is due immediately ⇒ sleep at floor."""
    t = RecurringTask(name="a", interval_s=60, run_fn=_noop)
    out = sleep_until_next_tick_s([t], now_unix_s=1_000.0, min_floor_s=0.5)
    assert out == 0.5


def test_sleep_returns_floor_when_overdue() -> None:
    t = RecurringTask(
        name="a",
        interval_s=60,
        run_fn=_noop,
        last_run_at_unix_s=900.0,
    )
    # due 960; now=2_000 → overdue. Returns floor.
    out = sleep_until_next_tick_s([t], now_unix_s=2_000.0, min_floor_s=0.5)
    assert out == 0.5


def test_sleep_caps_at_ceiling() -> None:
    """A task far in the future caps the sleep at the ceiling."""
    t = RecurringTask(
        name="a",
        interval_s=3600,
        run_fn=_noop,
        last_run_at_unix_s=1_000.0,
    )
    # due 4600; now=1_000 → 3600s away. Cap at 60.
    out = sleep_until_next_tick_s(
        [t],
        now_unix_s=1_000.0,
        max_ceiling_s=60.0,
    )
    assert out == 60.0


def test_sleep_returns_exact_delta_when_inside_bounds() -> None:
    t = RecurringTask(
        name="a",
        interval_s=60,
        run_fn=_noop,
        last_run_at_unix_s=1_000.0,
    )
    # due 1060; now=1_050 → 10s. Inside [0.5, 60].
    out = sleep_until_next_tick_s(
        [t],
        now_unix_s=1_050.0,
        min_floor_s=0.5,
        max_ceiling_s=60.0,
    )
    assert out == 10.0


# ── record_run_outcome ───────────────────────────────────────────────


def test_record_success_clears_failure_state() -> None:
    t = RecurringTask(
        name="a",
        interval_s=60,
        run_fn=_noop,
        consecutive_failures=3,
        cooldown_until_unix_s=999.0,
    )
    record_run_outcome(t, success=True, now_unix_s=1_000.0)
    assert t.last_run_at_unix_s == 1_000.0
    assert t.consecutive_failures == 0
    assert t.cooldown_until_unix_s is None


def test_record_failure_bumps_counter_and_sets_cooldown() -> None:
    t = RecurringTask(name="a", interval_s=60, run_fn=_noop)
    record_run_outcome(
        t,
        success=False,
        now_unix_s=1_000.0,
        failure_backoff_base_s=5.0,
        failure_backoff_cap_s=600.0,
    )
    assert t.last_run_at_unix_s == 1_000.0
    assert t.consecutive_failures == 1
    # 1st failure → 5s backoff.
    assert t.cooldown_until_unix_s == 1_005.0


def test_record_failure_backoff_is_exponential_and_capped() -> None:
    t = RecurringTask(name="a", interval_s=60, run_fn=_noop)
    # Three failures: 5, 10, 20.
    record_run_outcome(t, success=False, now_unix_s=1_000.0)
    record_run_outcome(t, success=False, now_unix_s=1_005.0)
    record_run_outcome(t, success=False, now_unix_s=1_015.0)
    assert t.cooldown_until_unix_s == 1_015.0 + 20.0  # 3rd → 20s

    # Many more failures should cap at 600.
    for i in range(20):
        record_run_outcome(
            t,
            success=False,
            now_unix_s=1_100.0 + i,
            failure_backoff_base_s=5.0,
            failure_backoff_cap_s=600.0,
        )
    assert t.consecutive_failures == 23
    # Most recent cooldown is capped.
    assert t.cooldown_until_unix_s == (1_100.0 + 19) + 600.0


# ── RecurringScheduler integration ───────────────────────────────────


@pytest.mark.asyncio
async def test_scheduler_runs_registered_task() -> None:
    """A task registered before start runs at least once."""
    sched = RecurringScheduler()
    counter = {"n": 0}

    async def _bump():
        counter["n"] += 1

    sched.register(RecurringTask(name="bump", interval_s=0.05, run_fn=_bump))
    await sched.start()
    await asyncio.sleep(0.15)  # let the supervisor tick a few times
    await sched.stop()
    assert counter["n"] >= 1


@pytest.mark.asyncio
async def test_scheduler_isolates_failing_task() -> None:
    """A raising task doesn't kill the supervisor; other tasks still run."""
    sched = RecurringScheduler()
    failures = {"n": 0}
    successes = {"n": 0}

    async def _raise():
        failures["n"] += 1
        raise RuntimeError("boom")

    async def _ok():
        successes["n"] += 1

    sched.register(RecurringTask(name="raise", interval_s=0.05, run_fn=_raise))
    sched.register(RecurringTask(name="ok", interval_s=0.05, run_fn=_ok))
    await sched.start()
    await asyncio.sleep(0.15)
    await sched.stop()
    assert failures["n"] >= 1
    assert successes["n"] >= 1
    # The failing task picked up a cooldown.
    raising = sched.tasks()[0] if sched.tasks()[0].name == "raise" else sched.tasks()[1]
    assert raising.consecutive_failures >= 1


@pytest.mark.asyncio
async def test_scheduler_register_replaces_by_name() -> None:
    """Re-registering a task name replaces the previous entry."""
    sched = RecurringScheduler()
    sched.register(RecurringTask(name="t", interval_s=60, run_fn=_noop))
    sched.register(RecurringTask(name="t", interval_s=120, run_fn=_noop))
    tasks = sched.tasks()
    assert len(tasks) == 1
    assert tasks[0].interval_s == 120


@pytest.mark.asyncio
async def test_scheduler_unregister_removes_task() -> None:
    sched = RecurringScheduler()
    sched.register(RecurringTask(name="t", interval_s=60, run_fn=_noop))
    sched.unregister("t")
    assert sched.tasks() == []


@pytest.mark.asyncio
async def test_scheduler_stop_is_idempotent() -> None:
    sched = RecurringScheduler()
    await sched.stop()  # never started — no-op
    await sched.start()
    await sched.stop()
    await sched.stop()  # second stop — no-op


# ── AnonymizeService integration ─────────────────────────────────────


@pytest.mark.asyncio
async def test_service_start_initializes_scheduler() -> None:
    svc = AnonymizeService()
    await svc.start()
    counter = {"n": 0}

    async def _tick():
        counter["n"] += 1

    svc.register_recurring(
        RecurringTask(name="tick", interval_s=0.05, run_fn=_tick),
    )
    await asyncio.sleep(0.15)
    await svc.stop()
    assert counter["n"] >= 1


@pytest.mark.asyncio
async def test_service_register_recurring_before_start_is_picked_up() -> None:
    """A task registered before start() runs once the scheduler boots."""
    svc = AnonymizeService()
    counter = {"n": 0}

    async def _tick():
        counter["n"] += 1

    svc.register_recurring(
        RecurringTask(name="tick", interval_s=0.05, run_fn=_tick),
    )
    await svc.start()
    await asyncio.sleep(0.15)
    await svc.stop()
    assert counter["n"] >= 1
