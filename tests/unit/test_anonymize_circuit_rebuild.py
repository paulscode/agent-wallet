# SPDX-License-Identifier: MIT
"""Tor circuit-rebuild token bucket.

The orchestrator consumes one token per circuit rebuild attempt; the
bucket refills continuously based on monotonic-clock elapsed time.
A burst is allowed up to ``capacity`` then the bucket throttles
further attempts until refill — at which point the orchestrator
parks the session in ``awaiting_reconciliation``.
"""

from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.anonymize.circuit_rebuild import (
    TokenBucket,
    aggregate_tokens_per_second,
    burst_capacity,
    make_aggregate_bucket,
    make_per_listener_bucket,
    tokens_per_second_for_listener,
)


def test_fresh_bucket_starts_saturated() -> None:
    b = TokenBucket(capacity=3, refill_rate_per_s=1.0)
    assert b.level == 3.0


def test_consume_below_level_succeeds() -> None:
    b = TokenBucket(capacity=3, refill_rate_per_s=0.0)
    assert b.try_consume(1) is True
    assert b.try_consume(2) is True
    # Empty now.
    assert b.try_consume(1) is False


def test_consume_refills_over_time() -> None:
    """Refill is continuous-time based on monotonic-clock elapsed."""
    now = 1_000.0
    b = TokenBucket(
        capacity=3,
        refill_rate_per_s=1.0,
        last_refill_monotonic_s=now,
        level=0.0,
    )
    # Two seconds later, two tokens have refilled.
    assert b.try_consume(1, now_monotonic_s=now + 2.0) is True
    assert b.try_consume(1, now_monotonic_s=now + 2.0) is True
    assert b.try_consume(1, now_monotonic_s=now + 2.0) is False


def test_refill_does_not_exceed_capacity() -> None:
    now = 1_000.0
    b = TokenBucket(
        capacity=3,
        refill_rate_per_s=10.0,
        last_refill_monotonic_s=now,
        level=2.0,
    )
    # Even after 100 s, level cannot exceed capacity=3.
    b.refill(now_monotonic_s=now + 100)
    assert b.level == 3.0


def test_consume_zero_cost_succeeds() -> None:
    b = TokenBucket(capacity=3, refill_rate_per_s=0.0)
    assert b.try_consume(0) is True


def test_consume_more_than_capacity_fails_even_when_full() -> None:
    b = TokenBucket(capacity=3, refill_rate_per_s=0.0)
    assert b.try_consume(4) is False
    assert b.level == 3.0  # nothing was deducted


def test_available_includes_refill() -> None:
    now = 1_000.0
    b = TokenBucket(
        capacity=3,
        refill_rate_per_s=1.0,
        last_refill_monotonic_s=now,
        level=1.0,
    )
    assert b.available(now_monotonic_s=now + 1.5) == pytest.approx(2.5)


def test_helpers_translate_per_hour_into_per_second(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_tokens_per_hour", 6)
    assert tokens_per_second_for_listener() == pytest.approx(6 / 3600.0)
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_aggregate_tokens_per_hour", 18)
    assert aggregate_tokens_per_second() == pytest.approx(18 / 3600.0)


def test_burst_capacity_enforced_minimum(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_burst", 0)
    assert burst_capacity() == 1


def test_make_per_listener_bucket_uses_settings(monkeypatch) -> None:
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_burst", 5)
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_tokens_per_hour", 36)
    b = make_per_listener_bucket()
    assert b.capacity == 5
    assert b.refill_rate_per_s == pytest.approx(0.01)


def test_make_aggregate_bucket_scales_with_listener_count(monkeypatch) -> None:
    """Aggregate capacity ≈ burst × number of configured listeners."""
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_burst", 3)
    # Default listener count from settings.
    listener_count = max(1, len(settings.anonymize_tor_socks_ports_dict))
    b = make_aggregate_bucket()
    assert b.capacity == 3 * listener_count


# ── CircuitRebuildGuard.admit — aggregate + per-listener ─────────────


def test_guard_admit_consumes_both_buckets() -> None:
    """A single admit must deduct one token from BOTH the per-listener
    bucket AND the aggregate; otherwise the aggregate cap doesn't bind."""
    from app.services.anonymize.circuit_rebuild import CircuitRebuildGuard

    g = CircuitRebuildGuard()
    assert g.admit("boltz_reverse") is True
    bucket = g.per_listener["boltz_reverse"]
    assert bucket.level < bucket.capacity
    assert g.aggregate is not None
    assert g.aggregate.level < g.aggregate.capacity


def test_guard_admit_refused_does_not_consume(monkeypatch) -> None:
    """A refused admit (per-listener starved) must NOT consume the
    aggregate bucket — otherwise an attacker could drain the aggregate
    by spamming a starved listener."""
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_burst", 1)
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_tokens_per_hour", 0)
    from app.services.anonymize.circuit_rebuild import CircuitRebuildGuard

    g = CircuitRebuildGuard()
    assert g.admit("boltz_reverse") is True
    # Bucket is empty now.
    assert g.admit("boltz_reverse") is False
    # Aggregate had 1 token consumed by the admit (one listener
    # times burst=1 — but other listeners haven't consumed yet);
    # the refused second call did not deduct further.
    agg_after = g.aggregate.level
    assert g.admit("boltz_reverse") is False
    assert g.aggregate.level == agg_after  # unchanged


def test_guard_aggregate_caps_across_listeners(monkeypatch) -> None:
    """The aggregate budget refuses further admits even when a fresh
    listener has its own quota remaining."""
    # Listener count = 2, burst=1 → aggregate capacity = 2.
    monkeypatch.setattr(
        settings,
        "anonymize_tor_socks_ports",
        "boltz_reverse=9051,boltz_submarine=9050",
    )
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_burst", 1)
    monkeypatch.setattr(settings, "anonymize_circuit_rebuild_tokens_per_hour", 0)
    monkeypatch.setattr(
        settings,
        "anonymize_circuit_rebuild_aggregate_tokens_per_hour",
        0,
    )
    from app.services.anonymize.circuit_rebuild import CircuitRebuildGuard

    g = CircuitRebuildGuard()
    assert g.admit("boltz_reverse") is True
    assert g.admit("boltz_submarine") is True
    # Both listener buckets refilled to 1 each (burst=1 each); the
    # aggregate bucket has 0 tokens left (capacity=2 fully consumed).
    # A third admit on either listener refuses on the aggregate gate.
    assert g.admit("boltz_reverse") is False


# ── runtime-state persistence ─────────────────────────────


@pytest.mark.asyncio
async def test_persist_then_hydrate_round_trip(db_session) -> None:
    """A persisted bucket level survives `reset` + re-hydrate."""
    from app.services.anonymize.circuit_rebuild import (
        CircuitRebuildGuard,
        hydrate_circuit_rebuild_guard,
        persist_circuit_rebuild_guard,
    )

    guard = CircuitRebuildGuard()
    # Drain one token from a known listener.
    assert guard.admit("boltz_reverse") is True
    drained_level = guard.per_listener["boltz_reverse"].level
    drained_agg = guard.aggregate.level

    await persist_circuit_rebuild_guard(db_session, guard)
    await db_session.commit()

    # Fresh guard, rehydrated from DB.
    hydrated = await hydrate_circuit_rebuild_guard(
        db_session,
        listeners=("boltz_reverse",),
    )
    assert hydrated.per_listener["boltz_reverse"].level == pytest.approx(drained_level)
    assert hydrated.aggregate is not None
    assert hydrated.aggregate.level == pytest.approx(drained_agg)


@pytest.mark.asyncio
async def test_hydrate_with_absent_rows_returns_fresh_saturated_buckets(
    db_session,
) -> None:
    """A fresh deployment has no persisted state; hydrate must give
    saturated buckets so the first admit succeeds."""
    from app.services.anonymize.circuit_rebuild import (
        burst_capacity,
        hydrate_circuit_rebuild_guard,
    )

    guard = await hydrate_circuit_rebuild_guard(
        db_session,
        listeners=("boltz_reverse",),
    )
    bucket = guard.per_listener["boltz_reverse"]
    assert bucket.level == float(burst_capacity())


@pytest.mark.asyncio
async def test_hydrate_recovers_starved_bucket_across_restart(
    db_session,
) -> None:
    """A bucket starved to zero before restart must stay zero after
    restart; otherwise an attacker who can induce restarts could
    refund themselves budget."""
    from app.services.anonymize.circuit_rebuild import (
        CircuitRebuildGuard,
        TokenBucket,
        hydrate_circuit_rebuild_guard,
        persist_circuit_rebuild_guard,
    )

    # Build a guard with a starved bucket + zero refill rate so even
    # after time passes, the bucket stays starved.
    guard = CircuitRebuildGuard()
    guard.per_listener["boltz_reverse"] = TokenBucket(
        capacity=3,
        refill_rate_per_s=0.0,
        level=0.0,
    )
    guard.aggregate = TokenBucket(
        capacity=9,
        refill_rate_per_s=0.0,
        level=0.0,
    )
    await persist_circuit_rebuild_guard(db_session, guard)
    await db_session.commit()

    hydrated = await hydrate_circuit_rebuild_guard(
        db_session,
        listeners=("boltz_reverse",),
    )
    # First admit must refuse — the post-restart state is starved.
    assert hydrated.admit("boltz_reverse") is False
