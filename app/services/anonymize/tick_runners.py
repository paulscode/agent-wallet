# SPDX-License-Identifier: MIT
"""Adapter functions that wire pure tick helpers to the async scheduler.

Each adapter returns a zero-arg async :class:`scheduler.RunFn` the
:class:`RecurringScheduler` invokes on its cadence. The body of each
adapter:

1. Opens a DB session via the injected ``session_factory``.
2. Reads the relevant high-water mark from ``anonymize_runtime_state``.
3. Calls the matching pure decision helper.
4. Persists outcomes (audit row, HWM bump, gc bitfield update).

Adapters are kept thin so unit tests can plug in a mock
``session_factory`` and a mock ``audit_writer`` to exercise the
adapter wiring without standing up a real DB or audit chain.
"""

from __future__ import annotations

import time as _time
from typing import TYPE_CHECKING, Any, AsyncContextManager, Awaitable, Callable

from app.core.config import settings
from app.services.anonymize.audit_emitter import (
    enumerate_pending_buckets,
)
from app.services.anonymize.audit_summary import (
    BucketSummary,
    build_audit_payload,
    build_bucket_summary,
    collect_session_counts_for_bucket,
)
from app.services.anonymize.gc import (
    fetch_decoy_catchup_sessions,
    fetch_retention_eligible_sessions,
    gc_tick_due,
    run_decoy_chain_anchor_redact_pass,
)
from app.services.anonymize.runtime_state import (
    read_runtime_state,
    write_runtime_state,
)

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from app.services.anonymize.service import AnonymizeService

# Type aliases keep the adapter signatures legible.
SessionFactory = Callable[[], "AsyncContextManager"]
AuditWriter = Callable[[dict[str, Any]], Awaitable[None]]


def make_audit_emit_run_fn(
    *,
    session_factory: SessionFactory,
    audit_writer: AuditWriter,
    now_fn: Callable[[], float] = _time.time,
) -> Callable[[], Awaitable[None]]:
    """Audit-bucket summary emitter run-fn.

    On each tick:

    * Reads ``audit_chain_last_emitted_bucket_start_unix_s`` from the
      runtime-state registry.
    * Enumerates pending buckets via :func:`enumerate_pending_buckets`.
    * For each pending bucket, runs
      :func:`collect_session_counts_for_bucket` + builds a
      :class:`BucketSummary` with the configured k-anonymity threshold.
    * Aggregates into one window emission and calls ``audit_writer``
      with the byte-pinned audit payload.
    * Bumps the HWM to the last-emitted bucket start.

    The whole body is a no-op when no buckets are pending.
    """
    _hwm_key = "audit_chain_last_emitted_bucket_start_unix_s"

    async def _run() -> None:
        async with session_factory() as db:
            raw = await read_runtime_state(db, key=_hwm_key)
            hwm: int | None
            if isinstance(raw, dict) and "value" in raw:
                hwm = int(raw["value"])
            elif isinstance(raw, int):
                hwm = raw
            else:
                hwm = None

            pending = enumerate_pending_buckets(
                last_emitted_bucket_start_unix_s=hwm,
                now_unix_s=now_fn(),
            )
            if not pending:
                return

            bucket_s = int(settings.anonymize_audit_bucket_s)
            min_count = int(settings.anonymize_audit_min_bucket_count)
            summaries: list[BucketSummary] = []
            for bucket_start in pending:
                by_status, by_source = await collect_session_counts_for_bucket(
                    db,
                    bucket_start_unix_s=bucket_start,
                    bucket_seconds=bucket_s,
                )
                summaries.append(
                    build_bucket_summary(
                        bucket_start_unix_s=bucket_start,
                        bucket_seconds=bucket_s,
                        counts_by_terminal_state=by_status,
                        counts_by_source_kind=by_source,
                        min_bucket_count=min_count,
                    )
                )

            from app.services.anonymize.audit_summary import (
                aggregate_window_emission,
            )

            window = aggregate_window_emission(
                summaries,
                window_start_unix_s=pending[0],
                window_end_unix_s=pending[-1] + bucket_s,
            )
            payload = build_audit_payload(window)
            await audit_writer(payload)

            await write_runtime_state(
                db,
                key=_hwm_key,
                payload={"value": int(pending[-1])},
            )
            await db.commit()

    return _run


def make_decoy_catchup_run_fn(
    *,
    session_factory: SessionFactory,
    batch_limit: int = 50,
) -> Callable[[], Awaitable[None]]:
    """Recurring decoy-output retention catch-up run-fn.

    Re-enqueues sessions that are past the retention horizon but
    haven't completed pass 10 (decoy chain-anchor redact).
    Bounded by ``batch_limit`` so one tick can't starve the rest of
    the scheduler.
    """

    async def _run() -> None:
        async with session_factory() as db:
            sessions = await fetch_decoy_catchup_sessions(
                db,
                limit=batch_limit,
            )
            if not sessions:
                return
            for sess in sessions:
                await run_decoy_chain_anchor_redact_pass(db, sess)
            await db.commit()

    return _run


def make_gc_sweep_run_fn(
    *,
    session_factory: SessionFactory,
    pass_runners: dict[str, Callable[..., Awaitable[bool]]],
    batch_limit: int = 50,
    now_fn: Callable[[], float] = _time.time,
) -> Callable[[], Awaitable[None]]:
    """GC scheduler run-fn.

    Fires per-pass GC bodies for retention-eligible sessions:

    * Fetches up to ``batch_limit`` eligible sessions.
    * For each session, picks the next unset pass bit via the
      registry and dispatches to ``pass_runners[name]``.
    * After the batch, bumps ``last_successful_gc_at``.

    ``pass_runners`` lets the orchestrator swap implementations per
    test (e.g., to stub the decoy runner that requires the
    decoy table to exist).
    """
    from app.services.anonymize.gc import select_next_pass_for_session

    _health_key = "last_successful_gc_at"

    async def _run() -> None:
        async with session_factory() as db:
            # Cadence-gate the actual sweep so back-to-back ticks
            # (e.g., from a re-registration) don't beat on the DB.
            raw = await read_runtime_state(db, key=_health_key)
            last_at: float | None
            if isinstance(raw, dict) and "value" in raw:
                last_at = float(raw["value"])
            else:
                last_at = None
            if not gc_tick_due(
                last_successful_at_unix_s=last_at,
                now_unix_s=now_fn(),
            ):
                return

            sessions = await fetch_retention_eligible_sessions(
                db,
                limit=batch_limit,
            )
            for sess in sessions:
                pick = select_next_pass_for_session(sess.gc_passes_completed)
                if pick is None:
                    continue
                pass_name, _bit = pick
                runner = pass_runners.get(pass_name)
                if runner is None:
                    continue
                await runner(db, sess)

            await write_runtime_state(
                db,
                key=_health_key,
                payload={"value": now_fn()},
            )
            await db.commit()

    return _run


def _respawn_resumed_session(service: "AnonymizeService", session_id: "UUID") -> None:
    """Spawn the production per-session loop for a session the probe just
    resumed out of ``AWAITING_RECONCILIATION``.

    Uses the same router + hop dispatcher as boot-time re-hydration so a
    resumed session picks up exactly where it left off. Best-effort: a
    spawn failure is logged but never breaks the probe sweep.
    """
    import logging as _logging

    from app.core.database import get_session_maker
    from app.services.anonymize.hop_dispatcher import default_hop_step_fn
    from app.services.anonymize.metadata import ANONYMIZE_LOGGER_NAME
    from app.services.anonymize.observation_router import default_observation_fn

    try:
        service.spawn_session_task(
            session_id=session_id,
            session_factory=get_session_maker(),
            observation_fn=default_observation_fn,
            hop_step_fn=default_hop_step_fn(),
        )
    except Exception:  # noqa: BLE001
        _logging.getLogger(ANONYMIZE_LOGGER_NAME).exception(
            "reconciliation probe: failed to re-arm driver for resumed session %s",
            session_id,
        )


def make_reconciliation_probe_run_fn(
    *,
    service: "AnonymizeService",
    session_factory: SessionFactory,
    now_fn: Callable[[], "datetime"] | None = None,
    sleep_fn: Callable[[float], Awaitable[None]] | None = None,
    rng: Callable[[float, float], float] | None = None,
) -> Callable[[], Awaitable[None]]:
    """Auto-retry probe + wedge detector tick.

    Each tick:

    1. Sleeps a random jitter (0..interval*jitter_frac) before
       starting work. The supervisor's fixed cadence + per-tick
       jitter together produce the "blends with background
       traffic" property — successive ticks land at slightly
       different absolute times, breaking a clock-aligned
       fingerprint.
    2. Runs the wedge detector so wedged active sessions are
       routed into AWAITING_RECONCILIATION before the auto-retry
       sweep walks the AR queue. Class A reasons then auto-recover
       on the next tick.
    3. Walks AR rows and applies the per-session attempt logic
       (with cooldown gating).
    4. Bumps the runtime-state HWM so successive ticks are visible.
    """
    import asyncio as _asyncio
    import secrets as _secrets
    from datetime import datetime, timezone

    from app.services.anonymize.reconciliation_probe import (
        apply_wedge_detector,
        attempt_reconciliation,
        fetch_awaiting_reconciliation_sessions,
        is_in_cooldown,
    )

    if now_fn is None:

        def _default_now() -> "datetime":
            return datetime.now(timezone.utc)

        now_fn = _default_now
    if sleep_fn is None:
        sleep_fn = _asyncio.sleep
    if rng is None:
        # Anti-fingerprinting jitter draws from a CSPRNG so the probe
        # cadence can't be predicted from a recovered PRNG state.
        rng = _secrets.SystemRandom().uniform

    _health_key = "last_successful_reconciliation_probe_at"

    async def _run() -> None:
        # Pre-tick jitter. Cap below the interval so two
        # back-to-back ticks can't compound into a full-interval skip.
        interval_s = float(
            settings.anonymize_reconciliation_probe_interval_s,
        )
        jitter_frac = max(
            0.0,
            min(
                0.5,
                float(
                    settings.anonymize_reconciliation_probe_jitter_frac,
                ),
            ),
        )
        if jitter_frac > 0 and interval_s > 0:
            jitter_s = rng(0.0, interval_s * jitter_frac)
            if jitter_s > 0:
                await sleep_fn(jitter_s)

        import logging as _logging

        from app.services.anonymize.metadata import (
            ANONYMIZE_LOGGER_NAME as _LOGGER_NAME,
        )

        _logger = _logging.getLogger(_LOGGER_NAME)

        async with session_factory() as db:
            now = now_fn()
            # 1) Wedge detector — flip any active rows idle past the
            # budget into AR. ``apply_wedge_detector`` uses the
            # configured budget by default. Commit after this step so
            # the AR sweep below sees the just-flipped rows and so a
            # later exception can't roll back the flips.
            try:
                await apply_wedge_detector(
                    db,
                    service=service,
                    now=now,
                )
                await db.commit()
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "reconciliation probe: wedge detector failed",
                )
                # Roll back any partial writes from the failed wedge
                # pass so the AR sweep starts in a clean session.
                try:
                    await db.rollback()
                except Exception:  # noqa: BLE001
                    pass

            # 2) Auto-retry sweep. Cooldown-aware: skip rows still in
            # backoff. we commit per-row so a bad row's
            # exception can't poison the session for subsequent
            # rows.
            batch_size = int(
                settings.anonymize_reconciliation_probe_batch_size,
            )
            try:
                ar_rows = await fetch_awaiting_reconciliation_sessions(
                    db,
                    limit=batch_size,
                )
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "reconciliation probe: fetch failed",
                )
                ar_rows = []

            for sess in ar_rows:
                if is_in_cooldown(sess, now=now):
                    continue
                try:
                    outcome = await attempt_reconciliation(
                        db,
                        sess,
                        service=service,
                        now=now,
                    )
                    await db.commit()
                    # Re-arm a driver. A resumed session is moved back to a
                    # live status but has no per-session loop (the original
                    # exited, which is why it wedged). Without a driver it
                    # would sit idle until the next restart and leak against
                    # the in-flight cap. Spawn the production loop unless one
                    # is somehow already tracked for this id.
                    if (
                        getattr(outcome, "kind", None) == "retried"
                        and not service.is_session_task_running(str(sess.id))
                    ):
                        _respawn_resumed_session(service, sess.id)
                except Exception:  # noqa: BLE001
                    _logger.exception(
                        "reconciliation probe: attempt failed for %s",
                        sess.id,
                    )
                    # Roll back the per-row partial work so the next
                    # row's attempt starts clean.
                    try:
                        await db.rollback()
                    except Exception:  # noqa: BLE001
                        pass

            # 3) HWM for the health card / debugging.
            await write_runtime_state(
                db,
                key=_health_key,
                payload={"value": now.timestamp()},
            )
            await db.commit()

    return _run


__all__ = [
    "AuditWriter",
    "SessionFactory",
    "make_audit_emit_run_fn",
    "make_decoy_catchup_run_fn",
    "make_gc_sweep_run_fn",
    "make_reconciliation_probe_run_fn",
]
