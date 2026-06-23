# SPDX-License-Identifier: MIT
"""AnonymizeService orchestrator.

The single entry point ``app/dashboard/api.py`` holds against. Each
``Hop`` exposes ``prepare()``, ``execute()``, ``poll()``, ``cancel()``,
``refund()`` (all ``async``); the orchestrator reduces a session by
repeatedly calling ``poll()`` on the head hop until it transitions,
then advancing.

A single asyncio task per session runs from ``app.main`` startup
(re-hydrating ``created`` / ``sourcing`` / ``ln_holding`` / ``delaying``
/ ``hopping`` / ``exiting`` / ``confirming`` rows from the DB on
boot). No Celery dependency added.

The LN-source path covers ``ext-lightning`` + ``lightning-self``
sources with the ``ln_self_pay`` + ``reverse`` hops. The orchestrator
is established here, with the per-state transitions alongside the
robustness items.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, AsyncContextManager, Callable, Coroutine, cast

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from .metadata import ANONYMIZE_LOGGER_NAME
from .scheduler import RecurringScheduler, RecurringTask
from .state_machine import (
    IllegalStateTransitionError,
    assert_graph_covers_every_enum_value,
    assert_legal_transition,
    is_terminal,
)
from .tick import TickAction, TickObservations

if TYPE_CHECKING:
    from uuid import UUID

    from fastapi import FastAPI

    from .per_session_loop import HopStepFn, ObservationFn
    from .quote_cache import CacheEntry
    from .rate_limit import ThreeBudgetLimiter

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


# Prefixes ``tick.decide_tick_action`` adds to the wrapped audit-log
# reason string. The persisted ``awaiting_reconciliation_reason``
# column wants the unwrapped code (the classifier consumes it).
_TICK_REASON_PREFIXES = ("reconcile:", "hop_failure:")


def _strip_tick_reason_prefix(reason: str) -> str:
    """Return the raw reason code, stripping any tick-added prefix."""
    for prefix in _TICK_REASON_PREFIXES:
        if reason.startswith(prefix):
            return reason[len(prefix) :]
    return reason


@dataclass
class AnonymizeServiceState:
    """Mutable state the orchestrator manages across its lifecycle.

    Held on the service instance, never on a module-level global, so
    test runs can replace the service without leaking state between
    cases.
    """

    started: bool = False
    per_session_tasks: dict[str, asyncio.Task] = field(default_factory=dict)
    scheduler: "RecurringScheduler | None" = None
    create_rate_limiter: "ThreeBudgetLimiter | None" = None


# Type for the dependency-injected DB session factory.
SessionFactory = Callable[[], AsyncSession]


class AnonymizeService:
    """State-machine driver for anonymize sessions.

    The service is constructed at startup with its dependencies injected
    by :mod:`app.main`. The service wires:

    * the ``AsyncSession`` factory used by per-session tasks,
    * the per-session task supervisor that re-hydrates non-terminal
      rows on boot,
    * the recurring-task scheduler that drives rotation / GC / NTP
      ticks (each on its own advisory-locked cadence).

    Per-state execution methods (``_tick_created``, ``_tick_funding``,
    ...) live in the hop-specific modules under
    :mod:`app.services.anonymize.hops`; the orchestrator dispatches
    based on the session's current status string.
    """

    def __init__(
        self,
        *,
        session_factory: SessionFactory | None = None,
    ) -> None:
        # The session factory is plumbed in by ``app.main`` at startup
        # so unit tests can construct a service without a live DB.
        self._session_factory = session_factory
        self._state = AnonymizeServiceState()

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self) -> None:
        """Assert invariants then re-hydrate per-session tasks.

        Idempotent: a second call is a no-op so the orchestrator can
        recover from a partial-start (e.g., a downstream dependency
        raised mid-startup and the caller retries).
        """
        if self._state.started:
            return
        # Invariant — every enum value the storage layer can produce
        # has a row in the transition graph.
        assert_graph_covers_every_enum_value()
        logger.info("AnonymizeService starting up")
        # Stand up (but do not yet populate) the recurring-task
        # supervisor. Callers register tasks via :meth:`register_recurring`
        # before the orchestrator starts processing sessions.
        from .scheduler import RecurringScheduler

        if self._state.scheduler is None:
            self._state.scheduler = RecurringScheduler()
        await self._state.scheduler.start()
        self._state.started = True

    async def stop(self) -> None:
        """Cancel every per-session task + the scheduler; wait to settle."""
        if not self._state.started:
            return
        for sid, task in list(self._state.per_session_tasks.items()):
            task.cancel()
        if self._state.per_session_tasks:
            await asyncio.gather(
                *self._state.per_session_tasks.values(),
                return_exceptions=True,
            )
        self._state.per_session_tasks.clear()
        if self._state.scheduler is not None:
            await self._state.scheduler.stop()
        self._state.started = False
        logger.info("AnonymizeService stopped")

    def spawn_session_task(
        self,
        *,
        session_id: "UUID",
        session_factory: Callable[[], "AsyncContextManager"],
        observation_fn: "ObservationFn",
        hop_step_fn: "HopStepFn | None" = None,
    ) -> None:
        """Spawn the per-session loop task and track it for shutdown.

        Lazily imports :mod:`per_session_loop` so module-load
        ordering with the scheduler stays clean. The per-session
        task is registered on the service so :meth:`stop` cancels
        it cleanly at shutdown.

        ``hop_step_fn`` is the per-source-kind hop-execution body
        (e.g., :func:`hops.reverse.execute_reverse_hop_step` bound
        with deps). When omitted, the loop runs without hop side
        effects — useful for the cancel/refund-only path.
        """
        from .per_session_loop import make_per_session_loop_run_fn

        run_fn = make_per_session_loop_run_fn(
            service=self,
            session_factory=session_factory,
            observation_fn=observation_fn,
            session_id=session_id,
            hop_step_fn=hop_step_fn,
        )
        # ``make_per_session_loop_run_fn`` is declared as returning
        # ``Callable[[], Awaitable[None]]`` but the run fn is an
        # ``async def`` and so always produces a coroutine at runtime;
        # cast so ``create_task`` (which wants a Coroutine) type-checks.
        task = asyncio.create_task(cast(Coroutine[Any, Any, None], run_fn()))
        self.register_task(str(session_id), task)

    def create_rate_limiter(self) -> "ThreeBudgetLimiter":
        """Lazy-initialised per-process three-budget rate limiter.

        Used by the create endpoint to enforce per-cookie + per-user +
        per-IP creation budgets. The limit + window come
        from settings; this method just hands back the same instance
        on every call so counters persist across requests.
        """
        from .rate_limit import ThreeBudgetLimiter

        if self._state.create_rate_limiter is None:
            self._state.create_rate_limiter = ThreeBudgetLimiter(
                limit_per_window=int(settings.anonymize_reuse_check_rate_limit_per_hour),
                window_seconds=3600.0,
            )
        return self._state.create_rate_limiter

    def register_recurring(self, task: "RecurringTask") -> None:
        """Add a recurring task to the supervisor.

        Lazily initialises the scheduler so callers can register
        tasks before :meth:`start` runs; the scheduler picks them up
        on its first decision pass.
        """
        from .scheduler import RecurringScheduler

        if self._state.scheduler is None:
            self._state.scheduler = RecurringScheduler()
        self._state.scheduler.register(task)

    # ── State-machine transition helper ──────────────────────────────

    async def transition_session(
        self,
        db: AsyncSession,
        session: AnonymizeSession,
        *,
        to_status: AnonymizeStatus | str,
        reason: str,
    ) -> None:
        """Apply a state transition + flush. Refuses illegal edges.

        Every status-mutating write inside the orchestrator goes
        through this method so the transition graph is the
        single source of truth. Audit events + downstream effects
        are the caller's responsibility (this method returns before
        the side effects so the caller composes them inside the same
        transaction).
        """
        new_value = to_status.value if isinstance(to_status, AnonymizeStatus) else to_status
        old_value = session.status
        try:
            assert_legal_transition(from_status=old_value, to_status=new_value)
        except IllegalStateTransitionError:
            logger.error(
                "refused illegal transition %s → %s on session %s (reason=%s)",
                old_value,
                new_value,
                session.id,
                reason,
            )
            raise
        if old_value == new_value:
            return  # idempotent re-write
        session.status = new_value
        await db.flush()
        logger.info(
            "session %s: %s → %s (reason=%s)",
            session.id,
            old_value,
            new_value,
            reason,
        )

    async def transition_to_awaiting_reconciliation(
        self,
        db: AsyncSession,
        session: AnonymizeSession,
        *,
        reason: str,
    ) -> None:
        """Route a session into ``AWAITING_RECONCILIATION`` atomically.

        Writes the reconciliation columns the recovery path
        consumes:

        * ``pre_reconciliation_status`` — the live status the session
          left, so the auto-retry probe can route back to the same
          hop after a successful retry. Captured fresh on every
          non-AR → AR transition because the resume target is "where
          the session was when it failed", not "where it was on the
          very first AR entry".
        * ``awaiting_reconciliation_reason`` — the persisted reason
          code so reason-based dispatch + UI triage work.

        Per recovery, ``reconciliation_attempts`` and
        ``last_reconciliation_attempt_ts`` **accumulate across the
        session's lifetime** — they are deliberately NOT reset here.
        A session that bounces in and out of AR multiple times
        carries its full lifetime attempt count, so the auto-retry
        budget bounds total retries (not just per-cycle retries) and
        the audit log can identify repeatedly-reconciled sessions
        for operator triage. The manual ``/reconciliation/retry``
        endpoint resets the counters explicitly when the operator
        wants a fresh budget — see the endpoint's docstring.

        Idempotent when the session is already in
        ``AWAITING_RECONCILIATION``: the existing
        ``pre_reconciliation_status`` is preserved (it captures the
        first transition, which is what reconciliation actually wants
        to resume to). The reason is overwritten to reflect the most
        recent cause; attempt counter / timestamp are also preserved
        so an in-flight reconciliation cycle isn't disrupted by a
        duplicate write.
        """
        from_status = session.status
        target = AnonymizeStatus.AWAITING_RECONCILIATION.value

        if from_status == target:
            # Already there. Refresh the reason (most-recent wins)
            # but don't disturb the in-flight reconciliation cycle.
            session.awaiting_reconciliation_reason = reason
            await db.flush()
            return

        # Snapshot pre-status BEFORE the transition flush. We rewrite
        # this on every fresh entry so the resume target reflects
        # the latest pre-AR status (a session that failed in
        # CONFIRMING after a previous resume should resume back to
        # CONFIRMING, not the original EXITING).
        session.pre_reconciliation_status = from_status
        session.awaiting_reconciliation_reason = reason
        # NOTE: ``reconciliation_attempts`` and
        # ``last_reconciliation_attempt_ts`` are intentionally NOT
        # reset here. New sessions inherit the DB default
        # of 0 / NULL on first entry; subsequent re-entries
        # preserve the accumulated count.

        # transition_session raises on illegal edges — let it propagate.
        # All source states that can fail already permit this edge.
        await self.transition_session(
            db,
            session,
            to_status=target,
            reason=reason,
        )

    # ── Per-session task supervisor ──────────────────────────────────

    def register_task(self, session_id: str, task: asyncio.Task) -> None:
        """Track ``task`` so :meth:`stop` can cancel it.

        Replaces any existing task for the same ``session_id`` — the
        orchestrator never runs two per-session tasks concurrently
        for the same session (advisory lock + DB row check enforce
        that on the path that creates the task).
        """
        existing = self._state.per_session_tasks.get(session_id)
        if existing is not None and not existing.done():
            existing.cancel()
        self._state.per_session_tasks[session_id] = task

    def is_session_task_running(self, session_id: str) -> bool:
        task = self._state.per_session_tasks.get(session_id)
        return task is not None and not task.done()

    def in_flight_count(self) -> int:
        """Number of per-session tasks currently running.

        Useful for tests and for the dashboard health card. Does NOT
        substitute for the DB-state-based count the admission
        gate uses.
        """
        return sum(1 for t in self._state.per_session_tasks.values() if not t.done())

    # ── Per-session tick ─────────────────────────────────────────────

    async def tick_session(
        self,
        db: AsyncSession,
        session: AnonymizeSession,
        observations: "TickObservations",
    ) -> "TickAction":
        """One per-session orchestrator step.

        Resolves the next action via :func:`tick.decide_tick_action`,
        applies the state-machine transition when applicable,
        and returns the chosen action so the caller can log / count.

        The function is the single source-of-truth for state mutation:
        the per-session task body only calls into this method, never
        into ``transition_session`` directly. This keeps the
        observation→decision→write loop atomic.
        """
        from .tick import decide_tick_action

        action = decide_tick_action(session, observations)

        if action.kind in ("transition", "reconcile", "fail"):
            if action.to_status is None:
                # Defensive guard — decide_tick_action sets this for
                # every non-wait/non-noop branch.
                raise RuntimeError(f"tick action {action.kind} missing to_status")
            if action.to_status == AnonymizeStatus.AWAITING_RECONCILIATION.value:
                # Route through the helper so the four reconciliation
                # columns (pre_reconciliation_status, reason, attempts,
                # last_attempt_ts) are populated atomically.
                #
                # action.reason carries a tick-prefixed audit string
                # (e.g. "reconcile:mpp_k_floor_exhausted"); strip the
                # prefix so the persisted column is the raw reason
                # code the classifier consumes.
                await self.transition_to_awaiting_reconciliation(
                    db,
                    session,
                    reason=_strip_tick_reason_prefix(action.reason),
                )
            else:
                await self.transition_session(
                    db,
                    session,
                    to_status=action.to_status,
                    reason=action.reason,
                )
        return action

    # ── Read-side helpers ────────────────────────────────────────────

    @staticmethod
    def is_session_terminal(session: AnonymizeSession) -> bool:
        return is_terminal(session.status)


# Module-level singleton mirrored on the boltz_service / lnd_service
# pattern. Constructed lazily so test imports don't pay startup cost.
anonymize_service: AnonymizeService | None = None


def get_anonymize_service() -> AnonymizeService:
    global anonymize_service
    if anonymize_service is None:
        anonymize_service = AnonymizeService()
    return anonymize_service


def reset_anonymize_service() -> None:
    """Test helper — drop the module-level singleton."""
    global anonymize_service
    anonymize_service = None


async def bootstrap_anonymize_orchestrator(app: "FastAPI | None" = None) -> AnonymizeService:
    """Wire production tick adapters + start the orchestrator.

    Called from:func:`app.main.lifespan` after the startup
    gates pass. Returns the live service so the caller can stash it
    on app state (the dashboard endpoints continue to read it via
    :func:`get_anonymize_service` for compatibility).

    Wires three recurring adapters:

    * Audit-bucket emission.
    * GC sweep — LN-source deployments only run the destination-anchor
      redact pass; the rest are no-ops there.
    * Decoy retention catch-up — no-op until on-chain self-source
      deployments populate ``anonymize_decoy_output``.

    ``app`` is the FastAPI app whose ``state.anonymize_health`` the
    recurring health-emitting ticks (clock-skew probe, Tor recheck)
    update in place. Tests that bootstrap the orchestrator without
    a real FastAPI app pass ``None``; the health emitter no-ops.
    """
    from app.core.database import get_session_maker
    from app.models.audit_log import AuditLog
    from app.services.anonymize.gc import (
        run_chain_anchor_redact_pass,
        run_event_collapse_pass,
        run_fingerprint_coarsen_pass,
        run_fingerprint_columns_pass,
        run_hop_idempotency_key_null_pass,
        run_last_error_null_pass,
        run_pipeline_json_truncate_pass,
        run_reuse_key_purge_pass,
        run_swap_anchor_severance_pass,
    )
    from app.services.anonymize.quote_token import (
        assert_quote_token_keyset_loadable,
    )
    from app.services.anonymize.tick_runners import (
        make_audit_emit_run_fn,
        make_decoy_catchup_run_fn,
        make_gc_sweep_run_fn,
    )
    from app.services.audit_service import _finalize_entry

    # Refuse to start the orchestrator without
    # a loadable quote-token HMAC key. A deployment that bypasses
    # this raises every quote endpoint to 503; better to fail loud
    # at boot.
    assert_quote_token_keyset_loadable()

    svc = get_anonymize_service()
    # Stash the live FastAPI app so health-emitting recurring ticks
    # can push fresh values onto ``app.state.anonymize_health``
    # without importing :mod:`app.main` (which would create a cycle).
    if app is not None:
        svc._fastapi_app = app  # type: ignore[attr-defined]
    session_maker = get_session_maker()

    # MultiFernet canary-decrypt validates the destination-
    # address Fernet bundle round-trips against a deployment-pinned
    # plaintext. A leg of the key set that fails to decrypt the
    # canary surfaces a clear error at boot rather than silently
    # corrupting every new session's destination column.
    from .crypto import run_canary_decrypt

    async with session_maker() as canary_db:
        await run_canary_decrypt(canary_db)

    # Q7 — boot-time clock-skew hydration. If the DB holds a recent
    # measurement (within 2× recheck interval), seed
    # ``clock_skew_status`` directly from it so users opening the
    # wizard in the first few seconds after restart don't see the
    # 20-second "Calibrating time sync…" banner unnecessarily. The
    # recurring probe still runs immediately and refreshes the value
    # in the background.
    if app is not None:
        from app.core.config import settings as _settings

        from .clock import (
            is_clock_skew_within_threshold,
            load_clock_skew_state,
        )

        max_age = float(_settings.anonymize_clock_recheck_interval_s) * 2
        async with session_maker() as hydrate_db:
            cached = await load_clock_skew_state(hydrate_db)
        health = getattr(app.state, "anonymize_health", None)
        if isinstance(health, dict) and not cached.is_stale(max_age_s=max_age):
            within = is_clock_skew_within_threshold(cached)
            health["clock_skew_status"] = "healthy" if within else "unhealthy"
            health["clock_skew_within_threshold"] = within
            health["clock_skew_ms"] = int(cached.skew_ms or 0)
            health["clock_skew_threshold_ms"] = int(
                _settings.anonymize_max_clock_skew_ms,
            )
            health["clock_skew_warmup_completes_at_unix_s"] = None
        elif isinstance(health, dict):
            # No fresh cached state — wizard sees "unknown" until the
            # first probe tick fires (which happens within seconds of
            # bootstrap via ``last_run_at_unix_s=None`` → due at -inf).
            health.setdefault("clock_skew_status", "unknown")
            health.setdefault(
                "clock_skew_threshold_ms",
                int(_settings.anonymize_max_clock_skew_ms),
            )

    async def _audit_writer(payload: dict) -> None:
        async with session_maker() as db:
            entry = AuditLog(
                api_key_id=None,
                api_key_name="__system__",
                action="anonymize.bucket_summary",
                resource="anonymize_session",
                details=payload,
                success=True,
            )
            await _finalize_entry(db, entry)
            await db.commit()

    audit_run_fn = make_audit_emit_run_fn(
        session_factory=session_maker,
        audit_writer=_audit_writer,
    )
    decoy_run_fn = make_decoy_catchup_run_fn(session_factory=session_maker)
    gc_run_fn = make_gc_sweep_run_fn(
        session_factory=session_maker,
        pass_runners={
            "pipeline_truncate": run_pipeline_json_truncate_pass,
            "event_collapse": run_event_collapse_pass,
            "reuse_key_purge": run_reuse_key_purge_pass,
            "chain_anchor_redact": run_chain_anchor_redact_pass,
            "fingerprint_coarsen": run_fingerprint_coarsen_pass,
            "last_error_null": run_last_error_null_pass,
            "fingerprint_columns": run_fingerprint_columns_pass,
            "swap_anchor_sever": run_swap_anchor_severance_pass,
            "hop_idempotency_key_null": run_hop_idempotency_key_null_pass,
            # decoy_chain_anchor_redact runs only via decoy_catchup.
        },
    )

    from app.core.config import settings as _settings

    svc.register_recurring(
        RecurringTask(
            name="audit_emit",
            interval_s=float(_settings.anonymize_audit_bucket_s),
            run_fn=audit_run_fn,
        )
    )
    svc.register_recurring(
        RecurringTask(
            name="decoy_catchup",
            interval_s=float(_settings.anonymize_gc_catchup_interval_s),
            run_fn=decoy_run_fn,
        )
    )
    svc.register_recurring(
        RecurringTask(
            name="gc_sweep",
            interval_s=float(_settings.anonymize_gc_tick_interval_s),
            run_fn=gc_run_fn,
        )
    )
    svc.register_recurring(
        RecurringTask(
            name="clock_skew_probe",
            interval_s=float(_settings.anonymize_clock_recheck_interval_s),
            run_fn=_clock_skew_probe_run,
        )
    )
    svc.register_recurring(
        RecurringTask(
            name="tor_bootstrap_recheck",
            interval_s=float(_settings.anonymize_tor_bootstrap_recheck_interval_s),
            run_fn=_tor_bootstrap_recheck_run,
        )
    )
    # Rotation tick. Cadence is 1 hour (the idempotency
    # floor); the run-fn walks every policy and emits due/not-due decisions.
    svc.register_recurring(
        RecurringTask(
            name="rotation_tick",
            interval_s=3600.0,
            run_fn=_rotation_tick_run,
        )
    )
    # Auto-retry probe + wedge detector. The boot
    # delay is implemented via ``cooldown_until_unix_s`` so the first
    # tick fires N seconds after process start; subsequent ticks use
    # the configured interval.
    from .tick_runners import make_reconciliation_probe_run_fn

    _reconciliation_probe_run = make_reconciliation_probe_run_fn(
        service=svc,
        session_factory=session_maker,
    )
    import time as _boot_time

    svc.register_recurring(
        RecurringTask(
            name="reconciliation_probe",
            interval_s=float(
                _settings.anonymize_reconciliation_probe_interval_s,
            ),
            run_fn=_reconciliation_probe_run,
            cooldown_until_unix_s=(_boot_time.time() + float(_settings.anonymize_reconciliation_probe_boot_delay_s)),
        )
    )
    # Chain-confirmation poll cadence is the Boltz poll interval
    # for parity with the reverse-exit observer.
    svc.register_recurring(
        RecurringTask(
            name="chain_poll",
            interval_s=float(_settings.anonymize_boltz_poll_interval_s),
            run_fn=_chain_poll_tick_run,
        )
    )
    # Self-broadcast fallback fires at the same cadence; cheap
    # to no-op when no session is in EXITING.
    svc.register_recurring(
        RecurringTask(
            name="self_broadcast_fallback",
            interval_s=float(_settings.anonymize_boltz_poll_interval_s),
            run_fn=_self_broadcast_tick_run,
        )
    )
    # Randomized quote-cache refresh cadence in
    # ``[refresh_min_s, refresh_max_s]``. We register at the midpoint;
    # the run-fn re-samples on each tick to break any operator-side
    # cadence pattern.
    _qc_min = int(_settings.anonymize_quote_cache_refresh_min_s)
    _qc_max = int(_settings.anonymize_quote_cache_refresh_max_s)
    _qc_cadence = float((_qc_min + _qc_max) / 2) if _qc_max >= _qc_min else 600.0
    svc.register_recurring(
        RecurringTask(
            name="quote_cache_refresh",
            interval_s=_qc_cadence,
            run_fn=_quote_cache_refresh_run,
        )
    )

    await svc.start()

    # Backfill ``pre_reconciliation_status`` on legacy
    # AWAITING_RECONCILIATION rows that pre-date the helper.
    # Runs before run_startup_reconciliation so the resume path sees
    # populated pre-status when the heuristic was able to infer one.
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    from .reconciliation_probe import (
        apply_startup_pre_status_heuristic,
    )

    try:
        async with session_maker() as _heuristic_db:
            _heuristic_applied = await apply_startup_pre_status_heuristic(
                _heuristic_db,
                now=_dt.now(_tz.utc),
            )
            await _heuristic_db.commit()
        if _heuristic_applied:
            logger.info(
                "anonymize startup heuristic applied to %d row(s)",
                _heuristic_applied,
            )
    except Exception:  # noqa: BLE001 — heuristic must never deny boot
        logger.exception("anonymize startup heuristic failed")

    # Re-hydrate non-terminal sessions on boot. Uses the
    # production router AND the reverse-hop dispatcher so re-spawned
    # tasks pick up where they left off — including issuing or
    # claiming the Boltz reverse swap.
    from .hop_dispatcher import default_hop_step_fn
    from .observation_router import default_observation_fn
    from .startup_reconciliation import run_startup_reconciliation

    summary = await run_startup_reconciliation(
        service=svc,
        session_factory=session_maker,
        observation_fn=default_observation_fn,
        hop_step_fn=default_hop_step_fn(),
    )
    logger.info(
        "anonymize startup reconciliation: resumed=%d reconciled=%d",
        summary.resumed_count,
        summary.reconciled_count,
    )
    return svc


async def _clock_skew_probe_run() -> None:
    """Recurring clock-skew watcher tick.

    Drives the four-state ``clock_skew_status`` machine described
    :

    * ``warming_up`` — set at the start of the tick; the wizard's
      polling reads this + ``clock_skew_warmup_completes_at_unix_s``
      to render the calibrating banner.
    * ``healthy`` — set when the probe produces a measurement and
      ``|skew| ≤ ANONYMIZE_MAX_CLOCK_SKEW_MS``.
    * ``unhealthy`` — set on a successful measurement whose skew
      exceeds the threshold, OR on a failed measurement (fewer than
      ``ANONYMIZE_CLOCK_SKEW_MIN_SAMPLES_FOR_DECISION`` usable
      samples).

    The legacy boolean ``clock_skew_within_threshold`` mirrors
    ``status == "healthy"`` so external readers (e.g. self-broadcast
    tick) keep working unchanged.
    """
    import logging as _logging
    import time as _time

    from app.core.config import settings as _settings
    from app.core.database import get_session_maker

    from .clock import (
        is_clock_skew_within_threshold,
        probe_clock_skew_via_http,
        store_clock_skew_state,
    )
    from .metadata import ANONYMIZE_LOGGER_NAME

    log = _logging.getLogger(ANONYMIZE_LOGGER_NAME)

    # Mark sampling in progress + seed countdown data for the wizard.
    # Q5 — only the INITIAL probe (prior status was unknown) flips
    # status to ``warming_up``. Subsequent ticks leave the prior
    # ``healthy``/``unhealthy`` in place so the wizard's Confirm
    # button stays enabled (or stays blocked) while the refresh
    # happens in the background. The wizard reads
    # ``warmup_completes_at_unix_s`` to render a small "refreshing"
    # indicator independent of the status enum.
    target_samples = int(_settings.anonymize_clock_skew_samples_per_tick)
    window_s = float(_settings.anonymize_clock_skew_sample_window_s)
    prior_status = _read_anonymize_health("clock_skew_status") or "unknown"
    if prior_status == "unknown":
        _update_anonymize_health("clock_skew_status", "warming_up")
    _update_anonymize_health(
        "clock_skew_warmup_completes_at_unix_s",
        _time.time() + window_s,
    )
    _update_anonymize_health("clock_skew_samples_collected", 0)
    _update_anonymize_health("clock_skew_samples_target", target_samples)
    _update_anonymize_health(
        "clock_skew_threshold_ms",
        int(_settings.anonymize_max_clock_skew_ms),
    )

    def _progress(samples_collected: int) -> None:
        _update_anonymize_health(
            "clock_skew_samples_collected",
            samples_collected,
        )

    measured = await probe_clock_skew_via_http(progress_fn=_progress)

    if measured.skew_ms is None:
        # Q5 — a subsequent-tick failure to gather min samples does
        # NOT downgrade a previously-healthy status. We log the
        # warning, clear the refresh indicator, and leave the prior
        # decisive state intact. Only the *initial* tick (status was
        # ``unknown`` / ``warming_up`` before this probe) flips to
        # ``unhealthy`` so the wizard surfaces the failure.
        log.warning(
            "anonymize clock-skew probe: below MIN_SAMPLES_FOR_DECISION; health gate stays closed until next tick.",
        )
        if prior_status in ("unknown", "warming_up"):
            _update_anonymize_health("clock_skew_status", "unhealthy")
            _update_anonymize_health("clock_skew_within_threshold", False)
        _update_anonymize_health("clock_skew_warmup_completes_at_unix_s", None)
        return

    async with get_session_maker()() as db:
        await store_clock_skew_state(db, measured)
        await db.commit()

    within = is_clock_skew_within_threshold(measured)
    _update_anonymize_health(
        "clock_skew_status",
        "healthy" if within else "unhealthy",
    )
    _update_anonymize_health("clock_skew_within_threshold", within)
    _update_anonymize_health("clock_skew_ms", int(measured.skew_ms))
    _update_anonymize_health("clock_skew_warmup_completes_at_unix_s", None)
    log.info(
        "anonymize clock-skew probe: skew_ms=%d within_threshold=%s samples=%d sources=%d",
        int(measured.skew_ms),
        within,
        int(measured.sample_count),
        len(measured.sources_consulted),
    )


def _update_anonymize_health(key: str, value: object) -> None:
    """Push a fresh health-card value onto ``app.state.anonymize_health``.

    The orchestrator does not import ``app.main`` to avoid an import
    cycle; instead it grabs the live FastAPI app via the running
    service's stashed handle (set by the lifespan path) and falls
    back to a no-op when no app handle is registered (e.g., tests
    that run the probe directly).
    """
    try:
        svc = get_anonymize_service()
        app = getattr(svc, "_fastapi_app", None)
        if app is None:
            return
        state = getattr(app, "state", None)
        if state is None:
            return
        health = getattr(state, "anonymize_health", None)
        if not isinstance(health, dict):
            return
        health[key] = value
    except Exception:  # noqa: BLE001
        # The health card is best-effort; the persisted runtime
        # state remains the source-of-truth for the broadcast tick.
        return


def _read_anonymize_health(key: str) -> object | None:
    """Return the current value of ``app.state.anonymize_health[key]``.

    Mirrors :func:`_update_anonymize_health` — returns ``None`` when
    no app is registered or the key is absent. Used by the probe
    runner to read its own prior state (e.g., to preserve a healthy
    status across a subsequent-tick re-probe).
    """
    try:
        svc = get_anonymize_service()
        app = getattr(svc, "_fastapi_app", None)
        if app is None:
            return None
        state = getattr(app, "state", None)
        if state is None:
            return None
        health = getattr(state, "anonymize_health", None)
        if not isinstance(health, dict):
            return None
        return health.get(key)
    except Exception:  # noqa: BLE001
        return None


async def _tor_bootstrap_recheck_run() -> None:
    """Recurring Tor bootstrap recheck tick.

    Speaks to the configured Tor control port via
    :func:`tor.probe_tor_bootstrap_status` and pushes the resulting
    ``fully_bootstrapped`` boolean onto
    ``app.state.anonymize_health["tor_bootstrap_ready"]`` so the
    create-endpoint admission gate can refuse session creation
    until Tor is fully bootstrapped.

    A control-port that doesn't answer (Tor not running yet, wrong
    port, auth failure) registers as ``tor_bootstrap_ready=False``
    so the gate fails closed.
    """
    import logging as _logging

    from .metadata import ANONYMIZE_LOGGER_NAME
    from .tor import is_tor_bootstrap_ready, probe_tor_bootstrap_status

    log = _logging.getLogger(ANONYMIZE_LOGGER_NAME)

    status = await probe_tor_bootstrap_status()
    ready = is_tor_bootstrap_ready(status)
    _update_anonymize_health("tor_bootstrap_ready", ready)
    log.info(
        "anonymize tor bootstrap probe: ready=%s reachable=%s progress=%d circuit=%s",
        ready,
        status.control_port_reachable,
        status.bootstrap_phase_progress,
        status.circuit_established,
    )


async def _chain_poll_tick_run() -> None:
    """Recurring chain-confirmation poll.

    Walks every session in ``CONFIRMING`` whose ``claim_txid`` is
    populated and queries the dedicated anonymize chain client
    (:func:`chain_egress.get_anonymize_tx_confirmations`) for the
    current confirmation depth. Updates ``claim_tx_confirmations``
    on the row so the per-session loop's
    :func:`reverse_observe.observe_reverse_exit` can decide the
    ``CONFIRMING → COMPLETED`` /
    ``COMPLETED_WITH_REORG_UNCERTAINTY`` transition.

    A drop in confirmation depth between ticks is treated as a reorg
    observation; the row's ``claim_tx_reorg_observed_count`` is bumped
    and the give-up threshold lives downstream in
    :func:`reverse_observe._read_chain_confirmations`.

    Unconfigured / unreachable chain backend → noop. The supervisor's
    health card surfaces the absent backend separately.
    """
    import logging as _logging

    from sqlalchemy import select

    from app.core.database import get_session_maker
    from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

    from .chain_egress import get_anonymize_tx_confirmations
    from .metadata import ANONYMIZE_LOGGER_NAME

    log = _logging.getLogger(ANONYMIZE_LOGGER_NAME)

    async with get_session_maker()() as db:
        stmt = (
            select(AnonymizeSession)
            .where(AnonymizeSession.status == AnonymizeStatus.CONFIRMING.value)
            .where(AnonymizeSession.deleted_at.is_(None))
            .where(AnonymizeSession.claim_txid.is_not(None))
        )
        rows = (await db.execute(stmt)).scalars().all()
        if not rows:
            return

        dirty = False
        for sess in rows:
            # The query filters ``claim_txid IS NOT NULL`` so every row
            # here carries a txid.
            assert sess.claim_txid is not None  # WHERE claim_txid IS NOT NULL
            data, err = await get_anonymize_tx_confirmations(sess.claim_txid)
            if err is not None or data is None:
                log.warning(
                    "anonymize chain poll: session=%s tx=%s read failed: %s",
                    sess.id,
                    sess.claim_txid,
                    err,
                )
                continue
            new_confs = int(data.get("confirmations", 0))
            prev_confs = int(sess.claim_tx_confirmations or 0)
            if new_confs != prev_confs:
                sess.claim_tx_confirmations = new_confs
                dirty = True
            # A confirmed → lower-confirmed transition implies the
            # claim tx's containing block was orphaned. Count the
            # observation against the give-up threshold.
            if prev_confs > 0 and new_confs < prev_confs:
                sess.claim_tx_reorg_observed_count = int(sess.claim_tx_reorg_observed_count or 0) + 1
                dirty = True
        if dirty:
            await db.commit()


async def _self_broadcast_tick_run() -> None:
    """Self-broadcast fallback recurring tick.

    For every session in ``EXITING`` whose ``broadcast_deadline_unix_s``
    has passed without the claim TX being observed on chain:

    1. Read :func:`broadcast.decide_self_broadcast_action` against
       the persisted state.
    2. On ``"self_broadcast"``, persist
       ``self_broadcast_attempted_at_ts`` *before* posting the
       cached ``claim_tx_hex`` through
       :func:`chain_egress.anonymize_broadcast_tx` (
       crash-consistency — the timestamp must hit the DB before
       the chain backend sees the hex).
    3. Record the returned txid on the row so the chain-poll
       tick can take over confirmation tracking.
    """
    import logging
    import time as _time
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    from sqlalchemy import select

    from app.core.database import get_session_maker
    from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

    from .broadcast import BroadcastState, decide_self_broadcast_action
    from .chain_egress import anonymize_broadcast_tx
    from .clock import load_clock_skew_state
    from .metadata import ANONYMIZE_LOGGER_NAME

    logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)

    async with get_session_maker()() as db:
        stmt = (
            select(AnonymizeSession)
            .where(AnonymizeSession.status == AnonymizeStatus.EXITING.value)
            .where(AnonymizeSession.deleted_at.is_(None))
            .where(AnonymizeSession.claim_tx_hex.is_not(None))
        )
        rows = (await db.execute(stmt)).scalars().all()
        if not rows:
            return

        clock_state = await load_clock_skew_state(db)

        for sess in rows:
            broadcast_at_ts = sess.claim_broadcast_at_ts
            deadline = sess.broadcast_deadline_unix_s
            if deadline is None and broadcast_at_ts is not None:
                deadline = int(broadcast_at_ts.timestamp())
            # ``BroadcastState`` wants a Unix timestamp (float); the
            # column persists a tz-aware ``datetime`` — convert so the
            # decision helper's float arithmetic doesn't blow up.
            attempted_at = sess.self_broadcast_attempted_at_ts
            state = BroadcastState(
                broadcast_deadline_unix_s=int(deadline) if deadline else None,
                self_broadcast_attempted_at_ts=(attempted_at.timestamp() if attempted_at is not None else None),
                claim_tx_observed_on_chain=bool(sess.claim_txid),
                poll_interval_s=int(settings.anonymize_boltz_poll_interval_s),
            )
            decision = decide_self_broadcast_action(
                state,
                clock_state=clock_state,
                now_unix_s=_time.time(),
            )
            if decision != "self_broadcast":
                continue

            # Record attempt timestamp BEFORE egress so a
            # crash mid-broadcast doesn't fire it twice on restart.
            sess.self_broadcast_attempted_at_ts = _dt.now(_tz.utc)
            await db.commit()

            # The query filters ``claim_tx_hex IS NOT NULL`` so the hex
            # is always present on these rows.
            assert sess.claim_tx_hex is not None  # WHERE claim_tx_hex IS NOT NULL
            txid, broadcast_err = await anonymize_broadcast_tx(
                sess.claim_tx_hex,
            )
            if broadcast_err is not None:
                logger.warning(
                    "anonymize self-broadcast: session=%s failed: %s",
                    sess.id,
                    broadcast_err,
                )
                continue

            sess.claim_txid = txid
            await db.commit()
            logger.info(
                "anonymize self-broadcast: session=%s txid=%s",
                sess.id,
                txid,
            )


async def _quote_cache_refresh_run() -> None:
    """Randomized quote-cache refresh tick.

    Walks the operator registry and refreshes one entry per
    tick through the dedicated ``quote_cache_refresh`` SOCKS listener,
    HMAC-signing each entry under
    ``ANONYMIZE_QUOTE_CACHE_SIGNING_KEY_FERNET`` so the read path can
    reject a tampered cache line.

    Single-operator deployments without the curated registry fall back to a
    single ``default`` operator entry; the round-robin then degenerates
    to repeated calls against the same operator, but the listener
    isolation + cadence randomization + signature still hold. Failed
    egress preserves the existing cache line so a transient Boltz
    outage doesn't drop the cache to empty (the staleness threshold
    handles persistent failures via).
    """
    import logging as _logging
    import time as _time

    from .boltz_egress import fetch_reverse_pair_info_for_cache
    from .metadata import ANONYMIZE_LOGGER_NAME
    from .operators import load_operator_registry
    from .quote_cache import (
        CacheEntry,
        CacheKey,
        get_quote_cache,
        sign_cache_entry,
    )
    from .tor import sample_first_egress_jitter_s

    log = _logging.getLogger(ANONYMIZE_LOGGER_NAME)

    # First-egress jitter. The very first
    # invocation of this tick is also the first anonymize-egress
    # call from a fresh process; sleeping a uniform-random window
    # in ``[0, ANONYMIZE_FIRST_EGRESS_BOOTSTRAP_JITTER_S)`` denies
    # a passive observer the ability to pair the wallet host's
    # process-start moment with first-egress landing on Tor.
    cache_module_marker = get_quote_cache()
    if not getattr(cache_module_marker, "_qc_first_egress_jitter_applied", False):
        jitter_s = sample_first_egress_jitter_s()
        cache_module_marker._qc_first_egress_jitter_applied = True  # type: ignore[attr-defined]  # dynamic first-egress latch, not a declared field
        if jitter_s > 0.0:
            log.info(
                "anonymize first-egress jitter: sleeping %.2fs before first refresh",
                jitter_s,
            )
            import asyncio as _asyncio

            await _asyncio.sleep(jitter_s)

    try:
        registry = load_operator_registry()
    except Exception as exc:  # noqa: BLE001
        log.warning("anonymize quote-cache refresh: registry load failed: %s", exc)
        registry = []
    operator_ids = [e.operator_id for e in registry] or ["default"]

    # Round-robin: persist the current cursor in the cache object's
    # mutable state. The simple modulo over the entry count covers
    # the single-operator case (same index every tick) and the
    # multi-operator case (cursor advances 0,1,...,k-1,0,...).
    cache = get_quote_cache()
    cursor_attr = "_qc_refresh_cursor"
    cursor = int(getattr(cache, cursor_attr, 0)) % max(1, len(operator_ids))
    operator_id = operator_ids[cursor]
    setattr(cache, cursor_attr, (cursor + 1) % max(1, len(operator_ids)))

    key = CacheKey(operator_id=operator_id, pair="BTC/BTC", asset="BTC")
    payload, error = await fetch_reverse_pair_info_for_cache(operator_id)
    if error is not None:
        log.warning(
            "anonymize quote-cache refresh: operator=%s egress failed: %s",
            operator_id,
            error,
        )
        # Preserve the existing entry on failure staleness
        # path handles persistent outage.
        return

    fetched_at = float(_time.time())
    generation = 0
    signature = sign_cache_entry(
        key=key,
        payload=payload or {},
        fetched_at_unix_s=fetched_at,
        signing_key_generation=generation,
    )
    cache.put(
        CacheEntry(
            key=key,
            payload=payload or {},
            fetched_at_unix_s=fetched_at,
            operator_signature=signature,
            signing_key_generation=generation,
        )
    )


async def _rotation_tick_run() -> None:
    """Recurring key-rotation tick.

    Walks every :func:`rotation.all_policies` policy, reads the
    persisted ``<policy>.runtime_state_key`` timestamp from
    ``anonymize_runtime_state``, decides whether a rotation is due
    via :func:`is_rotation_due`, and on "due" stamps a fresh
    timestamp so the idempotency floor advances.

    The actual key-material rewrite + sentinel-overwrite of
    rotated-out columns lands with the matching purge passes (the
     reuse-key-purge and hop-idempotency-key-null
    passes are wired into the GC sweep). This tick records when a
    rotation *event* occurred; the GC sweep does the purge work.
    """
    import logging
    import time as _time

    from app.core.database import get_session_maker

    from .metadata import ANONYMIZE_LOGGER_NAME
    from .rotation import all_policies, is_rotation_due
    from .runtime_state import read_runtime_state, write_runtime_state

    logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)

    async with get_session_maker()() as db:
        for policy in all_policies():
            raw = await read_runtime_state(db, key=policy.runtime_state_key)
            last: float | None = None
            if isinstance(raw, dict) and "value" in raw:
                try:
                    last = float(raw["value"])
                except (TypeError, ValueError):
                    last = None
            if is_rotation_due(policy, last_rotation_unix_s=last):
                now = float(_time.time())
                logger.info(
                    "anonymize rotation policy=%s due (cadence=%dd retention=%dd; last=%s)",
                    policy.name,
                    policy.rotation_days,
                    policy.retention_days,
                    last,
                )
                await write_runtime_state(
                    db,
                    key=policy.runtime_state_key,
                    payload={"value": now},
                )
                # Quote-cache rotation pre-warm pass.
                # When the quote-cache signing key rotates, every
                # cache entry signed under the rotated-out key is
                # re-signed in place at the documented rate. Failure
                # here is non-fatal: the read path falls back to the
                # soft-stale flow which blocks for refresh.
                if policy.name == "quote_cache_signing":
                    try:
                        _run_quote_cache_resign_pass(active_generation=int(now))
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "anonymize quote-cache resign pass failed: %s",
                            exc,
                        )
                # Register the new quote-token HMAC key
                # generation in the cross-replica DB index. Replicas
                # whose in-memory keyset is still on the old
                # generation use this row to resolve the new one
                # without re-reading the operator's Fernet bundle.
                if policy.name == "quote_token_hmac":
                    try:
                        await _register_active_quote_token_generation(
                            db,
                            generation=int(now),
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.warning(
                            "anonymize quote-token generation registry write failed: %s",
                            exc,
                        )
        await db.commit()


async def _register_active_quote_token_generation(
    db: AsyncSession,
    *,
    generation: int,
) -> None:
    """Write the active quote-token generation to the DB index.

    The rotation tick calls this on ``quote_token_hmac`` rotation
    so other replicas can resolve the new generation via
    :func:`quote_token.lookup_key_generation_via_db`. Failure is
    non-fatal — the next tick re-registers + the in-memory verify
    path still works on the rotating replica.
    """
    from .quote_token import (
        load_quote_token_keyset,
        register_quote_token_generation,
    )

    keyset = load_quote_token_keyset()
    if keyset is None or not keyset.keys:
        return
    # The active generation's raw key material is the first slot in
    # the loaded Fernet bundle; the fingerprint records *which* key
    # material is associated with the generation number.
    active_key = keyset.keys[0]
    await register_quote_token_generation(
        db,
        generation=generation,
        key_bytes=bytes(active_key),
    )


def _run_quote_cache_resign_pass(*, active_generation: int) -> None:
    """Re-sign every quote-cache entry under the new key.

    Iterates the in-memory cache (the read path's source of truth)
    and re-signs each entry. Throttled by
    ``ANONYMIZE_QUOTE_CACHE_RESIGN_RATE_PER_S`` so the CPU spike is
    bounded. We intentionally run synchronously inside the rotation
    tick — the pass is small (single-operator cache holds one entry
    per operator) and the throttle keeps it well within tick budget.
    """
    from .quote_cache import (
        get_quote_cache,
        run_resign_pass,
        sign_cache_entry,
    )

    cache = get_quote_cache()
    entries = cache.all()
    if not entries:
        return

    def _sign(entry: "CacheEntry", generation: int) -> bytes | None:
        return sign_cache_entry(
            key=entry.key,
            payload=entry.payload,
            fetched_at_unix_s=entry.fetched_at_unix_s,
            signing_key_generation=generation,
        )

    rebuilt, _ = run_resign_pass(
        entries,
        active_signing_key_generation=active_generation,
        # ``sign_cache_entry`` returns ``bytes | None`` (None when no
        # signing key is configured); ``run_resign_pass`` declares
        # ``sign_fn`` as returning ``bytes`` but stores the result into
        # ``CacheEntry.operator_signature`` which is ``bytes | None``, so
        # a None result is runtime-safe.
        sign_fn=_sign,  # type: ignore[arg-type]  # upstream sign_fn type stricter than its bytes|None storage
    )
    for entry in rebuilt:
        cache.put(entry)


__all__ = [
    "AnonymizeService",
    "AnonymizeServiceState",
    "get_anonymize_service",
    "reset_anonymize_service",
]
