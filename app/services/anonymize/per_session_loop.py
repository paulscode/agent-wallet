# SPDX-License-Identifier: MIT
"""Per-session orchestrator task body.

The :class:`AnonymizeService` spawns one of these loops per non-
terminal session. Each loop body is a small wrapper around the pure
helpers shipped in earlier batches:

* :func:`startup_reconciliation.classify_session` decides whether to
  resume or route to ``awaiting_reconciliation`` at spawn time.
* :func:`tick.decide_tick_action` decides the next state transition
  based on the injected ``observation_fn`` output.
* :class:`AnonymizeService.tick_session` applies the transition.

The loop terminates when the session reaches a terminal status or
when the supervisor cancels the task. Errors raised by the
observation callback or by the DB writes are logged and the loop
retries after a backoff so a transient external error doesn't kill
the per-session task.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, AsyncContextManager, Awaitable, Callable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession

from .metadata import ANONYMIZE_LOGGER_NAME
from .tick import TickObservations

if TYPE_CHECKING:
    from .service import AnonymizeService

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


# An observation collector is an injected async callback the loop
# invokes once per tick. Production wires this to the hop-specific
# modules (LN / chain / Boltz polls); tests pass a Mock.
ObservationFn = Callable[
    [AsyncSession, AnonymizeSession],
    Awaitable[TickObservations],
]


@dataclass(frozen=True)
class PerSessionLoopConfig:
    """Knobs the loop body reads on each iteration."""

    poll_interval_s: float
    poll_jitter_min_s: float = 0.5
    poll_jitter_max_s: float = 5.0


def default_loop_config() -> PerSessionLoopConfig:
    """Resolve the per-session loop config from settings."""
    return PerSessionLoopConfig(
        poll_interval_s=float(settings.anonymize_boltz_poll_interval_s),
    )


def sample_jittered_poll_sleep_s(
    config: PerSessionLoopConfig | None = None,
    *,
    rng: secrets.SystemRandom | None = None,
) -> float:
    """Jittered sleep between per-session ticks.

    Returns ``config.poll_interval_s + Uniform(jitter_min, jitter_max)``
    so two simultaneously-spawned tasks don't lock-step their polls.
    """
    cfg = config or default_loop_config()
    rng = rng or secrets.SystemRandom()
    lo = max(0.0, float(cfg.poll_jitter_min_s))
    hi = max(lo, float(cfg.poll_jitter_max_s))
    return float(cfg.poll_interval_s) + rng.uniform(lo, hi)


HopStepFn = Callable[[AsyncSession, AnonymizeSession], Awaitable[Any]]


async def _noop_hop_step(_db: AsyncSession, _session: AnonymizeSession) -> None:
    """Default hop-step fn — does nothing. Production wires the
    reverse-hop dispatcher per session source kind."""
    return None


def make_per_session_loop_run_fn(
    *,
    service: "AnonymizeService",
    session_factory: Callable[[], "AsyncContextManager"],
    observation_fn: ObservationFn,
    session_id: UUID,
    sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    config: PerSessionLoopConfig | None = None,
    hop_step_fn: HopStepFn | None = None,
) -> Callable[[], Awaitable[None]]:
    """Build the async loop body for one session id.

    The loop:
    1. Opens a fresh DB session each tick (so an error doesn't poison
       a long-lived ORM identity map).
    2. Reads the session row by id.
    3. If terminal or missing, exits.
    4. Calls ``observation_fn(db, session)``.
    5. Calls ``service.tick_session(db, session, obs)``.
    6. Commits + sleeps with the jitter.

    A raise in any step is logged and the loop sleeps a backoff
    interval before the next iteration; this matches the
    "bounded-retry, never terminate the per-session task on a
    transient error" contract.
    """
    cfg = config or default_loop_config()
    sid = session_id
    hop_fn: HopStepFn = hop_step_fn or _noop_hop_step
    # Per-session consecutive-failure counter. After N failures
    # the loop transitions the session into ``AWAITING_RECONCILIATION``
    # instead of looping forever on a wedged dependency. ``N`` defaults
    # to ``ANONYMIZE_HEALTH_FLIP_THRESHOLD`` so the threshold composes
    # with the health-gate hysteresis the orchestrator already honors.
    consecutive_failures = 0
    bounded_retry_threshold = max(
        2,
        int(settings.anonymize_health_flip_threshold) * 3,
    )

    async def _run() -> None:
        nonlocal consecutive_failures
        while True:
            try:
                async with session_factory() as db:
                    sess = await _load(db, sid, for_update=True)
                    if sess is None:
                        logger.info(
                            "per-session loop %s: row missing — exiting",
                            sid,
                        )
                        return
                    if service.is_session_terminal(sess):
                        logger.info(
                            "per-session loop %s: terminal — exiting",
                            sid,
                        )
                        return
                    # Hop step runs BEFORE observation. The
                    # step issues side effects (issue swap, pay
                    # invoice, run claim, broadcast); the observer
                    # then reads the resulting state. Each step is
                    # idempotent so a re-run is safe.
                    outcome = await hop_fn(db, sess)
                    # Surface hop-step failures. The outcome was
                    # previously discarded, so a session could wedge at a
                    # hop (e.g. a Boltz swap-create returning 400) and
                    # retry every tick with nothing shown to the
                    # operator. Log the raw detail at WARNING and persist
                    # it to ``last_error`` — the redaction listener
                    # scrubs the persisted copy, and the dashboard
                    # Details panel renders it. Clear it on a step that
                    # makes progress so a recovered session doesn't carry
                    # a stale error.
                    _out_kind = getattr(outcome, "kind", None)
                    if _out_kind == "error":
                        _detail = getattr(outcome, "detail", "") or "hop step failed"
                        logger.warning(
                            "per-session loop %s: hop step error: %s",
                            sid,
                            _detail,
                        )
                        sess.last_error = _detail
                    elif _out_kind not in (None, "noop"):
                        sess.last_error = None
                    obs = await observation_fn(db, sess)
                    action = await service.tick_session(db, sess, obs)
                    await db.commit()
                    consecutive_failures = 0  # successful tick clears counter
                    if action.kind == "noop_terminal":
                        return
                    if service.is_session_terminal(sess):
                        return
            except asyncio.CancelledError:
                logger.info("per-session loop %s: cancelled", sid)
                raise
            except Exception:  # noqa: BLE001
                consecutive_failures += 1
                logger.exception(
                    "per-session loop %s: tick raised (failure %d/%d); backing off",
                    sid,
                    consecutive_failures,
                    bounded_retry_threshold,
                )
                if consecutive_failures >= bounded_retry_threshold:
                    # Bounded-retry exhausted. Route to
                    # awaiting_reconciliation in a fresh transaction
                    # so the recovery path can pick it up.
                    try:
                        async with session_factory() as recovery_db:
                            row = await _load(recovery_db, sid)
                            if row is not None and not service.is_session_terminal(row):
                                from app.models.anonymize_session import (
                                    AnonymizeStatus,
                                )

                                from .state_machine import (
                                    is_legal_transition,
                                )

                                if is_legal_transition(
                                    from_status=row.status,
                                    to_status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
                                ):
                                    await service.transition_to_awaiting_reconciliation(
                                        recovery_db,
                                        row,
                                        reason="bounded_retry_exhausted",
                                    )
                                    await recovery_db.commit()
                    except Exception:  # noqa: BLE001
                        logger.exception(
                            "per-session loop %s: recovery transition failed",
                            sid,
                        )
                    return
            await sleep_fn(sample_jittered_poll_sleep_s(cfg))

    return _run


async def _load(db: AsyncSession, sid: UUID, *, for_update: bool = False) -> AnonymizeSession | None:
    """Read one session row by id, excluding soft-deleted rows.

    ``for_update`` takes a row-level write lock (``SELECT … FOR UPDATE``)
    that the tick holds until it commits. Because the whole tick — the
    fund-moving hop step, observation, and status transition — runs in
    one transaction, the lock makes a second driver of the same session
    (a duplicate loop, or the reconciliation probe) block until this tick
    commits, then re-read the advanced status, rather than executing the
    same hop concurrently. The clause is a no-op on SQLite (the test
    backend), where the suite is single-threaded.
    """
    stmt = select(AnonymizeSession).where(AnonymizeSession.id == sid).where(AnonymizeSession.deleted_at.is_(None))
    if for_update:
        stmt = stmt.with_for_update()
    return (await db.execute(stmt)).scalar_one_or_none()


__all__ = [
    "ObservationFn",
    "PerSessionLoopConfig",
    "default_loop_config",
    "make_per_session_loop_run_fn",
    "sample_jittered_poll_sleep_s",
]
