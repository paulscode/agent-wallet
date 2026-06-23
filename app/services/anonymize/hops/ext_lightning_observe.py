# SPDX-License-Identifier: MIT
"""Ext-lightning source observation collector.

For sessions whose source is ``ext-lightning``, the funding step is
"depositor pays a blinded BOLT11 invoice we issued":

* In ``CREATED`` / ``FUNDING``: wait for the depositor to pay; the
  hop-execution body's LND-invoice poll loop signals settlement.
  Wallclock fallback: signal settlement once the session is
  past the configured ``ANONYMIZE_EXT_DEPOSIT_MIN_DWELL_S`` floor
  (so a test deployment without a live LND can still drive the
  state machine).
* In ``LN_HOLDING``: hold for the dwell window
  ``Uniform(ANONYMIZE_EXT_DEPOSIT_MIN_DWELL_S, ANONYMIZE_EXT_DEPOSIT_MAX_DWELL_S)``;
  the lower bound is what the observer uses as the gate. Once
  elapsed, advance.
* In ``DELAYING`` / ``HOPPING`` / ``EXITING`` / ``CONFIRMING``: the
  reverse-exit observer takes over via the router.

The observer is pure-time-based — no LND poll on this path — so the
orchestrator can drive ext-lightning sessions end-to-end without a
live LND invoice payment. The live LND-invoice poll lands with the
hop-execution body.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from ..tick import TickObservations


async def observe_ext_lightning(
    db: AsyncSession,
    session: AnonymizeSession,
) -> TickObservations:
    """Build a ``TickObservations`` snapshot for an ext-lightning session."""
    status = session.status

    if status == AnonymizeStatus.CREATED.value:
        # Wallet has issued the deposit primitive (BOLT 11 invoice or
        # BOLT 12 offer); the per-session task ticks while we wait.
        #
        # For BOLT 12 deposits the inbound responder + reconciliation
        # sweep keep ``bolt12_invoices.status`` in sync with LND;
        # we authoritatively check for a paid inbound invoice rather
        # than trusting the time-based stub. When the deposit is
        # BOLT 11 the time-based fallback applies (the live
        # ``lookup_invoice`` poll for BOLT 11 lands in a follow-on).
        settled = await _bolt12_deposit_settled(db, session)
        if settled is not None:
            return TickObservations(funding_invoice_settled=bool(settled))
        return TickObservations(funding_invoice_settled=True)

    if status == AnonymizeStatus.FUNDING.value:
        settled = await _bolt12_deposit_settled(db, session)
        if settled is not None:
            return TickObservations(funding_invoice_settled=bool(settled))
        return TickObservations(funding_invoice_settled=True)

    if status == AnonymizeStatus.DELAYING.value:
        # Ext-deposit dwell + the intra-mix delay window
        # both have to elapse before we hop to the exit.
        elapsed = _dwell_and_delay_elapsed(session)
        return TickObservations(
            delay_window_elapsed=elapsed,
            # The default pipeline has no intermediate hops.
            is_last_hop=True,
        )

    # LN_HOLDING / HOPPING / EXITING / CONFIRMING — observer is
    # silent; the router layers the reverse-exit observer on top.
    return TickObservations()


def _dwell_and_delay_elapsed(session: AnonymizeSession) -> bool:
    """Composite dwell + delay window.

    The session must have been in DELAYING for at least
    ``max(ANONYMIZE_EXT_DEPOSIT_MIN_DWELL_S, pipeline.delay_policy.min_seconds)``
    before the orchestrator advances to EXITING.
    """
    dwell_floor = max(
        int(settings.anonymize_ext_deposit_min_dwell_s),
        _delay_min_seconds(session),
    )
    if dwell_floor <= 0:
        return True
    base = session.updated_at or session.created_at
    if base is None:
        return False
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (now - base).total_seconds() >= float(dwell_floor)


def _delay_min_seconds(session: AnonymizeSession) -> int:
    pj = session.pipeline_json or {}
    delay = pj.get("delay_policy", {}) if isinstance(pj, dict) else {}
    try:
        return int(delay.get("min_seconds", 0))
    except (TypeError, ValueError):
        return 0


async def _bolt12_deposit_settled(
    db: AsyncSession,
    session: AnonymizeSession,
) -> bool | None:
    """Return ``True`` / ``False`` for a BOLT 12 deposit session, or
    ``None`` when the session is not on the BOLT 12 deposit path.

    A ``None`` signal tells the caller to fall back to the legacy
    time-based behavior (BOLT 11 deposits + sessions whose deposit
    primitive hasn't been minted yet).
    """
    pj = session.pipeline_json
    if not isinstance(pj, dict):
        return None
    src = pj.get("source") or {}
    if not isinstance(src, dict):
        return None
    if src.get("deposit_method") != "bolt12":
        return None
    if not src.get("deposit_offer_id"):
        # BOLT 12 was requested but the offer mint failed at
        # session-create time. Fall back to the legacy path so the
        # session can still be operator-recovered.
        return None
    from ..deposit_observe import (
        find_paid_inbound_bolt12_invoice_for_session,
    )

    paid_at, _err = await find_paid_inbound_bolt12_invoice_for_session(
        db,
        session_pipeline_json=pj,
    )
    return paid_at is not None


__all__ = ["observe_ext_lightning"]
