# SPDX-License-Identifier: MIT
"""LN-self-pay observation collector.

For sessions whose source is ``lightning-self``, the funding step is
"pay an internal LN invoice from our own wallet" — there's no
external counterparty involved in deposit settlement. The self-pay
HTLC is fired by the self-pay hop body, which records its outcome in
``pipeline_json["self_pay_status"]``; this collector reads that flag
plus the system clock to drive state advancement:

* ``CREATED`` → signal ``funding_invoice_settled=True`` on the first
  tick so the session advances to ``FUNDING``, where the hop body
  fires the self-payment.
* ``FUNDING`` → signal ``funding_invoice_settled=True`` only once
  ``self_pay_status`` is ``settled`` — the gate that holds the
  session at ``FUNDING`` until the self-payment lands, then advances
  it to ``LN_HOLDING``.
* ``DELAYING`` → signal ``delay_window_elapsed=True`` once
  ``now > session.updated_at + delay_policy.min_seconds``.
* ``EXITING`` / ``CONFIRMING`` → these depend on the Boltz reverse
  swap + chain client; this collector signals nothing and the
  reverse-exit observer drives them.

The collector is a pure read of the session row + the system clock —
no Boltz / LND calls.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from ..tick import TickObservations


async def observe_ln_self_pay(
    db: AsyncSession,
    session: AnonymizeSession,
) -> TickObservations:
    """Build a ``TickObservations`` snapshot for an ln-self-pay session.

    Pure read on the session row + the system clock; no external
    state. The orchestrator's per-session loop calls this with a
    fresh DB session each tick.
    """
    status = session.status
    if status == AnonymizeStatus.CREATED.value:
        # Advance to FUNDING, where the hop body fires the self-pay.
        return TickObservations(funding_invoice_settled=True)

    if status == AnonymizeStatus.FUNDING.value:
        # Hold at FUNDING until the hop body records the self-payment
        # as settled; only then advance to LN_HOLDING. ``None`` (not
        # ``False``) means "wait" — the dispatcher refuses to advance.
        pj = session.pipeline_json or {}
        settled = isinstance(pj, dict) and pj.get("self_pay_status") == "settled"
        return TickObservations(funding_invoice_settled=True if settled else None)

    if status == AnonymizeStatus.DELAYING.value:
        elapsed = _delay_elapsed(session)
        return TickObservations(
            delay_window_elapsed=elapsed,
            # The default pipeline has no intermediate hops so
            # the next stop after DELAYING is EXITING.
            is_last_hop=True,
        )

    # LN_HOLDING / HOPPING / EXITING / CONFIRMING — the collector
    # returns an empty snapshot. LN_HOLDING → DELAYING is an
    # unconditional tick transition; the reverse-exit observer drives
    # EXITING / CONFIRMING.
    return TickObservations()


def _delay_elapsed(session: AnonymizeSession) -> bool:
    """Has the session's intra-mix delay elapsed?

    Reads ``delay_policy.min_seconds`` from the frozen
    ``pipeline_json`` so a live-config change can't shorten an
    in-flight session's delay below what the user agreed to.
    """
    delay_min_s = _delay_min_seconds(session)
    if delay_min_s <= 0:
        return True
    base = session.updated_at or session.created_at
    if base is None:
        return False
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (now - base).total_seconds() >= float(delay_min_s)


def _delay_min_seconds(session: AnonymizeSession) -> int:
    """Read ``delay_policy.min_seconds`` from the frozen pipeline JSON."""
    pj = session.pipeline_json or {}
    delay = pj.get("delay_policy", {}) if isinstance(pj, dict) else {}
    try:
        return int(delay.get("min_seconds", 0))
    except (TypeError, ValueError):
        return 0


__all__ = [
    "observe_ln_self_pay",
]
