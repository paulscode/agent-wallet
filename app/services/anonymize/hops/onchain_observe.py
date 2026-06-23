# SPDX-License-Identifier: MIT
"""/ — on-chain source observation collector.

Drives the state machine for ``onchain-self`` / ``ext-onchain``
sessions through the submarine pre-stages. The submarine hop body
performs the side effects (issue / fund / poll settlement / refund);
this collector reads the persisted state and translates it into
:class:`TickObservations` that the dispatcher consumes.

Two pieces of state matter:

1. **Submarine settlement**: once the on-chain lockup tx confirms +
   Boltz pays the wallet's invoice, the submarine leg is done and
   the session advances to ``HOPPING`` (then DELAYING via
   inter-leg delay) and finally ``EXITING``.

2. ** inter-leg delay**: the dispatcher's ``DELAYING`` →
   ``HOPPING`` / ``EXITING`` transition is gated on
   ``delay_window_elapsed``. For on-chain sources the inter-leg
   delay is computed from ``submarine_funding_broadcast_at_ts`` +
   the pipeline's persisted ``inter_leg_delay.min_seconds``. The
   observation collector returns ``delay_window_elapsed=True``
   only once that delta has actually elapsed.

This module is pure-read: it never mutates DB state. The submarine
hop body owns persistence.
"""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from ..tick import TickObservations

_FALLBACK_INTER_LEG_MIN_S: int = 6 * 3600  # documented floor.


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _inter_leg_delay_window_s(session: AnonymizeSession) -> tuple[int, int]:
    """Return ``(min_seconds, max_seconds)`` from the pipeline_json's
    persisted ``inter_leg_delay`` or the documented fallback."""
    pj = session.pipeline_json or {}
    leg = pj.get("inter_leg_delay") if isinstance(pj, dict) else None
    if not isinstance(leg, dict):
        return _FALLBACK_INTER_LEG_MIN_S, _FALLBACK_INTER_LEG_MIN_S * 8
    try:
        mn = int(leg.get("min_seconds", _FALLBACK_INTER_LEG_MIN_S))
        mx = int(leg.get("max_seconds", mn))
    except (TypeError, ValueError):
        mn = _FALLBACK_INTER_LEG_MIN_S
        mx = mn * 8
    if mx < mn:
        mx = mn
    return mn, mx


def _sample_delay_target_s(
    min_s: int,
    max_s: int,
    *,
    rng: secrets.SystemRandom | None = None,
) -> int:
    """Sample a uniform-random target delay inside the window."""
    rng = rng or secrets.SystemRandom()
    if max_s <= min_s:
        return int(min_s)
    return int(rng.uniform(float(min_s), float(max_s)))


async def observe_onchain_source(
    db: AsyncSession,
    session: AnonymizeSession,
) -> TickObservations:
    """Build a :class:`TickObservations` for an on-chain source session.

    Status-keyed read:

    * ``SOURCING`` — wait for the submarine hop body to issue the swap.
    * ``FUNDING`` — wait for the funding tx to broadcast.
    * ``LN_HOLDING`` — submarine pending; once
      ``submarine_swap_status`` reports ``transaction.claimed`` or
      ``invoice.settled``, advance to DELAYING via the dispatcher's
      LN_HOLDING → DELAYING transition.
    * ``DELAYING`` — the inter-leg delay gate. Returns
      ``delay_window_elapsed=True`` only once the configured
      window has elapsed since the submarine funding broadcast.
    * ``HOPPING`` — for ``ext-onchain`` / ``onchain-self`` the
      submarine is the only pre-exit hop; ``hop_completed=True`` is
      set when settlement is observed.
    * other → empty.
    """
    pj = session.pipeline_json or {}
    if not isinstance(pj, dict):
        return TickObservations()

    status = session.status

    if status == AnonymizeStatus.SOURCING.value:
        return TickObservations()

    if status == AnonymizeStatus.FUNDING.value:
        # Hop body sets ``funding_invoice_settled`` semantics via the
        # ``submarine_funding_broadcast_at_ts`` marker: once the tx
        # is broadcast, advance to LN_HOLDING.
        if pj.get("submarine_funding_broadcast_at_ts"):
            return TickObservations(funding_invoice_settled=True)
        return TickObservations()

    if status == AnonymizeStatus.LN_HOLDING.value:
        # The submarine hop's poll loop records the latest server
        # status in pipeline_json. Once Boltz has paid the wallet's
        # invoice, the submarine leg is done.
        sub_status = pj.get("submarine_swap_status")
        if sub_status in {"transaction.claimed", "invoice.settled"}:
            return TickObservations(funding_invoice_settled=True)
        return TickObservations()

    if status == AnonymizeStatus.HOPPING.value:
        # The submarine is the only pre-exit hop for on-chain
        # sources. Once settlement observed it's done; advance to
        # DELAYING.
        sub_status = pj.get("submarine_swap_status")
        if sub_status in {"transaction.claimed", "invoice.settled"}:
            return TickObservations(
                hop_completed=True,
                is_last_hop=True,
            )
        return TickObservations()

    if status == AnonymizeStatus.DELAYING.value:
        # The inter-leg delay window between submarine
        # completion and reverse-leg start. The window's start is
        # the funding-broadcast timestamp (the moment the
        # submarine first emitted an on-chain side-effect).
        start = _parse_iso(pj.get("submarine_funding_broadcast_at_ts"))
        if start is None:
            # No funding timestamp ⇒ submarine never started; we
            # can't gate on delay. Pass through as elapsed so the
            # state machine doesn't wedge (this is the fail-open
            # path; the enforcement only fires for sessions
            # that actually completed the submarine leg).
            return TickObservations(
                delay_window_elapsed=True,
                is_last_hop=True,
            )
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        elapsed_s = max(0.0, time.time() - start.timestamp())
        # Sample (or read) the per-session target inside the window.
        # The first read samples; subsequent reads reuse the value
        # persisted into pipeline_json via the next tick's writer.
        target_s = pj.get("inter_leg_delay_target_s")
        if not isinstance(target_s, (int, float)) or int(target_s) <= 0:
            mn, mx = _inter_leg_delay_window_s(session)
            target_s = _sample_delay_target_s(mn, mx)
        elapsed = elapsed_s >= float(target_s)
        return TickObservations(
            delay_window_elapsed=bool(elapsed),
            is_last_hop=True,
        )

    return TickObservations()


__all__ = [
    "observe_onchain_source",
    "_inter_leg_delay_window_s",
    "_sample_delay_target_s",
    "_parse_iso",
]
