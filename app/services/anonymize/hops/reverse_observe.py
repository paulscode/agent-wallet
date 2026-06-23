# SPDX-License-Identifier: MIT
"""Reverse-leg observation collector.

For sessions whose exit is a Boltz reverse swap (every LN-source
exit), the per-session loop needs to know:

* When the claim transaction has been observed on-chain (so the
  ``EXITING → CONFIRMING`` transition fires).
* When the claim transaction has reached
  ``ANONYMIZE_CLAIM_MIN_CONFIRMATIONS`` (so ``CONFIRMING → COMPLETED``
  fires), or when a reorg gives up after
  ``ANONYMIZE_CLAIM_REORG_GIVEUP_BLOCKS`` blocks of churn
  (``CONFIRMING → COMPLETED_WITH_REORG_UNCERTAINTY``).

This module ships the *observer* — a pure read against the live
``BoltzSwap`` row + the chain backend's confirmation count. The
hop-execution body that *issues* the reverse swap + Musig2 claim
lives alongside; that body persists the ``claim_tx_hex`` and bumps
``claim_broadcast_at_ts``, which this observer reads.

The observer is wallclock + DB-state driven; no Boltz HTTP poll is
needed because the swap row reflects the latest known state once
the hop-execution body's poll loop updates it.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from ..tick import TickObservations


async def observe_reverse_exit(
    db: AsyncSession,
    session: AnonymizeSession,
) -> TickObservations:
    """Build a ``TickObservations`` for an EXITING / CONFIRMING session.

    Returns empty observations for any other status; combined with
    the source-specific observer (LN-self-pay, ext-lightning) the
    full state-machine path is covered.
    """
    status = session.status
    if status == AnonymizeStatus.EXITING.value:
        return TickObservations(
            claim_tx_observed_on_chain=_claim_tx_observed(session),
        )
    if status == AnonymizeStatus.CONFIRMING.value:
        confs, reorg_uncertain = await _read_chain_confirmations(db, session)
        min_confs = int(settings.anonymize_claim_min_confirmations)
        return TickObservations(
            claim_tx_min_confirmations_reached=confs >= min_confs,
            claim_tx_reorg_uncertainty=reorg_uncertain,
        )
    return TickObservations()


def _claim_tx_observed(session: AnonymizeSession) -> bool:
    """True iff the claim-tx has been broadcast (crash-
    consistency: ``claim_broadcast_at_ts`` is persisted *before*
    the broadcast goes out, so the observer treats its presence as
    "issued, awaiting confirmation")."""
    ts = getattr(session, "claim_broadcast_at_ts", None)
    return ts is not None


async def _read_chain_confirmations(
    db: AsyncSession,
    session: AnonymizeSession,
) -> tuple[int, bool]:
    """Return (confs, reorg_uncertainty).

    The implementation reads ``claim_tx_confirmations`` from the
    session row, populated by the hop-execution body's chain-poll
    loop. ``reorg_uncertainty`` is True iff the session row's
    ``claim_tx_reorg_observed_count`` exceeds
    ``ANONYMIZE_CLAIM_REORG_GIVEUP_BLOCKS``.

    Returning ``(0, False)`` when neither column is populated keeps
    the observer waiting; the hop-execution body fills them in as
    confirmations roll in.
    """
    confs = int(getattr(session, "claim_tx_confirmations", 0) or 0)
    reorgs = int(getattr(session, "claim_tx_reorg_observed_count", 0) or 0)
    give_up = int(settings.anonymize_claim_reorg_giveup_blocks)
    reorg_uncertain = reorgs >= give_up
    return confs, reorg_uncertain


__all__ = [
    "observe_reverse_exit",
]
