# SPDX-License-Identifier: MIT
"""Per-source-kind observation collector dispatch.

The per-session task loop calls a single ``observation_fn(db,
session)`` each tick. Different source kinds need different collectors
(LN-self-pay has no external dependencies; ext-lightning needs to
watch the deposit invoice; on-chain sources need chain confirmations).

This module exposes :func:`make_default_observation_fn` which routes
to the correct per-kind collector based on the session's
``source_kind`` column. The orchestrator passes this router as the
``observation_fn`` when spawning per-session tasks via
:meth:`AnonymizeService.spawn_session_task`.
"""

from __future__ import annotations

import dataclasses

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from .hops.ext_lightning_observe import observe_ext_lightning
from .hops.ln_self_pay_observe import observe_ln_self_pay
from .hops.onchain_observe import observe_onchain_source
from .hops.reverse_observe import observe_reverse_exit
from .state_machine import is_terminal
from .tick import TickObservations


def _merge_obs(*obs_list: TickObservations) -> TickObservations:
    """Combine multiple observations — later fields override earlier
    non-None values. Used to layer the source-side and exit-side
    collectors so each owns its piece of the state machine."""
    merged = TickObservations()
    for o in obs_list:
        non_none = {k: v for k, v in o.__dict__.items() if v is not None}
        merged = dataclasses.replace(merged, **non_none)
    return merged


async def default_observation_fn(
    db: AsyncSession,
    session: AnonymizeSession,
) -> TickObservations:
    """Route to the per-source-kind observation collector + the
    reverse-exit observer.

    Every session exits via Boltz reverse so the exit observer
    always layers on top of the source-side observer.
    """
    # Source-side: which observation applies depends on source_kind.
    if session.source_kind == "lightning-self":
        source_obs = await observe_ln_self_pay(db, session)
    elif session.source_kind == "ext-lightning":
        source_obs = await observe_ext_lightning(db, session)
    elif session.source_kind in {"onchain-self", "ext-onchain"}:
        # On-chain sources — drives SOURCING/FUNDING/LN_HOLDING/
        # HOPPING/DELAYING transitions including the inter-leg
        # delay enforcement.
        source_obs = await observe_onchain_source(db, session)
    else:
        source_obs = TickObservations()

    # Exit-side: only meaningful for EXITING / CONFIRMING statuses,
    # but cheap to call always (returns empty obs for everything else).
    exit_obs = TickObservations()
    if session.status in (
        AnonymizeStatus.EXITING.value,
        AnonymizeStatus.CONFIRMING.value,
    ):
        exit_obs = await observe_reverse_exit(db, session)

    obs = _merge_obs(source_obs, exit_obs)

    # Persisted-reason promotion: when a hop body has set
    # ``session.awaiting_reconciliation_reason`` (e.g. reverse-hop
    # K-fallback exhaustion at), surface it as
    # ``reconcile_reason`` so :func:`tick.decide_tick_action` can
    # advance the session from EXITING/CONFIRMING/etc. into
    # AWAITING_RECONCILIATION. Without this hop bodies record the
    # reason but the state never changes — the session wedges.
    reason = (session.awaiting_reconciliation_reason or "").strip()
    already_routed = session.status == AnonymizeStatus.AWAITING_RECONCILIATION.value
    if reason and not obs.reconcile_reason and not already_routed and not is_terminal(session.status):
        obs = dataclasses.replace(obs, reconcile_reason=reason)

    return obs


__all__ = [
    "default_observation_fn",
]
