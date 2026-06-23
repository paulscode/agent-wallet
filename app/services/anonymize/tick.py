# SPDX-License-Identifier: MIT
"""Per-session orchestrator tick dispatcher.

The orchestrator's per-session task runs a small loop:

    while not is_session_terminal(session):
        obs = await collect_observations(session)
        action = decide_tick_action(session, obs)
        await apply_tick_action(service, db, session, action)
        await asyncio.sleep(jittered_poll_interval())

This module ships the *pure* :func:`decide_tick_action` so the
state-machine + hop dispatch can be exercised by unit tests with no
DB / Boltz / LND dependencies. The actual ``collect_observations``
+ ``apply_tick_action`` are thin wrappers around
:class:`AnonymizeService.transition_session` and per-hop external
calls; they live alongside the hop modules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSourceKind,
    AnonymizeStatus,
)

from .state_machine import (
    is_legal_transition,
    is_terminal,
    legal_next_statuses,
)

TickKind = Literal[
    "noop_terminal",  # Session terminal — task should exit.
    "wait",  # Nothing to do this tick.
    "transition",  # Apply :attr:`TickAction.to_status`.
    "reconcile",  # Route to awaiting_reconciliation.
    "fail",  # Terminal failure.
]


@dataclass(frozen=True)
class TickAction:
    """One per-session tick's decided action.

    ``kind`` chooses one of the documented branches. For ``transition``
    and ``reconcile`` / ``fail``, the orchestrator passes ``to_status``
    + ``reason`` to :meth:`AnonymizeService.transition_session`.
    """

    kind: TickKind
    to_status: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class TickObservations:
    """External-world snapshot the dispatcher needs.

    All inputs are optional so each hop only populates what it knows.
    The dispatcher refuses to advance when a required observation is
    absent — it returns ``wait`` rather than guessing.
    """

    # ── hop-execution outcomes ──
    funding_invoice_settled: bool | None = None  # LN_HOLDING from FUNDING
    delay_window_elapsed: bool | None = None  # next hop or exit
    hop_completed: bool | None = None  # advance past HOPPING
    is_last_hop: bool | None = None  # → EXITING vs DELAYING
    claim_tx_observed_on_chain: bool | None = None  # exit-tx visible
    claim_tx_min_confirmations_reached: bool | None = None  # CONFIRMING → COMPLETED
    claim_tx_reorg_uncertainty: bool | None = None  # → COMPLETED_WITH_REORG_UNCERTAINTY

    # ── escape hatches ──
    fatal_error_kind: str | None = None  # → FAILED with reason
    reconcile_reason: str | None = None  # → AWAITING_RECONCILIATION
    user_cancel_requested: bool | None = None  # → CANCELLED
    user_refund_requested: bool | None = None  # → REFUNDING


def decide_tick_action(
    session: AnonymizeSession,
    obs: TickObservations,
) -> TickAction:
    """Pure decision: given a session row + observations, what's next?

    Order of checks:
    1. Terminal — exit immediately, no further work.
    2. Fatal error from a hop — go FAILED.
    3. Reconcile signal — go AWAITING_RECONCILIATION.
    4. User-initiated cancel — go CANCELLED (state-machine permitting).
    5. User-initiated refund — go REFUNDING (state-machine permitting).
    6. Per-status forward progress decision.
    7. Otherwise wait.
    """
    status = session.status

    if is_terminal(status):
        return TickAction(kind="noop_terminal")

    if obs.fatal_error_kind:
        return TickAction(
            kind="fail" if _can_fail(status) else "reconcile",
            to_status=AnonymizeStatus.FAILED.value
            if _can_fail(status)
            else AnonymizeStatus.AWAITING_RECONCILIATION.value,
            reason=f"hop_failure:{obs.fatal_error_kind}",
        )

    if obs.reconcile_reason and _can_reconcile(status):
        return TickAction(
            kind="reconcile",
            to_status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
            reason=f"reconcile:{obs.reconcile_reason}",
        )

    if obs.user_cancel_requested and _can_cancel(status):
        return TickAction(
            kind="transition",
            to_status=AnonymizeStatus.CANCELLED.value,
            reason="user_cancel",
        )

    if obs.user_refund_requested and _can_refund(status):
        return TickAction(
            kind="transition",
            to_status=AnonymizeStatus.REFUNDING.value,
            reason="user_refund_request",
        )

    # Forward-progress dispatch keyed on current status.
    return _forward_dispatch(status, obs, session.source_kind)


def _forward_dispatch(status: str, obs: TickObservations, source_kind: str) -> TickAction:
    """Per-status forward-progress decision."""
    if status == AnonymizeStatus.CREATED.value:
        # The create-endpoint path persists every session in CREATED and
        # schedules the per-session task to advance from here.
        #
        # Invoice-funded sources (ln-self-pay pays its own hold invoice;
        # ext-lightning waits for the depositor to pay) advance to
        # FUNDING the moment that invoice settles — they never use
        # SOURCING.
        if obs.funding_invoice_settled is True:
            return TickAction(
                kind="transition",
                to_status=AnonymizeStatus.FUNDING.value,
                reason="initial_dispatch",
            )
        # On-chain sources have no inbound invoice to settle at CREATED.
        # They advance to SOURCING, where the submarine hop issues the
        # swap and broadcasts the wallet's on-chain funding. Without this
        # they would wait at CREATED forever (the on-chain observer emits
        # nothing before SOURCING).
        if source_kind in (
            AnonymizeSourceKind.ONCHAIN_SELF.value,
            AnonymizeSourceKind.EXT_ONCHAIN.value,
        ):
            return TickAction(
                kind="transition",
                to_status=AnonymizeStatus.SOURCING.value,
                reason="onchain_initial_dispatch",
            )
        return TickAction(kind="wait")

    if status == AnonymizeStatus.FUNDING.value:
        if obs.funding_invoice_settled is True:
            return TickAction(
                kind="transition",
                to_status=AnonymizeStatus.LN_HOLDING.value,
                reason="funding_invoice_settled",
            )
        return TickAction(kind="wait")

    if status == AnonymizeStatus.LN_HOLDING.value:
        return TickAction(
            kind="transition",
            to_status=AnonymizeStatus.DELAYING.value,
            reason="ln_holding_to_delaying",
        )

    if status == AnonymizeStatus.DELAYING.value:
        if obs.delay_window_elapsed is True:
            target = AnonymizeStatus.EXITING.value if obs.is_last_hop is True else AnonymizeStatus.HOPPING.value
            return TickAction(
                kind="transition",
                to_status=target,
                reason="delay_window_elapsed",
            )
        return TickAction(kind="wait")

    if status == AnonymizeStatus.HOPPING.value:
        if obs.hop_completed is True:
            target = AnonymizeStatus.EXITING.value if obs.is_last_hop is True else AnonymizeStatus.DELAYING.value
            return TickAction(
                kind="transition",
                to_status=target,
                reason="hop_completed",
            )
        return TickAction(kind="wait")

    if status == AnonymizeStatus.EXITING.value:
        if obs.claim_tx_observed_on_chain is True:
            return TickAction(
                kind="transition",
                to_status=AnonymizeStatus.CONFIRMING.value,
                reason="claim_tx_observed",
            )
        return TickAction(kind="wait")

    if status == AnonymizeStatus.CONFIRMING.value:
        if obs.claim_tx_reorg_uncertainty is True:
            return TickAction(
                kind="transition",
                to_status=AnonymizeStatus.COMPLETED_WITH_REORG_UNCERTAINTY.value,
                reason="reorg_uncertainty",
            )
        if obs.claim_tx_min_confirmations_reached is True:
            return TickAction(
                kind="transition",
                to_status=AnonymizeStatus.COMPLETED.value,
                reason="min_confirmations_reached",
            )
        return TickAction(kind="wait")

    # AWAITING_RECONCILIATION / AWAITING_CHANNEL_CLOSE / SOURCING /
    # REFUNDING — these have hop-specific recovery flows the hop
    # modules implement directly. The dispatcher's default is wait.
    return TickAction(kind="wait")


# ─── Predicates used in the early-exit branches ──────────────────────


def _can_fail(status: str) -> bool:
    return is_legal_transition(
        from_status=status,
        to_status=AnonymizeStatus.FAILED.value,
    )


def _can_reconcile(status: str) -> bool:
    return is_legal_transition(
        from_status=status,
        to_status=AnonymizeStatus.AWAITING_RECONCILIATION.value,
    )


def _can_cancel(status: str) -> bool:
    return is_legal_transition(
        from_status=status,
        to_status=AnonymizeStatus.CANCELLED.value,
    )


def _can_refund(status: str) -> bool:
    return is_legal_transition(
        from_status=status,
        to_status=AnonymizeStatus.REFUNDING.value,
    )


def filter_to_legal_target(*, from_status: str, candidate: str) -> str | None:
    """If ``candidate`` isn't a legal successor of ``from_status``,
    return ``None`` so the caller can ``reconcile`` instead.

    The forward dispatcher trusts the orchestrator to call it with
    a consistent session row; this guard catches the case where a
    race re-wrote the status between observation and decision.
    """
    if candidate in legal_next_statuses(from_status):
        return candidate
    return None


__all__ = [
    "TickAction",
    "TickKind",
    "TickObservations",
    "decide_tick_action",
    "filter_to_legal_target",
]
