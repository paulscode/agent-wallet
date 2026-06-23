# SPDX-License-Identifier: MIT
"""Submarine hop body — on-chain BTC → LN.

Drives the wallet through the Boltz submarine-swap protocol:

1. **Issue** (``SOURCING`` → ``FUNDING``): wallet generates a fresh
   BOLT11 invoice via LND, then POSTs ``/swap/submarine`` to Boltz
   through the anonymize HTTP wrapper. The response carries the
   on-chain lockup address the wallet now funds.
2. **Funding** (``FUNDING`` → ``LN_HOLDING``): the orchestrator
   broadcasts an on-chain tx paying the lockup address from the
   wallet's coin selector (the coin_control flow).
   The submarine hop body persists ``funding_tx_hex`` +
   ``funding_broadcast_at_ts`` BEFORE broadcast (crash
   consistency).
3. **Settlement** (``LN_HOLDING`` → next hop): once Boltz observes
   the lockup tx confirmed, it pays the wallet's invoice over LN.
   Settlement is observed via the status poll.
4. **Refund path** (only when the server stalls past
   ``timeout_block_height``): the wallet broadcasts a refund tx
   spending the lockup output back to its own change address using
   the persisted refund private key.

Submarine and reverse legs go through *distinct* Boltz
operators (``BOLTZ_SUBMARINE_API_URL`` / ``BOLTZ_REVERSE_API_URL``).
Mandatory inter-leg delay 6–48 h between submarine
completion and reverse-swap creation.

The hop is idempotent: every external side-effect is bracketed by
:func:`hop_idempotency.record_hop_attempt_started` /
``record_hop_attempt_completed`` events so a crash mid-step lets
the next tick read persisted state and resume without re-issuing.
Production wires the adapters in :class:`SubmarineHopDeps` to live
``AnonymizeBoltzClient`` / ``LNDService`` / chain-client / coin
selector. Tests inject mocks so the hop body can be exercised
without a live Boltz / LND / chain backend.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import (
    AnonymizeSession,
    AnonymizeSessionEvent,
    AnonymizeStatus,
)

from ..hop_idempotency import (
    HopAttemptKey,
    dispatch_hop_attempt,
    has_hop_attempt_completed,
    make_hop_idempotency_key,
    record_hop_attempt_completed,
    record_hop_attempt_started,
)
from ..metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


@dataclass
class SubmarineHopDeps:
    """Adapters the submarine hop body calls into.

    Tests inject mocks; production binds them to live
    ``AnonymizeBoltzClient`` / ``LNDService`` / chain-client /
    coin-selector / refund subprocess. Each adapter returns
    ``(result, error)`` so the hop body records outcomes without
    raising up into the per-session loop's bounded-retry budget.
    """

    boltz_create_submarine_swap: Callable[..., Awaitable[tuple[Any, Any]]]
    boltz_get_swap_status: Callable[..., Awaitable[tuple[Any, Any, Any]]]
    lnd_add_invoice: Callable[..., Awaitable[tuple[Any, Any]]]
    build_and_broadcast_funding_tx: Callable[..., Awaitable[tuple[Any, Any]]]
    run_refund_subprocess: Callable[..., Awaitable[tuple[Any, Any]]]
    chain_broadcast_tx: Callable[[str], Awaitable[tuple[Any, Any]]]
    # Optional pre-lockup inbound re-check. Given the bin amount the
    # node must RECEIVE over LN from the provider, returns a refusal
    # string when our inbound capacity can't cover it, else None.
    # Best-effort: returns None on any error so a transient fault never
    # blocks. Default None → re-check skipped (back-compat for existing
    # deps constructions / tests that don't exercise it). Production
    # wires it to ``inbound_preflight``.
    check_inbound_sufficient: Optional[Callable[[int], Awaitable[Optional[str]]]] = None


@dataclass(frozen=True)
class SubmarineHopOutcome:
    """Result of one submarine-hop step."""

    kind: str  # 'noop' | 'issued_swap' | 'funded' | 'observed_settlement'
    # | 'refund_broadcast' | 'error'
    detail: str = ""


_NOOP = SubmarineHopOutcome(kind="noop")


def _key_for(
    session: AnonymizeSession,
    hop_kind: str,
    attempt: int,
) -> HopAttemptKey:
    """Build a :class:`HopAttemptKey` for a submarine hop step."""
    import hashlib

    sid_bytes = (
        session.id.bytes
        if hasattr(session.id, "bytes")
        else hashlib.blake2b(
            str(session.id).encode("utf-8"),
            digest_size=16,
        ).digest()
    )
    stable_nonce = hashlib.blake2b(
        b"%s|%s|%d" % (sid_bytes, hop_kind.encode("utf-8"), attempt),
        digest_size=16,
    ).digest()
    key_str = make_hop_idempotency_key(
        key_bytes=b"\x00" * 32,
        nonce=stable_nonce,
        session_id=sid_bytes,
        hop_index=0,
        hop_kind=hop_kind,
        attempt=attempt,
    )
    return HopAttemptKey(
        session_id=session.id,
        hop_index=0,
        hop_kind=hop_kind,
        attempt=attempt,
        idempotency_key=key_str,
        nonce=stable_nonce,
        key_generation=0,
    )


async def execute_submarine_hop_step(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: SubmarineHopDeps,
) -> SubmarineHopOutcome:
    """One per-session tick of the submarine-hop body.

    Dispatches on the session's current status. Each step is
    idempotent: a crash mid-step lets the next tick read persisted
    state and resume without re-issuing side effects.
    """
    if session.status == AnonymizeStatus.SOURCING.value:
        return await _step_issue_swap(db, session, deps)
    if session.status == AnonymizeStatus.FUNDING.value:
        return await _step_fund_lockup(db, session, deps)
    if session.status == AnonymizeStatus.LN_HOLDING.value:
        return await _step_observe_settlement(db, session, deps)
    return _NOOP


def _has_issued_swap(session: AnonymizeSession) -> bool:
    pj = session.pipeline_json or {}
    if not isinstance(pj, dict):
        return False
    return bool(pj.get("submarine_swap_id"))


async def _step_issue_swap(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: SubmarineHopDeps,
) -> SubmarineHopOutcome:
    """Mint an LN invoice + POST /swap/submarine.

    Bracket the side-effect with ``hop_attempt_started`` /
    ``hop_attempt_completed`` so a crash mid-call doesn't issue
    a duplicate swap.
    """
    if _has_issued_swap(session):
        return SubmarineHopOutcome(
            kind="noop",
            detail="submarine_swap_already_issued",
        )

    key = _key_for(session, "submarine_create", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=key.idempotency_key,
    ):
        return SubmarineHopOutcome(
            kind="noop",
            detail="submarine_create_already_completed",
        )

    bin_amount = int(session.bin_amount_sat or 0)
    if bin_amount <= 0:
        return SubmarineHopOutcome(
            kind="error",
            detail="bin_amount_sat must be positive",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "submarine_add_invoice"},
    )
    await db.flush()

    invoice_data, err = await deps.lnd_add_invoice(
        amount_sat=bin_amount,
        memo="anonymize submarine swap",
    )
    if err is not None or invoice_data is None:
        return SubmarineHopOutcome(
            kind="error",
            detail=f"add_invoice_failed:{err}",
        )
    invoice = (
        invoice_data.get("payment_request")
        if isinstance(invoice_data, dict)
        else getattr(invoice_data, "payment_request", "")
    ) or ""
    if not invoice:
        return SubmarineHopOutcome(
            kind="error",
            detail="add_invoice_returned_no_payment_request",
        )

    swap, err = await deps.boltz_create_submarine_swap(
        db=db,
        invoice=invoice,
        session=session,
    )
    if err is not None or swap is None:
        return SubmarineHopOutcome(
            kind="error",
            detail=f"submarine_create_failed:{err}",
        )

    pj = dict(session.pipeline_json or {})
    pj["submarine_swap_id"] = str(getattr(swap, "boltz_swap_id", swap))
    pj["submarine_lockup_address"] = str(getattr(swap, "boltz_lockup_address", "") or "")
    pj["submarine_timeout_block_height"] = int(getattr(swap, "timeout_block_height", 0) or 0)
    pj["submarine_invoice"] = invoice
    session.pipeline_json = pj

    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"swap_id": pj["submarine_swap_id"]},
    )
    return SubmarineHopOutcome(
        kind="issued_swap",
        detail=pj["submarine_swap_id"],
    )


async def _step_fund_lockup(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: SubmarineHopDeps,
) -> SubmarineHopOutcome:
    """Build + broadcast the wallet's funding tx to the lockup address.

    Persists ``submarine_funding_tx_hex`` + ``...broadcast_at_ts``
    BEFORE broadcast (crash consistency).
    """
    pj = session.pipeline_json or {}
    if not isinstance(pj, dict):
        return SubmarineHopOutcome(
            kind="error",
            detail="malformed_pipeline_json",
        )
    lockup_address = pj.get("submarine_lockup_address")
    if not lockup_address:
        return SubmarineHopOutcome(
            kind="error",
            detail="missing_lockup_address",
        )

    if pj.get("submarine_funding_tx_hex"):
        return _NOOP

    key = _key_for(session, "submarine_fund_lockup", attempt=1)
    # The funding tx spends the wallet's own UTXOs, and a rebuild on
    # recovery selects coins afresh — so a second build+broadcast is a
    # genuine double-spend, not an idempotent retry (unlike an LN pay,
    # which LND dedups by payment hash). The decision is taken from the
    # *durably committed* attempt trail:
    #   * completed        → funding already done; no-op.
    #   * started-only     → the process died in the broadcast window;
    #                        re-issuing would double-fund. Route to
    #                        reconciliation so the on-chain outcome is
    #                        verified before any further action.
    #   * neither          → first attempt; commit the started marker,
    #                        then broadcast.
    decision = await dispatch_hop_attempt(db, idempotency_key=key.idempotency_key)
    if decision == "completed_idempotent_no_op":
        return SubmarineHopOutcome(
            kind="noop",
            detail="lockup_funding_already_completed",
        )
    if decision == "verify_remote_state":
        from app.services.anonymize.service import get_anonymize_service

        await get_anonymize_service().transition_to_awaiting_reconciliation(
            db,
            session,
            reason="submarine_funding_in_doubt",
        )
        return SubmarineHopOutcome(
            kind="error",
            detail="submarine_funding_in_doubt",
        )

    # Inbound pre-lockup re-check (mirrors the Braiins on-chain deposit
    # pre-send re-check + the reverse hop's mpp_k_floor reconciliation
    # routing). The submarine settlement needs THIS node to RECEIVE the
    # bin amount over Lightning from the provider. Inbound that was
    # sufficient at session creation can drop before the lockup (most
    # relevant for ext-onchain, which dwells waiting for the deposit).
    # Re-check BEFORE broadcasting the on-chain funding tx: if our node
    # can no longer receive it, route to AWAITING_RECONCILIATION instead
    # of locking funds and then waiting ~the swap timeout for a refund —
    # no funds move. Best-effort: ``check_inbound_sufficient`` returns
    # None on any LND error (never blocks) and the whole step is skipped
    # when the dep is unwired or the feature flag is off.
    if deps.check_inbound_sufficient is not None:
        receive_sats = int(session.bin_amount_sat or 0)
        refusal = await deps.check_inbound_sufficient(receive_sats)
        if refusal:
            db.add(
                AnonymizeSessionEvent(
                    session_id=session.id,
                    ts=datetime.now(timezone.utc),
                    kind="inbound_insufficient_at_lockup",
                    detail_json={"receive_sats": receive_sats},
                )
            )
            # Route via the shared helper so all four reconciliation
            # columns are populated atomically (same write-site contract
            # as the reverse hop's mpp_k_floor_exhausted path). No funds
            # have moved — the broadcast below never runs.
            from app.services.anonymize.service import get_anonymize_service

            await get_anonymize_service().transition_to_awaiting_reconciliation(
                db,
                session,
                reason="inbound_insufficient_at_lockup",
            )
            return SubmarineHopOutcome(
                kind="error",
                detail="inbound_insufficient_at_lockup",
            )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "fund_lockup"},
    )
    # Commit the started marker durably BEFORE the broadcast. A crash in
    # the broadcast window then leaves a started-without-completed trail
    # that the ``verify_remote_state`` branch above detects on recovery,
    # rather than a clean slate that would re-fund. (The tick's row lock
    # is released by this commit; the reconciliation probe ignores
    # non-wedged active sessions, so it does not race the remainder of
    # the tick.)
    await db.commit()

    expected_amount = int(session.bin_amount_sat or 0)
    funding_result, err = await deps.build_and_broadcast_funding_tx(
        lockup_address=lockup_address,
        amount_sat=expected_amount,
        session=session,
    )
    if err is not None or funding_result is None:
        return SubmarineHopOutcome(
            kind="error",
            detail=f"funding_failed:{err}",
        )

    tx_hex = funding_result.get("tx_hex") if isinstance(funding_result, dict) else str(funding_result)
    txid = funding_result.get("txid") if isinstance(funding_result, dict) else None

    pj = dict(session.pipeline_json or {})
    pj["submarine_funding_tx_hex"] = tx_hex
    pj["submarine_funding_txid"] = txid
    pj["submarine_funding_broadcast_at_ts"] = datetime.now(timezone.utc).isoformat()
    session.pipeline_json = pj

    # Mirror the lockup txid onto the BoltzSwap row so the manual
    # fee-bump endpoint can identify the outpoint to RBF. The
    # auto-stamp listener on BoltzSwap.lockup_txid populates
    # lockup_broadcast_at as a side effect.
    if txid:
        try:
            from sqlalchemy import select as _select

            from app.models.boltz_swap import BoltzSwap as _BoltzSwap

            swap_id = pj.get("submarine_swap_id")
            if swap_id:
                row = await db.execute(_select(_BoltzSwap).where(_BoltzSwap.boltz_swap_id == str(swap_id)))
                swap_row = row.scalar_one_or_none()
                if swap_row is not None and not swap_row.lockup_txid:
                    swap_row.lockup_txid = txid
        except Exception:  # noqa: BLE001
            # Mirror is best-effort; pipeline_json remains the
            # source of truth for the hop body.
            logger.debug(
                "Failed to mirror submarine lockup txid onto BoltzSwap row",
                exc_info=True,
            )

    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"funding_txid": txid or ""},
    )
    return SubmarineHopOutcome(kind="funded", detail=txid or "")


async def _step_observe_settlement(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: SubmarineHopDeps,
) -> SubmarineHopOutcome:
    """Poll Boltz for settlement status.

    Once the swap status reaches ``transaction.claimed`` (Boltz has
    paid the wallet's invoice), the per-session loop transitions
    the session into the next hop. If the swap timed out without
    settlement, the refund path fires via :func:`_step_refund`.
    """
    pj = session.pipeline_json or {}
    swap_id = pj.get("submarine_swap_id")
    if not swap_id:
        return SubmarineHopOutcome(
            kind="error",
            detail="missing_submarine_swap_id",
        )

    # Pass the bound
    # submarine operator_id so the status poll hits the SAME
    # operator the swap was created with. Otherwise the poll
    # defaults to ``BOLTZ_SUBMARINE_ONION_URL`` / ``BOLTZ_ONION_URL``
    # which may not be where the swap actually lives.
    op_id = getattr(session, "submarine_operator_id", None) or pj.get(
        "submarine_operator_id",
    )
    status, _data, err = await deps.boltz_get_swap_status(
        swap_id,
        operator_id=op_id,
    )
    if err is not None:
        return SubmarineHopOutcome(kind="error", detail=f"poll_status:{err}")

    # Persist the latest server status so the on-chain observation
    # collector can drive the dispatcher's LN_HOLDING/HOPPING
    # transitions on the next tick.
    pj_writable = dict(session.pipeline_json or {})
    pj_writable["submarine_swap_status"] = str(status or "")
    session.pipeline_json = pj_writable
    await db.flush()

    if status in {"transaction.claimed", "invoice.settled"}:
        return SubmarineHopOutcome(
            kind="observed_settlement",
            detail=str(status),
        )
    if status in {"swap.expired", "invoice.failedToPay"}:
        return await _step_refund(db, session, deps)
    return SubmarineHopOutcome(
        kind="noop",
        detail=f"awaiting_settlement:{status}",
    )


async def _step_refund(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: SubmarineHopDeps,
) -> SubmarineHopOutcome:
    """refund path — spend the lockup back to the wallet.

    Bracketed with hop_attempt_started/completed so a crash mid-
    refund doesn't double-broadcast.
    """
    key = _key_for(session, "submarine_refund", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=key.idempotency_key,
    ):
        return SubmarineHopOutcome(
            kind="noop",
            detail="submarine_refund_already_completed",
        )

    pj = session.pipeline_json or {}
    swap_id = pj.get("submarine_swap_id")
    if not swap_id:
        return SubmarineHopOutcome(
            kind="error",
            detail="missing_submarine_swap_id",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "submarine_refund"},
    )
    await db.flush()

    refund_tx_hex, err = await deps.run_refund_subprocess(
        swap_id=swap_id,
        session=session,
    )
    if err is not None or not refund_tx_hex:
        return SubmarineHopOutcome(
            kind="error",
            detail=f"refund_subprocess:{err or 'no_hex'}",
        )

    broadcast_result, broadcast_err = await deps.chain_broadcast_tx(
        refund_tx_hex,
    )
    if broadcast_err is not None:
        return SubmarineHopOutcome(
            kind="error",
            detail=f"refund_broadcast:{broadcast_err}",
        )

    # Label the refund-tx output as
    # ``auto:anonymize-refund`` so the wallet's coin selector
    # excludes it from non-anonymize flows. The refund tx has a
    # single output sending back to the wallet's change address;
    # outpoint format ``<refund_txid>:0``.
    refund_txid: str | None = None
    if isinstance(broadcast_result, str):
        refund_txid = broadcast_result
    elif isinstance(broadcast_result, dict):
        refund_txid = broadcast_result.get("txid")

    from ..coin_control import (
        apply_refund_lockdown_label,
        refund_lockdown_enabled,
    )

    if refund_txid and refund_lockdown_enabled():
        try:
            await apply_refund_lockdown_label(
                db,
                outpoint=f"{refund_txid}:0",
                reason="timeout",
                spent_txid=None,
            )
            # Emit the ``anonymize_refund_locked`` event.
            from app.models.anonymize_session import (
                AnonymizeSessionEvent,
            )

            db.add(
                AnonymizeSessionEvent(
                    session_id=session.id,
                    ts=datetime.now(timezone.utc),
                    kind="anonymize_refund_locked",
                    detail_json={
                        "outpoint": f"{refund_txid}:0",
                        "reason": "timeout",
                    },
                )
            )
            await db.flush()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "submarine hop %s: refund lockdown label write failed: %s",
                session.id,
                exc,
            )

    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"refund_broadcast": True, "refund_txid": refund_txid or ""},
    )
    return SubmarineHopOutcome(kind="refund_broadcast", detail=str(swap_id))


__all__ = [
    "SubmarineHopOutcome",
    "SubmarineHopDeps",
    "execute_submarine_hop_step",
]
