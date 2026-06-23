# SPDX-License-Identifier: MIT
"""BOLT 12 exit-hop body — LN→LN exit for BIP-353 destinations.

Used by sessions whose pipeline exit is ``kind == "bolt12_pay"`` — the
publisher of a BIP-353 handle published only a BOLT 12 offer (no
on-chain fallback). The session terminates with a Lightning payment
to the resolved offer rather than a Boltz reverse-swap exit.

The hop body wraps the existing :mod:`app.api.bolt12` pay-offer
machinery with the anonymize-stack hardenings:

1. Hop-idempotency events bracket the external invreq + settlement
   call (— ``hop_attempt_started`` / ``hop_attempt_completed``)
   so a crash mid-call resumes cleanly on restart.
2. ``payment_hash_hex`` is persisted into ``pipeline_json`` BEFORE the
   settlement so a crash mid-settlement lets the reconciliation
   sweep (existing :func:`reconcile_outbound`) catch up.
3. Outcomes (``paid`` / ``failed`` / ``in_flight``) are reflected
   into the session row's status + per-pipeline_json markers so the
   dispatcher knows whether to drive forward, idle, or hand off to
   reconciliation.

The body is dispatched per-tick by :func:`execute_bolt12_pay_hop_step`;
the per-session loop runs it when the session status is EXITING and
the pipeline exit is ``bolt12_pay``. Like the reverse hop body, each
phase is idempotent so a re-tick after a crash resumes without
double-paying.

Production wires the single adapter in :class:`Bolt12PayHopDeps` to
:func:`app.api.bolt12._perform_pay_offer` via a thin shim. Tests
inject mocks so the hop body can be exercised without a live LND or
BOLT 12 orchestrator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from ..hop_idempotency import (
    HopAttemptKey,
    has_hop_attempt_completed,
    make_hop_idempotency_key,
    record_hop_attempt_completed,
    record_hop_attempt_started,
)
from ..metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


@dataclass
class Bolt12PayHopDeps:
    """Adapter the hop body calls into.

    The single adapter pays a BOLT 12 offer and returns a
    ``(result, error)`` tuple. Production wires this to the existing
    :func:`app.api.bolt12._perform_pay_offer` flow (sans the FastAPI
    HTTPException shell); tests inject a mock.

    The result dict must carry:
    * ``status`` — one of ``"paid"``, ``"failed"``, ``"in_flight"``
    * ``payment_hash_hex`` — the inbound invoice's payment hash (used
      for reconciliation if the settlement is in-flight at restart)
    * ``preimage_hex`` — only when ``status == "paid"``
    * ``error`` — only when ``status == "failed"``
    """

    pay_bolt12_offer: Callable[..., Awaitable[tuple[Any, Any]]]


@dataclass(frozen=True)
class HopStepOutcome:
    """Result of one BOLT 12-pay-hop step."""

    kind: str  # 'noop' | 'paid' | 'failed' | 'in_flight' | 'error'
    detail: str = ""


_NOOP = HopStepOutcome(kind="noop")


def _key_for(
    session: AnonymizeSession,
    hop_kind: str,
    attempt: int,
) -> HopAttemptKey:
    """Build a :class:`HopAttemptKey` for a session + hop kind.

    Mirrors the keying used by the reverse hop body — a stable nonce
    derived from ``(session_id, hop_kind, attempt)`` so the
    idempotency key round-trips across crashes.
    """
    import hashlib

    stable_nonce = hashlib.blake2b(
        b"%s|%s|%d"
        % (
            session.id.bytes if hasattr(session.id, "bytes") else str(session.id).encode("utf-8"),
            hop_kind.encode("utf-8"),
            attempt,
        ),
        digest_size=16,
    ).digest()
    sid_bytes = (
        session.id.bytes
        if hasattr(session.id, "bytes")
        else hashlib.blake2b(
            str(session.id).encode("utf-8"),
            digest_size=16,
        ).digest()
    )
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


async def execute_bolt12_pay_hop_step(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: Bolt12PayHopDeps,
) -> HopStepOutcome:
    """One per-session tick of the BOLT 12-pay-hop body.

    Dispatches on the session's current status. EXITING drives the
    pay; COMPLETED / any terminal status is a no-op (the per-session
    loop should not have invoked us in the first place, but be
    defensive against a tight-race re-tick after the terminal write).
    """
    if session.status == AnonymizeStatus.EXITING.value:
        return await _step_exiting(db, session, deps)
    return _NOOP


async def _step_exiting(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: Bolt12PayHopDeps,
) -> HopStepOutcome:
    """Drive an EXITING bolt12_pay session through pay → terminal state.

    State machine:
    * Read the bound offer + amount from ``pipeline_json``.
    * If already paid (``bolt12_pay_outcome.status == "paid"``), no-op.
    * Otherwise call the adapter; record the outcome + transition.
    """
    pj = session.pipeline_json or {}
    exit_block = pj.get("exit") or {}
    offer = (exit_block.get("bolt12_offer") or "").strip()
    if not offer:
        # Defensive — the pipeline validator should have refused this
        # at quote time, but a corrupt row mustn't drive a no-op tick
        # forever. Mark the session for reconciliation by surfacing
        # the error; the per-session loop's failure handler routes it
        # to ``awaiting_reconciliation``.
        return HopStepOutcome(
            kind="error",
            detail="bolt12_pay_exit_missing_offer",
        )

    existing = pj.get("bolt12_pay_outcome") or {}
    if existing.get("status") == "paid":
        return _NOOP
    if existing.get("status") == "in_flight":
        # An earlier tick kicked off the payment but the adapter
        # returned ``in_flight``. The reconciliation sweep is
        # responsible for closing this out — we don't re-issue the
        # invreq because that would mint a second invoice with a
        # different payment_hash and risk double-paying. Idle.
        return HopStepOutcome(kind="in_flight", detail="awaiting_reconciliation")

    bin_amount = int(session.bin_amount_sat or 0)
    if bin_amount <= 0:
        return HopStepOutcome(
            kind="error",
            detail="bolt12_pay_exit_missing_bin_amount",
        )

    key = _key_for(session, "bolt12_pay", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=key.idempotency_key,
    ):
        # The persisted hop_attempt_completed row says we already
        # ran. Trust the marker over the in-memory pipeline_json
        # (e.g., a worker that crashed AFTER recording the event
        # but BEFORE flushing pipeline_json). Mark terminal and
        # idle.
        return HopStepOutcome(
            kind="noop",
            detail="bolt12_pay_already_completed",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={
            "step": "bolt12_pay",
            "amount_sat": bin_amount,
        },
    )
    await db.flush()

    result, error = await deps.pay_bolt12_offer(
        offer=offer,
        amount_msat=bin_amount * 1000,
        session=session,
    )
    if error is not None or result is None:
        logger.warning(
            "anonymize bolt12_pay hop %s: settlement failed: %s",
            session.id,
            error,
        )
        # Persist the failure into pipeline_json so a follow-up tick
        # doesn't re-issue blindly + the reconciliation sweep can
        # see the recorded failure.
        new_pj = dict(pj)
        new_pj["bolt12_pay_outcome"] = {
            "status": "failed",
            "error": str(error),
            "recorded_at_unix_s": int(datetime.now(timezone.utc).timestamp()),
        }
        session.pipeline_json = new_pj
        await record_hop_attempt_completed(
            db,
            key=key,
            detail={"status": "failed", "error": str(error)},
        )
        # Transition to FAILED — the per-session loop routes a
        # FAILED row to reconciliation (no on-chain claim to wait on
        # for a BOLT 12-only exit).
        session.status = AnonymizeStatus.FAILED.value
        return HopStepOutcome(kind="failed", detail=str(error))

    status = str(result.get("status") or "").lower()
    payment_hash_hex = str(result.get("payment_hash_hex") or "")
    preimage_hex = result.get("preimage_hex")

    new_pj = dict(pj)
    new_pj["bolt12_pay_outcome"] = {
        "status": status,
        "payment_hash_hex": payment_hash_hex,
        "preimage_hex": preimage_hex,
        "recorded_at_unix_s": int(datetime.now(timezone.utc).timestamp()),
    }
    session.pipeline_json = new_pj

    if status == "paid":
        await record_hop_attempt_completed(
            db,
            key=key,
            detail={
                "status": "paid",
                "payment_hash_hex": payment_hash_hex,
            },
        )
        # BOLT 12 exit settles on LN — no on-chain confirmation step.
        # Skip CONFIRMING entirely and transition COMPLETED.
        session.status = AnonymizeStatus.COMPLETED.value
        if not session.completed_at:
            session.completed_at = datetime.now(timezone.utc)
        return HopStepOutcome(kind="paid", detail=payment_hash_hex)

    if status == "in_flight":
        # Keep the hop_attempt_started row open — the reconciliation
        # sweep will record the completion once LND's lookup_payment
        # resolves the in-flight HTLC.
        return HopStepOutcome(kind="in_flight", detail=payment_hash_hex)

    # status == "failed" (or any non-terminal we don't recognise).
    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"status": status, "payment_hash_hex": payment_hash_hex},
    )
    session.status = AnonymizeStatus.FAILED.value
    return HopStepOutcome(
        kind="failed",
        detail=str(result.get("error") or status),
    )


__all__ = [
    "Bolt12PayHopDeps",
    "HopStepOutcome",
    "execute_bolt12_pay_hop_step",
]
