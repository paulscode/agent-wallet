# SPDX-License-Identifier: MIT
"""Liquid round-trip hop body — LN→L-BTC→LN via Boltz reverse +
submarine swaps.

The hop runs an LN-balance through a Liquid intermediate residency
before re-egressing back to LN-balance. Two Boltz swap legs:

1. **LN→L-BTC** (``HOPPING``): a Boltz **reverse** swap with
   ``to: L-BTC`` that pays an LN invoice and credits a CT-blinded
   Liquid address we own (after a cooperative MuSig2 claim from
   Boltz's blinded lockup).
2. **Liquid dwell** (``AWAITING_LIQUID_DWELL``): wait a randomized
   3–24 h delay; the CT-blinded balance sits on Liquid during this
   window so an observer correlating LN-in and LN-out by time has
   to span the dwell.
3. **L-BTC→LN** (``HOPPING``): a Boltz **submarine** swap with
   ``from: L-BTC`` that pays an LN invoice we own once the wallet
   locks the dwell-resident L-BTC at the address Boltz returns —
   pushing the balance back into LN for the next hop or for direct
   exit.

 note: Liquid blinds amounts to passive observers but the
Liquid federation has full visibility during signing. The runbook
in ``docs/anonymize.md`` documents this; the hop is opt-in via
``ANONYMIZE_LIQUID_ENABLED`` and the score-breakdown copy frames
it as amount-blinding, not endpoint-blinding.

Liquid blinding pubkeys derive from
``ANONYMIZE_LIQUID_SEED_FERNET`` via :mod:`liquid_seed`; never from
the LND wallet seed. The per-session derivation index is recorded in
``anonymize_session.liquid_blinding_seed_enc`` (Fernet-wrapped at-
rest so a DB-snapshot adversary cannot enumerate the index).

Production binds the adapters in :class:`LiquidHopDeps` to the Boltz
reverse + submarine swap HTTP clients (``liquid_swap.LiquidSwapClient``)
and the local Liquid backend; tests inject mocks so the hop body
runs without a live Boltz / Liquid daemon.

This module ships the skeleton: deps, outcome, dispatch by status,
and the dwell-sampling helper. The actual Boltz reverse / submarine
HTTP calls live in ``liquid_swap.py`` alongside the Liquid HTTP
client.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

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
class LiquidHopDeps:
    """Adapters the Liquid-hop body calls into.

    Each returns ``(result, error)`` so the hop body records outcomes
    without raising into the per-session loop's bounded-retry budget.

    ``swap_state`` is the dispatcher's in-process per-swap cache —
    the hop body persists + restores it across restarts via
    :mod:`liquid_swap_state_persistence` so the wallet-generated
    secrets (preimage, claim private key) survive a crash between
    LN-payment broadcast and Liquid-claim broadcast.
    """

    # Process-wide cache of per-swap state, populated by the create
    # adapters and read by the observe / claim / lock adapters.
    swap_state: dict[str, dict[str, Any]]

    # LN→L-BTC: Boltz reverse swap (``to: L-BTC``) that takes an LN
    # invoice and lands the L-BTC at Boltz's blinded lockup address.
    # Returns ``({"swap_id": ..., "lbtc_address": ..., "invoice": ...}, error)``.
    boltz_create_ln_to_lbtc_swap: Callable[..., Awaitable[tuple[Any, Any]]]
    # LN payment of the swap invoice. Returns ``(status, error)``.
    lnd_send_payment: Callable[..., Awaitable[tuple[Any, Any]]]
    # Liquid-side observer for Boltz's lockup; stashes the tx hex
    # for the cooperative claim. Returns ``(lockup_utxo_str, error)``.
    liquid_observe_credit: Callable[..., Awaitable[tuple[Any, Any]]]
    # Cooperative MuSig2 claim: spends the Boltz lockup to a wallet-
    # owned CT address derived per-session. Returns ``(claim_txid, error)``.
    liquid_claim_lockup: Callable[..., Awaitable[tuple[Any, Any]]]
    # Wallet-side observer for the claim TX confirmation. Returns
    # ``(confirmed_bool, error)``.
    liquid_observe_wallet_credit: Callable[..., Awaitable[tuple[Any, Any]]]
    # L-BTC→LN: Boltz submarine swap (``from: L-BTC``) that pays an
    # LN invoice we own. Returns ``({"swap_id": ...}, error)``.
    boltz_create_lbtc_to_ln_swap: Callable[..., Awaitable[tuple[Any, Any]]]
    # Build + broadcast the Liquid spend that funds Boltz's submarine
    # lockup address from the wallet's claimed CT UTXO. Returns
    # ``(lock_txid, error)``.
    liquid_lock_for_submarine: Callable[..., Awaitable[tuple[Any, Any]]]
    # LN-side observer for the final settlement. Returns
    # ``(settled, error)``.
    lnd_observe_invoice_settled: Callable[..., Awaitable[tuple[Any, Any]]]

    # Per-leg operator-id attribution. Populated from
    # ``LiquidLegSelection`` by :func:`build_default_liquid_hop_deps`;
    # the hop body stamps them onto the session at swap-id storage
    # time so recovery code has DB-resident attribution without
    # re-deriving the in-process selection. ``None`` is legitimate
    # when the deployment runs without a signed operator registry
    # (env-pin-only) — the recovery banner falls back to the URL in
    # that case.
    ln_to_lbtc_operator_id: Optional[str] = None
    lbtc_to_ln_operator_id: Optional[str] = None


@dataclass(frozen=True)
class LiquidHopOutcome:
    """Result of one Liquid-hop step."""

    kind: str  # 'noop' | 'ln_to_lbtc_initiated' | 'lbtc_credited' |
    # 'dwell_scheduled' | 'lbtc_to_ln_initiated' |
    # 'completed' | 'error'
    detail: str = ""


_NOOP = LiquidHopOutcome(kind="noop")


def _key_for(
    session: AnonymizeSession,
    hop_kind: str,
    attempt: int,
) -> HopAttemptKey:
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


def sample_liquid_dwell_s(rng: secrets.SystemRandom | None = None) -> float:
    """Sample a uniform-random Liquid dwell delay.

    Defaults to 3–24 h band so the dwell window is wide enough to
    decorrelate the LN-in and LN-out timestamps but short enough to
    keep per-session capital lockup manageable.
    """
    rng = rng or secrets.SystemRandom()
    lo = int(settings.anonymize_liquid_min_dwell_s)
    hi = int(settings.anonymize_liquid_max_dwell_s)
    if hi < lo:
        return float(lo)
    return rng.uniform(float(lo), float(hi))


def is_liquid_hop_enabled() -> bool:
    """True iff the operator has opted into the Liquid hop."""
    return bool(getattr(settings, "anonymize_liquid_enabled", False))


async def execute_liquid_hop_step(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LiquidHopDeps,
) -> LiquidHopOutcome:
    """One per-session tick of the Liquid-hop body.

    Dispatches on the session's current status + the per-session
    pipeline_json markers. Each step is idempotent: a crash mid-step
    lets the next tick read persisted state and resume without
    re-issuing side effects.

    The hop is a no-op when ``ANONYMIZE_LIQUID_ENABLED=false`` — the
    per-session loop short-circuits before dispatching to this body,
    but the gate is asserted here as defense-in-depth.

    Restart-recovery: the in-process ``deps.swap_state`` cache is
    hydrated from the session's encrypted persistence blob on every
    tick + re-persisted at the end. A crash between two ticks loses
    nothing — the wallet-generated secrets (preimage, claim privkey)
    survive a process restart.
    """
    if not is_liquid_hop_enabled():
        return LiquidHopOutcome(kind="noop", detail="liquid_hop_disabled")

    # Hydrate the per-session swap_state cache from the persisted
    # encrypted blob. No-op when the cache already has live entries.
    from ..liquid_swap_state_persistence import (
        persist_session_swap_state,
        restore_session_swap_state,
    )

    restore_session_swap_state(session, deps.swap_state)

    try:
        if session.status == AnonymizeStatus.HOPPING.value:
            pj = session.pipeline_json or {}
            # Leg 1: LN → L-BTC.
            if not pj.get("liquid_ln_to_lbtc_swap_id"):
                return await _step_initiate_ln_to_lbtc(db, session, deps)
            # Observe Boltz's lockup landing on Liquid (stashes the tx
            # hex for the cooperative claim subprocess).
            if not pj.get("liquid_lbtc_utxo"):
                return await _step_observe_lbtc_credit(db, session, deps)
            # Cooperative MuSig2 claim to a wallet-owned CT address.
            if not pj.get("liquid_lbtc_claim_txid"):
                return await _step_claim_lbtc_to_wallet(db, session, deps)
            # Wait for the claim to confirm so the wallet's UTXO is
            # mined before we schedule the dwell (defends against
            # orphan races).
            if not pj.get("liquid_lbtc_claim_confirmed"):
                return await _step_observe_claim_confirmation(db, session, deps)
            if not pj.get("liquid_dwell_until_unix_s"):
                return await _step_schedule_dwell(db, session)
            return _NOOP

        if session.status == AnonymizeStatus.AWAITING_LIQUID_DWELL.value:
            pj = session.pipeline_json or {}
            dwell_until = float(pj.get("liquid_dwell_until_unix_s") or 0)
            if datetime.now(timezone.utc).timestamp() < dwell_until:
                return LiquidHopOutcome(
                    kind="noop",
                    detail="awaiting_liquid_dwell",
                )
            # Leg 2: L-BTC → LN.
            if not pj.get("liquid_lbtc_to_ln_swap_id"):
                return await _step_initiate_lbtc_to_ln(db, session, deps)
            # Build + broadcast the Liquid spend funding Boltz's lockup.
            if not pj.get("liquid_submarine_lock_txid"):
                return await _step_lock_lbtc_for_submarine(db, session, deps)
            return await _step_observe_lbtc_to_ln_settlement(db, session, deps)

        return _NOOP
    finally:
        # Re-persist the swap_state cache after any in-step mutation.
        # The outer caller's transaction commits ``session.pipeline_json``
        # along with whatever other row mutations the step produced.
        persist_session_swap_state(session, deps.swap_state)


# ── HOPPING — leg 1: LN→L-BTC ───────────────────────────────────────


async def _step_initiate_ln_to_lbtc(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LiquidHopDeps,
) -> LiquidHopOutcome:
    """Create the LN→L-BTC chain swap + pay its invoice."""
    key = _key_for(session, "liquid_ln_to_lbtc", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=key.idempotency_key,
    ):
        return LiquidHopOutcome(
            kind="noop",
            detail="ln_to_lbtc_already_completed",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "create_swap"},
    )
    await db.flush()

    bin_amount = int(session.bin_amount_sat or 0)
    if bin_amount <= 0:
        return LiquidHopOutcome(
            kind="error",
            detail="bin_amount_sat must be positive",
        )

    # Decrypt the per-session SLIP-77 derivation index assigned at
    # session-create time. The claim adapter uses this to derive a
    # wallet-controlled CT destination address for the cooperative
    # claim TX. A missing index here is a hard error: the session
    # was created without the index even though uses_liquid=True.
    if not session.liquid_blinding_seed_enc:
        return LiquidHopOutcome(
            kind="error",
            detail="session is missing liquid_blinding_seed_enc",
        )
    from ..liquid_seed import (
        LiquidSeedError,
        decrypt_session_blinding_seed_index,
    )

    try:
        blinding_seed_index = decrypt_session_blinding_seed_index(
            session.liquid_blinding_seed_enc,
        )
    except LiquidSeedError as exc:
        return LiquidHopOutcome(
            kind="error",
            detail=f"blinding_seed_decrypt_failed:{exc}",
        )

    swap, err = await deps.boltz_create_ln_to_lbtc_swap(
        amount_sat=bin_amount,
        session_id=session.id,
        blinding_seed_index=blinding_seed_index,
    )
    if err is not None or not swap:
        return LiquidHopOutcome(
            kind="error",
            detail=f"ln_to_lbtc_create_failed:{err}",
        )

    invoice = swap.get("invoice") if isinstance(swap, dict) else None
    swap_id = swap.get("swap_id") if isinstance(swap, dict) else None
    if not invoice or not swap_id:
        return LiquidHopOutcome(
            kind="error",
            detail="ln_to_lbtc_swap_missing_invoice",
        )

    pay_result, err = await deps.lnd_send_payment(
        payment_request=invoice,
        amount_sat=bin_amount,
    )
    if err is not None:
        # Same transient-error contract as the Braiins-Deposit fix
        # (see ``app/tasks/boltz_tasks.py`` for the rationale). LND's
        # ``send_payment_v2`` returns:
        #
        # * ``Payment failed: …`` — definitive terminal FAILED (LND
        #   surfaced ``status: FAILED`` in the SendPaymentV2 stream;
        #   the HTLC is gone, retry would only spin).
        # * ``Connection failed: …`` / ``Request failed: …`` /
        #   ``LND error (5xx): …`` / ``Payment did not reach a
        #   terminal state`` — the HTTP stream dropped, but LND does
        #   NOT cancel an in-flight HTLC when its caller goes away.
        #   The HTLC may still be in-flight at Boltz.
        # * ``payment is in transition`` (409 from a retry attempt
        #   while the first call's HTLC is still pending) — same
        #   semantics: HTLC alive, just wait.
        #
        # For everything except ``Payment failed:`` return ``noop``
        # so the per-session loop polls again without burning the
        # retry budget. The next tick's ``lnd_send_payment`` either
        # gets ``in transition`` (HTLC still alive) or sees the
        # original payment settle/fail.
        err_lower = err.lower()
        looks_transient = not err.startswith("Payment failed:") and (
            "connection failed" in err_lower
            or "request failed" in err_lower
            or "did not reach a terminal state" in err_lower
            or err_lower.startswith("lnd error (5")
            or "in transition" in err_lower
        )
        if looks_transient:
            return LiquidHopOutcome(
                kind="noop",
                detail=f"ln_to_lbtc_pay_in_flight:{err}",
            )
        return LiquidHopOutcome(
            kind="error",
            detail=f"ln_to_lbtc_pay_failed:{err}",
        )

    pj = dict(session.pipeline_json or {})
    pj["liquid_ln_to_lbtc_swap_id"] = str(swap_id)
    pj["liquid_ln_to_lbtc_paid_at_ts"] = datetime.now(timezone.utc).isoformat()
    session.pipeline_json = pj

    # Stamp the LN→L-BTC operator id for forensic attribution.
    # Idempotent: only set on first observation; recovery code may
    # re-write to the same value but never overwrites a non-NULL
    # historical attribution.
    if session.liquid_reverse_operator_id is None and deps.ln_to_lbtc_operator_id:
        session.liquid_reverse_operator_id = deps.ln_to_lbtc_operator_id

    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"swap_id": str(swap_id)},
    )
    return LiquidHopOutcome(kind="ln_to_lbtc_initiated", detail=str(swap_id))


async def _step_observe_lbtc_credit(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LiquidHopDeps,
) -> LiquidHopOutcome:
    """Wait for the LN→L-BTC credit to land on Liquid."""
    pj = session.pipeline_json or {}
    utxo, err = await deps.liquid_observe_credit(
        swap_id=pj.get("liquid_ln_to_lbtc_swap_id"),
        session_id=session.id,
    )
    if err is not None:
        return LiquidHopOutcome(
            kind="error",
            detail=f"liquid_observe_credit_failed:{err}",
        )
    if utxo is None:
        return LiquidHopOutcome(
            kind="noop",
            detail="awaiting_lbtc_credit",
        )

    pj = dict(pj)
    pj["liquid_lbtc_utxo"] = str(utxo)
    session.pipeline_json = pj
    return LiquidHopOutcome(kind="lbtc_credited", detail=str(utxo))


async def _step_claim_lbtc_to_wallet(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LiquidHopDeps,
) -> LiquidHopOutcome:
    """Cooperative MuSig2 claim of Boltz's lockup → wallet CT address.

    Idempotent: the adapter persists the claim txid before returning;
    a crash mid-step lets the next tick observe the pre-existing
    persistence and resume from the confirmation wait.
    """
    key = _key_for(session, "liquid_claim_lbtc", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=key.idempotency_key,
    ):
        return LiquidHopOutcome(
            kind="noop",
            detail="liquid_claim_already_completed",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "claim_lockup"},
    )
    await db.flush()

    pj = session.pipeline_json or {}
    claim_txid, err = await deps.liquid_claim_lockup(
        swap_id=pj.get("liquid_ln_to_lbtc_swap_id"),
        session_id=session.id,
    )
    if err is not None or not claim_txid:
        return LiquidHopOutcome(
            kind="error",
            detail=f"liquid_claim_lockup_failed:{err}",
        )

    pj = dict(pj)
    pj["liquid_lbtc_claim_txid"] = str(claim_txid)
    pj["liquid_lbtc_claim_broadcast_at_ts"] = datetime.now(timezone.utc).isoformat()
    session.pipeline_json = pj

    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"claim_txid": str(claim_txid)},
    )
    return LiquidHopOutcome(kind="lbtc_claimed", detail=str(claim_txid))


async def _step_observe_claim_confirmation(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LiquidHopDeps,
) -> LiquidHopOutcome:
    """Wait for the wallet's claim TX to confirm (1 conf is enough)."""
    pj = session.pipeline_json or {}
    confirmed, err = await deps.liquid_observe_wallet_credit(
        swap_id=pj.get("liquid_ln_to_lbtc_swap_id"),
        session_id=session.id,
    )
    if err is not None:
        return LiquidHopOutcome(
            kind="error",
            detail=f"liquid_observe_wallet_credit_failed:{err}",
        )
    if not confirmed:
        return LiquidHopOutcome(
            kind="noop",
            detail="awaiting_claim_confirmation",
        )

    pj = dict(pj)
    pj["liquid_lbtc_claim_confirmed"] = True
    pj["liquid_lbtc_claim_confirmed_at_ts"] = datetime.now(timezone.utc).isoformat()
    session.pipeline_json = pj
    return LiquidHopOutcome(
        kind="lbtc_claim_confirmed",
        detail=str(pj.get("liquid_lbtc_claim_txid") or ""),
    )


async def _step_schedule_dwell(
    db: AsyncSession,
    session: AnonymizeSession,
) -> LiquidHopOutcome:
    """Compute the dwell-until timestamp."""
    dwell_s = sample_liquid_dwell_s()
    dwell_until = datetime.now(timezone.utc).timestamp() + dwell_s
    pj = dict(session.pipeline_json or {})
    pj["liquid_dwell_until_unix_s"] = float(dwell_until)
    session.pipeline_json = pj
    return LiquidHopOutcome(
        kind="dwell_scheduled",
        detail=f"dwell_until_unix_s={dwell_until}",
    )


# ── AWAITING_LIQUID_DWELL — leg 2: L-BTC→LN ─────────────────────────


async def _step_initiate_lbtc_to_ln(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LiquidHopDeps,
) -> LiquidHopOutcome:
    """Create the L-BTC→LN chain swap once the dwell has elapsed."""
    key = _key_for(session, "liquid_lbtc_to_ln", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=key.idempotency_key,
    ):
        return LiquidHopOutcome(
            kind="noop",
            detail="lbtc_to_ln_already_completed",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "create_swap"},
    )
    await db.flush()

    pj = session.pipeline_json or {}
    swap, err = await deps.boltz_create_lbtc_to_ln_swap(
        lbtc_utxo=pj.get("liquid_lbtc_utxo"),
        amount_sat=int(session.bin_amount_sat or 0),
        session_id=session.id,
    )
    if err is not None or not swap:
        return LiquidHopOutcome(
            kind="error",
            detail=f"lbtc_to_ln_create_failed:{err}",
        )

    swap_id = swap.get("swap_id") if isinstance(swap, dict) else None
    if not swap_id:
        return LiquidHopOutcome(
            kind="error",
            detail="lbtc_to_ln_swap_missing_id",
        )

    pj = dict(pj)
    pj["liquid_lbtc_to_ln_swap_id"] = str(swap_id)
    pj["liquid_lbtc_to_ln_initiated_at_ts"] = datetime.now(timezone.utc).isoformat()
    session.pipeline_json = pj

    # Stamp the L-BTC→LN operator id (see leg-1 stamp comment).
    if session.liquid_submarine_operator_id is None and deps.lbtc_to_ln_operator_id:
        session.liquid_submarine_operator_id = deps.lbtc_to_ln_operator_id

    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"swap_id": str(swap_id)},
    )
    return LiquidHopOutcome(
        kind="lbtc_to_ln_initiated",
        detail=str(swap_id),
    )


async def _step_lock_lbtc_for_submarine(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LiquidHopDeps,
) -> LiquidHopOutcome:
    """Build + broadcast the Liquid spend funding Boltz's lockup.

    The wallet has a confirmed CT-blinded UTXO at its per-session
    address (produced by the leg-1 cooperative claim). This step
    spends that UTXO to the submarine lockup address Boltz returned
    in :meth:`_step_initiate_lbtc_to_ln`. Boltz then claims the
    lockup and settles the wallet's LN invoice.
    """
    key = _key_for(session, "liquid_lock_for_submarine", attempt=1)
    # The lock spends the wallet's own L-BTC UTXO, and a rebuild on
    # recovery selects coins afresh — so a second build+broadcast is a
    # genuine double-spend, not an idempotent retry. The decision is
    # taken from the durably committed attempt trail (see the BTC
    # submarine funding step for the same contract):
    #   * completed    → already locked; no-op.
    #   * started-only → died in the broadcast window; re-issuing would
    #                    double-fund. Route to reconciliation.
    #   * neither      → first attempt; commit the started marker, then
    #                    broadcast.
    decision = await dispatch_hop_attempt(db, idempotency_key=key.idempotency_key)
    if decision == "completed_idempotent_no_op":
        return LiquidHopOutcome(
            kind="noop",
            detail="liquid_lock_already_completed",
        )
    if decision == "verify_remote_state":
        from app.services.anonymize.service import get_anonymize_service

        await get_anonymize_service().transition_to_awaiting_reconciliation(
            db,
            session,
            reason="liquid_lock_in_doubt",
        )
        return LiquidHopOutcome(
            kind="error",
            detail="liquid_lock_in_doubt",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "lock_lbtc"},
    )
    # Durably commit the started marker BEFORE the broadcast so a crash
    # in the broadcast window leaves a started-without-completed trail the
    # ``verify_remote_state`` branch detects on recovery.
    await db.commit()

    pj = session.pipeline_json or {}
    lock_txid, err = await deps.liquid_lock_for_submarine(
        swap_id=pj.get("liquid_lbtc_to_ln_swap_id"),
        session_id=session.id,
    )
    if err is not None or not lock_txid:
        return LiquidHopOutcome(
            kind="error",
            detail=f"liquid_lock_for_submarine_failed:{err}",
        )

    pj = dict(pj)
    pj["liquid_submarine_lock_txid"] = str(lock_txid)
    pj["liquid_submarine_lock_broadcast_at_ts"] = datetime.now(timezone.utc).isoformat()
    session.pipeline_json = pj

    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"lock_txid": str(lock_txid)},
    )
    return LiquidHopOutcome(
        kind="lbtc_locked_for_submarine",
        detail=str(lock_txid),
    )


async def _step_observe_lbtc_to_ln_settlement(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: LiquidHopDeps,
) -> LiquidHopOutcome:
    """Wait for the L-BTC→LN invoice to settle."""
    pj = session.pipeline_json or {}
    settled, err = await deps.lnd_observe_invoice_settled(
        swap_id=pj.get("liquid_lbtc_to_ln_swap_id"),
        session_id=session.id,
    )
    if err is not None:
        return LiquidHopOutcome(
            kind="error",
            detail=f"lbtc_to_ln_observe_failed:{err}",
        )
    if not settled:
        return LiquidHopOutcome(
            kind="noop",
            detail="awaiting_lbtc_to_ln_settlement",
        )

    pj = dict(pj)
    pj["liquid_completed_at_ts"] = datetime.now(timezone.utc).isoformat()
    # Retention hygiene: once the round-trip has settled, the per-swap
    # secrets cache (preimage, claim privkey, refund privkey, wallet
    # UTXO blinding factors) is no longer load-bearing. Drop the
    # encrypted blob from pipeline_json + the in-memory cache so a
    # later DB snapshot doesn't retain wallet secrets indefinitely.
    pj.pop("liquid_swap_state_enc", None)
    session.pipeline_json = pj
    sid = str(session.id)
    for swap_id, entry in list(deps.swap_state.items()):
        if str(entry.get("session_id") or "") == sid:
            deps.swap_state.pop(swap_id, None)
    return LiquidHopOutcome(kind="completed", detail="liquid_round_trip_done")


__all__ = [
    "LiquidHopDeps",
    "LiquidHopOutcome",
    "execute_liquid_hop_step",
    "is_liquid_hop_enabled",
    "sample_liquid_dwell_s",
]
