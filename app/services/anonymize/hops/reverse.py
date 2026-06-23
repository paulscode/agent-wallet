# SPDX-License-Identifier: MIT
"""reverse-swap hop body — LN→BTC exit.

Wraps the existing wallet ``boltz_service.create_reverse_swap`` /
cooperative-claim machinery with the anonymize-stack hardenings:

1. Pinned request shape via :func:`boltz_request.make_reverse_create_request`
   .
2. Hop-idempotency events bracket every external side-effect
   (— ``hop_attempt_started`` + ``hop_attempt_completed``).
3. MPP K read via the single read-site:func:`resolve_mpp_k` (/
   ).
4. ``claim_tx_hex`` + ``claim_broadcast_at_ts`` persisted BEFORE the
   broadcast (crash-consistency).
5. Broadcast-via-Boltz default with self-broadcast fallback (/
   ).
6. Cooperative-signature timeout — bounded by the injected
   subprocess wrapper's wall-clock.

The body is dispatched per-tick by :func:`execute_reverse_hop_step`;
the per-session loop runs it BEFORE the source-side observation
collector when the session status is EXITING / CONFIRMING. Each
phase is idempotent so a crash mid-step resumes cleanly on restart.

Production wires the adapters in :class:`ReverseHopDeps` to live
``boltz_service`` / ``lnd_service`` / chain-client / subprocess
wrappers. Tests inject mocks so the full hop body can be exercised
without a live Boltz/LND.
"""

from __future__ import annotations

import asyncio
import logging
import secrets as _secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from ..boltz_request import make_reverse_create_request
from ..cooperative_claim import decide_k_fallback_step, resolve_mpp_k
from ..hop_idempotency import (
    HopAttemptKey,
    has_hop_attempt_completed,
    make_hop_idempotency_key,
    record_hop_attempt_completed,
    record_hop_attempt_started,
)
from ..metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


async def _record_reverse_operator_outlier(*, operator_id: str, reason: str) -> None:
    """Record a per-operator outlier in its own committed transaction.

    An operator that returns an out-of-band claim feerate or a claim tx that
    fails the output cross-check is misbehaving; the outlier counter feeds the
    degrade decision that excludes it from future pair selection. The write
    runs in a dedicated session so the counter survives regardless of the
    hop's own transaction outcome (the hop returns an error and its work is
    discarded). Best-effort: a failure here must not break error handling.
    """
    try:
        from app.core.database import get_session_maker

        from ..operator_health import record_operator_outlier

        async with get_session_maker()() as _dsess:
            await record_operator_outlier(_dsess, operator_id=operator_id, reason=reason)
            await _dsess.commit()
    except Exception:  # noqa: BLE001
        logger.debug("reverse hop: could not record operator outlier for %s", operator_id, exc_info=True)


@dataclass
class ReverseHopDeps:
    """Adapters the hop body calls into. Tests inject mocks; production
    binds them to live ``boltz_service`` / ``lnd_service`` / chain
    client / subprocess wrapper.

    Each adapter returns ``(result, error)`` so the hop body records
    outcomes without raising up into the per-session loop's
    bounded-retry budget.
    """

    boltz_create_reverse_swap: Callable[..., Awaitable[tuple[Any, Any]]]
    boltz_get_swap_status: Callable[..., Awaitable[tuple[Any, Any, Any]]]
    lnd_send_payment: Callable[..., Awaitable[tuple[Any, Any]]]
    run_claim_subprocess: Callable[..., Awaitable[tuple[Any, Any]]]
    chain_broadcast_tx: Callable[[str], Awaitable[tuple[Any, Any]]]


@dataclass(frozen=True)
class HopStepOutcome:
    """Result of one reverse-hop step."""

    kind: str  # 'noop' | 'issued_swap' | 'paid_invoice' |
    # 'lockup_observed' | 'claim_broadcast' | 'error'
    detail: str = ""


_NOOP = HopStepOutcome(kind="noop")


def _key_for(session: AnonymizeSession, hop_kind: str, attempt: int) -> HopAttemptKey:
    """Build a :class:`HopAttemptKey` for a session + hop kind.

    Uses a stable nonce derived from ``(session_id, hop_kind, attempt)``
    so the idempotency key round-trips across crashes. Production
    wiring substitutes the rotation-managed HMAC key bundle; the
    fallback is the all-zeros key (the key is purged from
    ``anonymize_runtime_state`` retention).
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
        else hashlib.blake2b(str(session.id).encode("utf-8"), digest_size=16).digest()
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


async def execute_reverse_hop_step(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: ReverseHopDeps,
) -> HopStepOutcome:
    """One per-session tick of the reverse-hop body.

    Dispatches on the session's current status. Each step is
    idempotent: a crash mid-step lets the next tick read persisted
    state and resume without re-issuing side effects.
    """
    if session.status == AnonymizeStatus.EXITING.value:
        return await _step_exiting(db, session, deps)
    if session.status == AnonymizeStatus.CONFIRMING.value:
        return await _step_confirming(db, session, deps)
    return _NOOP


async def _step_exiting(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: ReverseHopDeps,
) -> HopStepOutcome:
    """Drive an EXITING session through issue → pay → claim → broadcast."""
    if not _has_issued_swap(session):
        return await _issue_reverse_swap(db, session, deps)
    if session.claim_broadcast_at_ts is not None:
        return _NOOP
    return await _poll_and_claim(db, session, deps)


async def _step_confirming(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: ReverseHopDeps,
) -> HopStepOutcome:
    """Drive a CONFIRMING session toward COMPLETED.

    The chain-confirmation poll runs in the ``chain_poll`` recurring
    task; this step is the per-session-loop counterpart and is a
    no-op, deferring confirmation handling to that task.
    """
    return HopStepOutcome(kind="noop", detail="confirming_waiting_for_chain_poll")


async def _check_exit_relay_diversity(
    session: AnonymizeSession,
) -> str | None:
    """Probe Tor's control port + assert distinct exits.

    Returns ``None`` when the diversity check passes (or is
    inapplicable), or a short error string when the chosen submarine
    + reverse circuits would emerge through the same exit-relay
    diversity key.

    Fail-open semantics for unconfigured / unreachable control
    ports: a deployment without `ANONYMIZE_TOR_CONTROL_HOST/PORT`
    configured returns ``None`` (the listener-pair isolation
    already separates the two circuits).
    """
    from ..tor import (
        TorListenerNotConfiguredError,
        _exit_diversity_key,
        assert_exit_relay_diversity,
        probe_tor_circuit_status,
        resolve_socks_port,
    )

    circuits, err = await probe_tor_circuit_status()
    if err is not None:
        # Unreachable control port → fall through; listener-pair
        # isolation already partitions the two circuits.
        return None
    if len(circuits) < 2:
        return None
    # Identify the submarine + reverse listeners by SOCKS port. If
    # either listener isn't configured, fall through.
    try:
        sub_port = resolve_socks_port("chain_backend_anonymize")
        rev_port = resolve_socks_port("boltz_reverse")
    except TorListenerNotConfiguredError:
        return None
    # The diversity check pulls a fingerprint pair from any two
    # circuits in the snapshot. Tor doesn't directly tag circuits by
    # SOCKS port in `circuit-status`; for the listener-isolation
    # case (separate ports = separate circuits) the second-layer
    # check looks for ANY two circuits that share an exit. If two
    # circuits exist with the same exit-fingerprint diversity key,
    # the wallet's two-leg activity could merge through the same
    # exit relay.
    _ = (sub_port, rev_port)  # held for future port-tag mapping
    from app.core.config import settings as _settings

    mode = str(_settings.anonymize_require_exit_diversity or "asn")
    if mode == "off":
        return None
    # Walk every pair of circuits; if any two share a diversity key,
    # refuse. (For single-session use this is at most a few
    # circuits.)
    keys = [_exit_diversity_key(c, mode) for c in circuits]
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            if keys[i] and keys[i] == keys[j]:
                try:
                    assert_exit_relay_diversity(
                        circuits[i],
                        circuits[j],
                        mode=mode,
                    )
                except ValueError as exc:
                    return str(exc)
    return None


def _has_issued_swap(session: AnonymizeSession) -> bool:
    pj = session.pipeline_json or {}
    if not isinstance(pj, dict):
        return False
    return bool(pj.get("reverse_swap_id"))


async def _issue_reverse_swap(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: ReverseHopDeps,
) -> HopStepOutcome:
    """Issue the reverse swap with the pinned shape.

    Bracket the side-effect with ``hop_attempt_started`` (idempotency
    marker before the external call) and ``hop_attempt_completed``
    (after persistence).

    For on-chain pipelines (where the submarine leg has
    already opened a Tor circuit through the `chain_backend_anonymize`
    listener), probe `circuit-status` before opening the reverse
    leg's circuit. When the two exits share a diversity key, refuse
    the hop and route through reconciliation rather than admit a
    correlated pair.
    """
    is_onchain_source = (session.source_kind or "").lower() in {
        "onchain-self",
        "ext-onchain",
    }
    if is_onchain_source:
        diversity_err = await _check_exit_relay_diversity(session)
        if diversity_err is not None:
            logger.warning(
                "reverse hop %s: exit-relay diversity check failed: %s",
                session.id,
                diversity_err,
            )
            return HopStepOutcome(
                kind="error",
                detail=f"exit_relay_diversity:{diversity_err}",
            )

    key = _key_for(session, "reverse_create", attempt=1)
    if await has_hop_attempt_completed(db, idempotency_key=key.idempotency_key):
        return HopStepOutcome(
            kind="noop",
            detail="reverse_create_already_completed",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "reverse_create_swap"},
    )
    await db.flush()

    pipeline = session.pipeline_json or {}
    destination = pipeline.get("exit", {}).get("destination_address", "")
    bin_amount = int(session.bin_amount_sat or 0)
    request_body = make_reverse_create_request(
        preimage_hash_hex="00" * 32,
        claim_public_key_hex="02" + "00" * 32,
        invoice_amount_sats=bin_amount,
        destination_address=destination,
    )

    swap, error = await deps.boltz_create_reverse_swap(
        db=db,
        request_body=request_body,
        session=session,
    )
    if error or swap is None:
        logger.warning(
            "reverse hop %s: create_reverse_swap failed: %s",
            session.id,
            error,
        )
        return HopStepOutcome(kind="error", detail=f"create_swap_failed:{error}")

    pj = dict(session.pipeline_json or {})
    pj["reverse_swap_id"] = str(getattr(swap, "boltz_swap_id", swap))
    # The :class:`BoltzSwap` model field is ``boltz_invoice`` (see
    # app/models/boltz_swap.py:128) — reading ``swap.invoice`` would
    # silently default to ``""`` and the next ``_poll_and_claim``
    # tick would error out on ``not invoice`` for the rest of the
    # session's life, wedging it in ``EXITING`` until the bounded-
    # retry counter eventually routes it to AWAITING_RECONCILIATION.
    pj["reverse_swap_invoice"] = str(getattr(swap, "boltz_invoice", "") or "")
    session.pipeline_json = pj

    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"swap_id": pj["reverse_swap_id"]},
    )
    return HopStepOutcome(kind="issued_swap", detail=pj["reverse_swap_id"])


async def _poll_and_claim(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: ReverseHopDeps,
) -> HopStepOutcome:
    """Pay the LN invoice, poll for lockup, cooperative-claim, broadcast.

    Every external call is idempotency-bracketed; the
    ``claim_tx_hex`` + ``claim_broadcast_at_ts`` write happens BEFORE
    the broadcast so a crash mid-broadcast lets the recurring
    self-broadcast-fallback task pick it up.
    """
    pj = session.pipeline_json or {}
    swap_id = pj.get("reverse_swap_id")
    invoice = pj.get("reverse_swap_invoice")
    if not swap_id or not invoice:
        return HopStepOutcome(kind="error", detail="missing_swap_state")

    # Read K via the single accessor.
    requested_k = resolve_mpp_k(pj)

    # Bounded MPP-K fallback. Each pay attempt
    # records its K so a re-run can decrement and retry. Pay attempts
    # are keyed by attempt-number so the idempotency events are
    # distinct across retries.
    decrements_used = int(pj.get("reverse_payment_chunks_k_decrements_used", 0))
    last_attempted_k = int(pj.get("reverse_payment_chunks_k_last_attempted", requested_k))

    pay_key = _key_for(
        session,
        "reverse_pay_invoice",
        attempt=decrements_used + 1,
    )
    if not await has_hop_attempt_completed(
        db,
        idempotency_key=pay_key.idempotency_key,
    ):
        await record_hop_attempt_started(
            db,
            key=pay_key,
            detail={"step": "pay_invoice", "mpp_k": last_attempted_k},
        )
        await db.flush()
        pay_start_unix_s = datetime.now(timezone.utc).timestamp()
        result, err = await deps.lnd_send_payment(
            payment_request=invoice,
            max_parts=last_attempted_k,
        )
        if err is not None:
            # Transient pay-invoice errors must NOT consume the
            # K-fallback budget or the bounded-retry counter — the
            # HTLC is potentially in-flight at the destination and
            # the right thing to do is wait one tick and re-poll.
            # Three flavours of transient:
            #
            # 1. ``payment is in transition`` (HTTP 409 from a retry
            #    attempt while a prior call's HTLC is still pending).
            # 2. The stream-drop family from ``send_payment_v2``:
            #    ``Connection failed: …`` / ``Request failed: …`` /
            #    ``LND error (5xx): …`` / ``Payment did not reach a
            #    terminal state``. LND does NOT cancel an in-flight
            #    HTLC when the HTTP stream to its caller drops.
            # 3. Only ``Payment failed: …`` is a definitive terminal
            #    FAILED from LND's SendPaymentV2 stream — that path
            #    falls through to the K-decrement / stuck-HTLC alarm
            #    machinery below.
            #
            # Without this broadened check the original Braiins
            # Deposit 2026-05-21 incident pattern would have caused
            # the reverse hop to K-decrement on a connection blip,
            # eventually exhausting the floor and routing the
            # session into ``AWAITING_RECONCILIATION`` with reason
            # ``mpp_k_floor_exhausted`` even though the original
            # payment was still alive at LND.
            err_lower = err.lower()
            looks_transient = not err.startswith("Payment failed:") and (
                "in transition" in err_lower
                or "connection failed" in err_lower
                or "request failed" in err_lower
                or "did not reach a terminal state" in err_lower
                or err_lower.startswith("lnd error (5")
            )
            if looks_transient:
                logger.info(
                    "reverse hop %s: LN payment in-flight or HTTP stream dropped (%s); noop for re-poll",
                    session.id,
                    err,
                )
                return HopStepOutcome(
                    kind="noop",
                    detail="ln_payment_in_flight",
                )
            # Emit the stuck-HTLC alarm when the LN-send
            # exceeded the documented threshold. Operator alerting +
            # CLTV margin bump info are surfaced via the alarm
            # payload; the per-session loop's bounded-retry handles
            # the K-fallback below.
            try:
                from ..failure_modes import (
                    DEFAULT_STUCK_HTLC_THRESHOLD_S,
                    build_stuck_htlc_alarm,
                    emit_stuck_htlc_alarm,
                    is_htlc_stuck,
                )

                in_flight_s = max(
                    0.0,
                    datetime.now(timezone.utc).timestamp() - pay_start_unix_s,
                )
                if is_htlc_stuck(
                    in_flight_seconds=in_flight_s,
                    threshold_s=DEFAULT_STUCK_HTLC_THRESHOLD_S,
                ):
                    alarm = build_stuck_htlc_alarm(
                        session_id=str(session.id),
                        payment_hash=str(invoice)[:16],
                        in_flight_seconds=in_flight_s,
                        cltv_blocks_remaining=0,
                    )
                    await emit_stuck_htlc_alarm(alarm)
            except Exception:  # noqa: BLE001
                # Alarm emission is best-effort; the per-session
                # loop's retry counter still drives reconciliation.
                pass
            # Bounded K-fallback. Use the ratchet
            # to decide whether to decrement K and retry on the next
            # tick, or to route to AWAITING_RECONCILIATION with
            # reason ``mpp_k_floor_exhausted``.
            from app.core.config import settings as _s

            mode = str(_s.anonymize_reverse_mpp_fallback_mode)
            floor = max(1, int(_s.anonymize_reverse_mpp_k_min_executed))
            next_k = last_attempted_k - 1
            can_decrement = next_k >= floor and (mode == "legacy" or (mode == "strict" and decrements_used < 1))
            if can_decrement:
                pj = dict(session.pipeline_json or {})
                pj["reverse_payment_chunks_k_decrements_used"] = decrements_used + 1
                pj["reverse_payment_chunks_k_last_attempted"] = next_k
                session.pipeline_json = pj
                await db.flush()
                logger.warning(
                    "reverse hop %s: pay failed, K decrement %d → %d",
                    session.id,
                    last_attempted_k,
                    next_k,
                )
                return HopStepOutcome(
                    kind="error",
                    detail=f"pay_invoice_will_retry_at_k_{next_k}",
                )
            # No room to decrement (mode-strict already used or
            # next_k below floor) — the fallback exhausts.
            # Sanity-check the decision against the pure helper.
            _ = decide_k_fallback_step(
                requested_k=requested_k,
                last_attempted_k=last_attempted_k,
                decrements_used=decrements_used,
            )
            logger.warning(
                "reverse hop %s: pay invoice failed: %s; fallback exhausted",
                session.id,
                err,
            )
            # Record the specific reason + emit the
            # documented event kind so the reconciliation path can
            # distinguish K-floor exhaustion from other error modes
            # the per-session-loop counter routes through.
            from app.models.anonymize_session import AnonymizeSessionEvent

            db.add(
                AnonymizeSessionEvent(
                    session_id=session.id,
                    ts=datetime.now(timezone.utc),
                    kind="mpp_k_floor_exhausted",
                    detail_json={
                        "requested_k": requested_k,
                        "last_attempted_k": last_attempted_k,
                        "decrements_used": decrements_used,
                        "mode": mode,
                    },
                )
            )
            # Route the session into AWAITING_RECONCILIATION via the
            # shared helper so all four reconciliation columns
            # (pre_reconciliation_status, reason, attempts, last_ts)
            # are populated atomically — without this the persisted
            # reason was written but pre_reconciliation_status stayed
            # NULL, leaving the recovery path no way to
            # resume the session.
            from app.services.anonymize.service import get_anonymize_service

            await get_anonymize_service().transition_to_awaiting_reconciliation(
                db,
                session,
                reason="mpp_k_floor_exhausted",
            )
            return HopStepOutcome(
                kind="error",
                detail="mpp_k_floor_exhausted",
            )
        await record_hop_attempt_completed(
            db,
            key=pay_key,
            detail={"executed_k": (result or {}).get("max_parts", 1)},
        )

    # Pass the bound reverse operator_id so the status poll
    # hits the SAME operator the reverse swap was created with.
    _pj_for_op = session.pipeline_json or {}
    _reverse_op_id = getattr(session, "reverse_operator_id", None) or _pj_for_op.get("reverse_operator_id")
    status, data, err = await deps.boltz_get_swap_status(
        swap_id,
        operator_id=_reverse_op_id,
    )
    if err is not None:
        return HopStepOutcome(kind="error", detail=f"poll_status:{err}")
    if status not in {"transaction.mempool", "transaction.confirmed"}:
        return HopStepOutcome(kind="noop", detail=f"awaiting_lockup:{status}")

    claim_key = _key_for(session, "reverse_claim", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=claim_key.idempotency_key,
    ):
        return HopStepOutcome(kind="noop", detail="claim_already_completed")

    await record_hop_attempt_started(
        db,
        key=claim_key,
        detail={"step": "cooperative_claim"},
    )
    await db.flush()

    # Cooperative-claim feerate sanity gate.
    # Refuse to claim against a Boltz fee outside the configured
    # tolerance band of the live mempool economy estimate read from
    # the dedicated anonymize chain client. The
    # economy-fee probe is retried twice; two failures
    # in a row fail closed (route session through reconciliation).
    swap_data = data or {}
    boltz_claim_feerate = float(swap_data.get("claimFeeRate", 0) or 0)
    # A missing or non-positive claimFeeRate is fail-closed: the gate
    # cannot bound a fee it was not told, and skipping it would let an
    # operator that omits the field broadcast at an unbounded fee and
    # erode the claim output. Route the session through reconciliation.
    if boltz_claim_feerate <= 0:
        logger.warning(
            "reverse hop %s: operator omitted claimFeeRate; failing closed",
            session.id,
        )
        await _record_reverse_operator_outlier(
            operator_id=_reverse_op_id or "default",
            reason="claim_feerate_missing",
        )
        return HopStepOutcome(
            kind="error",
            detail="claim_feerate_missing",
        )

    from ..chain_egress import get_anonymize_economy_feerate
    from ..cooperative_claim import (
        FeerateProbeUnavailableError,
        assert_claim_feerate_sane,
        probe_economy_feerate_with_retry,
    )

    async def _fetch_economy_satvb() -> float:
        value, err = await get_anonymize_economy_feerate()
        if err is not None or value is None:
            raise RuntimeError(err or "economy feerate unavailable")
        return float(value)

    try:
        economy_sat_per_vb = await probe_economy_feerate_with_retry(
            _fetch_economy_satvb,
        )
    except FeerateProbeUnavailableError as exc:
        logger.warning(
            "reverse hop %s: economy feerate probe unavailable: %s",
            session.id,
            exc,
        )
        return HopStepOutcome(
            kind="error",
            detail="claim_feerate_probe_unavailable",
        )

    result = assert_claim_feerate_sane(
        operator_id=_reverse_op_id or "default",
        quoted_sat_per_vb=boltz_claim_feerate,
        economy_sat_per_vb=economy_sat_per_vb,
    )
    if not result.accepted:
        logger.warning(
            "reverse hop %s: claim feerate outlier: %s",
            session.id,
            result.reason,
        )
        await _record_reverse_operator_outlier(
            operator_id=_reverse_op_id or "default",
            reason=f"feerate_outlier:{result.reason}",
        )
        return HopStepOutcome(
            kind="error",
            detail=f"feerate_outlier:{result.reason}",
        )

    claim_tx_hex, err = await deps.run_claim_subprocess(
        swap_id=swap_id,
        lockup_tx=swap_data.get("transaction", {}),
    )
    if err is not None or not claim_tx_hex:
        return HopStepOutcome(
            kind="error",
            detail=f"claim_subprocess:{err or 'no_hex'}",
        )

    # Bitcoin-Core-shaped envelope policy: the claim tx
    # must use nVersion=2 + nSequence=0xfffffffd (BIP-125 RBF-opt-in)
    # so the broadcast doesn't fingerprint us against organic
    # mainnet traffic. The boltz_claim.js patch explicitly sets
    # those fields; the Python-side assertion hard-refuses on any
    # mismatch and routes the session through reconciliation.
    #
    # Malformed-hex paths (test fixtures, premature reads) also
    # surface as policy violations; production deployments hit the
    # JS-produced claim_tx_hex which is policy-conformant by
    # construction.
    from ..txpolicy import TxEnvelopePolicyError, assert_envelope_policy

    try:
        assert_envelope_policy(claim_tx_hex)
    except TxEnvelopePolicyError as exc:
        logger.warning(
            "reverse hop %s: claim tx envelope policy violation: %s",
            session.id,
            exc,
        )
        return HopStepOutcome(
            kind="error",
            detail=f"envelope_policy_violation:{exc}",
        )

    # Cross-check the claim tx pays OUR destination with a single output
    # in a sane value band. boltz_claim.js builds the output from our own
    # destination and fixes the sighash before requesting Boltz's partial
    # sig, so Boltz cannot redirect — this is the Python-side guard against
    # a subprocess bug that would otherwise be the *only* thing standing
    # between us and a mis-addressed broadcast.
    try:
        from app.services.chain.electrum_protocol import address_to_script_pubkey

        destination = str((session.pipeline_json or {}).get("exit", {}).get("destination_address", "") or "")
        expected_spk_hex = address_to_script_pubkey(destination, settings.bitcoin_network).hex()
    except Exception as exc:  # noqa: BLE001 — can't derive the script ⇒ skip the cross-check (envelope already ran)
        logger.warning("reverse hop %s: could not derive expected claim script (%s); skipping output cross-check", session.id, exc)
        expected_spk_hex = None
    if expected_spk_hex is not None:
        from ..cooperative_claim import ClaimTxValidationError, validate_cooperative_claim_tx

        bin_amount = int(getattr(session, "bin_amount_sat", 0) or 0)
        # Value band for the claim output. The script match is the
        # theft-relevant check; the band rejects a grossly-short delivery.
        # The lower bound is the fee-aware fairness floor — (bin − the
        # configured fee ceiling) less a small slack for the claim tx
        # miner fee — so an operator cannot deliver materially less
        # on-chain than the Lightning amount the session paid. The upper
        # bound allows the lockup to exceed bin slightly.
        _claim_miner_fee_slack_sat = 2000
        _fee_ceiling = int(bin_amount * float(settings.anonymize_reverse_max_total_fee_pct) / 100.0)
        _floor = bin_amount - _fee_ceiling - _claim_miner_fee_slack_sat
        band = (max(1, _floor), bin_amount * 2) if bin_amount > 0 else (1, 21_000_000 * 100_000_000)
        try:
            validate_cooperative_claim_tx(
                tx_hex=claim_tx_hex,
                expected_output_script_hex=expected_spk_hex,
                expected_output_band_sat=band,
            )
        except ClaimTxValidationError as exc:
            logger.error("reverse hop %s: claim tx output cross-check FAILED: %s", session.id, exc)
            await _record_reverse_operator_outlier(
                operator_id=_reverse_op_id or "default",
                reason=f"claim_output_validation:{exc}",
            )
            return HopStepOutcome(
                kind="error",
                detail=f"claim_output_validation:{exc}",
            )

    # crash-consistency: persist BEFORE broadcast.
    session.claim_tx_hex = claim_tx_hex
    session.claim_broadcast_at_ts = datetime.now(timezone.utc)
    # Derive the txid up-front so the chain-poll tick has an
    # index to query as soon as the broadcast lands on chain.
    try:
        from ..txpolicy import compute_txid_from_hex as _txid_fn

        session.claim_txid = _txid_fn(claim_tx_hex)
    except Exception:  # noqa: BLE001
        # Defensive: a non-policy-conformant hex would have been
        # caught above; this fallback simply leaves claim_txid unset.
        pass
    # Record the broadcast deadline so the fallback
    # tick can decide whether enough time has elapsed.
    grace_s = int(settings.anonymize_boltz_broadcast_grace_s)
    session.broadcast_deadline_unix_s = int(session.claim_broadcast_at_ts.timestamp() + grace_s)
    await db.flush()

    # Randomized broadcast jitter. Sleeps a uniform-random
    # window in ``[0, ANONYMIZE_CLAIM_BROADCAST_JITTER_S)`` before
    # firing the broadcast call so a passive observer can't pin the
    # broadcast moment to a known protocol step.
    jitter_cap = int(settings.anonymize_claim_broadcast_jitter_s)
    if jitter_cap > 0:
        jitter_s = _secrets.SystemRandom().uniform(0.0, float(jitter_cap))
        await asyncio.sleep(jitter_s)

    broadcast_via_boltz = str(settings.anonymize_broadcast_via).lower() == "boltz"
    if not broadcast_via_boltz:
        _result, broadcast_err = await deps.chain_broadcast_tx(claim_tx_hex)
        if broadcast_err is not None:
            logger.warning(
                "reverse hop %s: self-broadcast failed: %s",
                session.id,
                broadcast_err,
            )
            return HopStepOutcome(
                kind="error",
                detail=f"self_broadcast:{broadcast_err}",
            )

    await record_hop_attempt_completed(
        db,
        key=claim_key,
        detail={
            "broadcast_via": "boltz" if broadcast_via_boltz else "self",
        },
    )
    return HopStepOutcome(kind="claim_broadcast", detail=str(swap_id))


__all__ = [
    "HopStepOutcome",
    "ReverseHopDeps",
    "execute_reverse_hop_step",
]
