# SPDX-License-Identifier: MIT
"""Recovery classifier for stuck Boltz swaps.

Pure functional layer that maps a ``BoltzSwap`` row (plus optional
chain context) into a structured recovery hint. The serialiser and
dashboard banner consume the hint to decide what copy to render and
which operator actions to expose.

The classifier is deliberately read-only — no DB, no chain RPC, no
side effects. Callers gather the inputs (chain tip heights, current
wall time, optional electrs reachability) and pass them in. This
keeps the rules unit-testable and lets the dashboard, cold-storage
API, and anonymize policy endpoint all share one source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.models.boltz_swap import BoltzSwap, SwapStatus

# ─── Thresholds ───────────────────────────────────────────────────────

#: Treat the swap as ``timeout_imminent`` when the Boltz lockup is
#: within this many blocks of expiry. Picked to give the operator
#: roughly 1 hour of wall time on mainnet (10-minute blocks) to
#: intervene with a cooperative or unilateral claim.
TIMEOUT_IMMINENT_BLOCKS: int = 6

#: Treat the swap as ``timeout_warning`` (informational) when the
#: lockup is within this many blocks — still safe, but the dashboard
#: shows a soft amber state so the operator notices early.
TIMEOUT_WARNING_BLOCKS: int = 30

#: ``CREATED`` for longer than this without advancing is suspicious.
#: Usually means the create-swap call succeeded but the background
#: task never picked up — restart-after-crash territory.
STUCK_IN_CREATED_SECONDS: int = 5 * 60

#: ``PAYING_INVOICE`` for longer than this means LND is wedged or the
#: route search has been exhausted. The recovery surface should expose
#: cooperative-claim once the swap moves to ``CLAIMING``, but in the
#: interim we want the operator to at least see the warning.
STUCK_IN_PAYING_INVOICE_SECONDS: int = 30 * 60

#: ``INVOICE_PAID`` for longer than this without the lockup being
#: detected means either Boltz is sitting on the funds or the chain
#: backend isn't seeing the mempool. Either way, alert the operator.
STUCK_IN_INVOICE_PAID_SECONDS: int = 20 * 60

#: Fallback upper bound for the Liquid dwell. The hop body picks a
#: dwell duration from ``ANONYMIZE_LIQUID_MAX_DWELL_S`` (default
#: 24h); when a session sits in ``awaiting_liquid_dwell`` for more
#: than (configured max + 1h) the session-level classifier marks it
#: stuck — usually a sign that electrs-liquid is unreachable or
#: behind. Used only when the session's frozen pipeline policy did
#: not record an explicit max-dwell value.
LIQUID_DWELL_STUCK_THRESHOLD_SECONDS: int = 25 * 3600

#: A present leg-2 submarine lockup means the wallet has locked L-BTC
#: for the final L-BTC→LN swap and it hasn't settled (settlement would
#: have advanced the session out of ``awaiting_liquid_dwell``). That is
#: refundable and concerning much sooner than a normal dwell, so the
#: classifier surfaces the refund levers after this shorter window.
LIQUID_SUBMARINE_STUCK_THRESHOLD_SECONDS: int = 3600

#: A leg-1 reverse-swap claim broadcast but unconfirmed for longer than
#: this means the cooperative claim is stuck. The wallet has revealed
#: the preimage (so its LN funds are committed) and must land the L-BTC
#: claim, so the classifier surfaces the post-timeout unilateral claim.
LIQUID_REVERSE_CLAIM_STUCK_THRESHOLD_SECONDS: int = 3600


# ─── Action identifiers ───────────────────────────────────────────────
# Strings the dashboard / API consumers match on. Keep stable — they
# are the contract between the classifier and the cold-storage
# endpoints exposed in this same patch.

ACTION_COOPERATIVE_CLAIM = "cooperative_claim"
ACTION_UNILATERAL_CLAIM = "unilateral_claim"
ACTION_RETRY_PAYMENT = "retry_payment"
ACTION_BUMP_FEE = "bump_fee"
# Liquid round-trip leg-2 (L-BTC→LN submarine) lockup refunds. Map to
# POST /anonymize/sessions/{id}/liquid-recovery/submarine/{cooperative,
# unilateral}-refund. Cooperative works anytime Boltz co-signs;
# unilateral is the post-timeout script-path fallback.
ACTION_LIQUID_COOPERATIVE_REFUND = "liquid_cooperative_refund"
ACTION_LIQUID_UNILATERAL_REFUND = "liquid_unilateral_refund"
# Liquid round-trip leg-1 (LN→L-BTC reverse) post-timeout claim. Maps to
# POST /anonymize/sessions/{id}/liquid-recovery/reverse/unilateral-claim.
# Surfaced when the wallet's cooperative claim is stuck after revealing
# the preimage — the L-BTC must be claimed or the (already-committed) LN
# funds are lost.
ACTION_LIQUID_REVERSE_UNILATERAL_CLAIM = "liquid_reverse_unilateral_claim"

# When a claim/lockup tx has been sitting in the mempool for at
# least this many seconds with no confirmation, the classifier
# recommends a manual fee bump (CPFP for wallet-broadcast reverse
# claims; RBF for wallet-broadcast submarine lockups). 4 hours.
FEE_BUMP_STALL_SECONDS = 4 * 60 * 60

# ─── States ───────────────────────────────────────────────────────────
# Short, machine-readable state identifiers. Banner copy is keyed off
# these in the dashboard. Kept in sync with the classifier's return
# values below.

STATE_CLEAN = "clean"
STATE_IN_PROGRESS = "in_progress"
STATE_STUCK_CREATED = "stuck_in_created"
STATE_STUCK_PAYING_INVOICE = "stuck_in_paying_invoice"
STATE_TRANSIENT_PAYMENT_ERROR = "transient_payment_error"
STATE_STUCK_INVOICE_PAID = "stuck_in_invoice_paid"
STATE_AWAITING_LOCKUP_CONFIRMATION = "awaiting_lockup_confirmation"
STATE_AWAITING_CLAIM = "awaiting_claim"
STATE_CLAIM_RETRY_AVAILABLE = "claim_retry_available"
STATE_TIMEOUT_WARNING = "timeout_warning"
STATE_TIMEOUT_IMMINENT = "timeout_imminent"
STATE_TIMEOUT_PASSED = "timeout_passed"
STATE_AWAITING_CONFIRMATIONS = "awaiting_confirmations"
STATE_COMPLETED = "completed"
STATE_FAILED = "failed"
STATE_REFUNDED = "refunded"
STATE_CANCELLED = "cancelled"

# Terminal classifier states \u2014 used to gate the cross-cutting
# submarine-lockup fee-bump augmentation off when the swap is no
# longer actionable.
_TERMINAL_STATES = frozenset(
    {
        STATE_COMPLETED,
        STATE_FAILED,
        STATE_REFUNDED,
        STATE_CANCELLED,
    }
)


SEVERITY_OK = "ok"
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"


# ─── Result type ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class RecoveryHint:
    """Structured advice for a single Boltz swap.

    ``state`` is the stable machine-readable identifier. ``severity``
    drives the dashboard banner colour. ``headline`` is a short
    user-facing label; ``detail`` is a one-sentence explanation.
    ``actions`` lists action IDs (see ``ACTION_*`` constants) the
    operator can take from the UI. ``metadata`` carries hint-specific
    context (e.g. ``blocks_until_timeout``).
    """

    state: str
    severity: str
    headline: str
    detail: str
    actions: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "severity": self.severity,
            "headline": self.headline,
            "detail": self.detail,
            "actions": list(self.actions),
            "metadata": dict(self.metadata),
        }


# ─── Helpers ──────────────────────────────────────────────────────────


_TRANSIENT_ERROR_PREFIX = "Payment attempt encountered a transient"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _seconds_since(ts: Optional[datetime], now: datetime) -> Optional[float]:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds()


# ─── Classifier ───────────────────────────────────────────────────────


def classify_recovery_state(
    swap: BoltzSwap,
    *,
    btc_tip_height: Optional[int] = None,
    claim_confirmations: Optional[int] = None,
    mempool_age_seconds: Optional[int] = None,
    lockup_mempool_age_seconds: Optional[int] = None,
    lockup_confirmations: Optional[int] = None,
    now: Optional[datetime] = None,
) -> RecoveryHint:
    """Map a ``BoltzSwap`` to a structured recovery hint.

    All optional inputs degrade gracefully:

    * ``btc_tip_height`` — when ``None``, the timeout-distance rows
      are skipped and the result falls through to status-based copy.
    * ``claim_confirmations`` — when ``None``, ``CLAIMED`` swaps
      report ``awaiting_confirmations`` without a count.
    * ``mempool_age_seconds`` — wallet-broadcast claim age. When
      ``>= FEE_BUMP_STALL_SECONDS`` and zero confirmations have
      landed yet, the ``CLAIMED`` row is augmented with a
      ``fee_bump_recommended`` metadata flag + ``ACTION_BUMP_FEE``
      action so the dashboard can offer a CPFP button.
    * ``lockup_mempool_age_seconds`` — wallet-broadcast lockup age
      (submarine direction only). When ``>= FEE_BUMP_STALL_SECONDS``
      and zero lockup confirmations have landed, the returned hint
      is augmented with the same fee-bump metadata + action so the
      dashboard can offer an RBF button against the lockup outpoint.
    * ``now`` — defaults to UTC wall clock. Tests inject a fixed
      value for determinism.
    """
    if now is None:
        now = _utc_now()

    hint = _classify_status(
        swap,
        btc_tip_height=btc_tip_height,
        claim_confirmations=claim_confirmations,
        mempool_age_seconds=mempool_age_seconds,
        now=now,
    )
    # Cross-cutting submarine-lockup fee-bump augmentation.
    # Only fires when the wallet has a lockup_txid stamped
    # (submarine direction), the lockup is still unconfirmed,
    # and the mempool age has crossed the stall threshold.
    if (
        getattr(swap, "lockup_txid", None)
        and lockup_mempool_age_seconds is not None
        and lockup_mempool_age_seconds >= FEE_BUMP_STALL_SECONDS
        and (lockup_confirmations or 0) == 0
        and hint.state not in _TERMINAL_STATES
        and not hint.metadata.get("fee_bump_recommended")
    ):
        new_meta = dict(hint.metadata)
        new_meta["fee_bump_recommended"] = True
        new_meta["lockup_mempool_age_seconds"] = int(lockup_mempool_age_seconds)
        new_meta["lockup_txid"] = swap.lockup_txid
        new_actions = tuple(hint.actions) + ((ACTION_BUMP_FEE,) if ACTION_BUMP_FEE not in hint.actions else ())
        hint = RecoveryHint(
            state=hint.state,
            severity=hint.severity,
            headline=hint.headline,
            detail=hint.detail,
            actions=new_actions,
            metadata=new_meta,
        )
    return hint


def _classify_status(
    swap: BoltzSwap,
    *,
    btc_tip_height: Optional[int],
    claim_confirmations: Optional[int],
    mempool_age_seconds: Optional[int],
    now: datetime,
) -> RecoveryHint:
    """Inner classifier — status-driven hint without lockup fee-bump.

    Factored out so the public ``classify_recovery_state`` can
    cleanly post-process the result with the submarine lockup
    fee-bump augmentation. Kept private; callers must use the
    public entry point.
    """
    status = swap.status
    error_message = swap.error_message or ""
    timeout_height = swap.timeout_block_height
    blocks_until_timeout: Optional[int] = None
    if btc_tip_height is not None and timeout_height is not None:
        blocks_until_timeout = timeout_height - btc_tip_height

    # ─── Terminal states ─────────────────────────────────────────
    if status == SwapStatus.COMPLETED:
        return RecoveryHint(
            state=STATE_COMPLETED,
            severity=SEVERITY_OK,
            headline="Swap complete",
            detail="Claim transaction confirmed; funds delivered to the destination address.",
        )

    if status == SwapStatus.FAILED:
        return RecoveryHint(
            state=STATE_FAILED,
            severity=SEVERITY_WARNING,
            headline="Swap failed",
            detail=error_message or "The swap failed before completion. No funds were sent.",
            metadata={"error_message": error_message} if error_message else {},
        )

    if status == SwapStatus.REFUNDED:
        return RecoveryHint(
            state=STATE_REFUNDED,
            severity=SEVERITY_INFO,
            headline="Swap refunded",
            detail=(
                "Boltz returned the lockup funds via the swap's refund path. "
                "This is the safe outcome when a reverse swap cannot complete."
            ),
        )

    if status == SwapStatus.CANCELLED:
        return RecoveryHint(
            state=STATE_CANCELLED,
            severity=SEVERITY_INFO,
            headline="Swap cancelled",
            detail="The swap was cancelled before any funds moved.",
        )

    # ─── Claim phase ─────────────────────────────────────────────
    if status == SwapStatus.CLAIMED:
        fee_bump_recommended = (
            mempool_age_seconds is not None
            and mempool_age_seconds >= FEE_BUMP_STALL_SECONDS
            and (claim_confirmations or 0) == 0
        )
        bump_meta: dict[str, object] = {}
        bump_actions: tuple[str, ...] = ()
        if fee_bump_recommended:
            # ``fee_bump_recommended`` is only True when
            # ``mempool_age_seconds is not None`` (see above).
            assert mempool_age_seconds is not None
            bump_meta["fee_bump_recommended"] = True
            bump_meta["mempool_age_seconds"] = int(mempool_age_seconds)
            bump_actions = (ACTION_BUMP_FEE,)
        if claim_confirmations is None:
            meta: dict[str, object] = {"claim_txid": swap.claim_txid} if swap.claim_txid else {}
            meta.update(bump_meta)
            return RecoveryHint(
                state=STATE_AWAITING_CONFIRMATIONS,
                severity=SEVERITY_INFO,
                headline="Awaiting confirmations",
                detail="Claim transaction broadcast; waiting for it to confirm on-chain.",
                actions=bump_actions,
                metadata=meta,
            )
        meta = {
            "claim_txid": swap.claim_txid,
            "claim_confirmations": claim_confirmations,
        }
        meta.update(bump_meta)
        return RecoveryHint(
            state=STATE_AWAITING_CONFIRMATIONS,
            severity=SEVERITY_INFO,
            headline=f"Awaiting confirmations ({claim_confirmations})",
            detail=(
                f"Claim transaction has {claim_confirmations} confirmation{'s' if claim_confirmations != 1 else ''}."
            ),
            actions=bump_actions,
            metadata=meta,
        )

    if status == SwapStatus.CLAIMING:
        # Timeout-aware variants come first — they are the most
        # urgent and override the generic "claim retry available"
        # copy.
        if blocks_until_timeout is not None:
            if blocks_until_timeout <= 0:
                return RecoveryHint(
                    state=STATE_TIMEOUT_PASSED,
                    severity=SEVERITY_CRITICAL,
                    headline="Lockup timeout passed",
                    detail=(
                        "The Boltz lockup timeout has been reached. The cooperative "
                        "claim path may no longer succeed. Use the unilateral claim "
                        "to spend the lockup via the swap's claim script."
                    ),
                    actions=(ACTION_UNILATERAL_CLAIM, ACTION_COOPERATIVE_CLAIM),
                    metadata={
                        "blocks_until_timeout": blocks_until_timeout,
                        "timeout_block_height": timeout_height,
                        "current_block_height": btc_tip_height,
                        "recovery_count": swap.recovery_count or 0,
                    },
                )
            if blocks_until_timeout <= TIMEOUT_IMMINENT_BLOCKS:
                return RecoveryHint(
                    state=STATE_TIMEOUT_IMMINENT,
                    severity=SEVERITY_CRITICAL,
                    headline=f"Timeout imminent ({blocks_until_timeout} blocks)",
                    detail=(
                        "The Boltz lockup expires very soon. Retry the cooperative "
                        "claim now; if it fails, the unilateral claim becomes "
                        "available once the timeout passes."
                    ),
                    actions=(ACTION_COOPERATIVE_CLAIM,),
                    metadata={
                        "blocks_until_timeout": blocks_until_timeout,
                        "timeout_block_height": timeout_height,
                        "current_block_height": btc_tip_height,
                        "recovery_count": swap.recovery_count or 0,
                    },
                )
            if blocks_until_timeout <= TIMEOUT_WARNING_BLOCKS:
                return RecoveryHint(
                    state=STATE_TIMEOUT_WARNING,
                    severity=SEVERITY_WARNING,
                    headline=f"Claim window narrowing ({blocks_until_timeout} blocks)",
                    detail=(
                        "The lockup timeout is approaching but the cooperative claim "
                        "should still succeed. Retry now if the swap has been "
                        "stuck for a while."
                    ),
                    actions=(ACTION_COOPERATIVE_CLAIM,),
                    metadata={
                        "blocks_until_timeout": blocks_until_timeout,
                        "timeout_block_height": timeout_height,
                        "current_block_height": btc_tip_height,
                        "recovery_count": swap.recovery_count or 0,
                    },
                )

        # Generic claim-phase rows.
        if (swap.recovery_count or 0) > 0 or error_message:
            return RecoveryHint(
                state=STATE_CLAIM_RETRY_AVAILABLE,
                severity=SEVERITY_WARNING,
                headline="Claim attempt failed; retry available",
                detail=(error_message or "A previous cooperative-claim attempt did not succeed. Retry is safe."),
                actions=(ACTION_COOPERATIVE_CLAIM,),
                metadata={
                    "recovery_count": swap.recovery_count or 0,
                    "error_message": error_message,
                },
            )
        return RecoveryHint(
            state=STATE_AWAITING_CLAIM,
            severity=SEVERITY_INFO,
            headline="Claiming on-chain",
            detail="The lockup transaction was detected. Constructing the claim transaction.",
        )

    if status == SwapStatus.INVOICE_PAID:
        age = _seconds_since(swap.updated_at, now)
        if age is not None and age > STUCK_IN_INVOICE_PAID_SECONDS:
            return RecoveryHint(
                state=STATE_STUCK_INVOICE_PAID,
                severity=SEVERITY_WARNING,
                headline="Lockup not yet seen",
                detail=(
                    "Lightning paid Boltz but the on-chain lockup has not been detected "
                    "yet. This is usually transient; if it persists, contact Boltz."
                ),
                metadata={"seconds_since_update": int(age)},
            )
        return RecoveryHint(
            state=STATE_AWAITING_LOCKUP_CONFIRMATION,
            severity=SEVERITY_INFO,
            headline="Awaiting lockup",
            detail="Lightning side paid; waiting for Boltz to publish the lockup transaction.",
        )

    if status == SwapStatus.PAYING_INVOICE:
        if error_message.startswith(_TRANSIENT_ERROR_PREFIX):
            return RecoveryHint(
                state=STATE_TRANSIENT_PAYMENT_ERROR,
                severity=SEVERITY_INFO,
                headline="Payment retrying",
                detail=error_message,
                metadata={"error_message": error_message},
            )
        age = _seconds_since(swap.updated_at, now)
        if age is not None and age > STUCK_IN_PAYING_INVOICE_SECONDS:
            return RecoveryHint(
                state=STATE_STUCK_PAYING_INVOICE,
                severity=SEVERITY_WARNING,
                headline="Lightning payment stuck",
                detail=(
                    "Lightning has been searching for a route for an extended period. "
                    "Check LND health and routing connectivity."
                ),
                metadata={"seconds_since_update": int(age)},
            )
        return RecoveryHint(
            state=STATE_IN_PROGRESS,
            severity=SEVERITY_OK,
            headline="Paying Lightning invoice",
            detail="LND is paying the Boltz hold invoice.",
        )

    if status == SwapStatus.CREATED:
        age = _seconds_since(swap.created_at, now)
        if age is not None and age > STUCK_IN_CREATED_SECONDS:
            return RecoveryHint(
                state=STATE_STUCK_CREATED,
                severity=SEVERITY_WARNING,
                headline="Swap not progressing",
                detail=(
                    "The swap was created but the background worker has not picked "
                    "it up. A restart-after-crash usually clears this; check Celery "
                    "worker logs."
                ),
                metadata={"seconds_since_creation": int(age)},
            )
        return RecoveryHint(
            state=STATE_IN_PROGRESS,
            severity=SEVERITY_OK,
            headline="Initialising swap",
            detail="Swap created; preparing to pay the Lightning invoice.",
        )

    # Defensive default. Should be unreachable given the SwapStatus
    # enum is exhausted above, but ``status`` is plain string-backed
    # so a future addition would fall through silently otherwise.
    return RecoveryHint(
        state=STATE_IN_PROGRESS,
        severity=SEVERITY_INFO,
        headline=f"Status: {status.value if hasattr(status, 'value') else status}",
        detail="No specific recovery guidance is available for this status.",
    )


# ─── Aggregation + session-level rules ────────────────────────────────


# Severity ordering for "worst-state" aggregation across swap legs.
_SEVERITY_RANK = {
    SEVERITY_OK: 0,
    SEVERITY_INFO: 1,
    SEVERITY_WARNING: 2,
    SEVERITY_CRITICAL: 3,
}


# Liquid-dwell state name. Kept as a string so this module does not
# need to import the AnonymizeStatus enum (avoids a layering cycle
# between the recovery classifier and the anonymize models).
_AWAITING_LIQUID_DWELL = "awaiting_liquid_dwell"
_HOPPING = "hopping"


def aggregate_recovery_hints(
    hints: list[RecoveryHint],
) -> Optional[RecoveryHint]:
    """Return the worst-severity hint from a list of per-swap hints.

    The Anonymize tab banner surfaces one row per session, but a
    session can have up to two ``BoltzSwap`` legs (LN↔on-chain and
    Liquid round-trip). The dashboard renders the most urgent of
    the leg-level hints. Ties prefer the first hint passed in
    (caller's ordering wins) so reverse-leg hints take precedence
    over submarine-leg hints when both are at the same severity —
    matches the user's mental model of "preimage already revealed
    is more urgent than waiting for the lockup".

    Returns ``None`` if the input list is empty so callers can
    suppress the ``recovery`` field entirely on sessions with no
    swap rows yet.
    """
    if not hints:
        return None
    worst = hints[0]
    worst_rank = _SEVERITY_RANK.get(worst.severity, 0)
    for h in hints[1:]:
        rank = _SEVERITY_RANK.get(h.severity, 0)
        if rank > worst_rank:
            worst = h
            worst_rank = rank
        elif rank == worst_rank and h.actions and not worst.actions:
            # At equal severity, an actionable hint (one that surfaces a
            # recovery button) wins over an informational one — so a
            # fund-recovery lever is never hidden behind an equally-severe
            # status note. Among equally-actionable ties the first still
            # wins (reverse-leg precedence).
            worst = h
    return worst


def classify_session_recovery_state(
    *,
    status: str,
    updated_at: Optional[datetime],
    pipeline_json: Optional[dict] = None,
    liquid_indexer_reachable: Optional[bool] = None,
    now: Optional[datetime] = None,
) -> Optional[RecoveryHint]:
    """Session-level recovery hint independent of per-swap state.

    Today this only fires for ``awaiting_liquid_dwell`` sessions that
    have been parked longer than the configured Liquid dwell upper
    bound + 1h. The most common cause is an unreachable
    electrs-liquid backend — the hop body cannot observe the
    dwell-output's confirmation depth and the session does not
    advance.

    Returns ``None`` when no session-level hint applies; callers
    should fall back to aggregating per-swap hints in that case.
    """
    if status not in (_AWAITING_LIQUID_DWELL, _HOPPING):
        return None
    if now is None:
        now = _utc_now()
    age = _seconds_since(updated_at, now)
    if age is None:
        return None

    pj = pipeline_json if isinstance(pipeline_json, dict) else {}

    # ── Leg-1 (LN→L-BTC reverse) claim stuck, in HOPPING ──
    # The wallet broadcast its cooperative claim (revealing the preimage,
    # so its LN funds are committed) but it hasn't confirmed. Past the
    # threshold, surface the post-timeout unilateral claim so the operator
    # can land the L-BTC directly. Suppressed once a unilateral claim has
    # been broadcast (waiting for it to confirm) or the claim confirmed.
    if status == _HOPPING:
        claim_stuck = bool(
            pj.get("liquid_lbtc_claim_txid")
            and not pj.get("liquid_lbtc_claim_confirmed")
            and not pj.get("liquid_reverse_unilateral_claim_txid")
        )
        if not claim_stuck or age < LIQUID_REVERSE_CLAIM_STUCK_THRESHOLD_SECONDS:
            return None
        return RecoveryHint(
            state="liquid_reverse_claim_stuck",
            severity=SEVERITY_WARNING,
            headline="Liquid claim stuck — manual claim available",
            detail=(
                "Your Liquid round-trip claimed funds from the swap provider, "
                "but the claim transaction hasn't confirmed. You can broadcast "
                "a direct (post-timeout) claim of your Liquid funds below; this "
                "works even if the swap provider is offline."
            ),
            actions=(ACTION_LIQUID_REVERSE_UNILATERAL_CLAIM,),
            metadata={
                "seconds_since_update": int(age),
                "claim_threshold_seconds": LIQUID_REVERSE_CLAIM_STUCK_THRESHOLD_SECONDS,
            },
        )

    # ── status == _AWAITING_LIQUID_DWELL from here ──
    # A present leg-2 submarine lockup means the wallet has locked L-BTC
    # for the final L-BTC→LN swap and it hasn't settled (settlement would
    # have advanced the session out of awaiting_liquid_dwell). Those funds
    # are recoverable, so use the shorter stuck threshold and offer the
    # refund levers.
    lockup_present = bool(
        isinstance(pipeline_json, dict)
        and pipeline_json.get("liquid_submarine_lock_txid")
        # Once a refund has been broadcast the lockup is spent — stop
        # offering the refund levers.
        and not pipeline_json.get("liquid_submarine_refund_txid")
    )

    # Resolve the upper bound from the frozen pipeline policy when
    # available; otherwise fall back to the module-level constant.
    max_dwell_s: Optional[int] = None
    if isinstance(pipeline_json, dict):
        liquid_block = pipeline_json.get("liquid")
        if isinstance(liquid_block, dict):
            raw = liquid_block.get("dwell_max_seconds")
            if isinstance(raw, (int, float)) and raw > 0:
                max_dwell_s = int(raw)
    if lockup_present:
        threshold = LIQUID_SUBMARINE_STUCK_THRESHOLD_SECONDS
    else:
        threshold = (max_dwell_s + 3600) if max_dwell_s else LIQUID_DWELL_STUCK_THRESHOLD_SECONDS
    if age < threshold:
        return None

    actions: tuple[str, ...] = ()
    if lockup_present:
        actions = (ACTION_LIQUID_COOPERATIVE_REFUND, ACTION_LIQUID_UNILATERAL_REFUND)
        headline = "Liquid swap stuck — refund available"
        detail = (
            "Your Liquid round-trip locked funds for the final swap leg, but "
            "it hasn't settled. You can refund the locked Liquid funds back to "
            "your wallet below — try the cooperative refund first; use the "
            "post-timeout refund only if that fails."
        )
    else:
        headline = "Liquid dwell holding longer than expected"
        if liquid_indexer_reachable is False:
            detail = (
                "Your Liquid round-trip is waiting for confirmations from the "
                "Liquid chain indexer, which is currently unreachable. If you "
                "operate the indexer yourself, check that the Liquid indexer "
                "container is running and synced; the session will resume "
                "automatically once the indexer is back."
            )
        else:
            detail = (
                "Your Liquid round-trip has been holding longer than the "
                "configured maximum dwell. The session will resume "
                "automatically once the Liquid indexer next reports the "
                "dwell output as spendable. No action is needed if the "
                "indexer is healthy."
            )

    return RecoveryHint(
        state="awaiting_liquid_dwell_stuck",
        severity=SEVERITY_WARNING,
        headline=headline,
        detail=detail,
        actions=actions,
        metadata={
            "seconds_since_update": int(age),
            "dwell_threshold_seconds": threshold,
            "liquid_indexer_reachable": liquid_indexer_reachable,
            "liquid_submarine_lockup_present": lockup_present,
        },
    )
