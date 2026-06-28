# SPDX-License-Identifier: MIT
"""
Braiins Deposit Service — round-amount deposit orchestrator.

Drives a multi-step pipeline that converts a Lightning-balance
debit into a "clean" round-amount on-chain send to a Braiins
Hashpower deposit address.

Lifecycle (LN-source only):

    CREATED ──advance()─▶ SWAPPING ──BoltzSwap COMPLETED─▶ FUNDED
                                                              │
                                                              ▼
    COMPLETED ◀── BROADCAST ◀── send_coins ◀── SENDING ◀──────┘

Off-ramps: CANCELLED (user before payment), REFUNDED (Boltz couldn't
settle), FAILED (hard error).
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.boltz_swap import BoltzSwap, SwapStatus
from app.models.braiins_deposit_session import (
    NON_TERMINAL_STATUSES,
    TERMINAL_STATUSES,
    BraiinsDepositFundingStrategy,
    BraiinsDepositSession,
    BraiinsDepositSourceKind,
    BraiinsDepositStatus,
)

logger = logging.getLogger(__name__)


# Canonical round-amount presets. The community-validated set the
# Braiins anti-fraud algorithm reliably clears.
BIN_AMOUNTS: tuple[int, ...] = (
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_000_000,
    3_000_000,
    4_000_000,
    5_000_000,
)

# Exact-amount (``include_extras=False``) dust-risk projection.
#
# When the user opts out of include-extras, the wallet keeps the
# remainder as a change UTXO. Network fees at broadcast time may
# differ from now, so we project the change against a PADDED fee
# rate to estimate the worst-plausible spend cost of that change
# UTXO. If the projected change is below that spend cost the user
# is warned that the change may be economically unspendable
# ("dust"). The threshold itself is computed via the canonical
# ``economic_dust_threshold_sats`` helper in ``dust_safe_send`` so
# the spend-vbytes constant stays in one place.
#
# ``multiplier=2x`` covers typical fee-spike envelopes without
# being so high that every quote triggers the warning.
_EXACT_AMOUNT_FEE_PADDING_MULTIPLIER: float = 2.0

# Coarse default for the final on-chain send fee priority -> vbyte mapping.
# Resolved against the live mempool fee estimates at send time; this
# table is just the fallback when fees aren't available.
_FALLBACK_FEE_VBYTES: dict[str, int] = {
    "low": 2,
    "medium": 6,
    "high": 20,
}


class BraiinsDepositError(Exception):
    """Service-layer hard failure. Caller maps to HTTP / state."""


# Substrings marking a TRANSIENT (recoverable) on-chain-send failure —
# connectivity / shutdown conditions where the send did NOT broadcast and
# the fresh UTXO is still in hand, so the session should stay recoverable
# (left at SENDING → ``_reconcile_after_send_crash`` rolls back to FUNDED
# and retries) rather than terminally FAILED. Mirrors the definitive-vs-
# transient error contract used by the Boltz payment path: only a genuine
# terminal failure should FAIL the session. "Event loop is closed" is the
# shutdown-race case (an in-flight LND call during app teardown).
_TRANSIENT_SEND_MARKERS: tuple[str, ...] = (
    "request failed",
    "connection failed",
    "event loop is closed",
    "timed out",
    "timeout",
    "temporarily unavailable",
    "did not reach a terminal state",
    "proxyerror",
    "proxy error",
    "socks",
    "readtimeout",
    "connecterror",
    "connection refused",
    "service unavailable",
)


def _is_transient_send_error(msg: Optional[str]) -> bool:
    """True if an on-chain-send error looks transient (connectivity /
    shutdown) rather than a definitive failure. Conservative: only known
    markers count as transient; anything unrecognised is treated as a real
    failure (which is still retry-eligible via /retry-send since the fresh
    UTXO is recorded)."""
    if not msg:
        return False
    s = msg.lower()
    return any(marker in s for marker in _TRANSIENT_SEND_MARKERS)


async def _emit_audit(
    db: AsyncSession,
    *,
    action: str,
    session: "BraiinsDepositSession",
    details: Optional[dict[str, Any]] = None,
    success: bool = True,
    error_message: Optional[str] = None,
) -> None:
    """Record a state-transition audit row with the
    relevant txid(s) in ``details``. Imports are local to keep the
    module's import graph minimal at startup.
    """
    try:
        from app.dashboard import DASHBOARD_KEY_ID
        from app.services.audit_service import log_dashboard_action

        source_kind_val = getattr(session, "source_kind", None)
        if source_kind_val is not None and hasattr(source_kind_val, "value"):
            source_kind_val = source_kind_val.value
        merged: dict[str, Any] = {
            "session_id": str(session.id),
            "purpose": "braiins_deposit",
            "source_kind": source_kind_val or "lightning",
            "status": session.status.value,
            "destination_address": session.destination_address,
        }
        if session.fresh_utxo_txid:
            merged["claim_txid"] = session.fresh_utxo_txid
        if session.send_txid:
            merged["send_txid"] = session.send_txid
        if details:
            merged.update(details)
        await log_dashboard_action(
            db,
            DASHBOARD_KEY_ID,
            action,
            "braiins_deposit",
            amount_sats=session.deposit_amount_sats,
            details=merged,
            success=success,
            error_message=error_message,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("braiins_deposit audit emit (%s) failed: %s", action, exc)


class BraiinsDepositQuote:
    """Cheap fee-breakdown shape returned by :meth:`quote`.

    No DB write; pure pricing. The wizard renders this on Step 2 and
    re-submits it back when calling ``POST /sessions`` so the
    server-side re-quote can detect staleness.

    When ``source_kind="onchain"`` the quote also carries
    submarine-side numbers (``submarine_*``) describing the leading
    on-chain → LN leg. ``required_onchain_balance_sats`` is the
    on-chain spend (lockup amount + funding-tx fee headroom);
    ``required_lightning_balance_sats`` is 0 for on-chain source.
    """

    def __init__(
        self,
        *,
        source_kind: str = BraiinsDepositSourceKind.LIGHTNING.value,
        deposit_amount_sats: int,
        invoice_amount_sats: int,
        boltz_percentage_fee_sats: int,
        boltz_miner_fee_sats: int,
        expected_fresh_utxo_sats: int,
        estimated_send_fee_sats: int,
        estimated_routing_fee_sats: int,
        total_fee_sats: int,
        required_lightning_balance_sats: int,
        boltz_min_sat: int,
        boltz_max_sat: int,
        # On-chain-source extras (zero for LN source):
        submarine_invoice_amount_sats: int = 0,
        submarine_lockup_amount_sats: int = 0,
        submarine_percentage_fee_sats: int = 0,
        submarine_miner_fee_sats: int = 0,
        submarine_funding_fee_sats: int = 0,
        required_onchain_balance_sats: int = 0,
        # External-source extras (zero for self-source):
        required_external_deposit_sats: int = 0,
        # Channel-open strategy extras (zero/empty for swap strategy):
        funding_strategy: str = "swap",
        channel_eligible: bool = False,
        channel_ineligible_reason: str = "",
        channel_capacity_sats: int = 0,
        channel_peer_pubkey: str = "",
        channel_peer_label: str = "",
        channel_funding_fee_sats: int = 0,
        channel_reserve_sats: int = 0,
        channel_inbound_gained_sats: int = 0,
        channel_bumped_to_min: bool = False,
        channel_excess_to_ln_sats: int = 0,
        # Dust prevention — arrival projection. Carries the
        # min/max amount the user can expect to land at Braiins
        # given current fee variability. ``feasible=False`` means
        # the wizard should disable this bin at current fees.
        arrival_min_sats: int = 0,
        arrival_max_sats: int = 0,
        arrival_feasible: bool = True,
        arrival_current_fee_rate_vb: int = 0,
        # Per-session send-mode flag. ``True`` (default) =
        # dust-safe no-change send (arrival range > bin amount).
        # ``False`` = exact-amount send with a change UTXO
        # returned to the wallet; ``expected_change_sats``
        # carries the projected change.
        include_extras: bool = True,
        expected_change_sats: int = 0,
        expected_change_dust_risk: bool = False,
        expected_change_dust_threshold_sats: int = 0,
    ) -> None:
        self.source_kind = source_kind
        self.deposit_amount_sats = deposit_amount_sats
        self.invoice_amount_sats = invoice_amount_sats
        self.boltz_percentage_fee_sats = boltz_percentage_fee_sats
        self.boltz_miner_fee_sats = boltz_miner_fee_sats
        self.expected_fresh_utxo_sats = expected_fresh_utxo_sats
        self.estimated_send_fee_sats = estimated_send_fee_sats
        self.estimated_routing_fee_sats = estimated_routing_fee_sats
        self.total_fee_sats = total_fee_sats
        self.required_lightning_balance_sats = required_lightning_balance_sats
        self.boltz_min_sat = boltz_min_sat
        self.boltz_max_sat = boltz_max_sat
        self.submarine_invoice_amount_sats = submarine_invoice_amount_sats
        self.submarine_lockup_amount_sats = submarine_lockup_amount_sats
        self.submarine_percentage_fee_sats = submarine_percentage_fee_sats
        self.submarine_miner_fee_sats = submarine_miner_fee_sats
        self.submarine_funding_fee_sats = submarine_funding_fee_sats
        self.required_onchain_balance_sats = required_onchain_balance_sats
        self.required_external_deposit_sats = required_external_deposit_sats
        self.funding_strategy = funding_strategy
        self.channel_eligible = channel_eligible
        self.channel_ineligible_reason = channel_ineligible_reason
        self.channel_capacity_sats = channel_capacity_sats
        self.channel_peer_pubkey = channel_peer_pubkey
        self.channel_peer_label = channel_peer_label
        self.channel_funding_fee_sats = channel_funding_fee_sats
        self.channel_reserve_sats = channel_reserve_sats
        self.channel_inbound_gained_sats = channel_inbound_gained_sats
        self.channel_bumped_to_min = channel_bumped_to_min
        self.channel_excess_to_ln_sats = channel_excess_to_ln_sats
        self.arrival_min_sats = arrival_min_sats
        self.arrival_max_sats = arrival_max_sats
        self.arrival_feasible = arrival_feasible
        self.arrival_current_fee_rate_vb = arrival_current_fee_rate_vb
        self.include_extras = include_extras
        self.expected_change_sats = expected_change_sats
        self.expected_change_dust_risk = expected_change_dust_risk
        self.expected_change_dust_threshold_sats = expected_change_dust_threshold_sats

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "deposit_amount_sats": self.deposit_amount_sats,
            "invoice_amount_sats": self.invoice_amount_sats,
            "boltz_percentage_fee_sats": self.boltz_percentage_fee_sats,
            "boltz_miner_fee_sats": self.boltz_miner_fee_sats,
            "expected_fresh_utxo_sats": self.expected_fresh_utxo_sats,
            "estimated_send_fee_sats": self.estimated_send_fee_sats,
            "estimated_routing_fee_sats": self.estimated_routing_fee_sats,
            "total_fee_sats": self.total_fee_sats,
            "required_lightning_balance_sats": self.required_lightning_balance_sats,
            "boltz_min_sat": self.boltz_min_sat,
            "boltz_max_sat": self.boltz_max_sat,
            "submarine_invoice_amount_sats": self.submarine_invoice_amount_sats,
            "submarine_lockup_amount_sats": self.submarine_lockup_amount_sats,
            "submarine_percentage_fee_sats": self.submarine_percentage_fee_sats,
            "submarine_miner_fee_sats": self.submarine_miner_fee_sats,
            "submarine_funding_fee_sats": self.submarine_funding_fee_sats,
            "required_onchain_balance_sats": self.required_onchain_balance_sats,
            "required_external_deposit_sats": self.required_external_deposit_sats,
            "funding_strategy": self.funding_strategy,
            "channel_eligible": self.channel_eligible,
            "channel_ineligible_reason": self.channel_ineligible_reason,
            "channel_capacity_sats": self.channel_capacity_sats,
            "channel_peer_pubkey": self.channel_peer_pubkey,
            "channel_peer_label": self.channel_peer_label,
            "channel_funding_fee_sats": self.channel_funding_fee_sats,
            "channel_reserve_sats": self.channel_reserve_sats,
            "channel_inbound_gained_sats": self.channel_inbound_gained_sats,
            "channel_bumped_to_min": self.channel_bumped_to_min,
            "channel_excess_to_ln_sats": self.channel_excess_to_ln_sats,
            "arrival_min_sats": self.arrival_min_sats,
            "arrival_max_sats": self.arrival_max_sats,
            "arrival_feasible": self.arrival_feasible,
            "arrival_current_fee_rate_vb": self.arrival_current_fee_rate_vb,
            "include_extras": self.include_extras,
            "expected_change_sats": self.expected_change_sats,
            "expected_change_dust_risk": self.expected_change_dust_risk,
            "expected_change_dust_threshold_sats": (self.expected_change_dust_threshold_sats),
        }


class BraiinsDepositService:
    """Orchestrates a single Braiins-Deposit session through its
    state machine. Stateless across calls — every operation reads
    the row from the DB and (where it mutates) takes a row lock.
    """

    # Class-level constant so callers can import without instantiating.
    BIN_AMOUNTS: tuple[int, ...] = BIN_AMOUNTS

    def __init__(
        self,
        *,
        boltz_service: Any = None,
        lnd_service: Any = None,
        mempool_fee_service: Any = None,
    ) -> None:
        # Lazy-import the singletons so tests can inject mocks without
        # triggering the production HTTP clients at module import time.
        if boltz_service is None:
            from app.services.boltz_service import boltz_service as _bs

            boltz_service = _bs
        if lnd_service is None:
            from app.services.lnd_service import lnd_service as _ln

            lnd_service = _ln
        if mempool_fee_service is None:
            from app.services.mempool_fee_service import (
                mempool_fee_service as _mp,
            )

            mempool_fee_service = _mp
        self._boltz = boltz_service
        self._lnd = lnd_service
        self._mempool = mempool_fee_service

    # ── Pricing ────────────────────────────────────────────────────

    async def quote(
        self,
        *,
        amount_sats: int,
        source_kind: str = BraiinsDepositSourceKind.LIGHTNING.value,
        include_extras: bool = True,
        funding_strategy: str = BraiinsDepositFundingStrategy.SWAP.value,
    ) -> tuple[Optional[BraiinsDepositQuote], Optional[str]]:
        """Compute the LN-balance debit and fee breakdown for a
        target ``amount_sats`` round deposit.

        ``source_kind="lightning"`` → single reverse swap;
        the LN balance is what's debited.

        ``source_kind="onchain"`` → submarine-then-reverse
        path; the on-chain balance is what's debited, and the quote
        carries both swap-legs' fees.

        ``include_extras`` (default True) selects the dust-safe
        no-change send. When False, the broadcast will send
        exactly ``amount_sats`` and return the remainder to the
        wallet as a change UTXO. The quote response reflects the
        chosen mode: with extras, ``arrival_min_sats < arrival_max_sats``;
        without extras, both collapse to ``amount_sats`` and
        ``expected_change_sats`` carries the projected change.

        Returns ``(quote, None)`` on success or ``(None, error)``.
        Pure: no DB write, no payment activity.
        """
        if amount_sats <= 0:
            return None, "Deposit amount must be positive"
        if source_kind not in (
            BraiinsDepositSourceKind.LIGHTNING.value,
            BraiinsDepositSourceKind.ONCHAIN.value,
            BraiinsDepositSourceKind.EXT_LIGHTNING.value,
            BraiinsDepositSourceKind.EXT_ONCHAIN.value,
        ):
            return None, f"Invalid source_kind: {source_kind}"
        # The ext kill switch hides ext sources at
        # the API layer; the service mirrors the check so internal
        # callers cannot accidentally route an ext quote when the
        # feature is disabled.
        if (
            source_kind
            in (
                BraiinsDepositSourceKind.EXT_LIGHTNING.value,
                BraiinsDepositSourceKind.EXT_ONCHAIN.value,
            )
            and not settings.braiins_deposit_ext_enabled
        ):
            return None, "External sources are disabled by the operator"

        pair_info, err = await self._boltz.get_reverse_pair_info()
        if err or pair_info is None:
            return None, f"Could not fetch swap rates: {err or 'unavailable'}"

        # Boltz reverse-swap fee breakdown.
        # ``fees_percentage`` is the operator's percentage of the
        # invoice. ``fees_miner_lockup + fees_miner_claim`` is the
        # combined chain fee Boltz subtracts from the on-chain
        # output (we pay the lockup; the claim leaves the wallet).
        try:
            boltz_pct = float(pair_info.get("fees_percentage", 0.0))
        except (TypeError, ValueError):
            boltz_pct = 0.0
        miner_lockup = int(pair_info.get("fees_miner_lockup", 0) or 0)
        miner_claim = int(pair_info.get("fees_miner_claim", 0) or 0)
        boltz_min = int(pair_info.get("min", 0) or 0)
        boltz_max = int(pair_info.get("max", 0) or 0)

        # Estimated on-chain send fee for the round-amount tx that
        # spends our fresh UTXO -> Braiins. Single-input single-output
        # P2TR spend is ~110 vbytes; the fallback covers the case
        # where ``mempool_fee_service`` can't be reached.
        vbytes = 110
        priority = settings.braiins_deposit_send_fee_priority
        sat_per_vbyte = _FALLBACK_FEE_VBYTES.get(priority, 6)
        try:
            fees, fee_err = await self._mempool.get_recommended_fees()
        except Exception:  # noqa: BLE001
            fees, fee_err = None, "unavailable"
        if fees and not fee_err:
            # mempool_fee_service returns a dict shape like
            # {"fastestFee": ..., "halfHourFee": ..., "hourFee": ...}.
            key = {
                "high": "fastestFee",
                "medium": "halfHourFee",
                "low": "hourFee",
            }.get(priority, "halfHourFee")
            v = fees.get(key)
            if isinstance(v, (int, float)) and v > 0:
                sat_per_vbyte = max(1, int(v))
        estimated_send_fee_sats = vbytes * sat_per_vbyte

        # Buffer absorbs fee drift between quote and send. The
        # change output coming back to the wallet is approximately
        # the buffer size; if fees spike, the buffer absorbs and
        # the change shrinks toward zero.
        buffer_sats = int(settings.braiins_deposit_safety_buffer_sats)

        # Target on-chain output (post-Boltz-claim) = amount + send
        # fee + buffer. Working backward to the invoice amount
        # (pre-claim) means inflating by Boltz fees.
        target_onchain = amount_sats + estimated_send_fee_sats + buffer_sats
        # Boltz subtracts ``miner_claim`` AND ``invoice * pct`` from
        # the invoice to get the on-chain amount. Solve for invoice:
        #     onchain = invoice * (1 - pct/100) - miner_claim
        # ->  invoice = (onchain + miner_claim) / (1 - pct/100)
        pct_factor = max(0.0001, 1.0 - boltz_pct / 100.0)
        invoice_amount_sats = int(
            (target_onchain + miner_claim) / pct_factor + 0.999  # round up
        )

        # Boltz takes its pct off the invoice; this is what they keep.
        boltz_percentage_fee_sats = max(0, int(invoice_amount_sats * boltz_pct / 100.0))

        expected_fresh_utxo_sats = invoice_amount_sats - boltz_percentage_fee_sats - miner_claim

        # 3% LN routing fee headroom mirrors the existing cold-storage
        # path's default (``routing_fee_limit_percent`` in boltz_tasks).
        # The actual paid routing fee is usually a small fraction of
        # this — we only need to RESERVE enough so payment can succeed.
        estimated_routing_fee_sats = int(invoice_amount_sats * 0.03)

        total_fee_sats = (
            boltz_percentage_fee_sats
            + miner_claim
            + miner_lockup
            + estimated_send_fee_sats
            + estimated_routing_fee_sats
        )

        required_lightning_balance_sats = invoice_amount_sats + estimated_routing_fee_sats

        # ── On-chain source extras ──────────────────────
        #
        # For ``source_kind="onchain"`` or ``source_kind="ext_onchain"``,
        # prepend a submarine swap that delivers
        # ``invoice_amount_sats + routing_headroom`` to our Lightning
        # balance. The wallet then funds Boltz's lockup with extra sats
        # to absorb the submarine pct fee and miner fee. For ext-OC the
        # math is the same — the wallet's on-chain balance has just been
        # bumped by the user's deposit, so the submarine leg is funded
        # from those sats.
        submarine_invoice_amount_sats = 0
        submarine_lockup_amount_sats = 0
        submarine_percentage_fee_sats = 0
        submarine_miner_fee_sats = 0
        submarine_funding_fee_sats = 0
        required_onchain_balance_sats = 0
        # The submarine leg is only used by the "swap" strategy. The
        # "channel" strategy (handled further down) replaces it entirely,
        # so we skip the submarine math + its pair-info fetch here.
        if (
            source_kind
            in (
                BraiinsDepositSourceKind.ONCHAIN.value,
                BraiinsDepositSourceKind.EXT_ONCHAIN.value,
            )
            and funding_strategy == BraiinsDepositFundingStrategy.SWAP.value
        ):
            sub_pair_info, sub_err = await self._boltz.get_submarine_pair_info()
            if sub_err or sub_pair_info is None:
                return None, (f"Could not fetch submarine swap rates: {sub_err or 'unavailable'}")
            try:
                sub_pct = float(sub_pair_info.get("fees_percentage", 0.1))
            except (TypeError, ValueError):
                sub_pct = 0.1
            sub_miner_lockup = int(sub_pair_info.get("fees_miner_lockup", 0) or 0)
            sub_min = int(sub_pair_info.get("min", 0) or 0)
            sub_max = int(sub_pair_info.get("max", 0) or 0)

            # The submarine invoice is what we want to RECEIVE on LN.
            # We need enough LN to pay the reverse-swap invoice +
            # routing headroom, so target = invoice_amount_sats +
            # estimated_routing_fee_sats.
            submarine_invoice_amount_sats = invoice_amount_sats + estimated_routing_fee_sats

            # Validate the submarine invoice amount falls within
            # Boltz's published submarine-pair limits before
            # ``create_submarine_swap`` is ever called. The user-
            # facing error here is much clearer than the one we'd
            # get back from Boltz mid-flow.
            if sub_min > 0 and submarine_invoice_amount_sats < sub_min:
                return None, (
                    f"This deposit amount is below the submarine swap "
                    f"minimum ({sub_min:,} sats). Try a larger deposit, "
                    "or use Lightning source instead."
                )
            if sub_max > 0 and submarine_invoice_amount_sats > sub_max:
                return None, (
                    f"This deposit amount is above the submarine swap "
                    f"maximum ({sub_max:,} sats). Try a smaller deposit, "
                    "or use Lightning source instead."
                )

            # Boltz charges ``sub_pct%`` of the invoice + the lockup
            # miner fee. The user funds the lockup with
            #     lockup_amount = invoice * (1 + pct/100) + miner_lockup
            pct_uplift = max(0.0, sub_pct / 100.0)
            submarine_percentage_fee_sats = int(submarine_invoice_amount_sats * pct_uplift + 0.999)
            submarine_miner_fee_sats = sub_miner_lockup
            submarine_lockup_amount_sats = (
                submarine_invoice_amount_sats + submarine_percentage_fee_sats + submarine_miner_fee_sats
            )

            # On-chain funding-tx fee for the user's send to Boltz's
            # lockup address. ~140 vbytes for a 1-in 2-out send.
            submarine_funding_fee_sats = max(1, 140 * sat_per_vbyte)
            required_onchain_balance_sats = submarine_lockup_amount_sats + submarine_funding_fee_sats

            # The LN balance is bumped by the submarine leg, so the
            # operator doesn't need ANY pre-existing LN balance.
            required_lightning_balance_sats = 0

            # Roll the submarine-side fees into the total.
            total_fee_sats = (
                total_fee_sats + submarine_percentage_fee_sats + submarine_miner_fee_sats + submarine_funding_fee_sats
            )

        # ── External-source intake amount ─────────────────
        #
        # ``required_external_deposit_sats`` is the number we surface
        # to the user on the await_funds screen — what they pay /
        # send from their other wallet. For ext-LN it equals the
        # Boltz reverse-swap invoice amount (the user pays Boltz's
        # invoice directly). For ext-OC it equals the wallet's intake
        # threshold (the user's deposit funds the submarine leg).
        # Both balance gates are zero for ext sources because we
        # don't gate on Agent-Wallet balance.
        required_external_deposit_sats = 0
        if source_kind == BraiinsDepositSourceKind.EXT_LIGHTNING.value:
            required_external_deposit_sats = invoice_amount_sats
            required_lightning_balance_sats = 0
        elif source_kind == BraiinsDepositSourceKind.EXT_ONCHAIN.value:
            required_external_deposit_sats = required_onchain_balance_sats
            required_onchain_balance_sats = 0

        # ── Channel-open strategy (on-chain sources) ───────────────
        #
        # Instead of a submarine swap, fund the deposit by OPENING a
        # channel to Megalithic and running the (unchanged) reverse swap
        # out of it. The channel is sized UP from the bin so its usable
        # outbound (capacity − reserve − safety) covers the reverse-swap
        # invoice; ~bin then arrives at Braiins, and the drained channel
        # leaves ~invoice-sized inbound capacity behind.
        channel_eligible = False
        channel_ineligible_reason = ""
        channel_capacity_sats = 0
        channel_peer_pubkey = ""
        channel_peer_label = ""
        channel_funding_fee_sats = 0
        channel_reserve_sats = 0
        channel_inbound_gained_sats = 0
        channel_bumped_to_min = False
        channel_excess_to_ln_sats = 0
        if funding_strategy == BraiinsDepositFundingStrategy.CHANNEL.value and source_kind in (
            BraiinsDepositSourceKind.ONCHAIN.value,
            BraiinsDepositSourceKind.EXT_ONCHAIN.value,
        ):
            from app.services import braiins_channel_peers as _peers

            if boltz_min and invoice_amount_sats < boltz_min:
                channel_ineligible_reason = f"below the swap minimum (~{boltz_min:,} sats)"
            elif boltz_max and invoice_amount_sats > boltz_max:
                channel_ineligible_reason = f"above the swap maximum (~{boltz_max:,} sats)"
            else:
                channel_capacity_sats = _peers.size_channel_capacity(invoice_amount_sats)
                peer = _peers.select_peer_for_capacity(channel_capacity_sats)
                # Below the smallest peer's minimum channel size? Bump the
                # capacity UP to that floor and use that peer — channels
                # have a minimum, so a small deposit opens a min-size
                # channel; the excess becomes the user's Lightning balance.
                if peer is None:
                    floor_peer = _peers.smallest_peer()
                    if (
                        floor_peer is not None
                        and channel_capacity_sats < floor_peer.min_sats
                        and (not floor_peer.max_sats or floor_peer.min_sats <= floor_peer.max_sats)
                    ):
                        channel_capacity_sats = floor_peer.min_sats
                        peer = floor_peer
                        channel_bumped_to_min = True
                if peer is None:
                    channel_ineligible_reason = "this amount is outside the channel-open range"
                else:
                    # Channel funding tx (~1-in/2-out P2TR ≈ 200 vbytes) at
                    # the channel fee priority.
                    channel_priority = settings.braiins_deposit_channel_fee_priority
                    chan_vb = _FALLBACK_FEE_VBYTES.get(channel_priority, 6)
                    if fees and not fee_err:
                        ckey = {
                            "high": "fastestFee",
                            "medium": "halfHourFee",
                            "low": "hourFee",
                        }.get(channel_priority, "halfHourFee")
                        cv = fees.get(ckey)
                        if isinstance(cv, (int, float)) and cv > 0:
                            chan_vb = max(1, int(cv))
                    channel_funding_fee_sats = 200 * chan_vb
                    channel_reserve_sats = int(channel_capacity_sats * _peers.RESERVE_PCT)
                    channel_inbound_gained_sats = invoice_amount_sats
                    # Spendable Lightning balance left in the new channel
                    # after the reverse swap pushes out the invoice amount
                    # and the reserve is held back. Tiny for a naturally-
                    # sized channel; large when the capacity was bumped up
                    # to the peer's minimum for a small deposit.
                    channel_excess_to_ln_sats = max(
                        0,
                        channel_capacity_sats - invoice_amount_sats - channel_reserve_sats,
                    )
                    # Display the peer we'll actually try FIRST: the small
                    # band attempts the cheapest small-channel-catalog peer
                    # (then falls back through the list at open time), while
                    # the large band stays on the proper node. Sizing above
                    # is unchanged (keyed off the configured presets), so this
                    # only changes the quoted peer label/pubkey shown to the
                    # user. Falls back to the sizing peer if the catalog is
                    # empty (non-mainnet / kill-switch).
                    _open_cands = _peers.channel_open_candidates(
                        channel_capacity_sats, network=settings.bitcoin_network
                    )
                    _display_peer = _open_cands[0] if _open_cands else peer
                    channel_peer_pubkey = _display_peer.pubkey
                    channel_peer_label = _display_peer.label
                    channel_eligible = True
                    # The channel funds the LN leg, so no LN balance is
                    # required; the on-chain spend / intake becomes the
                    # channel-sized figure.
                    required_lightning_balance_sats = 0
                    channel_required_onchain = channel_capacity_sats + channel_funding_fee_sats
                    if source_kind == BraiinsDepositSourceKind.ONCHAIN.value:
                        required_onchain_balance_sats = channel_required_onchain
                        required_external_deposit_sats = 0
                    else:  # EXT_ONCHAIN
                        required_external_deposit_sats = channel_required_onchain
                        required_onchain_balance_sats = 0
                    # Base total_fee already carries the reverse-swap fees
                    # (submarine block was skipped); add the funding-tx fee.
                    total_fee_sats = total_fee_sats + channel_funding_fee_sats

        # Dust prevention — project the arrival range. The
        # wallet broadcasts a NO-CHANGE send tx: the entire fresh
        # UTXO (≈ ``expected_fresh_utxo_sats``) is spent to Braiins
        # minus the network fee at send time. Since the fee at send
        # time isn't known yet, we project a min/max based on the
        # high/low fee priorities for the user's bin amount.
        #
        # When the user has opted into "exact amount" mode
        # (``include_extras=False``), we collapse the arrival range
        # to exactly the bin amount and compute the projected
        # change instead. Feasibility then requires the UTXO to
        # cover ``amount_sats + send_fee_at_high_priority``.
        expected_change_sats = 0
        expected_change_dust_risk = False
        expected_change_dust_threshold_sats = 0
        if include_extras:
            arrival_min_sats, arrival_max_sats, arrival_feasible = self._project_arrival_range_for_quote(
                expected_fresh_utxo_sats=expected_fresh_utxo_sats,
                bin_amount_sats=amount_sats,
                live_fees=fees if (fees and not fee_err) else None,
                fallback_priority=priority,
            )
        else:
            arrival_min_sats = amount_sats
            arrival_max_sats = amount_sats
            # Project the change at the current (priority) feerate.
            # ~140 vbytes covers a 1-in/2-out P2TR send (a hair
            # bigger than the no-change tx). Shared with the
            # dust-safe send module so the two stay aligned.
            from app.services.dust_safe_send import (
                _DEFAULT_ESTIMATED_VBYTES as _WITH_CHANGE_VBYTES,
            )

            with_change_vbytes = _WITH_CHANGE_VBYTES
            with_change_fee_sats = with_change_vbytes * sat_per_vbyte
            projected_change = expected_fresh_utxo_sats - amount_sats - with_change_fee_sats
            expected_change_sats = max(0, int(projected_change))
            # Feasible iff the UTXO covers the bin amount + the
            # send fee at the SAME priority the broadcast path
            # will pick. We don't need to project at high-fee
            # extremes because exact-amount mode doesn't have a
            # fee-buffer story; either the math works or it doesn't.
            arrival_feasible = expected_fresh_utxo_sats >= amount_sats + with_change_fee_sats
            # Dust-risk projection — at CURRENT fees the change
            # exists (``expected_change_sats > 0``), but the user
            # has to spend that change LATER, and fees usually
            # only go up from here. Model a worst-plausible future
            # spend cost (current * multiplier, floored to at
            # least current+1 sat/vB) and ask: at that rate, would
            # spending the change UTXO alone cost more than it's
            # worth? If so, raise a soft warning. The warning is
            # advisory only — we do NOT change feasibility, so the
            # user can still proceed if they understand the risk.
            padded_sat_per_vb = max(
                sat_per_vbyte + 1,
                int(round(sat_per_vbyte * _EXACT_AMOUNT_FEE_PADDING_MULTIPLIER)),
            )
            from app.services.dust_safe_send import (
                economic_dust_threshold_sats,
            )

            expected_change_dust_threshold_sats = economic_dust_threshold_sats(padded_sat_per_vb)
            expected_change_dust_risk = bool(
                expected_change_sats > 0 and expected_change_sats < expected_change_dust_threshold_sats
            )

        return (
            BraiinsDepositQuote(
                source_kind=source_kind,
                deposit_amount_sats=amount_sats,
                invoice_amount_sats=invoice_amount_sats,
                boltz_percentage_fee_sats=boltz_percentage_fee_sats,
                boltz_miner_fee_sats=miner_lockup + miner_claim,
                expected_fresh_utxo_sats=expected_fresh_utxo_sats,
                estimated_send_fee_sats=estimated_send_fee_sats,
                estimated_routing_fee_sats=estimated_routing_fee_sats,
                total_fee_sats=total_fee_sats,
                required_lightning_balance_sats=required_lightning_balance_sats,
                boltz_min_sat=boltz_min,
                boltz_max_sat=boltz_max,
                submarine_invoice_amount_sats=submarine_invoice_amount_sats,
                submarine_lockup_amount_sats=submarine_lockup_amount_sats,
                submarine_percentage_fee_sats=submarine_percentage_fee_sats,
                submarine_miner_fee_sats=submarine_miner_fee_sats,
                submarine_funding_fee_sats=submarine_funding_fee_sats,
                required_onchain_balance_sats=required_onchain_balance_sats,
                required_external_deposit_sats=required_external_deposit_sats,
                funding_strategy=funding_strategy,
                channel_eligible=channel_eligible,
                channel_ineligible_reason=channel_ineligible_reason,
                channel_capacity_sats=channel_capacity_sats,
                channel_peer_pubkey=channel_peer_pubkey,
                channel_peer_label=channel_peer_label,
                channel_funding_fee_sats=channel_funding_fee_sats,
                channel_reserve_sats=channel_reserve_sats,
                channel_inbound_gained_sats=channel_inbound_gained_sats,
                channel_bumped_to_min=channel_bumped_to_min,
                channel_excess_to_ln_sats=channel_excess_to_ln_sats,
                arrival_min_sats=arrival_min_sats,
                arrival_max_sats=arrival_max_sats,
                arrival_feasible=arrival_feasible,
                arrival_current_fee_rate_vb=sat_per_vbyte,
                include_extras=include_extras,
                expected_change_sats=expected_change_sats,
                expected_change_dust_risk=expected_change_dust_risk,
                expected_change_dust_threshold_sats=(expected_change_dust_threshold_sats),
            ),
            None,
        )

    def _project_arrival_range_for_quote(
        self,
        *,
        expected_fresh_utxo_sats: int,
        bin_amount_sats: int,
        live_fees: dict | None,
        fallback_priority: str,
    ) -> tuple[int, int, bool]:
        """Compute (min_arrival, max_arrival, feasible) for the
        dust-safe send. Min = arrival at "high" fee priority,
        max = arrival at "low" priority. Feasible iff both
        projections are >= bin amount (we never broadcast a tx
        that would underpay the bin).

        Falls back to ``_FALLBACK_FEE_VBYTES`` when live fees
        aren't available — the same fall-through the actual send
        step uses, so the projection mirrors the broadcast-time
        decision the wallet would make.
        """
        from app.services.dust_safe_send import project_no_change_send

        def _rate_for(priority: str) -> int:
            base = _FALLBACK_FEE_VBYTES.get(priority, 6)
            if not live_fees:
                return base
            key = {
                "high": "fastestFee",
                "medium": "halfHourFee",
                "low": "hourFee",
            }.get(priority, "halfHourFee")
            v = live_fees.get(key)
            if isinstance(v, (int, float)) and v > 0:
                return max(1, int(v))
            return base

        high_rate = _rate_for("high")
        low_rate = _rate_for("low")

        high_proj = project_no_change_send(
            source_value_sats=expected_fresh_utxo_sats,
            sat_per_vbyte=high_rate,
        )
        low_proj = project_no_change_send(
            source_value_sats=expected_fresh_utxo_sats,
            sat_per_vbyte=low_rate,
        )
        # If either projection is infeasible (UTXO can't cover the
        # fee), the deposit is infeasible at current fees. Surface
        # that to the wizard so the bin button can be disabled.
        if high_proj is None or low_proj is None:
            return 0, 0, False
        arrival_min = high_proj.arrived_at_destination  # high fee → smallest arrival
        arrival_max = low_proj.arrived_at_destination  # low fee → largest arrival
        # Feasible only if even the high-fee projection covers the
        # bin amount the user committed to.
        feasible = arrival_min >= int(bin_amount_sats)
        return arrival_min, arrival_max, feasible

    # ── Inbound pre-flight gate ─────────────────────────────────────

    async def _inbound_preflight(self, *, receive_sats: int) -> tuple[Optional[str], Optional[str]]:
        """Check whether THIS node can plausibly RECEIVE ``receive_sats``
        over Lightning — the necessary condition for the submarine leg
        of an on-chain deposit (Boltz pays our invoice).

        Returns ``(refusal, warning)``:
        - ``refusal`` (str) → a friendly, Lightning-recommending message
          when total inbound can't cover the amount; the caller must
          refuse before any on-chain lockup.
        - ``warning`` (str) → an advisory note when total inbound covers
          the amount but no single channel does (relies on Boltz MPP);
          non-blocking.

        Best-effort: returns ``(None, None)`` (allow) on any LND error or
        non-positive amount so a transient failure never blocks a deposit.
        """
        if receive_sats <= 0:
            return None, None
        cap, cap_err = await self._lnd.inbound_capacity()
        if cap_err is not None or cap is None:
            logger.warning(
                "BraiinsDeposit inbound pre-flight skipped (LND error): %s",
                cap_err,
            )
            return None, None
        total_in = int(cap.get("total_receivable_sats", 0) or 0)
        largest_in = int(cap.get("largest_channel_receivable_sats", 0) or 0)
        # Small headroom over the bare amount — Boltz pays the invoice
        # exactly, but channels need slack for the in-flight HTLC.
        margin = max(1000, receive_sats // 100)
        if total_in < receive_sats + margin:
            return (
                f"This on-chain deposit needs your node to receive "
                f"~{receive_sats:,} sats over Lightning from the swap "
                f"provider, but your inbound capacity is only "
                f"~{total_in:,} sats. Use a Lightning deposit instead, or "
                f"add inbound liquidity.",
                None,
            )
        if largest_in < receive_sats:
            return None, (f"single_channel_inbound={largest_in} < receive={receive_sats}; relies on Boltz MPP")
        return None, None

    async def _inbound_routability_probe(self, *, receive_sats: int) -> tuple[Optional[str], Optional[str]]:
        """Tier 2 — best-effort inbound routability probe.

        Asks LND whether a route exists from Boltz's LN node → our node
        for ``receive_sats`` (the submarine receive amount). This is the
        necessary signal the bare capacity gate can't give: capacity may
        be ample yet Boltz still can't *reach* us.

        Returns ``(refusal, warning)``:
        - ``refusal`` (str) → only when a confident "no route" is found
          AND ``braiins_deposit_routability_probe_enforce`` is set.
        - ``warning`` (str) → advisory note on a confident "no route"
          when enforcement is off (default).

        Strictly best-effort and ADVISORY by default: the local graph
        view can't model Boltz's fees / htlc-limits / live-liquidity /
        MPP, so "route found" does NOT guarantee success and a probe
        error never blocks. Returns ``(None, None)`` (allow) on any
        missing-input / probe error, when disabled, or on a non-positive
        amount.
        """
        if receive_sats <= 0:
            return None, None
        if not settings.braiins_deposit_routability_probe_enabled:
            return None, None

        boltz_pubkeys, b_err = await self._boltz.get_ln_node_pubkeys()
        if b_err is not None or not boltz_pubkeys:
            logger.info(
                "BraiinsDeposit routability probe skipped (Boltz nodes unavailable): %s",
                b_err,
            )
            return None, None

        info, i_err = await self._lnd.get_info()
        our_pubkey = (info or {}).get("identity_pubkey") if info else None
        if i_err is not None or not our_pubkey:
            logger.info(
                "BraiinsDeposit routability probe skipped (no local pubkey): %s",
                i_err,
            )
            return None, None

        # Probe with a generous fee allowance so a route isn't masked by
        # fee limits — Boltz pays the routing fee; we only care whether a
        # path exists.
        fee_limit = max(int(receive_sats), 1)
        any_route = False
        saw_no_route = False
        saw_probe_error = False
        for pk in boltz_pubkeys:
            quote, err = await self._lnd.query_routes(
                dest_pubkey_hex=our_pubkey,
                amount_sats=int(receive_sats),
                source_pubkey_hex=pk,
                fee_limit_sats=fee_limit,
            )
            if quote is not None:
                any_route = True
                break
            if err and "no route" in err.lower():
                saw_no_route = True
            else:
                saw_probe_error = True

        if any_route:
            return None, None
        # Only act on a CLEAN, unambiguous no-route signal: every probed
        # node said "no route" with no transient errors that could have
        # masked an existing path.
        if not saw_no_route or saw_probe_error:
            return None, None

        if settings.braiins_deposit_routability_probe_enforce:
            return (
                f"This on-chain deposit can't currently be completed: "
                f"there's no Lightning route from the swap provider to "
                f"your node for ~{receive_sats:,} sats. Use a Lightning "
                f"deposit instead, or add/rebalance inbound liquidity.",
                None,
            )
        return None, (f"routability_probe=no_route receive={receive_sats}")

    # ── Session creation ────────────────────────────────────────────

    @staticmethod
    async def _lock_in_flight_create(db: AsyncSession, api_key_id: UUID) -> None:
        """Per-key advisory lock serializing concurrent session creates.

        PostgreSQL-only (``pg_advisory_xact_lock``); released at
        transaction end. No-op on other dialects (e.g. SQLite in tests),
        where executing the unknown function would poison the
        transaction.
        """
        from sqlalchemy import text

        try:
            dialect_name = db.get_bind().dialect.name
        except Exception:  # noqa: BLE001
            dialect_name = ""
        if dialect_name != "postgresql":
            return
        # Two-int form: a fixed namespace + a 32-bit hash of the api key,
        # so the lock is scoped per key (concurrent creates for DIFFERENT
        # keys don't serialize against each other).
        namespace = 0x42B4  # "BraiinsDeposit create" namespace
        key32 = (api_key_id.int & 0x7FFFFFFF)
        try:
            await db.execute(
                text("SELECT pg_advisory_xact_lock(:ns, :k)"),
                {"ns": namespace, "k": key32},
            )
        except Exception:  # noqa: BLE001
            pass

    async def create_session(
        self,
        db: AsyncSession,
        *,
        api_key_id: UUID,
        amount_sats: int,
        destination_address: str,
        source_kind: str = BraiinsDepositSourceKind.LIGHTNING.value,
        include_extras: bool = True,
        funding_strategy: str = BraiinsDepositFundingStrategy.SWAP.value,
    ) -> tuple[Optional[BraiinsDepositSession], Optional[str]]:
        """Insert a CREATED row. Caller is expected to have validated
        the destination + checked the relevant balance via ``quote()``
        already.

        ``source_kind`` decides whether the first state transition is
        ``CREATED → SWAPPING`` (lightning source) or
        ``CREATED → SUBMARINE_SWAPPING → SWAPPING`` (onchain
        source). The state-machine advance loop reads ``source_kind``
        from the row to pick the branch.

        Refuses if the user already has an in-flight session (one at
        a time).
        """
        if source_kind not in (
            BraiinsDepositSourceKind.LIGHTNING.value,
            BraiinsDepositSourceKind.ONCHAIN.value,
            BraiinsDepositSourceKind.EXT_LIGHTNING.value,
            BraiinsDepositSourceKind.EXT_ONCHAIN.value,
        ):
            return None, f"Invalid source_kind: {source_kind}"
        if (
            source_kind
            in (
                BraiinsDepositSourceKind.EXT_LIGHTNING.value,
                BraiinsDepositSourceKind.EXT_ONCHAIN.value,
            )
            and not settings.braiins_deposit_ext_enabled
        ):
            return None, "External sources are disabled by the operator"

        # Funding-strategy validation. The channel-open strategy applies
        # only to on-chain sources and requires the operator flag.
        if funding_strategy not in (
            BraiinsDepositFundingStrategy.SWAP.value,
            BraiinsDepositFundingStrategy.CHANNEL.value,
        ):
            return None, f"Invalid funding_strategy: {funding_strategy}"
        is_channel = funding_strategy == BraiinsDepositFundingStrategy.CHANNEL.value
        if is_channel:
            if not settings.braiins_deposit_channel_open_enabled:
                return None, "Channel-open deposits are disabled by the operator"
            if source_kind not in (
                BraiinsDepositSourceKind.ONCHAIN.value,
                BraiinsDepositSourceKind.EXT_ONCHAIN.value,
            ):
                return None, ("Channel-open funding only applies to on-chain sources")

        # Cap of one in-flight session per api_key. Take a per-key
        # Postgres advisory lock so the check-then-insert below is
        # atomic against a concurrent create
        # for the same key (two requests could otherwise both pass the
        # existence check and both insert). No-op on non-Postgres (e.g.
        # SQLite in tests).
        await self._lock_in_flight_create(db, api_key_id)
        existing_q = (
            select(BraiinsDepositSession)
            .where(BraiinsDepositSession.api_key_id == api_key_id)
            .where(BraiinsDepositSession.status.in_([s.value for s in NON_TERMINAL_STATUSES]))
            .limit(1)
        )
        existing = (await db.execute(existing_q)).scalar_one_or_none()
        if existing is not None:
            return None, "in_flight_session_exists"

        # Inbound pre-flight for on-chain sources. The submarine leg
        # requires THIS node to RECEIVE the swap amount over Lightning
        # from Boltz; if our inbound capacity can't possibly cover it,
        # refuse now — before any on-chain lockup — and steer to the
        # Lightning-source path. Best-effort: skip on quote/LND error.
        # The channel strategy deliberately needs NO inbound (its reverse
        # swap is outbound-only), so the inbound gate/probe is bypassed for
        # it — else it would refuse exactly the deposits this path rescues.
        mpp_warning: Optional[str] = None
        probe_warning: Optional[str] = None
        if (
            source_kind
            in (
                BraiinsDepositSourceKind.ONCHAIN.value,
                BraiinsDepositSourceKind.EXT_ONCHAIN.value,
            )
            and not is_channel
        ):
            pf_quote, pf_err = await self.quote(
                amount_sats=amount_sats,
                source_kind=source_kind,
                include_extras=bool(include_extras),
            )
            if pf_err is None and pf_quote is not None:
                receive_sats = int(pf_quote.submarine_invoice_amount_sats)
                refusal, mpp_warning = await self._inbound_preflight(receive_sats=receive_sats)
                if refusal is not None:
                    return None, refusal
                # Tier 2 — routability probe (capacity is OK; can Boltz
                # actually reach us?). Refuses only under the enforce
                # setting; otherwise records an advisory warning.
                probe_refusal, probe_warning = await self._inbound_routability_probe(receive_sats=receive_sats)
                if probe_refusal is not None:
                    return None, probe_refusal

        created_detail = (
            f"source_kind={source_kind} funding_strategy={funding_strategy} include_extras={bool(include_extras)}"
        )
        if mpp_warning:
            created_detail = f"{created_detail} inbound_warning={mpp_warning}"
        if probe_warning:
            created_detail = f"{created_detail} probe_warning={probe_warning}"

        session = BraiinsDepositSession(
            api_key_id=api_key_id,
            deposit_amount_sats=amount_sats,
            destination_address=destination_address,
            source_kind=BraiinsDepositSourceKind(source_kind),
            funding_strategy=BraiinsDepositFundingStrategy(funding_strategy),
            # The final send (fresh UTXO → Braiins) is identical across all
            # sources, so the include-extras choice (whole-UTXO no-change vs
            # exact-bin-with-change) applies to the channel path exactly as
            # it does to Lightning. Respect the user's choice for every
            # source. (The channel *reserve* is a separate in-channel
            # leftover, unrelated to this on-chain send-step decision.)
            include_extras=bool(include_extras),
            status=BraiinsDepositStatus.CREATED,
            status_history=[
                {
                    "status": BraiinsDepositStatus.CREATED.value,
                    "timestamp": _utc_iso(),
                    "detail": created_detail,
                }
            ],
        )
        db.add(session)
        await db.commit()
        await db.refresh(session)
        return session, None

    # ── Read API ────────────────────────────────────────────────────

    async def get_session_by_id(self, db: AsyncSession, session_id: UUID) -> Optional[BraiinsDepositSession]:
        result = await db.execute(select(BraiinsDepositSession).where(BraiinsDepositSession.id == session_id))
        return result.scalar_one_or_none()

    async def list_recent_sessions(
        self,
        db: AsyncSession,
        *,
        api_key_id: Optional[UUID] = None,
        limit: int = 20,
    ) -> list[BraiinsDepositSession]:
        q = select(BraiinsDepositSession).order_by(BraiinsDepositSession.created_at.desc())
        if api_key_id is not None:
            q = q.where(BraiinsDepositSession.api_key_id == api_key_id)
        result = await db.execute(q.limit(limit))
        return list(result.scalars().all())

    # ── User actions ────────────────────────────────────────────────

    async def cancel_session(
        self,
        db: AsyncSession,
        session_id: UUID,
    ) -> tuple[bool, Optional[str]]:
        """User-initiated cancel. Allowed when:
          * status == CREATED (Boltz swap hasn't been requested yet), OR
          * status == SWAPPING AND the linked BoltzSwap is still in
            its own CREATED state (i.e., our LN payment hasn't been
            sent). In that case we also tell Boltz to cancel the swap.

        Once Boltz has settled the LN HTLC there is no safe way to
        unwind, so cancel after that point is refused; the session
        will reach REFUNDED on its own if Boltz can't complete, or
        FUNDED if it can.
        """
        session = await self._select_for_update(db, session_id)
        if session is None:
            return False, "Session not found or locked by another worker"
        if session.status == BraiinsDepositStatus.CREATED:
            session.record_transition(
                BraiinsDepositStatus.CANCELLED,
                detail="user cancelled before payment",
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_cancelled",
                session=session,
                details={"reason": "user_cancel_pre_swap"},
            )
            return True, None
        if session.status == BraiinsDepositStatus.SWAPPING:
            # Inspect the linked Boltz swap. If our LN payment hasn't
            # started, cancel both sides.
            if session.boltz_swap_id is None:
                return False, "Cancel not available (missing swap link)"
            swap = await self._get_boltz_swap(db, session.boltz_swap_id)
            if swap is None:
                return False, "Cancel not available (swap row gone)"
            if swap.status != SwapStatus.CREATED:
                return False, (
                    "Cancel is only available before the Lightning payment is sent. "
                    "The session will continue and either complete or refund automatically."
                )
            ok, err = await self._boltz.cancel_swap(db, swap)
            if not ok:
                return False, f"Could not cancel Boltz swap: {err or 'unknown'}"
            session.record_transition(
                BraiinsDepositStatus.CANCELLED,
                detail="user cancelled before LN payment",
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_cancelled",
                session=session,
                details={"reason": "user_cancel_pre_payment"},
            )
            return True, None
        if session.status == BraiinsDepositStatus.SUBMARINE_SWAPPING:
            # Once we've broadcast the lockup-funding tx,
            # the on-chain funds are out of our wallet and recovery
            # has to go through Boltz's cooperative refund or the
            # script-path timeout. We don't claim to "cancel" that;
            # the user just has to wait. Refuse cleanly.
            return False, (
                "Cancel isn't available once your on-chain funds have been "
                "sent. If the swap doesn't complete, Boltz will refund "
                "automatically after the timeout block."
            )
        if session.status == BraiinsDepositStatus.OPENING_CHANNEL:
            # The channel funding tx has been broadcast — the funds are
            # committed to the channel. We don't auto-unwind that; once the
            # channel confirms the deposit continues, or an operator closes
            # the channel to recover on-chain. Refuse cleanly.
            return False, (
                "Cancel isn't available once the channel funding transaction "
                "has been broadcast. The deposit will continue once the "
                "channel confirms."
            )
        if session.status == BraiinsDepositStatus.AWAITING_LN_FUNDS:
            # ext-LN: cancel the Boltz reverse swap (which
            # disposes the unpaid invoice on their side). The user
            # never paid, so no funds need to move.
            if session.boltz_swap_id is None:
                # No swap was created (shouldn't happen given the
                # transition only fires after swap creation, but be
                # defensive).
                session.record_transition(
                    BraiinsDepositStatus.CANCELLED,
                    detail="user cancelled before invoice paid",
                )
                await db.commit()
                await _emit_audit(
                    db,
                    action="braiins_deposit_session_cancelled",
                    session=session,
                    details={"reason": "user_cancel_pre_payment_ext_ln"},
                )
                return True, None
            swap = await self._get_boltz_swap(db, session.boltz_swap_id)
            if swap is not None and swap.status == SwapStatus.CREATED:
                ok, err = await self._boltz.cancel_swap(db, swap)
                if not ok:
                    return False, (f"Could not cancel Boltz swap: {err or 'unknown'}")
            session.record_transition(
                BraiinsDepositStatus.CANCELLED,
                detail="user cancelled before invoice paid",
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_cancelled",
                session=session,
                details={"reason": "user_cancel_pre_payment_ext_ln"},
            )
            return True, None
        if session.status == BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS:
            # ext-OC: cancel is allowed pre-funds. If the
            # user has already sent SOME sats, treat as a "cancel
            # forward" — move to FAILED so the refund-prompt panel
            # surfaces and the user can supply a refund address.
            received = int(session.ext_intake_received_sats or 0)
            if received > 0:
                session.record_transition(
                    BraiinsDepositStatus.FAILED,
                    detail=(f"user cancelled after receiving {received} sats; refund address required"),
                )
                session.error_message = (
                    "Cancelled after a deposit was received. Provide a refund address below to recover the funds."
                )
                await db.commit()
                await _emit_audit(
                    db,
                    action="braiins_deposit_session_failed",
                    session=session,
                    details={"reason": "user_cancel_after_partial_funds"},
                    success=False,
                    error_message=session.error_message,
                )
                return True, None
            session.record_transition(
                BraiinsDepositStatus.CANCELLED,
                detail="user cancelled before deposit",
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_cancelled",
                session=session,
                details={"reason": "user_cancel_pre_funds_ext_oc"},
            )
            return True, None
        if session.status in TERMINAL_STATUSES:
            return False, f"Session is already {session.status.value}"
        return False, (
            "Cancel is only available before the Lightning payment is sent. "
            "The session will continue and either complete or refund automatically."
        )

    async def regenerate_ext_lightning_invoice(
        self,
        db: AsyncSession,
        session_id: UUID,
    ) -> tuple[bool, Optional[str]]:
        """Re-mint the Boltz reverse-swap invoice for
        an ext-LN session whose original invoice has expired (or is
        about to). Cooperatively disposes the prior BoltzSwap row and
        re-links the session to a fresh one.

        Only allowed when:
          * status == AWAITING_LN_FUNDS
          * source_kind == EXT_LIGHTNING
          * the prior swap is still in BoltzSwap.CREATED (i.e. nobody
            has paid the invoice yet).
        """
        session = await self._select_for_update(db, session_id)
        if session is None:
            return False, "Session not found or locked by another worker"
        if session.status != BraiinsDepositStatus.AWAITING_LN_FUNDS:
            return False, (
                "Generate-new-invoice is only available while waiting for "
                f"a Lightning payment (got {session.status.value})"
            )
        if session.source_kind != BraiinsDepositSourceKind.EXT_LIGHTNING:
            return False, "Generate-new-invoice is only for external Lightning sources"
        if session.boltz_swap_id is None:
            return False, "No swap linked to this session"
        swap = await self._get_boltz_swap(db, session.boltz_swap_id)
        if swap is None:
            return False, "Linked swap row disappeared"
        if swap.status != SwapStatus.CREATED:
            return False, (
                "The previous invoice was already paid or has moved past the pending state — no fresh invoice needed."
            )

        # Cooperatively dispose the prior swap so Boltz doesn't keep
        # the LN HTLC reserved on their side.
        try:
            await self._boltz.cancel_swap(db, swap)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "BraiinsDeposit %s: prior swap cancel transient: %s",
                session.id,
                exc,
            )

        # Re-quote so fee drift is absorbed (spirit, applied to
        # the ext-LN invoice regeneration path).
        quote, qerr = await self.quote(
            amount_sats=session.deposit_amount_sats,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING.value,
        )
        if qerr or quote is None:
            return False, f"Could not re-quote: {qerr or 'unknown'}"

        # Need a fresh address since the prior swap used one. The
        # cooperative-dispose above releases nothing chain-side, but
        # binding a new address to a new swap keeps the audit trail
        # clean.
        addr_data, addr_err = await self._lnd.new_address(address_type="p2tr")
        if addr_err or not addr_data or not addr_data.get("address"):
            return False, (f"Could not generate a fresh address: {addr_err or 'empty'}")
        fresh_address = addr_data["address"]
        try:
            from app.services import utxo_service as _utxo

            await _utxo.record_address_purpose(db, fresh_address, "braiins_deposit")
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "record_address_purpose failed for %s: %s",
                fresh_address,
                exc,
            )

        new_swap, swap_err = await self._boltz.create_reverse_swap(
            db=db,
            api_key_id=session.api_key_id,
            invoice_amount_sats=quote.invoice_amount_sats,
            destination_address=fresh_address,
        )
        if swap_err or new_swap is None:
            return False, f"Swap creation failed: {swap_err}"

        session.boltz_swap_id = new_swap.id
        session.fresh_address = fresh_address
        session.ext_intake_amount_sats = quote.invoice_amount_sats
        # Stay in AWAITING_LN_FUNDS but record the event so the UI's
        # countdown can reset.
        session.record_transition(
            BraiinsDepositStatus.AWAITING_LN_FUNDS,
            detail=f"regenerated invoice; boltz_swap_id={new_swap.boltz_swap_id}",
        )
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_ext_ln_invoice_regenerated",
            session=session,
            details={
                "boltz_swap_id": new_swap.boltz_swap_id,
                "ext_intake_amount_sats": quote.invoice_amount_sats,
            },
        )
        return True, None

    async def submit_refund_address(
        self,
        db: AsyncSession,
        session_id: UUID,
        refund_address: str,
    ) -> tuple[bool, Optional[str]]:
        """Send the ext-OC intake amount back to a
        user-supplied address after the session failed. Validates the
        address via the existing ``validate_bitcoin_address`` helper,
        records the address + the resulting send txid, and emits an
        audit row.

        Only allowed when:
          * status == FAILED
          * source_kind == EXT_ONCHAIN
          * ext_intake_received_sats > 0
          * refund_txid is null (not already refunded)
        """
        if not refund_address or not isinstance(refund_address, str):
            return False, "Refund address is required"
        try:
            from app.core.validation import validate_bitcoin_address

            normalised = validate_bitcoin_address(refund_address)
        except Exception as exc:  # noqa: BLE001
            return False, f"Invalid refund address: {exc}"

        session = await self._select_for_update(db, session_id)
        if session is None:
            return False, "Session not found"
        if session.status != BraiinsDepositStatus.FAILED:
            return False, (f"Refund is only available after the session has failed (got {session.status.value})")
        if session.source_kind != BraiinsDepositSourceKind.EXT_ONCHAIN:
            return False, "Refund is only available for external on-chain sessions"
        if int(session.ext_intake_received_sats or 0) <= 0:
            return False, "No external deposit was received — nothing to refund"
        if session.refund_txid:
            return False, "A refund has already been sent"
        # Once the Boltz claim lands, the user's deposit outpoints
        # have been consumed by the submarine flow — pinning them in
        # send_coins would fail. At that point the recovery path is
        # ``retry_send`` against the fresh claim UTXO, not refund.
        if session.fresh_utxo_txid:
            return False, (
                "The deposit has already flowed downstream. Use 'Retry "
                "send' to finish the deposit instead of refunding."
            )

        amount_to_refund = int(session.ext_intake_received_sats or 0)
        priority = settings.braiins_deposit_ext_oc_refund_fee_priority
        sat_per_vbyte = _FALLBACK_FEE_VBYTES.get(priority, 6)
        try:
            fees, fee_err = await self._mempool.get_recommended_fees()
        except Exception:  # noqa: BLE001
            fees, fee_err = None, "unavailable"
        if fees and not fee_err:
            key = {
                "high": "fastestFee",
                "medium": "halfHourFee",
                "low": "hourFee",
            }.get(priority, "halfHourFee")
            v = fees.get(key)
            if isinstance(v, (int, float)) and v > 0:
                sat_per_vbyte = max(1, int(v))

        # Pin the refund send to the user's deposit outpoints so the
        # refund tx provably spends the user's deposit (avoids mixing
        # wallet UTXOs into the refund). ``send_all=True`` so the fee
        # comes out of the pinned amount rather than asking us to
        # specify an exact post-fee amount.
        outpoints: list[dict[str, Any]] = []
        for entry in session.ext_intake_txids or []:
            txid = (entry or {}).get("txid")
            vout = (entry or {}).get("vout")
            if isinstance(txid, str) and isinstance(vout, int):
                outpoints.append({"txid_str": txid, "output_index": vout})
        if not outpoints:
            return False, "Could not locate the deposit outpoints to refund"

        send_result, send_err = await self._lnd.send_coins(
            address=normalised,
            amount_sats=None,
            sat_per_vbyte=sat_per_vbyte,
            label=f"braiins_deposit_refund:{session.id}",
            outpoints=outpoints,
            send_all=True,
            min_confs=0,
        )
        if send_err or not send_result or not send_result.get("txid"):
            return False, f"Refund send failed: {send_err or 'no txid'}"

        session.refund_address = normalised
        session.refund_txid = send_result["txid"]
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_ext_oc_refund_sent",
            session=session,
            details={
                "refund_address": normalised,
                "refund_txid": send_result["txid"],
                "amount_refunded_sats": amount_to_refund,
                "sat_per_vbyte": sat_per_vbyte,
            },
        )
        return True, None

    async def recover_submarine_refund(
        self,
        db: AsyncSession,
        session_id: UUID,
    ) -> tuple[Optional[str], Optional[str]]:
        """Manual cooperative-refund retry for a submarine session.

        Used to recover funds locked in a Boltz HTLC after the
        session was projected to ``FAILED`` (e.g. invoice expired,
        swap expired, transaction failed). Mints a fresh wallet
        P2TR address and asks Boltz to cooperatively refund the
        lockup back to the wallet.

        Returns ``(refund_txid, None)`` on success,
        ``(None, error)`` on failure. The session is projected to
        ``REFUNDED`` and the underlying ``BoltzSwap`` row is
        updated; the call is idempotent against an already-refunded
        swap.
        """
        session = await self._select_for_update(db, session_id)
        if session is None:
            return None, "Session not found"
        if session.source_kind not in (
            BraiinsDepositSourceKind.LIGHTNING,
            BraiinsDepositSourceKind.ONCHAIN,
        ):
            return None, ("Cooperative refund is only available for self-funded (Lightning or on-chain) sessions")
        if session.submarine_boltz_swap_id is None:
            return None, "Session has no linked submarine Boltz swap"

        swap = await self._get_boltz_swap(db, session.submarine_boltz_swap_id)
        if swap is None:
            return None, "Linked submarine Boltz swap row not found"
        if swap.status == SwapStatus.REFUNDED:
            return swap.error_message or "already refunded", None
        if not swap.boltz_lockup_address:
            return None, ("Submarine swap was never funded — nothing to refund")

        refund_txid, refund_err = await self._attempt_cooperative_refund(swap)
        if refund_txid is None:
            return None, refund_err or "refund failed"

        # Project the success onto both rows + emit audit.
        swap.status = SwapStatus.REFUNDED
        swap.error_message = f"Manual cooperative refund broadcast; refund txid={refund_txid}"
        swap.completed_at = _utc_iso_dt()
        history = swap.status_history or []
        history.append(
            {
                "status": swap.status.value,
                "boltz_status": swap.boltz_status,
                "timestamp": _utc_iso(),
                "kind": "submarine_refund_manual",
                "refund_txid": refund_txid,
            }
        )
        swap.status_history = history

        session.record_transition(
            BraiinsDepositStatus.REFUNDED,
            detail=f"cooperative refund: {refund_txid}",
        )
        session.refund_txid = refund_txid
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_submarine_refund_broadcast",
            session=session,
            details={
                "refund_txid": refund_txid,
                "boltz_swap_id": swap.boltz_swap_id,
                "trigger": "manual",
            },
        )
        return refund_txid, None

    async def retry_send(
        self,
        db: AsyncSession,
        session_id: UUID,
        *,
        accept_underpay: bool = False,
    ) -> tuple[bool, Optional[str]]:
        """Reset a session that's blocking the send back to FUNDED so
        the next tick re-attempts. Used after:

          * A FAILED-after-FUNDED hard rejection (fee spike, mempool
            full, etc.). Operator clicks Retry to try again.
          * AWAITING_FEE_REDUCTION — the dust-prevention pre-
            flight refused to broadcast. ``accept_underpay=True``
            promotes the session AND clears the projection gate
            for the next attempt, so the broadcast goes through
            even though arrival will be below the bin. The user
            explicitly chose this over waiting.

        Without ``accept_underpay``, a retry on a parked session
        runs the projection again — useful for operators who want
        to nudge a re-check without overriding the safety floor.
        """
        session = await self._select_for_update(db, session_id)
        if session is None:
            return False, "Session not found"
        allowed_states = {
            BraiinsDepositStatus.FAILED,
            BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
        }
        if session.status not in allowed_states:
            return False, (
                f"Retry is only available on failed or awaiting-fee-reduction sessions (got {session.status.value})"
            )
        if session.fresh_utxo_txid is None:
            return False, "No fresh transaction recorded — cannot retry send"
        session.record_transition(
            BraiinsDepositStatus.FUNDED,
            detail=("retry-send requested (accept_underpay)" if accept_underpay else "retry-send requested"),
        )
        session.error_message = None
        session.send_infeasible_reason = None
        if accept_underpay:
            # Set a marker on the session so the next _advance_funded
            # skips the projection guard. Reuse send_infeasible_reason
            # as a one-shot override flag — the broadcast clears it.
            session.send_infeasible_reason = "operator_accept_underpay"
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_session_funded",
            session=session,
            details={
                "reason": "retry_send_reset",
                "accept_underpay": bool(accept_underpay),
            },
        )
        return True, None

    # ── State machine tick ──────────────────────────────────────────

    async def advance(
        self,
        db: AsyncSession,
        session_id: UUID,
    ) -> Optional[BraiinsDepositSession]:
        """One forward step of the state machine. Idempotent.

        On Postgres uses ``SELECT FOR UPDATE SKIP LOCKED`` so
        concurrent callers (dashboard poller + Celery beat + startup
        recovery) cannot race. The lock-loser sees ``None`` and the
        caller should retry on its own cadence.

        Returns the session row after one step (which may be the
        same state, e.g. SWAPPING waiting for Boltz claim) or
        ``None`` if the row is held by another worker.
        """
        session = await self._select_for_update(db, session_id)
        if session is None:
            return None
        if session.status in TERMINAL_STATUSES:
            # Keep the COMPLETED tx's confirmation count fresh
            # until it reaches 6, so a reorg-evicted send tx is
            # detectable (we record the latest count; the dashboard
            # can surface a warning).
            if session.status == BraiinsDepositStatus.COMPLETED:
                try:
                    await self._advance_completed_confirmation_watch(db, session)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "BraiinsDeposit %s post-completion conf watch transient: %s",
                        session.id,
                        exc,
                    )
            elif session.status == BraiinsDepositStatus.FAILED:
                # Opportunistic self-heal: a self-funded submarine
                # session that ended FAILED with no refund yet can
                # still recover funds locked in the Boltz HTLC via
                # cooperative Musig2 refund. The helper is rate-
                # limited and idempotent — safe to call every tick.
                try:
                    await self._advance_failed_self_heal(db, session)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "BraiinsDeposit %s FAILED self-heal transient: %s",
                        session.id,
                        exc,
                    )
            return session

        # Surface a non-fatal warning if the session has been
        # in CREATED for longer than the configured TTL without
        # advancing (typically because LND is locked or unreachable
        # at every tick). We never auto-FAIL — the warning is purely
        # informational on the session detail.
        #
        # The TTL is timed from the most recent CREATED entry in
        # ``status_history``, not from ``session.created_at``. This
        # matters for the on-chain source's re-entry pattern: after
        # SUBMARINE_SWAPPING settles we transition back to CREATED
        # before running the LN flow. Using ``created_at`` would fire
        # the warning immediately on every re-entry since the
        # original creation is usually >TTL ago by then.
        #
        # The ext-OC post-funded re-entry is bounded to one
        # tick (next advance() routes into ``_advance_created_onchain``);
        # in the typical case the CREATED dwell is far below the TTL
        # so no special skip is needed. The history-timestamp basis
        # protects us if a long delay does occur.
        if session.status == BraiinsDepositStatus.CREATED:
            try:
                from datetime import datetime, timezone

                ttl_s = int(settings.braiins_deposit_created_ttl_s)
                history = session.status_history or []
                # Find the most recent CREATED entry; fall back to
                # session.created_at if status_history is empty.
                last_created_ts: Optional[datetime] = None
                for entry in reversed(history):
                    if isinstance(entry, dict) and entry.get("status") == "created":
                        ts_str = entry.get("timestamp")
                        if isinstance(ts_str, str):
                            try:
                                last_created_ts = datetime.fromisoformat(ts_str)
                                if last_created_ts.tzinfo is None:
                                    last_created_ts = last_created_ts.replace(tzinfo=timezone.utc)
                                break
                            except ValueError:
                                continue
                if last_created_ts is None and session.created_at is not None:
                    last_created_ts = session.created_at
                if ttl_s > 0 and last_created_ts is not None:
                    now = datetime.now(timezone.utc)
                    age_s = (now - last_created_ts).total_seconds()
                    if age_s >= ttl_s and (session.error_message or "").find("still in CREATED") == -1:
                        session.error_message = (
                            f"Session has been in CREATED for {int(age_s)}s — check that LND is reachable."
                        )
                        await db.commit()
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "BraiinsDeposit %s CREATED-TTL check transient: %s",
                    session.id,
                    exc,
                )

        # Parallel "stuck" surface for SUBMARINE_SWAPPING.
        # Unlike CREATED-TTL (which signals "we never even started"),
        # this signals "Boltz has gone quiet after we funded the
        # lockup". The user has on-chain funds in flight to Boltz but
        # no settlement signal. Use the same LND-transient TTL knob
        # for the threshold.
        if session.status == BraiinsDepositStatus.SUBMARINE_SWAPPING:
            try:
                from datetime import datetime, timezone

                ttl_s = int(settings.braiins_deposit_lnd_transient_max_age_s)
                history = session.status_history or []
                if ttl_s > 0 and history:
                    last = history[-1]
                    last_ts = last.get("timestamp") if isinstance(last, dict) else None
                    if isinstance(last_ts, str):
                        try:
                            last_dt = datetime.fromisoformat(last_ts)
                        except ValueError:
                            last_dt = None
                        if last_dt is not None:
                            now = datetime.now(timezone.utc)
                            if last_dt.tzinfo is None:
                                last_dt = last_dt.replace(tzinfo=timezone.utc)
                            age_s = (now - last_dt).total_seconds()
                            marker = "Submarine swap stuck"
                            if age_s >= ttl_s and marker not in (session.error_message or ""):
                                session.error_message = (
                                    f"{marker} for {int(age_s)}s — Boltz hasn't "
                                    "settled the Lightning side. Boltz refunds "
                                    "automatically after the timeout block."
                                )
                                await db.commit()
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "BraiinsDeposit %s SUBMARINE_SWAPPING stuck check transient: %s",
                    session.id,
                    exc,
                )

        try:
            if session.status == BraiinsDepositStatus.CREATED:
                # On-chain / external routing for status=CREATED. Several flows
                # transition back to CREATED to re-enter a downstream
                # branch; ``status_history`` lets us pick the right one.
                history = session.status_history or []
                submarine_in_history = any(
                    isinstance(entry, dict) and entry.get("status") == "submarine_swapping" for entry in history
                )
                awaiting_oc_in_history = any(
                    isinstance(entry, dict) and entry.get("status") == "awaiting_onchain_funds" for entry in history
                )
                awaiting_ln_in_history = any(
                    isinstance(entry, dict) and entry.get("status") == "awaiting_ln_funds" for entry in history
                )
                # Channel-open strategy markers (on-chain sources only).
                is_channel = session.funding_strategy == BraiinsDepositFundingStrategy.CHANNEL
                channel_opened = session.channel_open_txid is not None
                # ext-LN: first time through CREATED, mint a
                # Boltz reverse swap and surface its invoice. After
                # AWAITING_LN_FUNDS we transition directly to SWAPPING,
                # never back to CREATED, so re-entry isn't a concern.
                if session.source_kind == BraiinsDepositSourceKind.EXT_LIGHTNING and not awaiting_ln_in_history:
                    await self._advance_created_ext_lightning(db, session)
                # ext-OC: first time through CREATED, mint a
                # fresh receive address and surface it. After deposit
                # confirms, ``_advance_awaiting_onchain_funds`` flips
                # us back to CREATED with ``awaiting_oc_in_history``
                # set; the next branch picks up there. (Both funding
                # strategies mint the intake the same way.)
                elif session.source_kind == BraiinsDepositSourceKind.EXT_ONCHAIN and not awaiting_oc_in_history:
                    await self._advance_created_ext_onchain(db, session)
                # Channel strategy — re-entry after the channel is active:
                # the channel was opened, we're back in CREATED, so run the
                # reverse-swap path (mirrors the submarine convergence). Must
                # precede the submarine branches (channel sessions never set
                # ``submarine_in_history``).
                elif is_channel and channel_opened:
                    await self._advance_created(db, session)
                # Channel strategy — open the channel (self-OC first pass, or
                # ext-OC post-intake re-entry). Replaces the submarine leg.
                elif is_channel and (
                    session.source_kind == BraiinsDepositSourceKind.ONCHAIN
                    or (session.source_kind == BraiinsDepositSourceKind.EXT_ONCHAIN and awaiting_oc_in_history)
                ):
                    await self._advance_created_onchain_via_channel(db, session)
                # ext-OC re-entry post-funded: run the standard
                # submarine flow (the user's deposit has bumped our
                # on-chain balance, so this is now equivalent to a
                # self-OC session from this point on).
                elif (
                    session.source_kind == BraiinsDepositSourceKind.EXT_ONCHAIN
                    and awaiting_oc_in_history
                    and not submarine_in_history
                ):
                    await self._advance_created_onchain(db, session)
                # self-OC: first time through CREATED, run the
                # submarine flow.
                elif session.source_kind == BraiinsDepositSourceKind.ONCHAIN and not submarine_in_history:
                    await self._advance_created_onchain(db, session)
                else:
                    # self-LN, or ext-OC/self-OC re-entry after
                    # submarine settled.
                    await self._advance_created(db, session)
            elif session.status == BraiinsDepositStatus.AWAITING_LN_FUNDS:
                await self._advance_awaiting_ln_funds(db, session)
            elif session.status == BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS:
                await self._advance_awaiting_onchain_funds(db, session)
            elif session.status == BraiinsDepositStatus.SUBMARINE_SWAPPING:
                await self._advance_submarine_swapping(db, session)
            elif session.status == BraiinsDepositStatus.OPENING_CHANNEL:
                await self._advance_opening_channel(db, session)
            elif session.status == BraiinsDepositStatus.SWAPPING:
                await self._advance_swapping(db, session)
            elif session.status == BraiinsDepositStatus.FUNDED:
                await self._advance_funded(db, session)
            elif session.status == BraiinsDepositStatus.AWAITING_FEE_REDUCTION:
                # Layer 4 — re-run the feasibility check. If fees
                # have dropped enough, promote back to FUNDED and
                # the next advance() builds the send tx.
                await self._advance_awaiting_fee_reduction(db, session)
            elif session.status == BraiinsDepositStatus.SENDING:
                # SENDING is an in-memory state we hold only across a
                # single send_coins call. If we re-enter advance and
                # still see SENDING, treat as a crash-mid-call and
                # reconcile via list_unspent / list_transactions.
                await self._reconcile_after_send_crash(db, session)
            elif session.status == BraiinsDepositStatus.BROADCAST:
                await self._advance_broadcast(db, session)
        except BraiinsDepositError as exc:
            logger.exception(
                "BraiinsDeposit %s hard-failed in %s: %s",
                session.id,
                session.status.value,
                exc,
            )
            session.record_transition(BraiinsDepositStatus.FAILED, detail=str(exc))
            session.error_message = str(exc)
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_failed",
                session=session,
                details={"reason": "hard_error"},
                success=False,
                error_message=str(exc),
            )
        except Exception as exc:  # noqa: BLE001
            # Treat unknown errors as transient — record on the
            # session but don't auto-FAIL. The next
            # tick retries. If we've been stuck in this state past
            # BRAIINS_DEPOSIT_LND_TRANSIENT_MAX_AGE_S, prepend a
            # "Stuck for Ns" prefix so the operator sees the urgency.
            logger.warning(
                "BraiinsDeposit %s transient error in %s: %s",
                session.id,
                session.status.value,
                exc,
            )
            stuck_prefix = ""
            try:
                from datetime import datetime, timezone

                ttl_s = int(settings.braiins_deposit_lnd_transient_max_age_s)
                history = session.status_history or []
                if ttl_s > 0 and history:
                    last = history[-1]
                    last_ts = last.get("timestamp") if isinstance(last, dict) else None
                    if isinstance(last_ts, str):
                        try:
                            last_dt = datetime.fromisoformat(last_ts)
                        except ValueError:
                            last_dt = None
                        if last_dt is not None:
                            now = datetime.now(timezone.utc)
                            if last_dt.tzinfo is None:
                                last_dt = last_dt.replace(tzinfo=timezone.utc)
                            age_s = int((now - last_dt).total_seconds())
                            if age_s >= ttl_s:
                                stuck_prefix = f"Stuck for {age_s}s — check that LND/Boltz is reachable. "
            except Exception:  # noqa: BLE001
                pass
            session.error_message = f"{stuck_prefix}transient: {exc}"
            await db.commit()
        return session

    # ── State transitions ──────────────────────────────────────────

    async def _advance_created(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """CREATED → SWAPPING.

        Mint a fresh P2TR address, ask Boltz for a reverse swap that
        pays it out at the computed invoice amount, then enqueue
        the Celery task that pays the swap invoice from our LN.
        """
        quote, err = await self.quote(amount_sats=session.deposit_amount_sats)
        if err or quote is None:
            raise BraiinsDepositError(f"Could not re-quote: {err}")

        addr_data, addr_err = await self._lnd.new_address(address_type="p2tr")
        if addr_err or not addr_data or not addr_data.get("address"):
            raise BraiinsDepositError(f"Could not generate a fresh address: {addr_err or 'empty'}")
        fresh_address = addr_data["address"]
        session.fresh_address = fresh_address
        # Tag the fresh address with a "braiins_deposit" purpose
        # so the UTXO-labels reconciler can apply an auto:receive
        # label as soon as the Boltz claim lands. Best-effort; a
        # purpose-recording failure is not a hard error.
        try:
            from app.services import utxo_service as _utxo

            await _utxo.record_address_purpose(db, fresh_address, "braiins_deposit")
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "record_address_purpose failed for %s: %s",
                fresh_address,
                exc,
            )

        # Channel-open strategy: pin the reverse-swap payment's first hop
        # to the freshly-opened channel so the deposit drains it (and the
        # inbound-gain benefit lands). Resolved here so the direct
        # activation call and any crash re-entry behave identically; NULL
        # for every other source (LND routes freely).
        outgoing_chan_id: Optional[str] = None
        if session.funding_strategy == BraiinsDepositFundingStrategy.CHANNEL and session.channel_open_txid:
            cp = f"{session.channel_open_txid}:{int(session.channel_open_output_index or 0)}"
            _active, _ch, _cerr = await self._lnd.channel_is_active(cp)
            if _ch:
                outgoing_chan_id = _ch.get("chan_id") or None

        swap, swap_err = await self._boltz.create_reverse_swap(
            db=db,
            api_key_id=session.api_key_id,
            invoice_amount_sats=quote.invoice_amount_sats,
            destination_address=fresh_address,
            outgoing_chan_id=outgoing_chan_id,
        )
        if swap_err or swap is None:
            raise BraiinsDepositError(f"Swap creation failed: {swap_err}")
        session.boltz_swap_id = swap.id
        session.record_transition(
            BraiinsDepositStatus.SWAPPING,
            detail=f"boltz_swap_id={swap.boltz_swap_id}",
        )
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_session_swapping",
            session=session,
            details={"boltz_swap_id": swap.boltz_swap_id},
        )

        # Kick off the LN payment + claim pipeline via the existing
        # Boltz Celery task. Best-effort — periodic recovery handles
        # the case where Celery isn't running.
        try:
            from app.tasks.boltz_tasks import process_boltz_swap

            process_boltz_swap.delay(str(swap.id))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not enqueue process_boltz_swap for %s: %s (periodic recovery will pick it up)",
                swap.id,
                exc,
            )

    async def _advance_created_onchain(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """CREATED → SUBMARINE_SWAPPING (on-chain source).

        Mint a Lightning invoice we want Boltz to pay, create a
        submarine swap, send the user's on-chain funds to Boltz's
        lockup address. After Boltz observes the funding tx and pays
        our invoice, ``_advance_submarine_swapping`` transitions us to
        the normal ``SWAPPING`` state.

        **Crash safety.** Each external side-effect (LN invoice mint,
        Boltz swap creation, on-chain funding broadcast) is committed
        to the session row before the next step starts. On restart,
        we branch on which fields are already set so we never repeat
        a side-effect — critically, we never double-fund Boltz's
        lockup address.
        """
        quote, err = await self.quote(
            amount_sats=session.deposit_amount_sats,
            source_kind=BraiinsDepositSourceKind.ONCHAIN.value,
        )
        if err or quote is None:
            raise BraiinsDepositError(f"Could not re-quote: {err}")

        # ── Step 1: Mint LN invoice (skip if already done) ──
        # We only need the payment_request here if the next step
        # (create_submarine_swap) hasn't run yet. When recovering from
        # a crash that happened AFTER the swap was created, we don't
        # need to look up the invoice at all.
        payment_request: Optional[str] = None
        need_payment_request = session.submarine_boltz_swap_id is None
        if not session.submarine_payment_hash_hex:
            inv, inv_err = await self._lnd.create_invoice(
                amount_sats=quote.submarine_invoice_amount_sats,
                memo=f"braiins_deposit:{session.id}",
                # 24h TTL. Boltz only attempts to pay our LN invoice
                # AFTER our on-chain lockup tx confirms; if the
                # funding tx takes >TTL to confirm (busy mempool /
                # low fee rate) the invoice expires before payment
                # is attempted and Boltz reports invoice.failedToPay
                # with failureReason="invoice expired", stranding the
                # locked funds. 24h matches Boltz's own ~144-block
                # submarine timeout envelope so the invoice is alive
                # for the full window during which the swap is
                # settle-able.
                expiry=86400,
            )
            if inv_err or not inv or not inv.get("payment_request"):
                raise BraiinsDepositError(
                    f"Could not create invoice for submarine swap: {inv_err or 'no payment_request'}"
                )
            session.submarine_payment_hash_hex = inv.get("r_hash") or None
            payment_request = inv.get("payment_request")
            await db.commit()
        elif need_payment_request:
            # Recovery branch: invoice already minted in a prior
            # advance call but the swap wasn't created. Look up the
            # invoice to retrieve the payment_request the next step
            # needs.
            inv_lookup, inv_err = await self._lnd.lookup_invoice(session.submarine_payment_hash_hex)
            if inv_err or not inv_lookup:
                raise BraiinsDepositError(
                    f"Could not look up the previously-minted submarine invoice: {inv_err or 'no data'}"
                )
            payment_request = inv_lookup.get("payment_request") or None
            if not payment_request:
                raise BraiinsDepositError(
                    "Looked-up submarine invoice has no payment_request — operator investigation required."
                )

        # ── Step 2: Create Boltz submarine swap (skip if already done) ──
        swap: Optional[BoltzSwap]
        if session.submarine_boltz_swap_id is None:
            # Drive the swap amount from the invoice Boltz will actually
            # settle, not the freshly re-quoted figure. Across a crash
            # recovery the invoice was minted on a prior tick and live
            # fees may have shifted the quote since; Boltz pays the
            # principal encoded in the invoice, so binding the swap amount
            # to that keeps the two in agreement (and matches the
            # principal check inside ``create_submarine_swap``). Fall back
            # to the quoted amount only when the principal can't be read.
            from app.core.bolt11 import principal_sats_from_bolt11

            if not payment_request:
                raise BraiinsDepositError("Submarine swap creation reached with no payment_request.")
            swap_invoice_amount_sats = (
                principal_sats_from_bolt11(payment_request) or quote.submarine_invoice_amount_sats
            )
            swap, swap_err = await self._boltz.create_submarine_swap(
                db=db,
                api_key_id=session.api_key_id,
                invoice=payment_request,
                invoice_amount_sats=swap_invoice_amount_sats,
            )
            if swap_err or swap is None:
                raise BraiinsDepositError(f"Submarine swap creation failed: {swap_err}")
            session.submarine_boltz_swap_id = swap.id
            session.submarine_lockup_address = swap.boltz_lockup_address
            session.submarine_lockup_amount_sats = swap.onchain_amount_sats
            await db.commit()
        else:
            # Recovery: swap row already linked. Reuse it.
            swap = await self._get_boltz_swap(db, session.submarine_boltz_swap_id)
            if swap is None:
                raise BraiinsDepositError(
                    "Linked submarine BoltzSwap row disappeared between ticks — operator investigation required."
                )

        # ── Step 3: Fund Boltz's lockup (skip if already broadcast) ──
        if not session.submarine_funding_txid:
            # Inbound re-check. Liquidity can change between create and
            # lockup; re-verify the node can still RECEIVE the swap
            # amount before we lock funds on-chain. On a refusal, cancel
            # the just-created (unfunded) Boltz swap and hard-fail so no
            # funds are locked only to be refunded.
            recheck_receive = int(swap.invoice_amount_sats or 0)
            refusal, _warn = await self._inbound_preflight(receive_sats=recheck_receive)
            if refusal is None:
                # Tier 2 — routability re-check. Only aborts under the
                # enforce setting (advisory warnings here aren't
                # actionable at lockup time, so they're dropped).
                refusal, _probe_warn = await self._inbound_routability_probe(receive_sats=recheck_receive)
            if refusal is not None:
                try:
                    await self._boltz.cancel_swap(db, swap)
                except Exception as cancel_exc:  # noqa: BLE001
                    logger.warning(
                        "BraiinsDeposit %s: failed to cancel submarine swap after inbound re-check refusal: %s",
                        session.id,
                        cancel_exc,
                    )
                raise BraiinsDepositError(refusal)

            priority = settings.braiins_deposit_send_fee_priority
            sat_per_vbyte = _FALLBACK_FEE_VBYTES.get(priority, 6)
            try:
                fees, fee_err = await self._mempool.get_recommended_fees()
            except Exception:  # noqa: BLE001
                fees, fee_err = None, "unavailable"
            if fees and not fee_err:
                key = {
                    "high": "fastestFee",
                    "medium": "halfHourFee",
                    "low": "hourFee",
                }.get(priority, "halfHourFee")
                v = fees.get(key)
                if isinstance(v, (int, float)) and v > 0:
                    sat_per_vbyte = max(1, int(v))

            send_result, send_err = await self._lnd.send_coins(
                address=swap.boltz_lockup_address,
                amount_sats=int(swap.onchain_amount_sats or 0),
                sat_per_vbyte=sat_per_vbyte,
                label=f"braiins_deposit_submarine:{session.id}",
                min_confs=1,
            )
            if send_err or not send_result or not send_result.get("txid"):
                raise BraiinsDepositError(f"Could not fund submarine lockup: {send_err or 'no txid'}")
            session.submarine_funding_txid = send_result["txid"]
            # Mirror the txid onto the BoltzSwap row so the manual
            # fee-bump endpoint can identify the outpoint to RBF.
            # The auto-stamp listener on BoltzSwap.lockup_txid will
            # populate lockup_broadcast_at as a side effect.
            if swap is not None and not swap.lockup_txid:
                swap.lockup_txid = send_result["txid"]
            await db.commit()

        # ── Step 4: Record the SUBMARINE_SWAPPING transition + audit ──
        # If we re-entered this function after a crash and reached
        # here, the prior session is still in CREATED state — we need
        # to promote it now.
        if session.status == BraiinsDepositStatus.CREATED:
            session.record_transition(
                BraiinsDepositStatus.SUBMARINE_SWAPPING,
                detail=(f"boltz_swap_id={swap.boltz_swap_id} funding_txid={session.submarine_funding_txid}"),
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_submarine_swapping",
                session=session,
                details={
                    "boltz_swap_id": swap.boltz_swap_id,
                    "submarine_funding_txid": session.submarine_funding_txid,
                    "submarine_lockup_amount_sats": session.submarine_lockup_amount_sats,
                },
            )

    async def _advance_created_onchain_via_channel(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """CREATED → OPENING_CHANNEL (channel funding strategy).

        Open a Lightning channel to Megalithic with the on-chain funds
        (sized up from the bin so the later reverse swap fits), then wait
        for it to become active in ``_advance_opening_channel``. This
        replaces the submarine leg for ``funding_strategy="channel"`` and
        needs no inbound routing.

        **Crash safety.** The funding tx is broadcast at most once,
        guarded on ``channel_open_txid`` (mirrors the submarine path's
        ``submarine_funding_txid`` guard). ``connect_peer`` failures are
        treated as transient (retry next tick); an ``open_channel`` error
        *before* broadcast is a clean hard-fail (no funds moved).
        """
        from app.services import braiins_channel_peers as _peers

        # Idempotency: already broadcast → ensure we're in OPENING_CHANNEL
        # and let the activation poller take over.
        if session.channel_open_txid:
            if session.status == BraiinsDepositStatus.CREATED:
                session.record_transition(
                    BraiinsDepositStatus.OPENING_CHANNEL,
                    detail=(f"channel_point={session.channel_open_txid}:{session.channel_open_output_index}"),
                )
                await db.commit()
            return

        quote, err = await self.quote(
            amount_sats=session.deposit_amount_sats,
            source_kind=session.source_kind.value,
            funding_strategy=BraiinsDepositFundingStrategy.CHANNEL.value,
        )
        if err or quote is None:
            raise BraiinsDepositError(f"Could not re-quote: {err}")
        if not quote.channel_eligible:
            raise BraiinsDepositError(
                f"Channel-open not possible for this amount: {quote.channel_ineligible_reason or 'ineligible'}"
            )

        capacity = int(quote.channel_capacity_sats)

        # When the operator has configured a
        # dashboard spend limit, it must apply to the actual channel
        # CAPACITY (the amount funded from on-chain balance), not the
        # smaller bin amount the create endpoint checked. Enforce it here,
        # against the sized-up capacity, failing closed before any peer
        # connect / funding broadcast. A limit of -1 (the default) is
        # "no limit" and leaves behavior unchanged.
        dash_limit = settings.dashboard_max_payment_sats
        if dash_limit is not None and dash_limit >= 0 and capacity > dash_limit:
            raise BraiinsDepositError(
                f"Channel capacity {capacity:,} sats exceeds the dashboard "
                f"spend limit of {dash_limit:,} sats."
            )

        # Ordered channel-open candidates. The large band is the single
        # proper node (Megalithic main); the small band is the small-channel
        # catalog peers cheapest-first, then the configured small preset as a
        # fallback. We try each in turn until one channel opens.
        candidates = _peers.channel_open_candidates(capacity, network=settings.bitcoin_network)
        if not candidates:
            raise BraiinsDepositError("No channel peer accepts a channel this size")

        # Funding-tx fee rate (channel fee priority). Peer-independent, so
        # compute it once before iterating candidates.
        priority = settings.braiins_deposit_channel_fee_priority
        sat_per_vbyte = _FALLBACK_FEE_VBYTES.get(priority, 6)
        try:
            fees, fee_err = await self._mempool.get_recommended_fees()
        except Exception:  # noqa: BLE001
            fees, fee_err = None, "unavailable"
        if fees and not fee_err:
            key = {
                "high": "fastestFee",
                "medium": "halfHourFee",
                "low": "hourFee",
            }.get(priority, "halfHourFee")
            v = fees.get(key)
            if isinstance(v, (int, float)) and v > 0:
                sat_per_vbyte = max(1, int(v))

        # Attempt each candidate, cheapest first. A connect failure is
        # TRANSIENT (peer briefly offline) → move to the next candidate. An
        # open failure happens BEFORE the funding tx is broadcast (no funds
        # moved) → also move on. The first channel that opens wins, and we
        # commit immediately so the broadcast guard at the top of this method
        # short-circuits any later tick (no double funding).
        connect_errors: list[str] = []
        open_errors: list[str] = []
        opened_peer: Optional[_peers.ChannelPeer] = None
        open_result: Optional[dict] = None
        for peer in candidates:
            _conn, conn_err = await self._lnd.connect_peer(peer.pubkey, peer.host)
            if conn_err:
                connect_errors.append(f"{peer.label}: {conn_err}")
                continue
            result, open_err = await self._lnd.open_channel(
                peer.pubkey,
                capacity,
                sat_per_vbyte=sat_per_vbyte,
                private=False,
            )
            if open_err or not result or not result.get("funding_txid"):
                open_errors.append(f"{peer.label}: {open_err or 'no funding_txid'}")
                continue
            opened_peer = peer
            open_result = result
            break

        if opened_peer is None or open_result is None:
            # No channel opened and no funds moved. If at least one peer was
            # reachable but rejected the open, that's a hard failure (the
            # parameters won't work anywhere). If NONE were reachable (all
            # connects failed), it's transient — raise a plain Exception so
            # advance() retries next tick rather than hard-failing.
            if open_errors:
                raise BraiinsDepositError(
                    "Could not open channel with any peer: " + "; ".join(open_errors + connect_errors)
                )
            raise RuntimeError("Could not connect to any channel peer: " + "; ".join(connect_errors))

        session.channel_peer_pubkey = opened_peer.pubkey
        session.channel_open_txid = open_result["funding_txid"]
        session.channel_open_output_index = int(open_result.get("output_index", 0))
        session.channel_capacity_sats = capacity
        session.error_message = None
        session.record_transition(
            BraiinsDepositStatus.OPENING_CHANNEL,
            detail=(
                f"peer={opened_peer.label} "
                f"channel_point={session.channel_open_txid}:"
                f"{session.channel_open_output_index} capacity={capacity}"
            ),
        )
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_session_opening_channel",
            session=session,
            details={
                "channel_peer_pubkey": opened_peer.pubkey,
                "channel_peer_label": opened_peer.label,
                "channel_open_txid": session.channel_open_txid,
                "channel_capacity_sats": capacity,
            },
        )

    async def _advance_opening_channel(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """OPENING_CHANNEL → (channel active) → reverse-swap path.

        Poll until the freshly-opened channel is active, then transition
        back to CREATED and run ``_advance_created`` — the same
        convergence the submarine path uses. While the channel is still
        confirming we stay here; if it never activates within
        ``braiins_deposit_channel_open_timeout_s`` we surface a "stuck"
        warning but NEVER auto-FAIL or auto-move funds (operator runbook).
        """
        if not session.channel_open_txid:
            raise BraiinsDepositError(
                "OPENING_CHANNEL but channel_open_txid missing — operator investigation required."
            )
        channel_point = f"{session.channel_open_txid}:{int(session.channel_open_output_index or 0)}"
        is_active, _ch, err = await self._lnd.channel_is_active(channel_point)
        if err is not None:
            # Transient LND error — stay in OPENING_CHANNEL, retry.
            raise RuntimeError(f"Channel activation poll failed: {err}")

        if not is_active:
            # Not yet usable. Surface a friendly progress/stuck note but
            # do not transition or touch funds.
            age_s = self._seconds_since_status(session, BraiinsDepositStatus.OPENING_CHANNEL)
            ttl = int(settings.braiins_deposit_channel_open_timeout_s)
            if ttl > 0 and age_s is not None and age_s >= ttl:
                session.error_message = (
                    f"Stuck opening channel for {age_s}s — needs attention "
                    f"(check the funding tx is confirming and the peer is up)."
                )
            else:
                session.error_message = "Opening channel — waiting for confirmations."
            await db.commit()
            return

        # Active → converge into the (unchanged) reverse-swap pipeline.
        # NOTE (future refinement): the reverse-swap payment routes out
        # via LND's choice. For the target user (no pre-existing outbound)
        # that's the new Megalithic channel, so it drains as intended and
        # ~capacity-sized inbound is gained. Pinning ``outgoing_chan_id``
        # to the new channel would make this deterministic for users who
        # DO have other outbound; deferred because it requires threading
        # the chan_id through the shared ``process_boltz_swap`` task.
        # Unpinned is benign — the deposit still completes and the bin
        # still arrives.
        session.error_message = None
        session.record_transition(
            BraiinsDepositStatus.CREATED,
            detail="channel active — re-entering reverse flow",
        )
        await db.commit()
        await self._advance_created(db, session)

    @staticmethod
    def _seconds_since_status(session: BraiinsDepositSession, status: BraiinsDepositStatus) -> Optional[int]:
        """Seconds since the most recent transition into ``status`` per
        ``status_history``; ``None`` if not found / unparseable."""
        from datetime import datetime, timezone

        history = session.status_history or []
        ts: Optional[str] = None
        for entry in history:
            if isinstance(entry, dict) and entry.get("status") == status.value:
                got = entry.get("timestamp")
                if isinstance(got, str):
                    ts = got
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(ts)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int((datetime.now(timezone.utc) - dt).total_seconds())

    async def _advance_submarine_swapping(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """SUBMARINE_SWAPPING → SWAPPING | REFUNDED | FAILED.

        Wait for Boltz to settle our LN invoice (which signals the
        submarine swap has completed). Once settled, the wallet has
        the freshly-received LN balance and we kick off the normal
        reverse-swap path by transitioning to ``SWAPPING``
        (handled by re-running ``_advance_created`` on the same row).

        Also polls Boltz's status string for the linked submarine
        swap so refund / expiry / failed-to-pay events are surfaced
        promptly rather than only via the transient-age warning.
        """
        if session.submarine_payment_hash_hex is None:
            raise BraiinsDepositError("SUBMARINE_SWAPPING but submarine_payment_hash_hex missing")

        # Check our LN invoice settlement state first — it's the
        # authoritative signal that Boltz paid us. The Boltz status
        # field is a confirming signal but lags.
        inv_data, inv_err = await self._lnd.lookup_invoice(session.submarine_payment_hash_hex)
        if inv_err is None and inv_data and inv_data.get("settled"):
            # Boltz paid our invoice; LN balance bumped. Take the
            # session into SWAPPING by running the normal
            # _advance_created flow (which mints fresh addr, creates
            # reverse swap, etc.). We have to flip the status back to
            # CREATED briefly so _advance_created's preconditions
            # hold, then let it re-transition to SWAPPING with its
            # own audit emission.
            session.record_transition(
                BraiinsDepositStatus.CREATED,
                detail="submarine settled — re-entering reverse flow",
            )
            await db.commit()
            await self._advance_created(db, session)
            return

        # Submarine still in flight from LND's POV. Poll Boltz's
        # status string so we catch the off-ramps (refund / expiry /
        # failed-to-pay). Without this, refunded submarine swaps
        # would sit in SUBMARINE_SWAPPING until the transient-age
        # warning fires hours later.
        if session.submarine_boltz_swap_id is not None:
            swap = await self._get_boltz_swap(db, session.submarine_boltz_swap_id)
            if swap is not None:
                # Project Boltz's status string onto our BoltzSwap
                # row. Best-effort: a transient Boltz outage is
                # absorbed by the next tick.
                await self._update_submarine_boltz_status(db, swap)

                if swap.status == SwapStatus.REFUNDED:
                    session.record_transition(
                        BraiinsDepositStatus.REFUNDED,
                        detail="boltz refunded submarine swap",
                    )
                    # Mirror the wallet-broadcast cooperative-refund txid
                    # onto the session so the dashboard's "refund tx" link
                    # works. The auto refund path (_update_submarine_boltz_status)
                    # only has the swap in scope, so it records the txid on
                    # swap.status_history; surface it here where we own the
                    # session. The manual + self-heal refund paths already
                    # set this directly.
                    if session.refund_txid is None:
                        session.refund_txid = _submarine_refund_txid_from_swap(swap)
                    await db.commit()
                    await _emit_audit(
                        db,
                        action="braiins_deposit_session_refunded",
                        session=session,
                        details={"reason": "boltz_submarine_refunded"},
                    )
                    return
                if swap.status in (SwapStatus.FAILED, SwapStatus.CANCELLED):
                    session.record_transition(
                        BraiinsDepositStatus.FAILED,
                        detail=(f"boltz submarine {swap.status.value}: {swap.error_message or ''}"),
                    )
                    session.error_message = swap.error_message or swap.status.value
                    await db.commit()
                    await _emit_audit(
                        db,
                        action="braiins_deposit_session_failed",
                        session=session,
                        details={"reason": f"boltz_submarine_{swap.status.value}"},
                        success=False,
                        error_message=session.error_message,
                    )
                    return
        # Otherwise: invoice still open, swap still in flight. Stay.

    async def _advance_created_ext_lightning(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """CREATED → AWAITING_LN_FUNDS (ext-lightning source).

        Mint a fresh P2TR address and ask Boltz for a reverse swap that
        pays it out at the computed invoice amount, but **do not** pay
        the invoice — the user will pay Boltz directly from their other
        Lightning wallet. We do not enqueue ``process_boltz_swap``
        either: the next ``advance()`` ticks ``_advance_awaiting_ln_funds``
        which polls Boltz's status string and drives the on-chain claim
        when the user's payment lands.
        """
        quote, err = await self.quote(
            amount_sats=session.deposit_amount_sats,
            source_kind=BraiinsDepositSourceKind.EXT_LIGHTNING.value,
        )
        if err or quote is None:
            raise BraiinsDepositError(f"Could not re-quote: {err}")

        addr_data, addr_err = await self._lnd.new_address(address_type="p2tr")
        if addr_err or not addr_data or not addr_data.get("address"):
            raise BraiinsDepositError(f"Could not generate a fresh address: {addr_err or 'empty'}")
        fresh_address = addr_data["address"]
        session.fresh_address = fresh_address
        try:
            from app.services import utxo_service as _utxo

            await _utxo.record_address_purpose(db, fresh_address, "braiins_deposit")
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "record_address_purpose failed for %s: %s",
                fresh_address,
                exc,
            )

        swap, swap_err = await self._boltz.create_reverse_swap(
            db=db,
            api_key_id=session.api_key_id,
            invoice_amount_sats=quote.invoice_amount_sats,
            destination_address=fresh_address,
        )
        if swap_err or swap is None:
            raise BraiinsDepositError(f"Swap creation failed: {swap_err}")
        session.boltz_swap_id = swap.id
        session.ext_intake_amount_sats = quote.invoice_amount_sats
        session.record_transition(
            BraiinsDepositStatus.AWAITING_LN_FUNDS,
            detail=f"boltz_swap_id={swap.boltz_swap_id}",
        )
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_ext_ln_invoice_issued",
            session=session,
            details={
                "boltz_swap_id": swap.boltz_swap_id,
                "ext_intake_amount_sats": quote.invoice_amount_sats,
            },
        )

    async def _advance_created_ext_onchain(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """CREATED → AWAITING_ONCHAIN_FUNDS (ext-onchain source).

        Mint a fresh P2TR receive address (labelled per session) and
        surface it to the user. The session then sits in
        ``AWAITING_ONCHAIN_FUNDS`` until the deposit confirms.
        """
        # Quote with the session's funding strategy so the intake amount
        # is sized for the actual on-chain→LN mechanism: the channel
        # strategy needs a LARGER intake (capacity + funding fee) than the
        # submarine swap. Defaulting to swap here would under-size the
        # intake and the later channel open would fail on balance.
        quote, err = await self.quote(
            amount_sats=session.deposit_amount_sats,
            source_kind=BraiinsDepositSourceKind.EXT_ONCHAIN.value,
            funding_strategy=session.funding_strategy.value,
        )
        if err or quote is None:
            raise BraiinsDepositError(f"Could not re-quote: {err}")
        if quote.required_external_deposit_sats <= 0:
            raise BraiinsDepositError("Quote produced zero required_external_deposit_sats")

        addr_data, addr_err = await self._lnd.new_address(address_type="p2tr")
        if addr_err or not addr_data or not addr_data.get("address"):
            raise BraiinsDepositError(f"Could not generate a receive address: {addr_err or 'empty'}")
        intake_address = addr_data["address"]
        session.ext_intake_address = intake_address
        session.ext_intake_amount_sats = quote.required_external_deposit_sats
        # Label the address so operators can audit-trail incoming
        # deposits. Best-effort.
        try:
            from app.services import utxo_service as _utxo

            await _utxo.record_address_purpose(db, intake_address, f"braiins_deposit:ext_intake:{session.id}")
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "record_address_purpose failed for %s: %s",
                intake_address,
                exc,
            )

        session.record_transition(
            BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
            detail=(f"intake_address={intake_address} required_sats={quote.required_external_deposit_sats}"),
        )
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_ext_oc_address_issued",
            session=session,
            details={
                "ext_intake_address": intake_address,
                "ext_intake_amount_sats": quote.required_external_deposit_sats,
            },
        )

    async def _advance_awaiting_ln_funds(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """AWAITING_LN_FUNDS → SWAPPING | CANCELLED | REFUNDED | FAILED.

        The user is paying Boltz's reverse-swap invoice from their other
        wallet. We do not pay the invoice. ``BoltzSwapService.advance_swap``
        is the central status poller — calling it from CREATED with
        Boltz reporting the user-paid invoice flips the swap to
        CLAIMING and broadcasts our cooperative claim, eventually
        landing the on-chain output at ``fresh_address``.
        """
        if session.boltz_swap_id is None:
            raise BraiinsDepositError("AWAITING_LN_FUNDS but no boltz_swap_id")
        swap = await self._get_boltz_swap(db, session.boltz_swap_id)
        if swap is None:
            raise BraiinsDepositError(f"Linked BoltzSwap {session.boltz_swap_id} disappeared")

        # Poll Boltz status + drive the cooperative claim if the user
        # has paid. Best-effort: a Boltz outage is absorbed; next tick
        # retries. The advance_swap call commits its own state changes.
        try:
            await self._boltz.advance_swap(db, swap)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "BraiinsDeposit %s advance_swap transient: %s",
                session.id,
                exc,
            )
            return
        # Re-read the swap state after advance_swap may have mutated it.
        swap = await self._get_boltz_swap(db, session.boltz_swap_id)
        if swap is None:
            return

        if swap.status == SwapStatus.REFUNDED:
            session.record_transition(
                BraiinsDepositStatus.REFUNDED,
                detail="boltz refunded reverse swap (ext-LN)",
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_refunded",
                session=session,
                details={"reason": "boltz_refunded_ext_ln"},
            )
            return
        if swap.status in (SwapStatus.FAILED, SwapStatus.CANCELLED):
            # The user never paid the invoice (or Boltz couldn't
            # settle). A clean unpaid-expiry
            # should land in CANCELLED — the user gets a clean
            # "start a new session" recovery, not a scary
            # "something went wrong" screen. We detect this by
            # checking the BoltzSwap error message for the
            # ``invoice.expired`` / ``swap.expired`` status string
            # that ``BoltzSwapService.advance_swap`` sets.
            err_text = (swap.error_message or "").lower()
            no_payment = (
                "invoice.expired" in err_text or "swap.expired" in err_text or "invoice.failedtopay" in err_text
            )
            terminal = (
                BraiinsDepositStatus.CANCELLED
                if swap.status == SwapStatus.CANCELLED or no_payment
                else BraiinsDepositStatus.FAILED
            )
            reason = (
                "ext_ln_invoice_expired"
                if no_payment and swap.status == SwapStatus.FAILED
                else f"boltz_reverse_{swap.status.value}"
            )
            session.record_transition(
                terminal,
                detail=f"boltz reverse {swap.status.value}: {swap.error_message or ''}",
            )
            session.error_message = swap.error_message or swap.status.value
            await db.commit()
            await _emit_audit(
                db,
                action=(
                    "braiins_deposit_session_cancelled"
                    if terminal == BraiinsDepositStatus.CANCELLED
                    else "braiins_deposit_session_failed"
                ),
                session=session,
                details={"reason": reason},
                success=terminal == BraiinsDepositStatus.CANCELLED,
                error_message=session.error_message,
            )
            return
        # The defining signal that the user has paid is Boltz reporting
        # the on-chain claim has landed (mempool or confirmed). At that
        # point ``BoltzSwapService.advance_swap`` will have moved the
        # swap into CLAIMING/CLAIMED/COMPLETED and recorded ``claim_txid``.
        if swap.claim_txid is not None:
            from datetime import datetime, timezone

            session.ext_funds_received_at = datetime.now(timezone.utc)
            session.record_transition(
                BraiinsDepositStatus.SWAPPING,
                detail=f"user paid invoice; claim_txid={swap.claim_txid}",
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_ext_ln_funds_received",
                session=session,
                details={
                    "boltz_swap_id": swap.boltz_swap_id,
                    "claim_txid": swap.claim_txid,
                },
            )
            return
        # Otherwise: invoice still unpaid (or paid but Boltz hasn't
        # broadcast the claim yet). Stay in AWAITING_LN_FUNDS.

    async def _advance_awaiting_onchain_funds(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """AWAITING_ONCHAIN_FUNDS → CREATED (re-entry) | CANCELLED.

        Poll LND for confirmed deposits at ``ext_intake_address``.
        Multi-tx additive deposits are aggregated. When the cumulative
        confirmed sum crosses the required threshold, transition back
        to CREATED so the dispatcher routes into the existing
        submarine-leg flow. Partial deposits update
        ``ext_intake_received_sats`` and emit an informational audit
        row but do not transition state.
        """
        if not session.ext_intake_address:
            raise BraiinsDepositError("AWAITING_ONCHAIN_FUNDS but ext_intake_address missing")
        required = int(session.ext_intake_amount_sats or 0)
        if required <= 0:
            raise BraiinsDepositError("AWAITING_ONCHAIN_FUNDS but ext_intake_amount_sats missing")

        utxos, lst_err = await self._lnd.list_unspent(min_confs=0)
        if lst_err:
            return
        if utxos is None:
            return
        threshold = max(1, int(settings.braiins_deposit_ext_oc_confirmations))
        received_sats = 0
        intake_txids: list[dict[str, Any]] = []
        for u in utxos:
            if u.get("address") != session.ext_intake_address:
                continue
            confs = int(u.get("confirmations", 0) or 0)
            amt = int(u.get("amount_sat", 0) or 0)
            # Record EVERY deposit seen at the intake address — including
            # 0-conf (mempool) ones — so the wizard can show "deposit
            # detected, waiting for confirmations" + a mempool link.
            # Only deposits at/above the confirmation threshold count
            # toward ``received_sats``, which gates advancing the session
            # (so 0-conf detection never moves funds early).
            intake_txids.append(
                {
                    "txid": (u.get("outpoint") or {}).get("txid_str", ""),
                    "vout": int((u.get("outpoint") or {}).get("output_index", 0)),
                    "amount_sat": amt,
                    "confirmations": confs,
                }
            )
            if confs >= threshold:
                received_sats += amt

        # Update running totals; emit a partial-deposit audit row if we
        # have any but not enough.
        prior = int(session.ext_intake_received_sats or 0)
        session.ext_intake_received_sats = received_sats
        session.ext_intake_txids = intake_txids
        await db.commit()
        if 0 < received_sats < required and received_sats != prior:
            await _emit_audit(
                db,
                action="braiins_deposit_ext_oc_funds_partial",
                session=session,
                details={
                    "received_sats": received_sats,
                    "required_sats": required,
                    "shortfall_sats": required - received_sats,
                },
            )
        if received_sats < required:
            # Not enough confirmed yet. If a deposit is already detected
            # (mempool / confirming), the funds are on the way — don't
            # nag with a stale warning, and clear any prior one. Only
            # flag stale when nothing has shown up at all.
            if intake_txids:
                if session.error_message:
                    session.error_message = None
                    await db.commit()
            else:
                self._maybe_flag_awaiting_oc_stale(session)
                await db.commit()
            return

        # Threshold met — re-enter the submarine flow.
        from datetime import datetime, timezone

        session.ext_funds_received_at = datetime.now(timezone.utc)
        session.record_transition(
            BraiinsDepositStatus.CREATED,
            detail=(f"ext-oc deposit confirmed: received_sats={received_sats} required_sats={required}"),
        )
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_ext_oc_funds_received",
            session=session,
            details={
                "received_sats": received_sats,
                "required_sats": required,
                "intake_tx_count": len(intake_txids),
            },
        )

    def _maybe_flag_awaiting_oc_stale(self, session: BraiinsDepositSession) -> None:
        """Set a non-fatal ``error_message`` when an ext-OC session has
        been waiting for funds longer than the configured TTL. The
        session stays in AWAITING_ONCHAIN_FUNDS — funds may still
        arrive; we never auto-cancel.
        """
        try:
            from datetime import datetime, timezone

            ttl_s = int(settings.braiins_deposit_ext_oc_funds_ttl_s)
            if ttl_s <= 0:
                return
            history = session.status_history or []
            last_awaiting_ts: Optional[datetime] = None
            for entry in reversed(history):
                if isinstance(entry, dict) and entry.get("status") == "awaiting_onchain_funds":
                    ts_str = entry.get("timestamp")
                    if isinstance(ts_str, str):
                        try:
                            last_awaiting_ts = datetime.fromisoformat(ts_str)
                            if last_awaiting_ts.tzinfo is None:
                                last_awaiting_ts = last_awaiting_ts.replace(tzinfo=timezone.utc)
                            break
                        except ValueError:
                            continue
            if last_awaiting_ts is None:
                return
            age_s = (datetime.now(timezone.utc) - last_awaiting_ts).total_seconds()
            marker = "Waiting for your deposit"
            if age_s >= ttl_s and marker not in (session.error_message or ""):
                session.error_message = (
                    f"{marker} — no on-chain activity in {int(age_s // 3600)}h. "
                    "Your address remains valid; funds will be picked up "
                    "automatically when they arrive."
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("ext-oc stale-warning check transient: %s", exc)

    async def _update_submarine_boltz_status(self, db: AsyncSession, swap: BoltzSwap) -> None:
        """Project Boltz's status string onto a submarine ``BoltzSwap``
        row. The existing ``BoltzSwapService.advance_swap`` is heavily
        reverse-swap specific (it tries to pay the invoice + run
        cooperative claims). For submarine swaps we just need to
        observe the status string and map the terminal off-ramps.

        Best-effort — Boltz network failures are absorbed silently;
        the next tick retries.
        """
        try:
            boltz_status, _data, err = await self._boltz.get_swap_status_from_boltz(swap.boltz_swap_id)
        except Exception:  # noqa: BLE001
            return
        if err or not boltz_status:
            return
        status_changed = swap.boltz_status != boltz_status
        if status_changed:
            swap.boltz_status = boltz_status
            history = swap.status_history or []
            history.append(
                {
                    "status": swap.status.value,
                    "boltz_status": boltz_status,
                    "timestamp": _utc_iso(),
                    "kind": "submarine",
                }
            )
            swap.status_history = history
        else:
            history = swap.status_history or []
        # Map the Boltz-side string onto our internal status field
        # for the submarine off-ramps. ``invoice.settled`` doesn't
        # need to update internal status here because the LN
        # invoice-settled signal (caught in the caller via
        # lookup_invoice) is the authoritative trigger for the
        # SWAPPING transition.
        if boltz_status == "transaction.refunded" and status_changed:
            swap.status = SwapStatus.REFUNDED
            swap.error_message = "Boltz refunded the submarine lockup back to the wallet."
            swap.completed_at = _utc_iso_dt()
        elif boltz_status in (
            "invoice.expired",
            "swap.expired",
            "invoice.failedToPay",
            "transaction.failed",
        ):
            # Funds are stuck in the Boltz lockup HTLC. Attempt a
            # cooperative refund (Musig2 key-path) before flagging
            # the swap as terminally FAILED — Boltz cooperates with
            # post-failure refunds immediately, no need to wait for
            # ``timeout_block_height``. Refund destination is a
            # fresh wallet-controlled P2TR address.
            #
            # Idempotent: only attempt if not already REFUNDED. This
            # also self-heals legacy rows that were marked FAILED
            # before the cooperative-refund flow existed — on the
            # next tick after deploy, ``boltz_status`` hasn't
            # changed but ``swap.status != REFUNDED`` so we still
            # try the refund.
            if swap.status == SwapStatus.REFUNDED:
                # Nothing to do — already recovered.
                pass
            else:
                refund_txid, refund_err = await self._attempt_cooperative_refund(swap)
                if refund_txid is not None:
                    swap.status = SwapStatus.REFUNDED
                    swap.error_message = (
                        f"Cooperative refund broadcast after Boltz status {boltz_status}; refund txid={refund_txid}"
                    )
                    swap.completed_at = _utc_iso_dt()
                    history.append(
                        {
                            "status": swap.status.value,
                            "boltz_status": boltz_status,
                            "timestamp": _utc_iso(),
                            "kind": "submarine_refund",
                            "refund_txid": refund_txid,
                        }
                    )
                    swap.status_history = history
                else:
                    swap.status = SwapStatus.FAILED
                    swap.error_message = (
                        f"Boltz submarine swap ended: {boltz_status} (cooperative refund attempt: {refund_err})"
                    )
                    swap.completed_at = _utc_iso_dt()
        await db.commit()

    async def _attempt_cooperative_refund(self, swap: BoltzSwap) -> tuple[Optional[str], Optional[str]]:
        """Mint a wallet address + call Boltz's cooperative refund.

        Returns ``(txid, None)`` on success, ``(None, error)`` on
        failure. Does *not* mutate the swap row — caller projects
        the result. Errors are logged but not raised; the parent
        lifecycle continues regardless.
        """
        try:
            addr_result, addr_err = await self._lnd.new_address("p2tr")
            if addr_err or not addr_result or not addr_result.get("address"):
                return None, (f"could not mint refund address: {addr_err or 'no address'}")
            refund_address = addr_result["address"]
            txid, err = await self._boltz.cooperative_refund_submarine(swap, refund_address=refund_address)
            if err:
                logger.warning(
                    "cooperative submarine refund failed for swap %s: %s",
                    swap.boltz_swap_id,
                    err,
                )
                return None, err
            logger.info(
                "cooperative submarine refund broadcast: swap=%s txid=%s",
                swap.boltz_swap_id,
                txid,
            )
            return txid, None
        except Exception as exc:  # noqa: BLE001
            logger.exception("unexpected error during cooperative submarine refund")
            return None, f"unexpected error: {exc}"

    async def _current_btc_tip_height(self) -> Optional[int]:
        """Best-effort current BTC chain-tip height (LND getinfo).

        Gates the post-timeout unilateral refund. ``None`` when the tip can't
        be read — the unilateral path then refuses rather than guessing whether
        the lockup timeout has passed.
        """
        try:
            info, err = await self._lnd.get_info()
        except Exception:  # noqa: BLE001
            return None
        if err is not None or not info:
            return None
        try:
            return int(info.get("block_height"))
        except (TypeError, ValueError):
            return None

    async def _attempt_unilateral_refund(
        self, swap: BoltzSwap, btc_tip_height: Optional[int]
    ) -> tuple[Optional[str], Optional[str]]:
        """Mint a wallet address + call Boltz's unilateral (script-path) refund.

        The post-timeout fallback to :meth:`_attempt_cooperative_refund` for
        when Boltz won't co-sign. The boltz-service call refuses cleanly until
        the lockup timeout has passed, so this is safe to call every tick.
        Returns ``(txid, None)`` on success, ``(None, error)`` otherwise; does
        not mutate the swap row — the caller projects the result.
        """
        try:
            addr_result, addr_err = await self._lnd.new_address("p2tr")
            if addr_err or not addr_result or not addr_result.get("address"):
                return None, (f"could not mint refund address: {addr_err or 'no address'}")
            refund_address = addr_result["address"]
            txid, err = await self._boltz.unilateral_refund_submarine(
                swap, refund_address=refund_address, btc_tip_height=btc_tip_height
            )
            if err:
                logger.warning(
                    "unilateral submarine refund failed for swap %s: %s",
                    swap.boltz_swap_id,
                    err,
                )
                return None, err
            logger.info(
                "unilateral submarine refund broadcast: swap=%s txid=%s",
                swap.boltz_swap_id,
                txid,
            )
            return txid, None
        except Exception as exc:  # noqa: BLE001
            logger.exception("unexpected error during unilateral submarine refund")
            return None, f"unexpected error: {exc}"

    async def _advance_failed_self_heal(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """Opportunistic recovery for FAILED self-funded submarine
        sessions whose Boltz swap is in a refundable terminal state
        and still has funds locked in the HTLC.

        Two distinct populations:
          * Legacy rows that ended FAILED *before* the cooperative-
            refund flow shipped (no auto-attempt was ever made).
          * New rows where the in-flight refund attempt itself
            failed (e.g. transient Boltz outage during the Musig2
            handshake).

        Rate-limited via a sentinel in ``error_message`` so the
        next-tick loop doesn't spam Boltz on persistent failures.
        Cleared from the sentinel only on success (status flips to
        REFUNDED) or operator-triggered manual recovery.
        """
        from datetime import datetime, timezone

        if session.source_kind not in (
            BraiinsDepositSourceKind.LIGHTNING,
            BraiinsDepositSourceKind.ONCHAIN,
        ):
            return
        if session.submarine_boltz_swap_id is None:
            return
        if session.refund_txid:
            return

        swap = await self._get_boltz_swap(db, session.submarine_boltz_swap_id)
        if swap is None or swap.status == SwapStatus.REFUNDED:
            return
        # Only HTLC-locking statuses are refundable. Anything else
        # (created, transaction.mempool, etc.) means there's no
        # confirmed lockup to refund yet.
        if swap.boltz_status not in (
            "invoice.expired",
            "swap.expired",
            "invoice.failedToPay",
            "transaction.failed",
        ):
            return

        # Throttle: at most one attempt per
        # ``braiins_deposit_self_heal_min_interval_s`` seconds. The
        # last-attempt timestamp lives in ``status_history`` under
        # the ``submarine_refund_attempt`` kind so we don't need a
        # new column.
        history = swap.status_history or []
        min_interval_s = 300  # 5 min; tight enough to recover within
        # a tick or two after deploy, loose enough not to hammer Boltz.
        now = datetime.now(timezone.utc)
        last_attempt_at: Optional[datetime] = None
        for entry in reversed(history):
            if not isinstance(entry, dict):
                continue
            if entry.get("kind") == "submarine_refund_attempt":
                ts = entry.get("timestamp")
                if isinstance(ts, str):
                    try:
                        last_attempt_at = datetime.fromisoformat(ts)
                        if last_attempt_at.tzinfo is None:
                            last_attempt_at = last_attempt_at.replace(tzinfo=timezone.utc)
                    except ValueError:
                        last_attempt_at = None
                break
        if last_attempt_at is not None and (now - last_attempt_at).total_seconds() < min_interval_s:
            return

        refund_txid, refund_err = await self._attempt_cooperative_refund(swap)
        refund_mode = "cooperative"
        # When Boltz won't cooperatively co-sign (e.g. it returns "cooperative
        # signatures are disabled"), fall back to the unilateral script-path
        # refund. It only succeeds once the chain tip has passed the swap's
        # timeout block height; before then it returns a "blocks remaining"
        # error and we retry next tick. This guarantees self-funded submarine
        # funds recover without operator action even if cooperative stays off.
        if refund_txid is None:
            btc_tip_height = await self._current_btc_tip_height()
            uni_txid, uni_err = await self._attempt_unilateral_refund(swap, btc_tip_height)
            if uni_txid is not None:
                refund_txid, refund_err, refund_mode = uni_txid, None, "unilateral"
            elif uni_err:
                refund_err = f"cooperative: {refund_err or 'failed'}; unilateral: {uni_err}"
        history.append(
            {
                "status": swap.status.value,
                "boltz_status": swap.boltz_status,
                "timestamp": _utc_iso(),
                "kind": "submarine_refund_attempt",
                "trigger": "self_heal",
                "mode": refund_mode,
                "refund_txid": refund_txid,
                "error": refund_err,
            }
        )
        swap.status_history = history
        if refund_txid is not None:
            swap.status = SwapStatus.REFUNDED
            swap.error_message = f"{refund_mode.capitalize()} refund broadcast via self-heal; refund txid={refund_txid}"
            swap.completed_at = _utc_iso_dt()
            session.record_transition(
                BraiinsDepositStatus.REFUNDED,
                detail=f"self-heal {refund_mode} refund: {refund_txid}",
            )
            session.refund_txid = refund_txid
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_submarine_refund_broadcast",
                session=session,
                details={
                    "refund_txid": refund_txid,
                    "boltz_swap_id": swap.boltz_swap_id,
                    "trigger": "self_heal",
                    "mode": refund_mode,
                },
            )
        else:
            # Persist the attempt history but leave session/swap in
            # FAILED so the next tick (after the throttle window)
            # tries again.
            await db.commit()
            logger.info(
                "self-heal submarine refund failed for session %s (boltz_swap=%s): %s — will retry after %ds",
                session.id,
                swap.boltz_swap_id,
                refund_err,
                min_interval_s,
            )

    async def _advance_swapping(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """SWAPPING → FUNDED | REFUNDED | FAILED.

        Re-read the linked BoltzSwap. Boltz state machine drives the
        LN payment + cooperative claim; we only project onto our
        own status.
        """
        if session.boltz_swap_id is None:
            raise BraiinsDepositError("SWAPPING but no boltz_swap_id linked")
        swap = await self._get_boltz_swap(db, session.boltz_swap_id)
        if swap is None:
            raise BraiinsDepositError(f"Linked BoltzSwap {session.boltz_swap_id} disappeared")

        if swap.status == SwapStatus.COMPLETED:
            # Claim tx broadcast + at least 1 conf per BoltzSwap.
            # Project the claim outpoint onto our session and check
            # the application-level confirmation threshold.
            await self._project_funded_utxo(db, session, swap)
            return
        if swap.status == SwapStatus.REFUNDED:
            session.record_transition(
                BraiinsDepositStatus.REFUNDED,
                detail="boltz refunded",
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_refunded",
                session=session,
                details={"reason": "boltz_refunded"},
            )
            return
        if swap.status in (SwapStatus.FAILED, SwapStatus.CANCELLED):
            session.record_transition(
                BraiinsDepositStatus.FAILED,
                detail=f"boltz {swap.status.value}: {swap.error_message or ''}",
            )
            session.error_message = swap.error_message or swap.status.value
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_failed",
                session=session,
                details={"reason": f"boltz_{swap.status.value}"},
                success=False,
                error_message=session.error_message,
            )
            return
        # Boltz still working (PAYING_INVOICE / INVOICE_PAID /
        # CLAIMING / CLAIMED). No-op; next tick.

    async def _project_funded_utxo(
        self,
        db: AsyncSession,
        session: BraiinsDepositSession,
        swap: BoltzSwap,
    ) -> None:
        """Resolve the fresh UTXO from the Boltz claim tx + check
        confirmations. Transitions SWAPPING -> FUNDED when ready.
        """
        # Find the outpoint in LND's wallet that lands at our fresh
        # address. ``list_unspent(min_confs=0)`` includes mempool so
        # we can record the outpoint as soon as Boltz broadcasts.
        utxos, lst_err = await self._lnd.list_unspent(min_confs=0)
        if lst_err:
            # Transient — let the next tick retry.
            logger.info(
                "BraiinsDeposit %s: list_unspent transient: %s",
                session.id,
                lst_err,
            )
            return
        if utxos is None:
            return
        # Normally we pin the match to ``swap.claim_txid``. But a
        # cooperative claim can settle the swap before the wallet
        # persists ``claim_txid`` (the claim broadcast succeeds, then
        # the subprocess errors — incident 2026-06-16). The fresh
        # address is single-use, so when ``claim_txid`` is missing the
        # lone UTXO sitting there IS the claim: match on the address
        # alone and backfill ``claim_txid`` so the record is complete.
        match: Optional[dict] = None
        for u in utxos:
            if u.get("address") != session.fresh_address:
                continue
            if swap.claim_txid and (u.get("outpoint", {}).get("txid_str") != swap.claim_txid):
                continue
            match = u
            break
        if match is None:
            if not swap.claim_txid:
                # Settled-without-claim and the claim UTXO isn't visible
                # yet (LND not indexed, or it was already spent). Wait
                # for a later tick rather than hard-failing the deposit.
                logger.info(
                    "BraiinsDeposit %s: swap COMPLETED but claim_txid "
                    "missing and no UTXO yet at fresh address; will retry",
                    session.id,
                )
            # LND hasn't indexed the claim tx yet. Wait.
            return

        if not swap.claim_txid:
            swap.claim_txid = match["outpoint"]["txid_str"]
            logger.info(
                "BraiinsDeposit %s: backfilled missing claim_txid=%s from fresh-address UTXO",
                session.id,
                swap.claim_txid,
            )

        session.fresh_utxo_txid = match["outpoint"]["txid_str"]
        session.fresh_utxo_vout = int(match["outpoint"]["output_index"])
        session.fresh_utxo_amount_sats = int(match["amount_sat"])

        # Check the confirmation threshold.
        threshold = max(0, int(settings.braiins_deposit_confirmations_before_send))
        confs = int(match.get("confirmations", 0) or 0)
        if confs < threshold:
            # Stay in SWAPPING; just persist the outpoint for the
            # next tick.
            await db.commit()
            return

        session.record_transition(
            BraiinsDepositStatus.FUNDED,
            detail=f"utxo={session.fresh_utxo_txid}:{session.fresh_utxo_vout} confs={confs}",
        )
        # Label the fresh UTXO so it shows up in the dashboard
        # UTXO list with a meaningful name and the auto:swap source
        # (excluded from default coin-selection per the existing
        # convention). Best-effort.
        try:
            from app.models.utxo_label import UtxoLabelSource
            from app.services import utxo_service as _utxo

            assert session.fresh_utxo_txid is not None  # set from match["outpoint"] above
            await _utxo.set_label(
                db,
                session.fresh_utxo_txid,
                int(session.fresh_utxo_vout),
                "Braiins deposit (claim)",
                source=UtxoLabelSource.AUTO_SWAP,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "set_label failed for fresh UTXO %s:%s: %s",
                session.fresh_utxo_txid,
                session.fresh_utxo_vout,
                exc,
            )
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_session_funded",
            session=session,
            details={
                "fresh_utxo_amount_sats": session.fresh_utxo_amount_sats,
                "confirmations": confs,
            },
        )

    async def _advance_funded(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """FUNDED → BROADCAST (or AWAITING_FEE_REDUCTION when fees
        spike too high for a dust-safe send).

        Build the send tx with the fresh UTXO pinned as the input
        set. When dust prevention is enabled, the tx has NO change
        output: the entire UTXO is spent to Braiins minus the
        network fee. The actual arrival amount is recorded in
        ``actual_sent_sats``.
        """
        if not session.fresh_utxo_txid or session.fresh_utxo_vout is None:
            raise BraiinsDepositError("FUNDED but fresh outpoint not recorded")

        # Compute fee rate from priority. Re-read live fees so a
        # session that sat in FUNDED for a while picks up the
        # current mempool.
        priority = settings.braiins_deposit_send_fee_priority
        sat_per_vbyte = _FALLBACK_FEE_VBYTES.get(priority, 6)
        try:
            fees, fee_err = await self._mempool.get_recommended_fees()
        except Exception:  # noqa: BLE001
            fees, fee_err = None, "unavailable"
        if fees and not fee_err:
            key = {
                "high": "fastestFee",
                "medium": "halfHourFee",
                "low": "hourFee",
            }.get(priority, "halfHourFee")
            v = fees.get(key)
            if isinstance(v, (int, float)) and v > 0:
                sat_per_vbyte = max(1, int(v))

        # Dust prevention: when enabled, build a no-change tx.
        # Pre-flight the feasibility so we never broadcast a tx that
        # would lose more to fees than the bin is worth.
        #
        # Per-session opt-out: when the user picked "exact amount"
        # mode at create time (``session.include_extras=False``),
        # fall through to the legacy with-change broadcast path
        # regardless of the operator-level dust-prevention flag.
        # The operator flag is an additional kill-switch that can
        # force the legacy path globally; it cannot force dust-
        # prevention onto a user who opted out.
        operator_dust_safe = bool(getattr(settings, "braiins_deposit_dust_prevention_enabled", True))
        user_include_extras = bool(getattr(session, "include_extras", True))
        use_dust_safe = operator_dust_safe and user_include_extras
        utxo_value = int(session.fresh_utxo_amount_sats or 0)
        # Operator-override path. Set by ``retry_send(accept_underpay=True)``
        # from a parked session. Skips the under-bin projection gate
        # so the broadcast goes through even when arrival < bin.
        # The override is one-shot: cleared on the SENDING transition
        # below regardless of broadcast outcome.
        operator_accept_underpay = session.send_infeasible_reason == "operator_accept_underpay"
        if use_dust_safe:
            from app.services.dust_safe_send import (
                InfeasibleSendError,
                build_and_broadcast_no_change_send,
                project_no_change_send,
            )

            # Pre-flight: is the send even feasible at this feerate?
            # Refuse if the projected arrival would be below the bin
            # amount (the user's signed-off floor). The user-visible
            # contract is "deposit lands at AT LEAST the bin amount";
            # falling below it without their re-consent would silently
            # shrink their hashpower credit. Operator override
            # (accept_underpay) bypasses the floor.
            projection = project_no_change_send(
                source_value_sats=utxo_value,
                sat_per_vbyte=sat_per_vbyte,
            )
            min_acceptable = int(session.deposit_amount_sats)
            if projection is None:
                # The UTXO can't even pay the network fee — broadcast
                # would create an invalid tx. ALWAYS park, even with
                # the operator override. There's nothing to broadcast.
                await self._park_for_fee_reduction(
                    db,
                    session,
                    sat_per_vbyte=sat_per_vbyte,
                    reason="fees_too_high_for_no_change_send",
                    utxo_value=utxo_value,
                    bin_amount=min_acceptable,
                )
                return
            if projection.arrived_at_destination < min_acceptable and not operator_accept_underpay:
                # Arrival is feasible but below the bin floor. Park
                # unless the operator has explicitly accepted the
                # underpay via retry_send(accept_underpay=True).
                await self._park_for_fee_reduction(
                    db,
                    session,
                    sat_per_vbyte=sat_per_vbyte,
                    reason="would_underpay_bin",
                    utxo_value=utxo_value,
                    bin_amount=min_acceptable,
                )
                return

        # Mark SENDING transiently (in-memory only — flush so a
        # concurrent advance() sees SENDING and reconciles instead
        # of double-sending). For idempotency on crash, we rely on
        # the outpoint pin.
        session.record_transition(
            BraiinsDepositStatus.SENDING,
            detail=f"sat_per_vbyte={sat_per_vbyte}",
        )
        # Clear any stale fee-reduction reason on resume.
        session.send_infeasible_reason = None
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_session_sending",
            session=session,
            details={
                "sat_per_vbyte": sat_per_vbyte,
                "dust_prevention": use_dust_safe,
                "include_extras": user_include_extras,
            },
        )

        actual_sent: int | None = None
        if use_dust_safe:
            try:
                result = await build_and_broadcast_no_change_send(
                    lnd=self._lnd,
                    source_txid=session.fresh_utxo_txid,
                    source_vout=int(session.fresh_utxo_vout),
                    source_value_sats=utxo_value,
                    destination_address=session.destination_address,
                    sat_per_vbyte=sat_per_vbyte,
                    label=f"braiins_deposit:{session.id}",
                    min_confs=0,  # we already gated on confirmations above
                )
            except InfeasibleSendError:
                # Fees moved between pre-flight and broadcast; park.
                await self._park_for_fee_reduction(
                    db,
                    session,
                    sat_per_vbyte=sat_per_vbyte,
                    reason="fees_too_high_for_no_change_send",
                    utxo_value=utxo_value,
                    bin_amount=int(session.deposit_amount_sats),
                )
                return
            except Exception as exc:  # noqa: BLE001
                if _is_transient_send_error(str(exc)):
                    # Connectivity/shutdown during the send (e.g. an app
                    # restart's "Event loop is closed", or "Request failed").
                    # The send did NOT broadcast and the fresh UTXO is
                    # intact, so keep the session RECOVERABLE: re-raise the
                    # original (non-BraiinsDepositError) so advance() records
                    # it as transient and leaves the session at SENDING —
                    # the next tick's reconciler rolls back to FUNDED and
                    # retries automatically instead of stranding it FAILED.
                    raise
                raise BraiinsDepositError(f"On-chain send failed: {exc}")
            session.send_txid = result.txid
            actual_sent = result.arrived_at_destination
        else:
            # Legacy path — kept behind the feature flag for fast
            # rollback. LND coin-selection produces a change output
            # that lands at the wallet; in high-fee environments that
            # change can be economic dust.
            send_result, send_err = await self._lnd.send_coins(
                address=session.destination_address,
                amount_sats=session.deposit_amount_sats,
                sat_per_vbyte=sat_per_vbyte,
                label=f"braiins_deposit:{session.id}",
                outpoints=[
                    {
                        "txid_str": session.fresh_utxo_txid,
                        "output_index": int(session.fresh_utxo_vout),
                    }
                ],
                min_confs=0,  # we already gated on confirmations above
            )
            if send_err or not send_result or not send_result.get("txid"):
                _msg = send_err or "no txid returned"
                if _is_transient_send_error(_msg):
                    # Recoverable connectivity/shutdown — keep the session
                    # at SENDING so the reconciler retries (see the
                    # dust-safe branch). Raise a non-BraiinsDepositError so
                    # advance() classifies it as transient, not terminal.
                    raise RuntimeError(f"On-chain send interrupted (transient): {_msg}")
                # Genuine hard failure — fee spike rejection, mempool full,
                # etc. FAILED, but still retry-eligible via /retry-send
                # because the fresh UTXO is recorded.
                raise BraiinsDepositError(f"On-chain send failed: {_msg}")
            session.send_txid = send_result["txid"]
            # Legacy path: arrival amount equals the bin amount; the
            # rest goes to wallet change (or dust, in high-fee envs).
            actual_sent = int(session.deposit_amount_sats)
        session.actual_sent_sats = actual_sent
        tip = self._mempool.cached_tip_height
        if not isinstance(tip, int):
            # Indexer tip unavailable — fall back to LND's height so the
            # stuck-warning heuristic still has a broadcast baseline.
            tip = await self._lnd_block_height()
        if isinstance(tip, int):
            session.broadcast_block_height = tip
        session.record_transition(
            BraiinsDepositStatus.BROADCAST,
            detail=f"txid={session.send_txid}",
        )
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_session_broadcast",
            session=session,
            details={
                "sat_per_vbyte": sat_per_vbyte,
                "actual_sent_sats": actual_sent,
                "bin_amount_sats": int(session.deposit_amount_sats),
            },
        )

    async def _park_for_fee_reduction(
        self,
        db: AsyncSession,
        session: BraiinsDepositSession,
        *,
        sat_per_vbyte: int,
        reason: str,
        utxo_value: int,
        bin_amount: int,
    ) -> None:
        """Layer 4 — park a session in AWAITING_FEE_REDUCTION when
        the send is infeasible at current fees. The periodic
        ``_advance_awaiting_fee_reduction`` ticker re-runs the
        feasibility check at ``braiins_deposit_fee_reduction_recheck_s``
        cadence and promotes back to FUNDED when fees fall."""
        session.record_transition(
            BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
            detail=(f"sat_per_vbyte={sat_per_vbyte} reason={reason} utxo={utxo_value} bin={bin_amount}"),
        )
        session.send_infeasible_reason = reason
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_session_awaiting_fee_reduction",
            session=session,
            details={
                "sat_per_vbyte": sat_per_vbyte,
                "reason": reason,
                "utxo_value_sats": utxo_value,
                "bin_amount_sats": bin_amount,
            },
        )

    async def _advance_awaiting_fee_reduction(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """Layer 4 — re-check feasibility against current fees.

        Cheap idempotent operation: re-compute the no-change-send
        projection at the current high-priority mempool fee. If
        projected arrival >= bin amount, promote back to FUNDED and
        the next advance() iteration will build the send tx. If
        still infeasible, stay parked.

        The advance loop's natural cadence is every 30 s (the
        dashboard poller) or 30 s (Celery ticker). Reconsider on
        every visit; the cost is one mempool fee fetch + arithmetic.
        """
        if not session.fresh_utxo_amount_sats or not session.fresh_utxo_txid:
            # Session was parked without the fresh UTXO recorded —
            # shouldn't happen in steady-state but guard defensively.
            return
        from app.services.dust_safe_send import project_no_change_send

        priority = settings.braiins_deposit_send_fee_priority
        sat_per_vbyte = _FALLBACK_FEE_VBYTES.get(priority, 6)
        try:
            fees, fee_err = await self._mempool.get_recommended_fees()
        except Exception:  # noqa: BLE001
            fees, fee_err = None, "unavailable"
        if fees and not fee_err:
            key = {
                "high": "fastestFee",
                "medium": "halfHourFee",
                "low": "hourFee",
            }.get(priority, "halfHourFee")
            v = fees.get(key)
            if isinstance(v, (int, float)) and v > 0:
                sat_per_vbyte = max(1, int(v))

        projection = project_no_change_send(
            source_value_sats=int(session.fresh_utxo_amount_sats),
            sat_per_vbyte=sat_per_vbyte,
        )
        bin_amount = int(session.deposit_amount_sats)
        if projection is None or projection.arrived_at_destination < bin_amount:
            # Still infeasible; stay parked. The dashboard sees
            # ``status=awaiting_fee_reduction`` and the operator can
            # watch the projection live.
            return

        # Feasible again — promote to FUNDED so the next advance()
        # iteration runs the send.
        session.record_transition(
            BraiinsDepositStatus.FUNDED,
            detail=(
                f"fees dropped to {sat_per_vbyte} sat/vB; "
                f"projected arrival {projection.arrived_at_destination} "
                f">= bin {bin_amount}"
            ),
        )
        session.send_infeasible_reason = None
        await db.commit()
        await _emit_audit(
            db,
            action="braiins_deposit_session_resumed_from_fee_reduction",
            session=session,
            details={
                "sat_per_vbyte": sat_per_vbyte,
                "projected_arrival_sats": projection.arrived_at_destination,
                "bin_amount_sats": bin_amount,
            },
        )

    async def _reconcile_after_send_crash(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """Recover a session left in SENDING after a process crash.

        :
        1. If the pinned outpoint is still unspent → safe to retry.
        2. If the outpoint is gone and we can find a tx that spends
           it AND pays the destination amount → record txid, advance
           to BROADCAST.
        3. Otherwise → FAILED (manual operator intervention).
        """
        if not session.fresh_utxo_txid or session.fresh_utxo_vout is None:
            raise BraiinsDepositError("SENDING but fresh outpoint not recorded")

        utxos, lst_err = await self._lnd.list_unspent(min_confs=0)
        if lst_err:
            return
        outpoint_still_present = False
        if utxos is not None:
            for u in utxos:
                op_ = u.get("outpoint", {}) or {}
                if op_.get("txid_str") == session.fresh_utxo_txid and int(op_.get("output_index", -1)) == int(
                    session.fresh_utxo_vout
                ):
                    outpoint_still_present = True
                    break
        if outpoint_still_present:
            # Roll back to FUNDED so the next tick re-attempts.
            session.record_transition(
                BraiinsDepositStatus.FUNDED,
                detail="reconcile: outpoint still unspent, retrying send",
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_funded",
                session=session,
                details={"reason": "reconcile_outpoint_unspent"},
            )
            return

        # Outpoint is gone — see if our tx made it on chain. We use
        # list_transactions to find a wallet tx that spent the
        # outpoint AND paid the destination amount.
        sent_txid = await self._find_send_txid_via_transactions(session)
        if sent_txid:
            session.send_txid = sent_txid
            tip = self._mempool.cached_tip_height
            if not isinstance(tip, int):
                tip = await self._lnd_block_height()
            if isinstance(tip, int):
                session.broadcast_block_height = tip
            session.record_transition(
                BraiinsDepositStatus.BROADCAST,
                detail=f"reconcile: recovered txid={sent_txid}",
            )
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_broadcast",
                session=session,
                details={"reason": "reconcile_recovered"},
            )
            return

        raise BraiinsDepositError(
            "Could not reconcile after crash — outpoint spent but "
            "no matching wallet tx found. Operator inspection required."
        )

    async def _find_send_txid_via_transactions(self, session: BraiinsDepositSession) -> Optional[str]:
        """Scan the LND wallet transaction list for a tx that
        spent our pinned outpoint AND paid the destination address
        the recorded round amount. Both signals together avoid a
        false positive on unrelated wallet txs that happen to share
        the same destination + amount.
        """
        get_txns = getattr(self._lnd, "get_transactions", None)
        if not callable(get_txns):
            return None
        try:
            txns, err = await get_txns()
        except Exception:  # noqa: BLE001
            return None
        if err or not txns:
            return None
        target_amount = int(session.deposit_amount_sats)
        pinned_outpoint = (
            f"{session.fresh_utxo_txid}:{int(session.fresh_utxo_vout)}"
            if session.fresh_utxo_txid and session.fresh_utxo_vout is not None
            else None
        )
        for tx in txns:
            # Primary signal: input set includes our pinned outpoint.
            inputs_ok = False
            if pinned_outpoint:
                prev = tx.get("previous_outpoints") or []
                for p in prev:
                    op = (p or {}).get("outpoint") or ""
                    if op == pinned_outpoint:
                        inputs_ok = True
                        break
            # Confirming signal: an output pays our destination with
            # AT LEAST the recorded round amount. The dust-prevention
            # send (the dust prevention plan) absorbs the
            # network fee into the output instead of producing
            # change, so the actual sent amount is normally LARGER
            # than the bin (utxo_value − fee, where utxo_value ≈
            # bin + buffer). Accepting ``amount >= bin`` covers both
            # the legacy exact-bin send and the new dust-safe send;
            # combined with the inputs_ok pin on the fresh outpoint
            # there's no false-positive risk.
            outputs_ok = False
            recovered_sent: int | None = None
            outs = tx.get("output_details") or []
            for o in outs:
                if o.get("address") == session.destination_address and int(o.get("amount", 0)) >= target_amount:
                    outputs_ok = True
                    recovered_sent = int(o.get("amount", 0))
                    break
            if inputs_ok and outputs_ok:
                txid = tx.get("tx_hash") or tx.get("txid")
                if txid:
                    # Populate ``actual_sent_sats`` from the recovered
                    # tx so post-crash sessions have the same display
                    # contract as cleanly-broadcast ones.
                    if recovered_sent is not None:
                        session.actual_sent_sats = recovered_sent
                    return str(txid)
        return None

    async def _lnd_tx_confirmations(self, txid: str) -> Optional[int]:
        """Confirmation count for ``txid`` from LND's own wallet tx list.

        LND broadcast the send tx, so it tracks the confirmation count
        independently of the external chain indexer — this is the
        fallback used when the indexer is unreachable / lagging. Returns
        ``None`` if LND can't answer or doesn't know the tx.
        """
        get_txns = getattr(self._lnd, "get_transactions", None)
        if not callable(get_txns):
            return None
        try:
            txns, err = await get_txns()
        except Exception:  # noqa: BLE001
            return None
        if err or not txns:
            return None
        needle = txid.lower()
        for tx in txns:
            h = str(tx.get("tx_hash") or tx.get("txid") or "").lower()
            if h == needle:
                try:
                    return max(0, int(tx.get("num_confirmations", 0) or 0))
                except (TypeError, ValueError):
                    return 0
        return None

    async def _lnd_block_height(self) -> Optional[int]:
        """Current chain tip per LND — a fallback when the indexer's
        cached tip is unavailable. Only trusted when LND reports it is
        synced to chain. Returns ``None`` otherwise.
        """
        get_info = getattr(self._lnd, "get_info", None)
        if not callable(get_info):
            return None
        try:
            info, err = await get_info()
        except Exception:  # noqa: BLE001
            return None
        if err or not info or not info.get("synced_to_chain"):
            return None
        try:
            h = int(info.get("block_height", 0) or 0)
        except (TypeError, ValueError):
            return None
        return h if h > 0 else None

    async def _advance_broadcast(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """BROADCAST → COMPLETED when confirmations cross the threshold.

        Reads the send-tx confirmation count from the chain indexer and
        falls back to LND (which broadcast the tx and tracks it) when the
        indexer is unreachable — so a flaky / lagging indexer can't
        strand a deposit whose tx has actually confirmed. Otherwise just
        refreshes ``send_confirmations`` and flags the stuck-warning.
        """
        if not session.send_txid:
            raise BraiinsDepositError("BROADCAST but send_txid missing")

        confs: Optional[int] = None
        via = "indexer"
        confs_data = await self._mempool.optional_confirmations(session.send_txid)
        if confs_data is not None:
            confs = int(confs_data.get("confirmations", 0) or 0)
        else:
            # Indexer down / lagging / tx not indexed — ask LND, which
            # broadcast this tx and tracks its own confirmation count.
            lnd_confs = await self._lnd_tx_confirmations(session.send_txid)
            if lnd_confs is not None:
                confs, via = lnd_confs, "lnd"

        if confs is None:
            # Neither backend could report on the tx. Never auto-FAIL —
            # surface an informative note (the tx is broadcast and the
            # funds are safe; this finishes once a backend answers) and
            # retry next tick. We deliberately do NOT run the stuck-warning
            # heuristic here: with no confirmation reading we can't claim
            # the tx is "stuck on low fees" — the accurate signal is that
            # the chain backend is unreachable.
            session.error_message = (
                "Can't reach your chain indexer to read confirmations — "
                "the transaction was broadcast and your funds are safe; "
                "this will finish automatically once the indexer is "
                "reachable again."
            )
            await db.commit()
            return

        session.send_confirmations = confs
        threshold = max(1, int(settings.braiins_deposit_confirmations_for_completion))
        if confs >= threshold:
            session.record_transition(
                BraiinsDepositStatus.COMPLETED,
                detail=f"confs={confs} via={via}",
            )
            session.error_message = None
            await db.commit()
            await _emit_audit(
                db,
                action="braiins_deposit_session_completed",
                session=session,
                details={"send_confirmations": confs, "confirmation_source": via},
            )
            return

        # A real reading, but below threshold (or still 0-conf in the
        # mempool). Clear any stale indexer-unavailable note and apply
        # the stuck-warning heuristic.
        session.error_message = None
        self._maybe_flag_stuck(session)
        await db.commit()

    async def _advance_completed_confirmation_watch(self, db: AsyncSession, session: BraiinsDepositSession) -> None:
        """Keep polling the send-tx confirmation count after
        COMPLETED until it reaches 6 (matches Cold Storage convention)
        so a reorg-evicted send tx is detected, not silently treated
        as completed. Does not change the session status; only updates
        ``send_confirmations`` so the dashboard can surface it.
        """
        if not session.send_txid:
            return
        if (session.send_confirmations or 0) >= 6:
            return
        confs_data = await self._mempool.optional_confirmations(session.send_txid)
        if confs_data is not None:
            confs = int(confs_data.get("confirmations", 0) or 0)
        else:
            # Same indexer fallback as the BROADCAST watch.
            lnd_confs = await self._lnd_tx_confirmations(session.send_txid)
            if lnd_confs is None:
                return
            confs = lnd_confs
        if confs != (session.send_confirmations or 0):
            session.send_confirmations = confs
            await db.commit()

    def _maybe_flag_stuck(self, session: BraiinsDepositSession) -> None:
        """Set a non-fatal ``error_message`` if the send tx has been
        broadcast for more than ``braiins_deposit_broadcast_stuck_blocks``
        without confirming. The session stays in BROADCAST.
        """
        tip = self._mempool.cached_tip_height
        if not isinstance(tip, int) or session.broadcast_block_height is None:
            return
        elapsed_blocks = tip - int(session.broadcast_block_height)
        threshold = int(settings.braiins_deposit_broadcast_stuck_blocks)
        if elapsed_blocks >= threshold:
            session.error_message = (
                f"Transaction not yet confirmed after {elapsed_blocks} blocks. "
                "Fees may have been too low — check the mempool explorer."
            )

    # ── Helpers ─────────────────────────────────────────────────────

    async def _select_for_update(self, db: AsyncSession, session_id: UUID) -> Optional[BraiinsDepositSession]:
        """Fetch a session with ``FOR UPDATE SKIP LOCKED`` (Postgres)
        or a plain select (SQLite/tests). Returns ``None`` when the
        row is locked by another worker.
        """
        stmt = (
            select(BraiinsDepositSession)
            .where(BraiinsDepositSession.id == session_id)
            .with_for_update(skip_locked=True)
        )
        try:
            return (await db.execute(stmt)).scalar_one_or_none()
        except Exception:
            # SQLite raises on with_for_update — fall back to plain.
            stmt2 = select(BraiinsDepositSession).where(BraiinsDepositSession.id == session_id)
            return (await db.execute(stmt2)).scalar_one_or_none()

    async def _get_boltz_swap(self, db: AsyncSession, swap_id: UUID) -> Optional[BoltzSwap]:
        result = await db.execute(select(BoltzSwap).where(BoltzSwap.id == swap_id))
        return result.scalar_one_or_none()

    # ── Recovery ────────────────────────────────────────────────────

    async def recover_pending_sessions(self, db: AsyncSession) -> list[dict[str, Any]]:
        """Tick every non-terminal session once. Called on startup and
        periodically from Celery beat. Also ticks recently-completed
        sessions whose send-tx confirmation count is still under 6
        (reorg watch).
        """
        from sqlalchemy import or_

        watch_statuses = [s.value for s in NON_TERMINAL_STATUSES]
        # Include COMPLETED rows whose send tx hasn't reached 6 conf yet
        # so a reorg-evicted send is detectable.
        # Also include FAILED self-funded submarine rows that still
        # have funds locked in the Boltz HTLC (no refund_txid +
        # linked submarine swap) so the cooperative-refund self-heal
        # path can recover them on the next tick.
        q = select(BraiinsDepositSession).where(
            or_(
                BraiinsDepositSession.status.in_(watch_statuses),
                (BraiinsDepositSession.status == BraiinsDepositStatus.COMPLETED.value)
                & (
                    (BraiinsDepositSession.send_confirmations.is_(None))
                    | (BraiinsDepositSession.send_confirmations < 6)
                ),
                (BraiinsDepositSession.status == BraiinsDepositStatus.FAILED.value)
                & BraiinsDepositSession.submarine_boltz_swap_id.is_not(None)
                & BraiinsDepositSession.refund_txid.is_(None),
            )
        )
        result = await db.execute(q)
        sessions = list(result.scalars().all())
        out: list[dict[str, Any]] = []
        for s in sessions:
            try:
                advanced = await self.advance(db, s.id)
                out.append(
                    {
                        "id": str(s.id),
                        "status": (advanced.status.value if advanced else s.status.value),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "BraiinsDeposit recover: failed to advance %s: %s",
                    s.id,
                    exc,
                )
                out.append({"id": str(s.id), "error": str(exc)})
        return out


def _submarine_refund_txid_from_swap(swap) -> Optional[str]:  # type: ignore[no-untyped-def]
    """Pull the wallet-broadcast cooperative-refund txid off a submarine
    BoltzSwap's ``status_history``.

    The auto / manual / self-heal refund paths all append an entry with a
    ``refund_txid`` key (kinds ``submarine_refund`` /
    ``submarine_refund_manual`` / ``submarine_refund_attempt``). Returns
    the most recent such txid, or ``None`` if the swap hasn't recorded a
    wallet refund (e.g. Boltz refunded its own lockup, which carries no
    wallet txid). Best-effort: never raises on a malformed history.
    """
    try:
        history = swap.status_history or []
    except Exception:  # noqa: BLE001
        return None
    for entry in reversed(history):
        if isinstance(entry, dict):
            txid = entry.get("refund_txid")
            if txid:
                return str(txid)
    return None


def _utc_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _utc_iso_dt():  # type: ignore[no-untyped-def]
    """UTC ``datetime`` for use as a column value."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


# Module-level singleton, mirroring ``boltz_service`` / ``lnd_service``.
braiins_deposit_service = BraiinsDepositService()
