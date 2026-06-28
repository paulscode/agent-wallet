# SPDX-License-Identifier: MIT
"""
Braiins Deposit Session model.

State machine for the LN→on-chain→Braiins pipeline. Links to a
``BoltzSwap`` row that handles the LN→on-chain leg; this model adds
the round-amount send-to-destination leg + crash-resumable state.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

import sqlalchemy as sa
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class BraiinsDepositStatus(str, enum.Enum):
    """State machine for a Braiins Deposit session.

    Forward path for ``source_kind="lightning"`` (self-sourced LN):
        CREATED -> SWAPPING -> FUNDED -> SENDING -> BROADCAST -> COMPLETED

    Forward path for ``source_kind="onchain"`` (self-sourced on-chain):
        CREATED -> SUBMARINE_SWAPPING -> SWAPPING -> FUNDED -> SENDING
                -> BROADCAST -> COMPLETED

    Forward path for ``source_kind="ext_lightning"`` (external LN):
        CREATED -> AWAITING_LN_FUNDS -> SWAPPING -> FUNDED -> SENDING
                -> BROADCAST -> COMPLETED
        The user pays Boltz's reverse-swap invoice directly; the wallet
        never custodies LN funds. Once Boltz signals the invoice is
        settled, the existing reverse-swap completion logic runs.

    Forward path for ``source_kind="ext_onchain"`` (external on-chain):
        CREATED -> AWAITING_ONCHAIN_FUNDS -> SUBMARINE_SWAPPING ->
                SWAPPING -> FUNDED -> SENDING -> BROADCAST -> COMPLETED
        The user sends to a fresh P2TR address we mint; once that
        deposit confirms, the existing submarine + reverse-swap flow
        runs from the wallet's freshly-bumped on-chain balance.

    Off-ramps:
        * CANCELLED — user cancelled before payment.
        * REFUNDED — Boltz could not settle the swap; LN balance restored
          (lightning source) or on-chain funds refunded (onchain source).
        * FAILED — hard failure with ``error_message``. For ext-OC
          sessions whose deposit already confirmed, a refund-prompt
          panel (.c) collects an address from the user and the
          ``refund_*`` columns record the recovery send.
    """

    CREATED = "created"
    AWAITING_LN_FUNDS = "awaiting_ln_funds"  # ext lightning
    AWAITING_ONCHAIN_FUNDS = "awaiting_onchain_funds"  # ext onchain
    SUBMARINE_SWAPPING = "submarine_swapping"  # on-chain source only
    # Channel-open alternative (on-chain sources, funding_strategy="channel"):
    # the channel funding tx is broadcast and we're waiting for it to
    # confirm + become active. Once active we re-enter the reverse-swap
    # path (same convergence as the submarine leg).
    OPENING_CHANNEL = "opening_channel"
    SWAPPING = "swapping"
    FUNDED = "funded"
    SENDING = "sending"
    # Layer 4 (dust prevention plan): the send-to-Braiins tx is
    # infeasible at current fees (broadcasting now would lose more
    # to fees than the bin amount). A periodic re-checker resumes
    # the session at FUNDED when fees fall.
    AWAITING_FEE_REDUCTION = "awaiting_fee_reduction"
    BROADCAST = "broadcast"
    COMPLETED = "completed"
    REFUNDED = "refunded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BraiinsDepositSourceKind(str, enum.Enum):
    """Where the input sats come from.

    ``LIGHTNING`` — this wallet's Lightning balance.
    ``ONCHAIN`` — this wallet's on-chain balance.
    ``EXT_LIGHTNING`` — a Lightning wallet other than this one
        (the user pays Boltz's reverse-swap invoice directly).
    ``EXT_ONCHAIN`` — an on-chain wallet other than this one
        (the user sends to a fresh address we generate).
    """

    LIGHTNING = "lightning"
    ONCHAIN = "onchain"
    EXT_LIGHTNING = "ext_lightning"
    EXT_ONCHAIN = "ext_onchain"


class BraiinsDepositFundingStrategy(str, enum.Enum):
    """How an on-chain source is converted to LN balance.

    * ``SWAP`` (default) — submarine swap (on-chain → LN via Boltz). The
      original behaviour; requires Boltz to route *inbound* to our node.
    * ``CHANNEL`` — open a Lightning channel to a recommended routing
      peer with the on-chain funds, then run the reverse swap
      (outbound-only). Bypasses inbound routing entirely. Applies only
      to on-chain sources.
    """

    SWAP = "swap"
    CHANNEL = "channel"


# Convenience set: ``source_kind`` values that route through the
# external-intake flow (AWAITING_LN_FUNDS / AWAITING_ONCHAIN_FUNDS).
EXTERNAL_SOURCE_KINDS: frozenset[BraiinsDepositSourceKind] = frozenset(
    {
        BraiinsDepositSourceKind.EXT_LIGHTNING,
        BraiinsDepositSourceKind.EXT_ONCHAIN,
    }
)


# States that the periodic ticker / startup recovery scan should pick up.
NON_TERMINAL_STATUSES: frozenset[BraiinsDepositStatus] = frozenset(
    {
        BraiinsDepositStatus.CREATED,
        BraiinsDepositStatus.AWAITING_LN_FUNDS,
        BraiinsDepositStatus.AWAITING_ONCHAIN_FUNDS,
        BraiinsDepositStatus.SUBMARINE_SWAPPING,
        BraiinsDepositStatus.OPENING_CHANNEL,
        BraiinsDepositStatus.SWAPPING,
        BraiinsDepositStatus.FUNDED,
        BraiinsDepositStatus.SENDING,
        BraiinsDepositStatus.AWAITING_FEE_REDUCTION,
        BraiinsDepositStatus.BROADCAST,
    }
)

# States that mean "no further automated work will happen here".
TERMINAL_STATUSES: frozenset[BraiinsDepositStatus] = frozenset(
    {
        BraiinsDepositStatus.COMPLETED,
        BraiinsDepositStatus.REFUNDED,
        BraiinsDepositStatus.FAILED,
        BraiinsDepositStatus.CANCELLED,
    }
)


class BraiinsDepositSession(Base):
    """Persistent record of a Braiins Deposit session."""

    __tablename__ = "braiins_deposit_sessions"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    api_key_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)

    # ── User-facing parameters (frozen at create time) ──
    deposit_amount_sats: Mapped[int] = mapped_column(BigInteger, nullable=False)
    destination_address: Mapped[str] = mapped_column(String(128), nullable=False)
    # Where the input sats come from. Defaults to lightning
    # for backward-compatibility with self-sourced LN rows.
    source_kind: Mapped[BraiinsDepositSourceKind] = mapped_column(
        Enum(
            BraiinsDepositSourceKind,
            name="braiins_deposit_source_kind",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=BraiinsDepositSourceKind.LIGHTNING,
    )
    # User-chosen send mode (frozen at create time).
    # * True  (default) — dust-safe NO-CHANGE send. The wallet
    #   absorbs any extras from the fresh UTXO into the deposit
    #   output (Braiins receives somewhat more than the bin).
    # * False — exact-amount send. The wallet sends exactly
    #   ``deposit_amount_sats`` and returns the remainder as a
    #   change UTXO. The change can be economically unspendable
    #   at high fees; surfaced to the user via an info bubble.
    include_extras: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=sa.true())
    # How an on-chain source is converted to LN (frozen at create time).
    # ``swap`` (default) = submarine swap; ``channel`` = open a channel
    # to a recommended routing peer instead (swap-bypass). Ignored for
    # Lightning sources.
    funding_strategy: Mapped[BraiinsDepositFundingStrategy] = mapped_column(
        Enum(
            BraiinsDepositFundingStrategy,
            name="braiins_deposit_funding_strategy",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=BraiinsDepositFundingStrategy.SWAP,
        server_default=BraiinsDepositFundingStrategy.SWAP.value,
    )

    # ── Channel-open-leg resources (funding_strategy="channel") ──
    # The routing peer we opened to + the funding outpoint
    # (channel_point = ``channel_open_txid:channel_open_output_index``).
    channel_peer_pubkey: Mapped[Optional[str]] = mapped_column(String(66), nullable=True)
    channel_open_txid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    channel_open_output_index: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    channel_capacity_sats: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    # ── Submarine-leg resources (on-chain source only) ──
    submarine_boltz_swap_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("boltz_swaps.id", ondelete="SET NULL"),
        nullable=True,
    )
    submarine_lockup_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    submarine_lockup_amount_sats: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    submarine_funding_txid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    submarine_payment_hash_hex: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # ── External-intake fields ──
    # Populated only when ``source_kind`` is ``EXT_LIGHTNING`` or
    # ``EXT_ONCHAIN``. ``ext_intake_address`` is set for ext-OC (the
    # fresh address surfaced to the user); ext-LN re-uses
    # ``BoltzSwap.lightning_invoice`` via ``boltz_swap_id``.
    ext_intake_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    # The exact intake amount the user must pay (ext-LN: amount of the
    # Boltz invoice; ext-OC: amount the user should send). Frozen at
    # ``CREATED → AWAITING_*`` time; updated by
    # ``regenerate_ext_lightning_invoice`` if a fresh invoice is minted.
    ext_intake_amount_sats: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    # Running sum of confirmed deposit amounts at ``ext_intake_address``
    # (ext-OC only). Drives the "you sent X, need Y more" UX.
    ext_intake_received_sats: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True, default=0)
    # List of confirmed deposit-tx records seen at ``ext_intake_address``.
    # Each entry: ``{txid, vout, amount_sat, confirmations}``. Supports
    # multi-tx additive deposits.
    # MutableList for the same reason as ``status_history`` — defends
    # against a future in-place ``.append(...)`` silently not persisting.
    # (Today the only writer reassigns the whole list, which is also safe.)
    ext_intake_txids: Mapped[Optional[list]] = mapped_column(
        MutableList.as_mutable(JSON()), nullable=True, default=list
    )
    # When the await-funds state exited forward (LN invoice settled or
    # on-chain deposit confirmed).
    ext_funds_received_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Populated only if the session reaches FAILED after we accepted
    # external funds. The user fills these in via the failure-screen
    # refund panel (.c).
    refund_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    refund_txid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # ── Resources we mint as the session runs ──
    fresh_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    boltz_swap_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("boltz_swaps.id", ondelete="SET NULL"),
        nullable=True,
    )
    fresh_utxo_txid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fresh_utxo_vout: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    fresh_utxo_amount_sats: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    send_txid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Dust prevention — the amount the wallet ACTUALLY broadcast
    # to the destination, which differs from ``deposit_amount_sats``
    # (the bin amount) because the dust-safe send absorbs network
    # fee into the output rather than producing wallet-side change.
    # Populated at the SENDING -> BROADCAST transition. Older rows
    # written before dust prevention shipped have NULL here; the
    # dashboard falls back to ``deposit_amount_sats`` for display.
    actual_sent_sats: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    send_confirmations: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    broadcast_block_height: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # Layer 4 — short reason describing why a session is parked in
    # AWAITING_FEE_REDUCTION. The dashboard renders this; recovery
    # doesn't depend on it.
    send_infeasible_reason: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )

    # ── State machine ──
    status: Mapped[BraiinsDepositStatus] = mapped_column(
        Enum(
            BraiinsDepositStatus,
            name="braiins_deposit_status",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=BraiinsDepositStatus.CREATED,
        index=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # MutableList so the in-place ``status_history.append(...)`` in
    # ``record_transition`` is tracked by SQLAlchemy and actually
    # persisted. With a plain JSON column the append mutates the Python
    # list but never marks the column dirty, so only the first entry
    # (set at INSERT) survives — leaving every reloaded session showing
    # just "created" and breaking the dashboard progress log.
    status_history: Mapped[Optional[list]] = mapped_column(MutableList.as_mutable(JSON()), nullable=True, default=list)

    # ── Timestamps ──
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, onupdate=_utc_now, nullable=False
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def record_transition(
        self,
        new_status: BraiinsDepositStatus,
        *,
        detail: Optional[str] = None,
    ) -> None:
        """Atomic-from-the-caller's-POV transition + append to history.

        Caller is responsible for committing. We only mutate ``self``.
        """
        self.status = new_status
        if self.status_history is None:
            self.status_history = []
        entry: dict = {
            "status": new_status.value,
            "timestamp": _utc_now().isoformat(),
        }
        if detail is not None:
            entry["detail"] = detail
        self.status_history.append(entry)
        if new_status == BraiinsDepositStatus.COMPLETED:
            self.completed_at = _utc_now()
