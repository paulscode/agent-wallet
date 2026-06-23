# SPDX-License-Identifier: MIT
"""
Boltz Swap Models — Reverse Submarine Swap state tracking for cold storage.

Stores all data needed to recover a swap after crash/restart:
preimage, claim key, swap tree, Boltz responses, and status history.

Sensitive fields (preimage_hex, claim_private_key_hex) are encrypted
at rest using Fernet (derived from SECRET_KEY).
"""

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Enum,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SwapStatus(str, enum.Enum):
    """Internal swap lifecycle status."""

    CREATED = "created"
    PAYING_INVOICE = "paying_invoice"
    INVOICE_PAID = "invoice_paid"
    CLAIMING = "claiming"
    CLAIMED = "claimed"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


class BoltzSwapDirection(str, enum.Enum):
    """Direction of Boltz swap."""

    REVERSE = "reverse"  # Lightning → On-chain (cold storage)


class BoltzSwap(Base):
    """Persistent record of a Boltz reverse submarine swap."""

    __tablename__ = "boltz_swaps"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)

    # -- Boltz identifiers --
    boltz_swap_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )
    direction: Mapped[BoltzSwapDirection] = mapped_column(
        Enum(
            BoltzSwapDirection,
            name="boltz_swap_direction",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=BoltzSwapDirection.REVERSE,
    )

    # -- API key context --
    api_key_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    # -- Swap parameters --
    invoice_amount_sats: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )
    onchain_amount_sats: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    destination_address: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
    )
    fee_percentage: Mapped[Optional[str]] = mapped_column(
        String(10),
        nullable=True,
    )
    miner_fee_sats: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    # Optional outgoing short-channel-id to pin the LN payment's first hop
    # (reverse swaps only). Set by the Braiins channel-open flow so the
    # reverse-swap payment drains the freshly-opened channel; NULL = let
    # LND choose the route (the default for every other caller).
    outgoing_chan_id: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )

    # -- Crypto material (encrypted at rest via Fernet) --
    # Populated after Boltz API responds, so nullable on initial creation
    preimage_hex: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,  # Fernet tokens are longer than raw hex
    )
    preimage_hash_hex: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    claim_private_key_hex: Mapped[Optional[str]] = mapped_column(
        String(512),
        nullable=True,
    )
    claim_public_key_hex: Mapped[Optional[str]] = mapped_column(
        String(66),
        nullable=True,
    )

    # -- Boltz response data --
    boltz_invoice: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    boltz_lockup_address: Mapped[Optional[str]] = mapped_column(
        String(256),
        nullable=True,
    )
    boltz_refund_public_key_hex: Mapped[Optional[str]] = mapped_column(
        String(66),
        nullable=True,
    )
    # Boltz's side of the Musig2 key set, persisted so cooperative
    # refunds (on submarine ``invoice.failedToPay`` / ``swap.expired``
    # off-ramps) can construct the partial-sig request without a
    # round-trip back to Boltz to re-fetch swap state. Populated for
    # submarine swaps from the ``claimPublicKey`` field in the Boltz
    # create response. Stays null for reverse swaps (where Boltz is
    # the refunder and our side is the claimer).
    boltz_claim_public_key_hex: Mapped[Optional[str]] = mapped_column(
        String(66),
        nullable=True,
    )
    # Set-once at swap creation, but wrapped in MutableDict for
    # defense-in-depth + consistency: a future in-place edit would then
    # persist instead of silently vanishing.
    boltz_swap_tree_json: Mapped[Optional[dict]] = mapped_column(
        MutableDict.as_mutable(JSON()),
        nullable=True,
    )
    timeout_block_height: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    boltz_blinding_key: Mapped[Optional[str]] = mapped_column(
        String(66),
        nullable=True,
    )

    # -- LND payment tracking --
    lnd_payment_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    lnd_payment_status: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
    )

    # -- Claim transaction --
    claim_tx_hex: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    claim_txid: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    # -- Lockup transaction --
    # Txid of the lockup transaction the wallet broadcast (submarine
    # direction) OR observed Boltz broadcast (reverse direction).
    # Populated by the wallet-broadcast call sites for submarine
    # swaps and used by the manual fee-bump endpoint to identify
    # the outpoint to RBF.
    lockup_txid: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )

    # -- Status tracking --
    status: Mapped[SwapStatus] = mapped_column(
        Enum(
            SwapStatus,
            name="boltz_swap_status",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=SwapStatus.CREATED,
    )
    boltz_status: Mapped[Optional[str]] = mapped_column(
        String(40),
        nullable=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    # MutableList so in-place ``status_history.append(...)`` mutations
    # are tracked + persisted (a plain JSON column silently drops them;
    # only whole-list reassignment would persist). Keeps the swap's
    # transition log complete regardless of which update pattern a call
    # site uses.
    status_history: Mapped[Optional[list]] = mapped_column(
        MutableList.as_mutable(JSON()),
        nullable=True,
        default=list,
    )

    # -- Recovery tracking --
    recovery_attempted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    recovery_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    # -- Timestamps --
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        onupdate=_utc_now,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    # When the lockup tx was first broadcast (wallet-broadcast for
    # submarine; observer-stamped for reverse). Used by the recovery
    # classifier to compute mempool age + recommend RBF/CPFP.
    lockup_broadcast_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    # When the claim tx was first broadcast (wallet-broadcast for
    # reverse; Boltz-broadcast for submarine — we stamp on first
    # CLAIMED sighting).
    claim_broadcast_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index("idx_boltz_swaps_status", "status"),
        Index("idx_boltz_swaps_api_key_id", "api_key_id"),
    )

    def __repr__(self) -> str:
        return f"<BoltzSwap {self.boltz_swap_id} status={self.status.value}>"


# ── claim_broadcast_at auto-stamp ────────────────────────────────────
#
# Stamp ``claim_broadcast_at`` exactly once when ``claim_txid`` first
# flips ``None → <value>``. The recovery classifier reads this column
# to compute mempool age + recommend a fee bump after the configured
# stall window.

from sqlalchemy import event as _sa_event


@_sa_event.listens_for(BoltzSwap.claim_txid, "set", propagate=True)
def _stamp_claim_broadcast_at(target: BoltzSwap, value: object, oldvalue: object, _initiator: object) -> None:
    """Auto-stamp claim_broadcast_at on first claim_txid assignment."""
    if not value:
        return
    if oldvalue == value:
        return
    if getattr(target, "claim_broadcast_at", None) is None:
        target.claim_broadcast_at = _utc_now()


@_sa_event.listens_for(BoltzSwap.lockup_txid, "set", propagate=True)
def _stamp_lockup_broadcast_at(target: BoltzSwap, value: object, oldvalue: object, _initiator: object) -> None:
    """Auto-stamp lockup_broadcast_at on first lockup_txid assignment."""
    if not value:
        return
    if oldvalue == value:
        return
    if getattr(target, "lockup_broadcast_at", None) is None:
        target.lockup_broadcast_at = _utc_now()
