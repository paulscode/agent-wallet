# SPDX-License-Identifier: MIT
"""BOLT 12 InvoiceRequest + Invoice models.

Two tables, one row each per side of an exchange:

* :class:`Bolt12InvoiceRequest` — when *we* are the payer: stores the
  invreq we sent (so we can resign / retry on time-out, and so the
  orchestrator can correlate the eventual invoice reply back to the
  payer key it used). When *we* are the issuer it stores the inbound
  invreq for audit + dedup.
* :class:`Bolt12Invoice` — the signed invoice in either direction. On
  the payer side we record the invoice we received and whether we
  paid it; on the issuer side we record the invoice we minted and
  whether it was paid.

The transient ``payer_id`` keypair is BIP-340-only and short-lived,
but we still encrypt its private half at rest so a DB compromise
alone cannot link historical payments back to this wallet's identity
key. The invoice ``preimage`` (revealed only on settlement) is also
encrypted because it constitutes proof of payment.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Bolt12Direction(str, enum.Enum):
    """Whether this row models a flow we initiated or received."""

    OUTBOUND = "outbound"  # we are the payer
    INBOUND = "inbound"  # we are the issuer


class Bolt12InvoiceRequestStatus(str, enum.Enum):
    PENDING = "pending"  # invreq sent / received, no invoice yet
    INVOICE_RECEIVED = "invoice_received"
    INVOICE_SENT = "invoice_sent"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Bolt12InvoiceStatus(str, enum.Enum):
    OPEN = "open"  # awaiting settlement
    PAID = "paid"
    EXPIRED = "expired"
    FAILED = "failed"


class Bolt12InvoiceRequest(Base):
    """An ``invoice_request`` either we sent or received."""

    __tablename__ = "bolt12_invoice_requests"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    api_key_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    # Outbound flows always reference the offer we're paying. Inbound
    # flows reference the offer we issued *if* we recognise it; an
    # invreq citing an unknown offer is still recorded with NULL FK
    # so we have an audit trail of probes.
    offer_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("bolt12_offers.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    direction: Mapped[Bolt12Direction] = mapped_column(
        Enum(
            Bolt12Direction,
            name="bolt12_direction",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )

    # -- The offer string the invreq mirrors. Kept verbatim so we can
    # always recompute the canonical merkle digest for verification.
    # NULL on offer-less rows (BOLT 12 refund / direct payment flow). --
    offer_bolt12: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # -- Public invreq fields --
    amount_msat: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    quantity: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    payer_note: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    payer_id_hex: Mapped[Optional[str]] = mapped_column(
        String(66),
        nullable=True,
        index=True,
    )

    # -- BOLT 12 ``invreq_metadata`` (16+ random bytes set by the
    # payer). The spec idempotency key for an invreq: re-sending
    # the same signed bytes MUST yield the same invoice reply.
    # The responder uses this to dedupe inbound invreqs and avoid
    # an LND-side invoice flood when a peer rotates ``payer_id``.
    # NULL on legacy rows backfilled by migration 013. --
    invreq_metadata_hex: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
        index=False,
    )

    # -- Encrypted at rest: payer transient private key (only set on
    # outbound rows where we generated it). --
    encrypted_payer_secret: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # -- Wire bytes (bech32 ``lnr1...`` string) for provenance / replay. --
    invreq_bolt12: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # -- Lifecycle --
    status: Mapped[Bolt12InvoiceRequestStatus] = mapped_column(
        Enum(
            Bolt12InvoiceRequestStatus,
            name="bolt12_invoice_request_status",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=Bolt12InvoiceRequestStatus.PENDING,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index("idx_bolt12_invreq_status", "status"),
        Index("idx_bolt12_invreq_created_at", "created_at"),
    )


class Bolt12Invoice(Base):
    """A signed BOLT 12 invoice — issued by us or received by us."""

    __tablename__ = "bolt12_invoices"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    api_key_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    invoice_request_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("bolt12_invoice_requests.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    direction: Mapped[Bolt12Direction] = mapped_column(
        Enum(
            Bolt12Direction,
            name="bolt12_direction",
            values_callable=lambda x: [e.value for e in x],
            create_type=False,  # enum already created by invreq table
        ),
        nullable=False,
    )

    # -- Wire bytes (bech32 ``lni1...`` string). --
    invoice_bolt12: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # -- Public, denormalised invoice fields. --
    amount_msat: Mapped[int] = mapped_column(BigInteger, nullable=False)
    payment_hash_hex: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    node_id_hex: Mapped[Optional[str]] = mapped_column(String(66), nullable=True)
    expiry: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # -- Settlement secrets (encrypted at rest). --
    encrypted_preimage: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # -- Lifecycle --
    status: Mapped[Bolt12InvoiceStatus] = mapped_column(
        Enum(
            Bolt12InvoiceStatus,
            name="bolt12_invoice_status",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=Bolt12InvoiceStatus.OPEN,
    )
    paid_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )

    # Telemetry #2: per-channel state snapshot captured at mint.
    # JSON shape mirrors ``ChannelDriftRow.to_dict()`` plus the
    # outbound max_htlc direction. Lets a post-mortem reconstruct
    # what the channel state actually was at mint time, so we can
    # ask "was this channel over-claiming the htlc_max when Ocean
    # tried to pay this specific invoice?" without depending on
    # whether the same channel state still holds days later.
    # NULL for invoices minted before the column existed and for
    # operators who set BOLT12_CHANNEL_SNAPSHOT_AT_MINT_ENABLED=false.
    channel_state_snapshot: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )
    """JSONB snapshot of every active channel's balance + gossiped
    inbound/outbound max_htlc at mint time. Roughly 500 bytes per
    row."""

    # Telemetry #3: settle-watchdog one-shot flag. Set when the
    # watchdog task emits a ``bolt12_invoice_settle_timeout`` audit
    # row for this row, so a slow LND or stuck reconcile pass
    # doesn't generate a flood of duplicate audit rows on every
    # subsequent watchdog tick.
    settle_timeout_audited_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    """Stamped by the watchdog. ``NULL`` means either the row
    settled within the window OR the watchdog hasn't yet noticed
    the row is overdue. A non-NULL value means we've already
    emitted the alert audit row for this invoice."""

    blinded_paths_summary: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )
    """Item 6 / Follow-up #4: per-path metadata captured at mint
    time. Lets the settle watchdog + settlement subscriber feed
    the per-intro circuit breaker without having to decode the
    stored ``invoice_bolt12`` bech32 blob. Shape:

    .. code-block:: json

        {
          "paths": [
            {
              "intro_pubkey": "035e4ff4…",
              "real_hops": 2,
              "htlc_max_msat_advertised": 60000000,
              "htlc_max_msat_clamped": 19800000,
              "terminal_peer_pubkey": "031cec…"  // null when unknown
            }
          ]
        }
    """

    __table_args__ = (
        Index("idx_bolt12_invoices_status", "status"),
        Index("idx_bolt12_invoices_created_at", "created_at"),
        # Defence-in-depth: an HTLC payment_hash MUST resolve to a
        # single invoice per tenant. Migration 014.
        UniqueConstraint(
            "api_key_id",
            "payment_hash_hex",
            name="uq_bolt12_invoices_payment_hash_per_key",
        ),
    )
