# SPDX-License-Identifier: MIT
"""UTXO label model.

Persists a per-outpoint label (operator-supplied or auto-derived)
plus lifecycle markers so we can:

* Surface labels in the dashboard UTXO list and the coin-control
  picker on the Send / Cold-Storage dialogs.
* Keep useful provenance for **spent** UTXOs (e.g. "Loop-out from
  500k sats") long enough that the user can audit recent activity
  in the *Recently spent* fold-down. Per the implementation plan
  we keep user-edited rows indefinitely and soft-purge
  auto/unlabelled rows after 30 days.
* Inherit a parent UTXO's label onto the change output it produces
  so labels survive routine sends / consolidations.

Outpoints are public on-chain data; labels themselves are short
operational notes. We therefore store ``label`` in plaintext rather
than going through the Fernet helper used for sensitive fields
elsewhere. If a future feature needs confidential labels they can
live in a separate encrypted column without disturbing this surface.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    DateTime,
    Enum,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UtxoLabelSource(str, enum.Enum):
    """How a label row came into existence.

    Stored as a plain string so the enum can grow without an
    ALTER TYPE migration on PostgreSQL — see
    ``values_callable`` below for the SQLAlchemy mapping.
    """

    USER = "user"  # explicit edit from the dashboard
    AUTO_RECEIVE = "auto:receive"  # generated address with a `purpose`
    AUTO_SWAP = "auto:swap"  # Boltz loop-out completion
    AUTO_CHANNEL_CLOSE = "auto:channel_close"  # detected via closedchannels
    INHERITED = "inherited"  # change output of a labelled spend


# Maximum length of a label, mirrored client-side and at the API layer.
LABEL_MAX_LEN = 80


class UtxoLabel(Base):
    """A label attached to a single (txid, vout) outpoint."""

    __tablename__ = "utxo_label"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    txid: Mapped[str] = mapped_column(String(64), nullable=False)
    """Big-endian hex txid of the output, lowercase."""

    vout: Mapped[int] = mapped_column(Integer, nullable=False)
    """Output index (0-based)."""

    label: Mapped[str] = mapped_column(String(LABEL_MAX_LEN), nullable=False, default="")
    """Free-form short label (≤ 80 chars). Empty string allowed when a
    row exists purely to record ``spent_at`` without a user note."""

    source: Mapped[UtxoLabelSource] = mapped_column(
        Enum(
            UtxoLabelSource,
            name="utxo_label_source",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=UtxoLabelSource.USER,
        server_default=UtxoLabelSource.USER.value,
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )

    spent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    """Set by the reconcile loop when the outpoint is no longer in
    LND's unspent set. ``NULL`` for live UTXOs."""

    spent_txid: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    """Optional reference to the spending transaction. Recorded by
    inherit-on-spend / consolidate flows; ``NULL`` if we only learned
    the spend via reconcile (LND doesn't surface spender txids in
    ``ListUnspent`` so reconcile alone can't fill this in)."""

    note: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    """Reserved for short internal markers, e.g. ``reorg``."""

    __table_args__ = (
        UniqueConstraint("txid", "vout", name="uq_utxo_label_outpoint"),
        Index("ix_utxo_label_spent_at", "spent_at"),
        Index("ix_utxo_label_txid", "txid"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"<UtxoLabel {self.txid[:8]}…:{self.vout} "
            f"label={self.label!r} src={self.source.value} "
            f"spent={self.spent_at is not None}>"
        )


class AddressPurpose(Base):
    """A user-supplied "purpose" string captured at receive-address time.

    The reconcile loop scans LND's ``ListUnspent`` and, for any UTXO
    whose address matches an unconsumed ``AddressPurpose`` row,
    creates a matching :class:`UtxoLabel` with
    ``source = AUTO_RECEIVE`` and ``label = purpose``. ``consumed_at``
    is then stamped on the row so a single purpose only seeds one
    label even if the address is reused (which we discourage but
    cannot prevent).
    """

    __tablename__ = "address_purpose"

    address: Mapped[str] = mapped_column(String(128), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(LABEL_MAX_LEN), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<AddressPurpose {self.address[:10]}… purpose={self.purpose!r} consumed={self.consumed_at is not None}>"
