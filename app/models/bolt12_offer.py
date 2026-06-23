# SPDX-License-Identifier: MIT
"""BOLT 12 Offer model.

Persists offers we *issue* (recipient flow) so the orchestrator can
re-derive the offer string later, surface them on the dashboard, and
join inbound invoices back to their originating offer.

We deliberately keep the offer's *raw* bech32-no-checksum string in
the DB rather than reconstituting it from the field-level decode —
this way a stored offer survives any future tweak to the codec layer
unchanged, and the BIP-353 / QR-code surfaces always render exactly
what the issuer originally signed.

Issuer-side secret material (transient signing keys, internal
metadata blobs that may carry payee identifiers) is encrypted at
rest via the Fernet helper from :mod:`app.core.encryption`. Public
fields are stored verbatim for indexing.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Bolt12OfferStatus(str, enum.Enum):
    """Lifecycle of an issued offer.

    ``ACTIVE`` — published; will accept new invoice_requests.
    ``DISABLED`` — soft-disabled by the operator; we still serve the
        existing invoice if someone replays an invreq, but new
        invreqs may be rejected by the orchestrator policy.
    ``EXPIRED`` — past its absolute expiry; informational only.
    """

    ACTIVE = "active"
    DISABLED = "disabled"
    EXPIRED = "expired"


class Bolt12OfferSource(str, enum.Enum):
    """How a row in ``bolt12_offers`` came into existence.

    Drives the dashboard split between the *Issue* tab (showing only
    ``ISSUED`` rows) and the *Pay* tab (showing ``IMPORTED`` and
    ``PAID`` rows). The orchestrator and audit chain do not branch
    on this value; it is purely a UX/provenance hint.
    """

    ISSUED = "issued"
    IMPORTED = "imported"
    PAID = "paid"


class Bolt12Offer(Base):
    """Persistent record of a BOLT 12 offer we issue."""

    __tablename__ = "bolt12_offers"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)

    # -- Issuer context --
    api_key_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    # -- Public, denormalised offer fields (also encoded in the bech32 string) --
    bolt12: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        unique=True,
    )
    """The full bech32-no-checksum ``lno1...`` string. Treated as the
    canonical identity of the offer (the spec hashes the encoded TLV
    stream, not any DB id, when computing the merchant's signing
    digest)."""

    description: Mapped[Optional[str]] = mapped_column(
        String(640),
        nullable=True,
    )
    amount_msat: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    currency: Mapped[Optional[str]] = mapped_column(
        String(8),
        nullable=True,
    )
    issuer: Mapped[Optional[str]] = mapped_column(
        String(256),
        nullable=True,
    )
    issuer_id_hex: Mapped[Optional[str]] = mapped_column(
        String(66),
        nullable=True,
        index=True,
    )

    # -- Lifecycle --
    status: Mapped[Bolt12OfferStatus] = mapped_column(
        Enum(
            Bolt12OfferStatus,
            name="bolt12_offer_status",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=Bolt12OfferStatus.ACTIVE,
    )
    source: Mapped[Bolt12OfferSource] = mapped_column(
        Enum(
            Bolt12OfferSource,
            name="bolt12_offer_source",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=Bolt12OfferSource.IMPORTED,
    )
    last_paid_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    absolute_expiry: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    quantity_max: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )

    is_default_receive: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    """Marks the canonical "give this to a recurring payer" offer for
    the owning API key. Exactly one live row per ``api_key_id`` may
    have this flag set; enforced by a partial unique index in
    migration ``012_bolt12_default_receive`` and by the orchestrator
    layer (:mod:`app.api.bolt12`) when promoting a new default."""

    # -- Issuer secrets (Fernet-encrypted at write, decrypted by services) --
    encrypted_metadata: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    """Operator-private metadata blob (e.g. payee account id used for
    accounting). Opaque to BOLT 12. Encrypted via
    :func:`app.core.encryption.encrypt_field` before INSERT."""

    # -- Audit fields --
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    min_real_hops_override: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    """Per-offer override for
    ``settings.bolt12_blinded_path_min_real_hops``. ``NULL`` means
    "use the global setting".

    Set to ``1`` for offers shared with known parties where
    blinded-path privacy isn't a concern (Ocean payouts, B2B,
    LSP receive). A 1-real-hop path goes ``intro=our_peer → us``,
    eliminating the intermediate hop where the 2026-06-06 Ocean
    failure happened — at the cost of revealing our direct peer
    as the reply intro.

    Auto-set to ``1`` at offer-issuance time when the offer's
    description matches a well-known payer whose
    ``requires_privacy`` is ``False`` (currently: Ocean only).
    Operators can override manually via the offer-configure
    endpoint."""

    __table_args__ = (
        Index("idx_bolt12_offers_status", "status"),
        Index("idx_bolt12_offers_created_at", "created_at"),
        Index("idx_bolt12_offers_source", "source"),
    )
