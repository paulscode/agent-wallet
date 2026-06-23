# SPDX-License-Identifier: MIT
"""
Audit log model — immutable record of all API operations.

Every mutation (payment, channel open, swap initiation) is logged
with the API key that performed it, the action, and relevant details.

Integrity: each entry stores a SHA-256 hash linking to the previous
entry, forming a tamper-evident chain.
"""

import json
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(Base):
    """Immutable audit log entry with hash-chain integrity."""

    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    api_key_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("api_keys.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    api_key_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    resource: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    details: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
    )
    amount_sats: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        nullable=True,
    )
    success: Mapped[bool] = mapped_column(
        default=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    prev_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    entry_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )

    __table_args__ = (
        Index("idx_audit_logs_created_at", "created_at"),
        Index("idx_audit_logs_action", "action"),
    )

    def compute_hash(self, *, secret: str | None = None) -> str:
        """Compute the keyed hash of this entry's full audit-relevant payload.

        Covers every column that can change the meaning of the audit
        record — including ``details``, ``error_message``, and
        ``ip_address`` — so any post-write tamper is detectable. The hash
        is a SECRET_KEY-derived HMAC, so only a holder of SECRET_KEY can
        produce valid chain hashes.

        ``secret`` overrides the key used for the MAC. New writes always use
        the current ``SECRET_KEY`` (``secret=None``); the verifier passes
        ``SECRET_KEY_PREVIOUS`` here to keep a chain written under the prior
        key verifiable across a rotation without a destructive re-anchor.
        """
        from app.core.security import audit_chain_hmac

        if self.created_at is None:
            created_at_iso = ""
        else:
            # Normalize to UTC for a stable representation across
            # backends that don't preserve tzinfo on roundtrip.
            ca = self.created_at
            if ca.tzinfo is None:
                ca = ca.replace(tzinfo=timezone.utc)
            else:
                ca = ca.astimezone(timezone.utc)
            created_at_iso = ca.isoformat()
        payload = json.dumps(
            {
                "id": str(self.id),
                "api_key_id": str(self.api_key_id),
                "api_key_name": self.api_key_name,
                "action": self.action,
                "resource": self.resource,
                "details": self.details,
                "amount_sats": self.amount_sats,
                "success": self.success,
                "error_message": self.error_message,
                "ip_address": self.ip_address,
                "prev_hash": self.prev_hash or "",
                "created_at": created_at_iso,
            },
            sort_keys=True,
            default=str,
        )
        return audit_chain_hmac(payload, secret=secret)

    def __repr__(self) -> str:
        return f"<AuditLog {self.action} key='{self.api_key_name}' at={self.created_at}>"
