# SPDX-License-Identifier: MIT
"""Audit-chain high-water state — a signed monotonic row count.

The keyed audit hash chain detects modification and reordering of
``audit_logs`` rows, but a verifier walking only the surviving rows
cannot tell that the *newest* rows were removed: a tail-truncated chain
is shorter but still internally self-consistent. This single-row table
records the authorized row count (incremented on every append, decreased
only by an authorized retention prune) together with the current head
hash, signed with the same SECRET_KEY-derived chain key as the row
hashes.

Because the signature is keyed, a party that can write the database but
does not hold SECRET_KEY cannot lower the recorded count to match a
truncated table, nor forge a fresh signed state. The chain verifier
compares the live ``count(*)`` against this recorded count and flags a
shortfall as truncation.
"""

from datetime import datetime, timezone

from sqlalchemy import BigInteger, CheckConstraint, DateTime, SmallInteger, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# The table holds exactly one row, pinned to this primary key.
HIGH_WATER_ROW_ID = 1


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditChainState(Base):
    """Signed high-water record for the audit hash chain (single row)."""

    __tablename__ = "audit_chain_state"
    __table_args__ = (CheckConstraint("id = 1", name="ck_audit_chain_state_singleton"),)

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, default=HIGH_WATER_ROW_ID)
    # Authorized number of audit rows: +1 per append, -deleted per prune.
    entry_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # Keyed hash of the newest row at the time the count was last updated.
    head_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    # HMAC over ``f"{entry_count}:{head_hash or ''}"`` with the chain key.
    state_hmac: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utc_now, onupdate=_utc_now
    )
