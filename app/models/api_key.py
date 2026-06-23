# SPDX-License-Identifier: MIT
"""
API Key model — stored hashed (SHA-256), never in plaintext.

Each key has:
- name: human-readable identifier
- key_hash: SHA-256 hash (used for lookup)
- scope: permission tier — ``monitor`` (read + receive), ``spend``
  (monitor + send payments / withdraw, for agents), or ``admin``
  (full control)
- is_active: can be disabled without deletion
- expires_at: optional expiry
- last_used_at: for monitoring
"""

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Index, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# Permission tiers, in increasing order of privilege. ``monitor`` is
# the floor: it reads all state and may receive funds (generate
# addresses, mint invoices) but can never move funds out.
SCOPE_MONITOR = "monitor"
SCOPE_SPEND = "spend"
SCOPE_ADMIN = "admin"
API_KEY_SCOPES = (SCOPE_MONITOR, SCOPE_SPEND, SCOPE_ADMIN)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class APIKey(Base):
    """Hashed API key for authenticated access."""

    __tablename__ = "api_keys"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    key_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )
    # Audit-only record of the digest a key carried under the *previous*
    # SECRET_KEY, captured the first time the key re-authenticates after a
    # rotation. Continuity across a rotation is achieved by rewriting
    # ``key_hash`` itself (see ``app.core.security.get_api_key``), NOT by
    # this column: it is never read in any authentication lookup or
    # ``compare_digest`` and MUST NOT be — accepting a key by a digest
    # computed under a retired secret would defeat the rotation. It exists
    # solely so an operator can inspect what a key hashed to before the
    # most recent rotation.
    key_hash_prev: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    # Permission tier: ``monitor`` | ``spend`` | ``admin``. The
    # canonical authority for what a key may do; ``is_admin`` /
    # ``can_spend`` below are derived from it.
    scope: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=SCOPE_MONITOR,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )

    __table_args__ = (Index("idx_api_keys_active", "is_active"),)

    @property
    def is_admin(self) -> bool:
        """Full-control key (manages channels, signs, admin ops)."""
        return self.scope == SCOPE_ADMIN

    @is_admin.setter
    def is_admin(self, value: bool) -> None:
        """Boolean alias onto the canonical ``scope`` column: ``True`` →
        ``admin``, ``False`` → ``monitor``. ``scope`` is the source of
        truth, so a caller wanting the ``spend`` tier sets ``scope``
        directly — the boolean has no value for it."""
        self.scope = SCOPE_ADMIN if value else SCOPE_MONITOR

    @property
    def can_spend(self) -> bool:
        """May move funds — send Lightning payments or withdraw on-chain."""
        return self.scope in (SCOPE_SPEND, SCOPE_ADMIN)

    def __repr__(self) -> str:
        return f"<APIKey name='{self.name}' scope='{self.scope}' active={self.is_active}>"
