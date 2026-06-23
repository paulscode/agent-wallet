# SPDX-License-Identifier: MIT
"""Add BOLT 12 offer / invoice_request / invoice tables.

Revision ID: 009_bolt12_tables
Revises: 008_audit_retention_chain_repair
Create Date: 2026-05-02 00:00:00.000000

Three tables landing together because they reference each other:

* ``bolt12_offers`` — offers we issue.
* ``bolt12_invoice_requests`` — invreqs we send (outbound) or
  receive (inbound). FK to ``bolt12_offers`` is nullable: an inbound
  invreq for an offer we don't recognise is still recorded for audit.
* ``bolt12_invoices`` — signed invoices in either direction. FK to
  ``bolt12_invoice_requests`` is RESTRICT — invoices outlive their
  triggering invreq from an audit perspective and we never want a
  cascade to silently delete them.

Three Postgres enums are introduced. ``bolt12_direction`` is shared
between the invreq and invoice tables, so we create it explicitly
and reuse it (``create_type=False`` on the second column).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "009_bolt12_tables"
down_revision: Union[str, None] = "008_audit_retention_chain_repair"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_OFFER_STATUS = postgresql.ENUM(
    "active",
    "disabled",
    "expired",
    name="bolt12_offer_status",
    create_type=False,
)
_DIRECTION = postgresql.ENUM(
    "outbound",
    "inbound",
    name="bolt12_direction",
    create_type=False,
)
_INVREQ_STATUS = postgresql.ENUM(
    "pending",
    "invoice_received",
    "invoice_sent",
    "timed_out",
    "failed",
    "cancelled",
    name="bolt12_invoice_request_status",
    create_type=False,
)
_INVOICE_STATUS = postgresql.ENUM(
    "open",
    "paid",
    "expired",
    "failed",
    name="bolt12_invoice_status",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    # Explicit creation with checkfirst so re-running on a partially
    # migrated DB (e.g. after a previous failure) is idempotent.
    # Column-bound ENUMs use ``create_type=False`` so ``create_table``
    # does not try to issue a second ``CREATE TYPE``.
    postgresql.ENUM("active", "disabled", "expired", name="bolt12_offer_status").create(bind, checkfirst=True)
    postgresql.ENUM("outbound", "inbound", name="bolt12_direction").create(bind, checkfirst=True)
    postgresql.ENUM(
        "pending",
        "invoice_received",
        "invoice_sent",
        "timed_out",
        "failed",
        "cancelled",
        name="bolt12_invoice_request_status",
    ).create(bind, checkfirst=True)
    postgresql.ENUM("open", "paid", "expired", "failed", name="bolt12_invoice_status").create(bind, checkfirst=True)

    op.create_table(
        "bolt12_offers",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "api_key_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column("bolt12", sa.Text(), nullable=False, unique=True),
        sa.Column("description", sa.String(length=640), nullable=True),
        sa.Column("amount_msat", sa.BigInteger(), nullable=True),
        sa.Column("currency", sa.String(length=8), nullable=True),
        sa.Column("issuer", sa.String(length=256), nullable=True),
        sa.Column("issuer_id_hex", sa.String(length=66), nullable=True),
        sa.Column(
            "status",
            _OFFER_STATUS,
            nullable=False,
            server_default="active",
        ),
        sa.Column("absolute_expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quantity_max", sa.BigInteger(), nullable=True),
        sa.Column("encrypted_metadata", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_bolt12_offers_api_key_id", "bolt12_offers", ["api_key_id"])
    op.create_index("ix_bolt12_offers_issuer_id_hex", "bolt12_offers", ["issuer_id_hex"])
    op.create_index("idx_bolt12_offers_status", "bolt12_offers", ["status"])
    op.create_index("idx_bolt12_offers_created_at", "bolt12_offers", ["created_at"])

    op.create_table(
        "bolt12_invoice_requests",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "api_key_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "offer_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("bolt12_offers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("direction", _DIRECTION, nullable=False),
        sa.Column("offer_bolt12", sa.Text(), nullable=False),
        sa.Column("amount_msat", sa.BigInteger(), nullable=True),
        sa.Column("quantity", sa.BigInteger(), nullable=True),
        sa.Column("payer_note", sa.String(length=512), nullable=True),
        sa.Column("payer_id_hex", sa.String(length=66), nullable=True),
        sa.Column("encrypted_payer_secret", sa.Text(), nullable=True),
        sa.Column("invreq_bolt12", sa.Text(), nullable=False),
        sa.Column(
            "status",
            _INVREQ_STATUS,
            nullable=False,
            server_default="pending",
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_bolt12_invoice_requests_api_key_id",
        "bolt12_invoice_requests",
        ["api_key_id"],
    )
    op.create_index(
        "ix_bolt12_invoice_requests_offer_id",
        "bolt12_invoice_requests",
        ["offer_id"],
    )
    op.create_index(
        "ix_bolt12_invoice_requests_payer_id_hex",
        "bolt12_invoice_requests",
        ["payer_id_hex"],
    )
    op.create_index(
        "idx_bolt12_invreq_status",
        "bolt12_invoice_requests",
        ["status"],
    )
    op.create_index(
        "idx_bolt12_invreq_created_at",
        "bolt12_invoice_requests",
        ["created_at"],
    )

    op.create_table(
        "bolt12_invoices",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "api_key_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "invoice_request_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("bolt12_invoice_requests.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("direction", _DIRECTION, nullable=False),
        sa.Column("invoice_bolt12", sa.Text(), nullable=False),
        sa.Column("amount_msat", sa.BigInteger(), nullable=False),
        sa.Column("payment_hash_hex", sa.String(length=64), nullable=False),
        sa.Column("node_id_hex", sa.String(length=66), nullable=True),
        sa.Column("expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("encrypted_preimage", sa.Text(), nullable=True),
        sa.Column(
            "status",
            _INVOICE_STATUS,
            nullable=False,
            server_default="open",
        ),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_bolt12_invoices_api_key_id", "bolt12_invoices", ["api_key_id"])
    op.create_index(
        "ix_bolt12_invoices_invoice_request_id",
        "bolt12_invoices",
        ["invoice_request_id"],
    )
    op.create_index(
        "ix_bolt12_invoices_payment_hash_hex",
        "bolt12_invoices",
        ["payment_hash_hex"],
    )
    op.create_index("idx_bolt12_invoices_status", "bolt12_invoices", ["status"])
    op.create_index("idx_bolt12_invoices_created_at", "bolt12_invoices", ["created_at"])


def downgrade() -> None:
    op.drop_index("idx_bolt12_invoices_created_at", table_name="bolt12_invoices")
    op.drop_index("idx_bolt12_invoices_status", table_name="bolt12_invoices")
    op.drop_index("ix_bolt12_invoices_payment_hash_hex", table_name="bolt12_invoices")
    op.drop_index("ix_bolt12_invoices_invoice_request_id", table_name="bolt12_invoices")
    op.drop_index("ix_bolt12_invoices_api_key_id", table_name="bolt12_invoices")
    op.drop_table("bolt12_invoices")

    op.drop_index("idx_bolt12_invreq_created_at", table_name="bolt12_invoice_requests")
    op.drop_index("idx_bolt12_invreq_status", table_name="bolt12_invoice_requests")
    op.drop_index(
        "ix_bolt12_invoice_requests_payer_id_hex",
        table_name="bolt12_invoice_requests",
    )
    op.drop_index(
        "ix_bolt12_invoice_requests_offer_id",
        table_name="bolt12_invoice_requests",
    )
    op.drop_index(
        "ix_bolt12_invoice_requests_api_key_id",
        table_name="bolt12_invoice_requests",
    )
    op.drop_table("bolt12_invoice_requests")

    op.drop_index("idx_bolt12_offers_created_at", table_name="bolt12_offers")
    op.drop_index("idx_bolt12_offers_status", table_name="bolt12_offers")
    op.drop_index("ix_bolt12_offers_issuer_id_hex", table_name="bolt12_offers")
    op.drop_index("ix_bolt12_offers_api_key_id", table_name="bolt12_offers")
    op.drop_table("bolt12_offers")

    bind = op.get_bind()
    _INVOICE_STATUS.drop(bind, checkfirst=True)
    _INVREQ_STATUS.drop(bind, checkfirst=True)
    _DIRECTION.drop(bind, checkfirst=True)
    _OFFER_STATUS.drop(bind, checkfirst=True)
