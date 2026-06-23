# SPDX-License-Identifier: MIT
"""Add ``invreq_metadata_hex`` to ``bolt12_invoice_requests``.

Revision ID: 013_bolt12_invreq_metadata_dedup
Revises: 012_bolt12_default_receive
Create Date: 2026-05-06 00:00:00.000000

Stores the BOLT 12 ``invreq_metadata`` (16+ random bytes set by the
payer at invreq construction) on each row. The spec mandates that
re-sending the same signed bytes MUST yield the same invoice reply;
without an idempotency anchor a hostile peer can rotate ``payer_id``
per invreq and bypass the per-payer rate limiter, forcing the
responder to mint fresh LND invoices indefinitely (see hardening
plan).

A partial unique index on
``(api_key_id, invreq_metadata_hex)`` WHERE
``direction='inbound' AND invreq_metadata_hex IS NOT NULL``
prevents duplicate inbound invreqs from being persisted; the
responder consults this index to decide between "replay an existing
invoice" and "mint a fresh one". Partial-index semantics let legacy
NULL rows coexist (they were inserted before the column existed).
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "013_bolt12_invreq_metadata_dedup"
down_revision: Union[str, None] = "012_bolt12_default_receive"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("bolt12_invoice_requests") as batch_op:
        batch_op.add_column(
            sa.Column(
                "invreq_metadata_hex",
                sa.String(length=128),
                nullable=True,
            )
        )

    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.create_index(
            "uq_bolt12_invreq_inbound_metadata",
            "bolt12_invoice_requests",
            ["api_key_id", "invreq_metadata_hex"],
            unique=True,
            postgresql_where=sa.text("direction = 'inbound' AND invreq_metadata_hex IS NOT NULL"),
        )
    else:
        op.create_index(
            "uq_bolt12_invreq_inbound_metadata",
            "bolt12_invoice_requests",
            ["api_key_id", "invreq_metadata_hex"],
            unique=False,
            sqlite_where=sa.text("direction = 'inbound' AND invreq_metadata_hex IS NOT NULL"),
        )


def downgrade() -> None:
    op.drop_index(
        "uq_bolt12_invreq_inbound_metadata",
        table_name="bolt12_invoice_requests",
    )
    with op.batch_alter_table("bolt12_invoice_requests") as batch_op:
        batch_op.drop_column("invreq_metadata_hex")
