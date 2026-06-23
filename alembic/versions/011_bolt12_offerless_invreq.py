# SPDX-License-Identifier: MIT
"""Allow offer-less BOLT 12 invreqs.

Revision ID: 011_bolt12_offerless_invreq
Revises: 010_bolt12_offer_provenance
Create Date: 2026-05-06 00:00:00.000000

Relaxes ``bolt12_invoice_requests.offer_bolt12`` to be NULLABLE so
the inbound responder can persist invreqs that did not arrive in
response to one of our published offers (BOLT 12 §"Requirements
for the Sender": offer-less / refund flow). For those rows
``offer_id`` is also NULL — see model docstring.

The existing wire-byte audit (``invreq_bolt12``) stays NOT NULL —
we always have the raw invreq we replied to.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "011_bolt12_offerless_invreq"
down_revision: Union[str, None] = "010_bolt12_offer_provenance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("bolt12_invoice_requests") as batch_op:
        batch_op.alter_column(
            "offer_bolt12",
            existing_type=sa.Text(),
            nullable=True,
        )


def downgrade() -> None:
    # Best-effort: any offer-less rows must be removed first or this
    # will fail. Operators downgrading should backfill or delete those
    # rows manually.
    with op.batch_alter_table("bolt12_invoice_requests") as batch_op:
        batch_op.alter_column(
            "offer_bolt12",
            existing_type=sa.Text(),
            nullable=False,
        )
