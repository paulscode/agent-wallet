# SPDX-License-Identifier: MIT
"""Add ``channel_state_snapshot`` + ``settle_timeout_audited_at`` to ``bolt12_invoices``.

Revision ID: 040_bolt12_invoice_telemetry_columns
Revises: 039_bolt12_issuer_id_unique_active
Create Date: 2026-06-05 12:00:00.000000

Two telemetry columns supporting the BOLT 12 receive-path
post-mortem workflow:

* ``channel_state_snapshot`` (JSON, nullable) — a per-channel
  balance + gossiped-policy blob captured at mint time. Lets a
  failure investigation reconstruct the channel state the
  invoice was minted under, without depending on the current
  live state.

* ``settle_timeout_audited_at`` (timestamptz, nullable) —
  one-shot watchdog flag. The
  ``bolt12_settlement_watchdog`` Celery task stamps this when it
  emits a ``bolt12_invoice_settle_timeout`` audit row for the
  invoice, so subsequent ticks don't generate duplicate alerts.

Both are NULL on existing rows; no backfill required.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "040_bolt12_invoice_telemetry_columns"
down_revision: Union[str, None] = "039_bolt12_issuer_id_unique_active"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("bolt12_invoices") as batch_op:
        batch_op.add_column(
            sa.Column(
                "channel_state_snapshot",
                sa.JSON(),
                nullable=True,
            )
        )
        batch_op.add_column(
            sa.Column(
                "settle_timeout_audited_at",
                sa.DateTime(timezone=True),
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("bolt12_invoices") as batch_op:
        batch_op.drop_column("settle_timeout_audited_at")
        batch_op.drop_column("channel_state_snapshot")
