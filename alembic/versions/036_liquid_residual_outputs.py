# SPDX-License-Identifier: MIT
"""Add ``liquid_residual_outputs`` table for residual-L-BTC recovery.

Revision ID: 036_liquid_residual_outputs
Revises: 035_anonymize_liquid_operator_ids
Create Date: 2026-05-26 00:00:00.000000

Tracks unspent L-BTC outputs at wallet-controlled addresses that
landed there after a unilateral Liquid recovery (cooperative
refund of the LN->L-BTC leg, or unilateral script-path claim of
a stuck reverse leg). These outputs are NOT part of any active
anonymize session — they are operator-owned residuals waiting to
be swept back to Lightning via a one-shot L-BTC->LN submarine
swap.

Schema mirrors the residual-output data model: identity columns
(txid, vout) + provenance (session_id when known) + economics
(value_sat, asset_id) + derivation pointer (address,
derivation_path) + lifecycle timestamps (discovered_at,
last_seen_at, recovered_at, dust_acknowledged_at).

Constraints:

* PRIMARY KEY on a synthetic uuid for FK ergonomics (session FK
  is the natural reference; a (txid, vout) PK would not survive
  a chain reorg replay edge-case where the txid is reused).
* UNIQUE on (txid, vout) so a re-scan that re-observes the same
  output upserts via the unique constraint instead of inserting
  a duplicate row.
* FK ``session_id`` on-delete SET NULL so retention purges of
  the parent ``anonymize_session`` row do not cascade-delete
  the residual audit history.
* CHECK ``value_sat > 0`` (a zero-value confidential output that
  unblinded to zero is a wallet bug, not a residual).
* Two partial indexes for the dashboard banner's hot query:
  one over un-recovered un-acknowledged rows (the banner total),
  one over recovered rows (audit page pagination).

No CHECK on ``asset_id`` matching L-BTC — the asset id is
network-dependent (mainnet vs. testnet vs. regtest) and the scan
task is the canonical filter for that. The column exists so
audit queries can confirm the scan didn't pick up a non-L-BTC
asset by mistake.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "036_liquid_residual_outputs"
down_revision: Union[str, None] = "035_anonymize_liquid_operator_ids"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "liquid_residual_outputs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
        ),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("anonymize_session.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("txid", sa.Text(), nullable=False),
        sa.Column("vout", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Text(), nullable=False),
        sa.Column("value_sat", sa.BigInteger(), nullable=False),
        sa.Column("address", sa.Text(), nullable=False),
        sa.Column("derivation_path", sa.Text(), nullable=False),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "recovered_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "recovered_swap_id",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "dust_acknowledged_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.CheckConstraint("value_sat > 0", name="ck_liquid_residual_value_positive"),
        sa.CheckConstraint("vout >= 0", name="ck_liquid_residual_vout_nonneg"),
        sa.UniqueConstraint("txid", "vout", name="uq_liquid_residual_outpoint"),
    )

    # Banner hot path: SUM(value_sat) WHERE recovered_at IS NULL
    # AND dust_acknowledged_at IS NULL. Partial index keeps the
    # banner check sub-millisecond regardless of historical row
    # count.
    op.create_index(
        "ix_liquid_residual_outputs_pending",
        "liquid_residual_outputs",
        ["discovered_at"],
        postgresql_where=sa.text("recovered_at IS NULL AND dust_acknowledged_at IS NULL"),
    )

    # Audit page: list rows the operator already swept, sorted by
    # recovery time. Partial so we don't index ~all rows when most
    # are still pending.
    op.create_index(
        "ix_liquid_residual_outputs_recovered_at",
        "liquid_residual_outputs",
        ["recovered_at"],
        postgresql_where=sa.text("recovered_at IS NOT NULL"),
    )

    # Per-session join used by the recovery flow when classifying
    # a session's stuck-recovery surface.
    op.create_index(
        "ix_liquid_residual_outputs_session_id",
        "liquid_residual_outputs",
        ["session_id"],
        postgresql_where=sa.text("session_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_liquid_residual_outputs_session_id",
        table_name="liquid_residual_outputs",
    )
    op.drop_index(
        "ix_liquid_residual_outputs_recovered_at",
        table_name="liquid_residual_outputs",
    )
    op.drop_index(
        "ix_liquid_residual_outputs_pending",
        table_name="liquid_residual_outputs",
    )
    op.drop_table("liquid_residual_outputs")
