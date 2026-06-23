# SPDX-License-Identifier: MIT
"""Braiins Deposit dust prevention (+ of plan).

Revision ID: 032_braiins_deposit_dust_prevention
Revises: 031_braiins_deposit_phase3
Create Date: 2026-05-22 10:00:00.000000

Adds two columns and one enum value to support the dust-prevention
plan:

* ``actual_sent_sats`` — the amount the wallet actually broadcast
  to the destination address. Differs from ``deposit_amount_sats``
  (the bin amount) because the new dust-safe send tx absorbs the
  fee from the output rather than producing wallet-side change.
  Nullable so old rows remain unaffected; new rows populate it at
  the SENDING -> BROADCAST transition.

* ``awaiting_fee_reduction`` enum value on
  ``braiins_deposit_status``. New (Layer 4) state for sessions
  whose send is infeasible at current fees. A periodic re-checker
  promotes the session back to FUNDED when fees fall enough to
  allow a dust-safe send.

* ``send_infeasible_reason`` — short string explaining why a
  session entered ``awaiting_fee_reduction``. Used by the
  dashboard to render a context-specific message; recovery
  doesn't depend on the value.

All new columns are nullable. ``ALTER TYPE ... ADD VALUE`` is
idempotent on PostgreSQL via ``IF NOT EXISTS`` (PG12+); on SQLite
the enum is a check-constrained string column rebuilt on next
attach so the column-level migration is a no-op.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "032_braiins_deposit_dust_prevention"
down_revision: Union[str, None] = "031_braiins_deposit_phase3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    if is_pg:
        # New status value for Layer 4 stuck-at-send recovery.
        op.execute("ALTER TYPE braiins_deposit_status ADD VALUE IF NOT EXISTS 'awaiting_fee_reduction'")

    # New columns. Both nullable so the migration is additive and
    # existing rows in any state are unaffected.
    op.add_column(
        "braiins_deposit_sessions",
        sa.Column("actual_sent_sats", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "braiins_deposit_sessions",
        sa.Column(
            "send_infeasible_reason",
            sa.String(length=128),
            nullable=True,
        ),
    )


def downgrade() -> None:
    # Drop the columns. Removing the enum value is omitted: PostgreSQL
    # has no DROP VALUE, and dropping the type requires migrating
    # every dependent column. Operators rolling back can leave the
    # enum value in place — it's just unused.
    op.drop_column("braiins_deposit_sessions", "send_infeasible_reason")
    op.drop_column("braiins_deposit_sessions", "actual_sent_sats")
