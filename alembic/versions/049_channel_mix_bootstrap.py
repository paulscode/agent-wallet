# SPDX-License-Identifier: MIT
"""Channel-mix bootstrap (capital-efficient inbound) executor.

Revision ID: 049_channel_mix_bootstrap
Revises: 048_channel_mix_runs
Create Date: 2026-06-29 00:00:00.000000

Adds the schema the sequential open→drain→recycle "bootstrap" executor
needs alongside the existing parallel channel-mix executor:

* Two new ``channel_mix_run_state`` enum values:
    - ``awaiting_funds`` — recyclable balance temporarily below the next
      open; transient, non-terminal.
    - ``stopped_insufficient`` — ran out of recyclable capital before the
      target; terminal, channels intact.

* New columns on ``channel_mix_runs``:
    - ``mode`` (NOT NULL, default ``"parallel"``) — execution strategy
      discriminator; the executor branches on it so existing parallel
      runs are untouched.
    - ``target_inbound_sats`` (nullable) — target-inbound framing goal.
    - ``realized_inbound_sats`` / ``total_fees_sats`` (NOT NULL, default 0)
      — running totals the loop updates as rounds settle.
    - ``stop_requested`` (NOT NULL, default false) — the dashboard's
      cooperative "stop after this round" flag.
    - ``bootstrap_params`` (JSON, nullable) — peer-selection + option
      inputs the loop needs to re-pick peers and recompute the schedule
      at runtime (rounds are appended as they run, not pre-materialized).

All new columns carry a server default (or are nullable) so existing
parallel-run rows are unaffected. The enum-value adds use
``ALTER TYPE ... ADD VALUE IF NOT EXISTS`` on PostgreSQL (transaction-
safe from PG12+) and are no-ops on SQLite (check-constrained string
columns are rebuilt on next attach).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "049_channel_mix_bootstrap"
down_revision: Union[str, None] = "048_channel_mix_runs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"

    if is_pg:
        # New run-state values. IF NOT EXISTS keeps the migration
        # idempotent across crash recovery during deploys.
        op.execute(
            "ALTER TYPE channel_mix_run_state ADD VALUE IF NOT EXISTS 'awaiting_funds'"
        )
        op.execute(
            "ALTER TYPE channel_mix_run_state ADD VALUE IF NOT EXISTS 'stopped_insufficient'"
        )

    with op.batch_alter_table("channel_mix_runs") as batch:
        batch.add_column(
            sa.Column(
                "mode",
                sa.String(length=16),
                nullable=False,
                server_default="parallel",
            )
        )
        batch.add_column(
            sa.Column("target_inbound_sats", sa.BigInteger(), nullable=True)
        )
        batch.add_column(
            sa.Column(
                "realized_inbound_sats",
                sa.BigInteger(),
                nullable=False,
                server_default="0",
            )
        )
        batch.add_column(
            sa.Column(
                "total_fees_sats",
                sa.BigInteger(),
                nullable=False,
                server_default="0",
            )
        )
        batch.add_column(
            sa.Column(
                "stop_requested",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            )
        )
        batch.add_column(sa.Column("bootstrap_params", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("channel_mix_runs") as batch:
        batch.drop_column("bootstrap_params")
        batch.drop_column("stop_requested")
        batch.drop_column("total_fees_sats")
        batch.drop_column("realized_inbound_sats")
        batch.drop_column("target_inbound_sats")
        batch.drop_column("mode")
    # NOTE: PostgreSQL does not support removing enum values without
    # rewriting the type. ``awaiting_funds`` and ``stopped_insufficient``
    # stay in ``channel_mix_run_state`` after downgrade — harmless, since
    # no remaining column references them.
