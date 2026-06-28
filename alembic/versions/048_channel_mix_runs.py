# SPDX-License-Identifier: MIT
"""Channel-mix executor run table.

Revision ID: 048_channel_mix_runs
Revises: 047_audit_chain_high_water
Create Date: 2026-06-27 00:00:00.000000

Persists per-channel state for the channel-mix planner's executor so a
Celery worker can resume mid-run after a crash. The granular per-
channel sub-state lives in a JSON column; only the run-wide rollup
state gets its own typed column + enum.

Includes a ``plan_token_digest`` UNIQUE column — SHA-256 of the
plan-token the executor was authorised with. The execute endpoint
looks this up before insertion so a re-submitted execute call (browser
retry, double-click, transient network loss) maps to the original
run rather than opening every channel twice; the UNIQUE constraint is
the backstop if two requests race past the pre-check.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "048_channel_mix_runs"
down_revision: Union[str, None] = "047_audit_chain_high_water"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_RUN_STATE_VALUES = (
    "queued",
    "in_progress",
    "complete",
    "partial_failure",
    "cancelled",
)


def upgrade() -> None:
    op.create_table(
        "channel_mix_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("api_key_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "plan_token_digest",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "state",
            sa.Enum(*_RUN_STATE_VALUES, name="channel_mix_run_state"),
            nullable=False,
            server_default="queued",
        ),
        sa.Column("minimum_sats", sa.BigInteger(), nullable=False),
        sa.Column("recommended_sats", sa.BigInteger(), nullable=False),
        sa.Column("channels", postgresql.JSON(), nullable=False),
        sa.Column("warnings", postgresql.JSON(), nullable=False),
        sa.Column("error_message", sa.String(length=1024), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "plan_token_digest",
            name="uq_channel_mix_runs_plan_token_digest",
        ),
    )
    op.create_index(
        "idx_channel_mix_runs_state",
        "channel_mix_runs",
        ["state"],
    )
    op.create_index(
        "idx_channel_mix_runs_api_key",
        "channel_mix_runs",
        ["api_key_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_channel_mix_runs_api_key", table_name="channel_mix_runs")
    op.drop_index("idx_channel_mix_runs_state", table_name="channel_mix_runs")
    op.drop_table("channel_mix_runs")
    # PostgreSQL retains the enum type after dropping the table; clean
    # it up so a re-apply doesn't trip on "type already exists."
    sa.Enum(name="channel_mix_run_state").drop(op.get_bind(), checkfirst=True)
