# SPDX-License-Identifier: MIT
"""Server-persisted dashboard key/value settings.

Revision ID: 050_dashboard_settings
Revises: 049_channel_mix_bootstrap
Create Date: 2026-06-30 00:00:00.000000

A tiny key/value table for dashboard preferences that must survive page
reloads / browser changes but reset on reinstall (data volume wiped).
Its first user is the onboarding "skip" flag, stored node-scoped so a
fresh node or fresh install shows the welcome wizard again.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "050_dashboard_settings"
down_revision: Union[str, None] = "049_channel_mix_bootstrap"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "dashboard_settings",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade() -> None:
    op.drop_table("dashboard_settings")
