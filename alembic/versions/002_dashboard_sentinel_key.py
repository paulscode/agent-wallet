# SPDX-License-Identifier: MIT
"""Add dashboard sentinel API key for FK integrity

Revision ID: 002_dashboard_sentinel_key
Revises: 001_initial
Create Date: 2026-04-18 00:00:00.000000
"""

import uuid
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision: str = "002_dashboard_sentinel_key"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Must match DASHBOARD_KEY_ID in app/dashboard/__init__.py
_DASHBOARD_KEY_ID = uuid.UUID("00000000-0000-0000-0000-da5b0a4d0000")


def upgrade() -> None:
    # Insert a sentinel API key row so dashboard-initiated swaps
    # and audit logs satisfy the FK constraint on api_key_id.
    op.execute(
        sa.text(
            """
            INSERT INTO api_keys (id, name, key_hash, is_admin, is_active, created_at)
            VALUES (:id, :name, :key_hash, true, true, now())
            ON CONFLICT (id) DO NOTHING
            """
        ).bindparams(
            sa.bindparam("id", _DASHBOARD_KEY_ID, type_=UUID(as_uuid=True)),
            sa.bindparam("name", "__dashboard__"),
            sa.bindparam("key_hash", "__dashboard_sentinel__"),
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text("DELETE FROM api_keys WHERE id = :id").bindparams(
            sa.bindparam("id", _DASHBOARD_KEY_ID, type_=UUID(as_uuid=True))
        )
    )
