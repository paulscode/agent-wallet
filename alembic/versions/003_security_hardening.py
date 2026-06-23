# SPDX-License-Identifier: MIT
"""Add audit log hash chain columns and re-encrypt sensitive fields

Revision ID: 003_security_hardening
Revises: 002_dashboard_sentinel_key
Create Date: 2026-04-18 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "003_security_hardening"
down_revision: Union[str, None] = "002_dashboard_sentinel_key"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add hash chain columns to audit_logs
    op.add_column("audit_logs", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column("audit_logs", sa.Column("entry_hash", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_logs", "entry_hash")
    op.drop_column("audit_logs", "prev_hash")
