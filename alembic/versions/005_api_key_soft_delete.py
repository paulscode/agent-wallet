# SPDX-License-Identifier: MIT
"""Add deleted_at column to api_keys for soft-delete.

Revision ID: 005_api_key_soft_delete
Revises: 004_reencrypt_fields
Create Date: 2026-04-30 00:00:01.000000

API keys are now soft-deleted: ``DELETE /admin/api-keys/{id}`` sets
``is_active=False`` and stamps ``deleted_at``. A separate
``POST /admin/api-keys/{id}/purge`` hard-deletes the row, but only
once the audit-log retention window has elapsed since soft-deletion.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "005_api_key_soft_delete"
down_revision: Union[str, None] = "004_reencrypt_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Enforce at the DB level that an API key cannot be hard-deleted
    # while audit-log rows still reference it. Hard-delete is gated
    # through ``POST /admin/api-keys/{id}/purge``, which only runs
    # after the audit retention window has elapsed.
    op.create_foreign_key(
        "fk_audit_logs_api_key_id",
        "audit_logs",
        "api_keys",
        ["api_key_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint("fk_audit_logs_api_key_id", "audit_logs", type_="foreignkey")
    op.drop_column("api_keys", "deleted_at")
