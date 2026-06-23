# SPDX-License-Identifier: MIT
"""Add key_hash_prev to api_keys for SECRET_KEY rotation.

Revision ID: 007_api_key_prev_hash
Revises: 006_recompute_audit_hashes
Create Date: 2026-04-30 00:00:03.000000

Adds a nullable ``key_hash_prev`` column. On a key-hash mismatch with
the current ``SECRET_KEY``, ``get_api_key`` falls back to a digest
computed under ``SECRET_KEY_PREVIOUS``; on success it rewrites the row
to the new digest and stashes the old digest in ``key_hash_prev``.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "007_api_key_prev_hash"
down_revision: Union[str, None] = "006_recompute_audit_hashes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("key_hash_prev", sa.String(64), nullable=True),
    )
    op.create_index(
        "idx_api_keys_key_hash_prev",
        "api_keys",
        ["key_hash_prev"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("idx_api_keys_key_hash_prev", table_name="api_keys")
    op.drop_column("api_keys", "key_hash_prev")
