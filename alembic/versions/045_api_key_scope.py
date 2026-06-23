# SPDX-License-Identifier: MIT
"""API-key permission scope.

Revision ID: 045_api_key_scope
Revises: 044_audit_chain_keyed_hmac
Create Date: 2026-06-19 00:00:00.000000

An API key's authority is a ``scope`` tier — ``monitor`` (read +
receive), ``spend`` (monitor + send payments / withdraw), or ``admin``
(full control). This installs the ``scope`` column and sets each key's
scope from ``is_admin`` (``is_admin`` → ``admin``, otherwise
``monitor``).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "045_api_key_scope"
down_revision: Union[str, None] = "044_audit_chain_keyed_hmac"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("scope", sa.String(length=16), nullable=False, server_default="monitor"),
    )
    op.execute("UPDATE api_keys SET scope = 'admin' WHERE is_admin = true")
    op.execute("UPDATE api_keys SET scope = 'monitor' WHERE is_admin = false")
    # The model assigns scope on insert, so the column carries no
    # server-side default once every row has an explicit value.
    op.alter_column("api_keys", "scope", server_default=None)
    op.drop_column("api_keys", "is_admin")


def downgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute("UPDATE api_keys SET is_admin = true WHERE scope = 'admin'")
    op.alter_column("api_keys", "is_admin", server_default=None)
    op.drop_column("api_keys", "scope")
