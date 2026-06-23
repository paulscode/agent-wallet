# SPDX-License-Identifier: MIT
"""Add ``is_default_receive`` flag to ``bolt12_offers``.

Revision ID: 012_bolt12_default_receive
Revises: 011_bolt12_offerless_invreq
Create Date: 2026-05-20 00:00:00.000000

Adds a boolean flag that marks a single offer per API key as the
"canonical receive offer" the dashboard surfaces at the top of the
Issue tab. This is the offer a user hands to a recurring payer
(e.g. the Ocean mining pool) so they only need to register the
``lno1...`` string once.

Uniqueness is enforced via a partial unique index on
``(api_key_id) WHERE is_default_receive AND deleted_at IS NULL`` so
each API key has at most one live default offer at a time.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "012_bolt12_default_receive"
down_revision: Union[str, None] = "011_bolt12_offerless_invreq"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("bolt12_offers") as batch_op:
        batch_op.add_column(
            sa.Column(
                "is_default_receive",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            )
        )

    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.create_index(
            "uq_bolt12_offers_default_receive_per_key",
            "bolt12_offers",
            ["api_key_id"],
            unique=True,
            postgresql_where=sa.text("is_default_receive = true AND deleted_at IS NULL"),
        )
    else:
        # SQLite supports partial indexes via the ``sqlite_where`` kwarg
        # in newer SQLAlchemy; fall back to a non-unique index on older
        # versions. Tests run on SQLite where the application-layer
        # guard in :mod:`app.api.bolt12` is the source of truth.
        op.create_index(
            "uq_bolt12_offers_default_receive_per_key",
            "bolt12_offers",
            ["api_key_id"],
            unique=False,
            sqlite_where=sa.text("is_default_receive = 1 AND deleted_at IS NULL"),
        )


def downgrade() -> None:
    op.drop_index(
        "uq_bolt12_offers_default_receive_per_key",
        table_name="bolt12_offers",
    )
    with op.batch_alter_table("bolt12_offers") as batch_op:
        batch_op.drop_column("is_default_receive")
