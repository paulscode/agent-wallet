# SPDX-License-Identifier: MIT
"""Add utxo_label + address_purpose tables for per-outpoint labels.

Revision ID: 015_utxo_labels
Revises: 014_bolt12_payment_hash_unique
Create Date: 2026-05-08 00:00:00.000000

Adds the persistent stores backing the dashboard UTXO management
feature.

``utxo_label`` associates a single (txid, vout) outpoint with:

* an ≤80-char free-form label,
* a ``source`` indicating provenance (user edit vs. auto-derived
  vs. inherited from a parent UTXO),
* a ``spent_at`` lifecycle marker so labels for spent outputs can
  appear in the *Recently spent* fold-down before being purged.

``address_purpose`` stores the optional "purpose" string the user
supplies when generating a fresh on-chain receive address. The
reconcile loop joins it against ``ListUnspent`` so the first UTXO
to land at a purpose-tagged address gets a matching ``auto:receive``
label written into ``utxo_label``.

Outpoints and addresses are public chain data and labels are short
operational notes, so we deliberately store them in plaintext rather
than running them through the Fernet helper.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "015_utxo_labels"
down_revision: Union[str, None] = "014_bolt12_payment_hash_unique"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Allowed values for the ``source`` enum. Kept as plain strings so we
# can grow the set without an ALTER TYPE on PostgreSQL — Alembic /
# SQLAlchemy will emit a CHECK-constrained VARCHAR rather than a
# native ENUM type when ``native_enum=False`` is in play. Here we use
# the native enum with ``values_callable`` matching the model.
_SOURCE_VALUES = (
    "user",
    "auto:receive",
    "auto:swap",
    "auto:channel_close",
    "inherited",
)


def upgrade() -> None:
    op.create_table(
        "utxo_label",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("txid", sa.String(64), nullable=False),
        sa.Column("vout", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(80), nullable=False, server_default=""),
        sa.Column(
            "source",
            sa.Enum(*_SOURCE_VALUES, name="utxo_label_source"),
            nullable=False,
            server_default="user",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("spent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("spent_txid", sa.String(64), nullable=True),
        sa.Column("note", sa.String(64), nullable=True),
        sa.UniqueConstraint("txid", "vout", name="uq_utxo_label_outpoint"),
    )
    op.create_index("ix_utxo_label_spent_at", "utxo_label", ["spent_at"])
    op.create_index("ix_utxo_label_txid", "utxo_label", ["txid"])

    op.create_table(
        "address_purpose",
        sa.Column("address", sa.String(128), primary_key=True),
        sa.Column("purpose", sa.String(80), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_address_purpose_consumed_at",
        "address_purpose",
        ["consumed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_address_purpose_consumed_at", table_name="address_purpose")
    op.drop_table("address_purpose")
    op.drop_index("ix_utxo_label_txid", table_name="utxo_label")
    op.drop_index("ix_utxo_label_spent_at", table_name="utxo_label")
    op.drop_table("utxo_label")
    # Drop the native enum type if PostgreSQL.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        sa.Enum(name="utxo_label_source").drop(bind, checkfirst=True)
