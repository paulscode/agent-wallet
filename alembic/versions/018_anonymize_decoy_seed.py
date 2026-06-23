# SPDX-License-Identifier: MIT
"""anonymize_decoy_output — on-chain self-source decoy-output table.

Revision ID: 018_anonymize_decoy_seed
Revises: 017_anonymize_feature_enabled_at_quantize
Create Date: 2026-05-11 00:00:01.000000

Owns the on-chain decoy outputs the
 consolidation flow emits to a separately-derived
wallet-controlled address. On-chain self-source ships *receive-only*; spending
requires importing the seed into a separate single-sig signer
(external user-funded sources add the in-process spending path).

The row layout:
* ``session_id`` is the session that produced the decoy output;
  retention nulls it to the all-zeros sentinel UUID.
* ``session_account`` is the BIP-86 account index, HMAC-derived
  from the session id under
  ``ANONYMIZE_DECOY_SEED_ACCOUNT_KEY``.
* ``derivation_index`` is the BIP-86 child index within the
  account.
* ``outpoint`` is the on-chain ``txid:vout`` of the decoy output;
  retention preserves unspent decoy outpoints (residual #34) so the
  wallet still tracks the UTXO.

The partial-unique index ``(session_account, derivation_index)``
predicate-restricted to ``WHERE session_id IS NOT NULL`` prevents
two live sessions from colliding on the same derivation path; the
sentinel-FK INSERT trigger is added in 016's pre-INSERT-trigger
infrastructure where on-chain self-source lands the actual writes.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "018_anonymize_decoy_seed"
down_revision: Union[str, None] = "017_anonymize_feature_enabled_at_quantize"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "anonymize_decoy_output",
        sa.Column(
            "id",
            sa.BigInteger(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column(
            "session_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey(
                "anonymize_session.id",
                ondelete="CASCADE",
            ),
            nullable=True,
        ),
        sa.Column("session_account", sa.Integer(), nullable=True),
        sa.Column("derivation_index", sa.Integer(), nullable=True),
        sa.Column("address", sa.Text(), nullable=True),
        sa.Column("value_sat", sa.BigInteger(), nullable=True),
        sa.Column("outpoint", sa.Text(), nullable=True),
        sa.Column(
            "seed_orphaned",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "spent_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    # Partial-unique index on the live-session predicate.
    # SQLite supports partial indexes; Postgres of course supports them.
    op.create_index(
        "ix_anonymize_decoy_output_live_derivation",
        "anonymize_decoy_output",
        ["session_account", "derivation_index"],
        unique=True,
        postgresql_where=sa.text("session_id IS NOT NULL"),
        sqlite_where=sa.text("session_id IS NOT NULL"),
    )
    # Index on outpoint for fast UTXO lookups.
    op.create_index(
        "ix_anonymize_decoy_output_outpoint",
        "anonymize_decoy_output",
        ["outpoint"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_anonymize_decoy_output_outpoint",
        table_name="anonymize_decoy_output",
    )
    op.drop_index(
        "ix_anonymize_decoy_output_live_derivation",
        table_name="anonymize_decoy_output",
    )
    op.drop_table("anonymize_decoy_output")
