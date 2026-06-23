# SPDX-License-Identifier: MIT
"""Add partial unique index on ``bolt12_offers.issuer_id_hex`` for live ACTIVE rows.

Revision ID: 039_bolt12_issuer_id_unique_active
Revises: 038_boltz_swap_lockup_txid
Create Date: 2026-06-02 00:00:00.000000

The same ``issuer_id_hex`` (the offer's encoded issuer node id)
must not have two simultaneously live ACTIVE rows in
``bolt12_offers``. Without this, an operator race during
offer-rotation can land two rows with the same issuer key —
which then collide on inbound-invreq matching: the responder
walks the rows in undefined order and may bind a fresh invoice
to the wrong row, or run the offer-less branch (which is gated
behind a setting) instead.

This is enforced as a *partial* unique index so:

* Soft-deleted rows (``deleted_at IS NOT NULL``) don't conflict
  with their replacement — offer rotation is allowed.
* Non-ACTIVE rows (``REVOKED`` / ``EXPIRED``) don't block the
  insert of a fresh ACTIVE row with the same issuer id.

Scoped to the whole table (not per ``api_key_id``) because the
issuer id is a wallet-wide private key; sharing it across API
keys would be a node-key reuse hazard.

PostgreSQL: real partial unique index via ``postgresql_where``.
SQLite (test only): a non-unique index with ``sqlite_where`` —
the application layer in ``app/api/bolt12.py`` is the source of
truth on the test driver.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "039_bolt12_issuer_id_unique_active"
down_revision: Union[str, None] = "038_boltz_swap_lockup_txid"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.create_index(
            "uq_bolt12_offer_issuer_id_active",
            "bolt12_offers",
            ["issuer_id_hex"],
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL AND status = 'active' AND issuer_id_hex IS NOT NULL"),
        )
    else:
        # SQLite: partial index supported via ``sqlite_where``. The
        # Bolt12OfferStatus Enum uses ``values_callable`` so the .value
        # ('active') is written to the DB on both dialects.
        op.create_index(
            "uq_bolt12_offer_issuer_id_active",
            "bolt12_offers",
            ["issuer_id_hex"],
            unique=False,
            sqlite_where=sa.text("deleted_at IS NULL AND status = 'active' AND issuer_id_hex IS NOT NULL"),
        )


def downgrade() -> None:
    op.drop_index(
        "uq_bolt12_offer_issuer_id_active",
        table_name="bolt12_offers",
    )
