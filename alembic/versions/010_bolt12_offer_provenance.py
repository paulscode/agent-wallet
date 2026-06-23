# SPDX-License-Identifier: MIT
"""Add provenance + last-paid tracking to bolt12_offers.

Revision ID: 010_bolt12_offer_provenance
Revises: 009_bolt12_tables
Create Date: 2026-05-05 00:00:00.000000

Adds two columns to ``bolt12_offers`` that let the dashboard tell
the three classes of rows apart without UI guesswork:

* ``source`` — how the row got here:
    - ``issued``   — minted by us via ``/api/bolt12/offers/issue``
    - ``imported`` — pasted into the dashboard and saved without paying
    - ``paid``     — first observed because the user paid it

* ``last_paid_at`` — most recent ``pay_offer`` timestamp, used for
  the "last paid" column in the Pay tab's Payees list.

Backfill rule for existing rows:
    * ``encrypted_metadata IS NOT NULL``  ⇒  ``issued``
      (only the issue flow stores the encrypted issuer signing seed).
    * everything else                     ⇒  ``imported``.
We can't retroactively distinguish ``imported`` vs ``paid`` from
existing data, so we choose the conservative default; future pay
flows will upgrade rows correctly.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "010_bolt12_offer_provenance"
down_revision: Union[str, None] = "009_bolt12_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_OFFER_SOURCE = postgresql.ENUM(
    "issued",
    "imported",
    "paid",
    name="bolt12_offer_source",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    postgresql.ENUM("issued", "imported", "paid", name="bolt12_offer_source").create(bind, checkfirst=True)

    op.add_column(
        "bolt12_offers",
        sa.Column(
            "source",
            _OFFER_SOURCE,
            nullable=False,
            server_default="imported",
        ),
    )
    op.add_column(
        "bolt12_offers",
        sa.Column(
            "last_paid_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # Backfill: rows with an encrypted issuer seed are the ones we
    # minted ourselves.
    op.execute("UPDATE bolt12_offers SET source = 'issued' WHERE encrypted_metadata IS NOT NULL")

    # Drop the server_default now that the table is fully populated;
    # we want application code to always set ``source`` explicitly.
    op.alter_column("bolt12_offers", "source", server_default=None)

    op.create_index("idx_bolt12_offers_source", "bolt12_offers", ["source"])


def downgrade() -> None:
    op.drop_index("idx_bolt12_offers_source", table_name="bolt12_offers")
    op.drop_column("bolt12_offers", "last_paid_at")
    op.drop_column("bolt12_offers", "source")
    bind = op.get_bind()
    postgresql.ENUM(name="bolt12_offer_source").drop(bind, checkfirst=True)
