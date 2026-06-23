# SPDX-License-Identifier: MIT
"""Add ``blinded_paths_summary`` to ``bolt12_invoices``.

Revision ID: 041_bolt12_blinded_paths_summary
Revises: 040_bolt12_invoice_telemetry_columns
Create Date: 2026-06-05 21:00:00.000000

Stores per-path metadata captured at mint time so the settlement
watchdog and HtlcEvent / settlement subscribers can feed the
per-intro circuit breaker (Follow-up #4) without decoding the
stored ``invoice_bolt12`` bech32 blob.

JSON shape mirrors the postprocess pipeline's output:

.. code-block:: json

    {
      "paths": [
        {
          "intro_pubkey": "035e4ff4…",
          "real_hops": 2,
          "htlc_max_msat_advertised": 60000000,
          "htlc_max_msat_clamped": 19800000,
          "terminal_peer_pubkey": "031cec…"
        }
      ]
    }

NULL on existing rows; no backfill required.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "041_bolt12_blinded_paths_summary"
down_revision: Union[str, None] = "040_bolt12_invoice_telemetry_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("bolt12_invoices") as batch_op:
        batch_op.add_column(
            sa.Column(
                "blinded_paths_summary",
                sa.JSON(),
                nullable=True,
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("bolt12_invoices") as batch_op:
        batch_op.drop_column("blinded_paths_summary")
