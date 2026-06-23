# SPDX-License-Identifier: MIT
"""Add per-leg operator-id columns for the Liquid hop.

Revision ID: 035_anonymize_liquid_operator_ids
Revises: 034_boltz_swap_claim_pubkey
Create Date: 2026-05-30 00:00:00.000000

The Liquid hop creates two Boltz chain swaps per session — a
reverse-analog leg (LN→L-BTC) and a submarine-analog leg
(L-BTC→LN) — but unlike the non-Liquid path it does NOT persist
``BoltzSwap`` rows for either; swap state lives in
``pipeline_json`` + an in-process cache. That left recovery code
with no DB-resident attribution of which operator handled which
leg.

These two nullable columns mirror the existing
``reverse_operator_id`` / ``submarine_operator_id`` on
``anonymize_session`` and are populated by the Liquid hop body at
swap-id-storage time (i.e. immediately after Boltz returns the
swap id, before any user funds move). NULL on sessions that
predate this migration and on non-Liquid sessions.

No CHECK constraint enforcing distinctness: single-Liquid-capable-
operator deployments legitimately collapse both legs onto the same
operator id (``legs_distinct=False`` in
``LiquidLegSelection``); the dispatcher already logs a diagnostic
warning when that happens.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "035_anonymize_liquid_operator_ids"
down_revision: Union[str, None] = "034_boltz_swap_claim_pubkey"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "anonymize_session",
        sa.Column(
            "liquid_reverse_operator_id",
            sa.Text(),
            nullable=True,
        ),
    )
    op.add_column(
        "anonymize_session",
        sa.Column(
            "liquid_submarine_operator_id",
            sa.Text(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("anonymize_session", "liquid_submarine_operator_id")
    op.drop_column("anonymize_session", "liquid_reverse_operator_id")
