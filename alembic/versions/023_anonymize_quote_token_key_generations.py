# SPDX-License-Identifier: MIT
"""anonymize_quote_token_key_generations — cross-replica key handoff.

Revision ID: 023_anonymize_quote_token_key_generations
Revises: 022_anonymize_session_claim_tx_columns
Create Date: 2026-05-10 00:00:07.000000

When the quote-token HMAC key rotates, a single replica
writes the new generation row first and other replicas may receive
verify requests carrying that generation before their in-memory
keyset has refreshed. The table holds the (generation, fingerprint,
created_at) tuple so the DB-fallback verify path in
``quote_token.decide_quote_token_verify_action`` can do a synchronous
``SELECT`` against the primary to recover the unknown generation.

The fingerprint is a SHA-256 hash of the raw HMAC key material (NOT
the key itself; the keyset still has to be configured locally via
``ANONYMIZE_QUOTE_TOKEN_HMAC_KEY_FERNET``). The fallback path uses
the fingerprint to confirm the configured keyset includes the
relevant material before attempting an HMAC verify.

Postgres deployments may attach a ``LISTEN/NOTIFY`` trigger to this
table so replicas refresh their in-memory cache without polling; the
polling fallback ships unconditionally and the LISTEN/NOTIFY
extension is operator-opt-in.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "023_anonymize_quote_token_key_generations"
down_revision: Union[str, None] = "022_anonymize_session_claim_tx_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "anonymize_quote_token_key_generations",
        sa.Column(
            "generation",
            sa.Integer(),
            primary_key=True,
            autoincrement=False,
        ),
        # SHA-256 hash of the raw 32-byte HMAC key material, hex.
        sa.Column(
            "key_fingerprint_hex",
            sa.String(64),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        # Rotated-out generations are kept here until the
        # retention horizon elapses, at which point the GC sweep
        # nulls the row. The retired_at column records the rotation
        # moment so the horizon can advance independently of
        # created_at (e.g., a rotation that lands long after the
        # generation was first used).
        sa.Column(
            "retired_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_table("anonymize_quote_token_key_generations")
