# SPDX-License-Identifier: MIT
"""anonymize_stepup_state — dedicated step-up nonce / lockout table.

Revision ID: 021_anonymize_stepup_state
Revises: 020b_anonymize_runtime_state_finalize
Create Date: 2026-05-10 00:00:05.000000

Moves step-up re-auth nonces and
verify-lockouts out of the general-purpose ``anonymize_runtime_state``
into a purpose-built table. Two design pressures motivate the split:

1. ``anonymize_runtime_state`` is a small fixed-key registry
   (``ANONYMIZE_RUNTIME_STATE_KEYS``); per-cookie nonce rows would
   explode the row count and the registry's deployment-topology
   guarantees (residual #33).
2. ``cookie_id_hmac`` is a privacy-sensitive value that benefits
   from its own Fernet bundle (``ANONYMIZE_STEPUP_COOKIE_HMAC_KEY_FERNET``)
   independent from the runtime-state value-encryption key set.

The table holds two row kinds discriminated by ``kind``:

* ``nonce`` — server-issued nonces awaiting verification, with TTL
  given by ``ANONYMIZE_STEPUP_NONCE_TTL_S``.
* ``lockout`` — per-cookie verify-rate-limit lockouts, with TTL given
  by ``ANONYMIZE_STEPUP_NONCE_VERIFY_LOCKOUT_S``.

A recurring purge task runs at 60 s cadence. ``cookie_id_hmac`` is the
HMAC under the dedicated key, never the cleartext cookie subject.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "021_anonymize_stepup_state"
down_revision: Union[str, None] = "020b_anonymize_runtime_state_finalize"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "anonymize_stepup_state",
        sa.Column(
            "id",
            sa.BigInteger(),
            primary_key=True,
            autoincrement=True,
        ),
        # 'nonce' or 'lockout'
        sa.Column("kind", sa.Text(), nullable=False),
        # HMAC of the cookie subject under
        # ANONYMIZE_STEPUP_COOKIE_HMAC_KEY_FERNET.
        sa.Column("cookie_id_hmac", sa.LargeBinary(), nullable=False),
        # For 'nonce': the issued nonce bytes (Fernet-encrypted).
        # For 'lockout': empty / NULL.
        sa.Column("nonce_enc", sa.LargeBinary(), nullable=True),
        # Optional category — e.g. 'override_decoy_spend',
        # 'override_refund_spend' — so the same cookie can have
        # multiple in-flight nonces for distinct flows.
        sa.Column("scope", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        # For lockouts: how many failed verify attempts the bucket saw.
        # Updated on each failed verify; reset on successful verify.
        sa.Column(
            "failed_verifies",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.CheckConstraint(
            "kind IN ('nonce', 'lockout')",
            name="ck_anonymize_stepup_kind",
        ),
    )
    op.create_index(
        "ix_anonymize_stepup_cookie_kind",
        "anonymize_stepup_state",
        ["cookie_id_hmac", "kind", "scope"],
    )
    op.create_index(
        "ix_anonymize_stepup_expires_at",
        "anonymize_stepup_state",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_anonymize_stepup_expires_at",
        table_name="anonymize_stepup_state",
    )
    op.drop_index(
        "ix_anonymize_stepup_cookie_kind",
        table_name="anonymize_stepup_state",
    )
    op.drop_table("anonymize_stepup_state")
