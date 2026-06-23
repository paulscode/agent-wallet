# SPDX-License-Identifier: MIT
"""Re-encrypt Boltz swap sensitive fields with per-field random salt (v2 format)

Revision ID: 004_reencrypt_fields
Revises: 003_security_hardening
Create Date: 2026-04-18 00:00:00.000000

This is a DATA migration. It reads all BoltzSwap rows with encrypted
preimage/claim keys and re-encrypts them using the new v2 format
(per-field random salt).  Legacy ciphertext (static salt) is transparently
decrypted during the migration.

IMPORTANT: Run this migration while the old SECRET_KEY is still active.
If rotating keys, set SECRET_KEY_PREVIOUS=<old_key> first.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "004_reencrypt_fields"
down_revision: Union[str, None] = "003_security_hardening"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Re-encrypt all encrypted fields to v2 format."""
    from app.core.encryption import re_encrypt_field

    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, preimage_hex, claim_private_key_hex FROM boltz_swaps"))
    for row in rows:
        swap_id = row[0]
        updates = {}
        if row[1]:
            new_val = re_encrypt_field(row[1])
            if new_val is not None:
                updates["preimage_hex"] = new_val
        if row[2]:
            new_val = re_encrypt_field(row[2])
            if new_val is not None:
                updates["claim_private_key_hex"] = new_val
        if updates:
            set_clauses = ", ".join(f"{k} = :v_{k}" for k in updates)
            params = {f"v_{k}": v for k, v in updates.items()}
            params["id"] = swap_id
            conn.execute(sa.text(f"UPDATE boltz_swaps SET {set_clauses} WHERE id = :id"), params)


def downgrade() -> None:
    # Re-encryption is one-way; v2 format is backwards-compatible at the
    # application level (decrypt_field handles both formats).
    pass
