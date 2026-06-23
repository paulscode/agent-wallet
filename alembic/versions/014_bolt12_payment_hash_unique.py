# SPDX-License-Identifier: MIT
"""Add unique index on ``bolt12_invoices.(api_key_id, payment_hash_hex)``.

Revision ID: 014_bolt12_payment_hash_unique
Revises: 013_bolt12_invreq_metadata_dedup
Create Date: 2026-05-06 00:00:01.000000

A given ``payment_hash`` MUST resolve to at most one in-flight
invoice per tenant: if two distinct invreqs ever produced rows
sharing the same ``payment_hash_hex``, a settlement HTLC could be
mis-attributed across them. This is a defence-in-depth check on
top of LND's own per-preimage uniqueness.

Scoped to ``api_key_id`` so multi-tenant deployments do not get
spurious 23505s when distinct tenants happen to share an
``r-hash`` from independent LND nodes (the index is rooted in our
mapping table, not in LND's keysend ledger).
"""

from typing import Sequence, Union

from alembic import op

revision: str = "014_bolt12_payment_hash_unique"
down_revision: Union[str, None] = "013_bolt12_invreq_metadata_dedup"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite (test) and PostgreSQL (prod) both support a composite
    # unique index here \u2014 ``payment_hash_hex`` is NOT NULL on every
    # row so no partial filter is required.
    op.create_index(
        "uq_bolt12_invoices_payment_hash_per_key",
        "bolt12_invoices",
        ["api_key_id", "payment_hash_hex"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_bolt12_invoices_payment_hash_per_key",
        table_name="bolt12_invoices",
    )
