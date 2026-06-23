# SPDX-License-Identifier: MIT
"""Initial schema — api_keys, boltz_swaps, audit_logs

Revision ID: 001_initial
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── API Keys ──────────────────────────────────────────────────────
    op.create_table(
        "api_keys",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("key_hash", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("is_admin", sa.Boolean, default=False, nullable=False),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("idx_api_keys_active", "api_keys", ["is_active"])

    # ── Boltz Swaps ───────────────────────────────────────────────────
    op.create_table(
        "boltz_swaps",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        # Boltz identifiers
        sa.Column("boltz_swap_id", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column(
            "direction",
            sa.Enum("reverse", name="boltz_swap_direction"),
            nullable=False,
            server_default="reverse",
        ),
        # API key context
        sa.Column(
            "api_key_id",
            UUID(as_uuid=True),
            sa.ForeignKey("api_keys.id"),
            nullable=False,
            index=True,
        ),
        # Swap parameters
        sa.Column("invoice_amount_sats", sa.BigInteger, nullable=False),
        sa.Column("onchain_amount_sats", sa.BigInteger, nullable=True),
        sa.Column("destination_address", sa.String(256), nullable=False),
        sa.Column("fee_percentage", sa.String(10), nullable=True),
        sa.Column("miner_fee_sats", sa.BigInteger, nullable=True),
        # Crypto material (encrypted at rest via Fernet)
        sa.Column("preimage_hex", sa.String(512), nullable=True),
        sa.Column("preimage_hash_hex", sa.String(64), nullable=True),
        sa.Column("claim_private_key_hex", sa.String(512), nullable=True),
        sa.Column("claim_public_key_hex", sa.String(66), nullable=True),
        # Boltz response data
        sa.Column("boltz_invoice", sa.Text, nullable=True),
        sa.Column("boltz_lockup_address", sa.String(256), nullable=True),
        sa.Column("boltz_refund_public_key_hex", sa.String(66), nullable=True),
        sa.Column("boltz_swap_tree_json", JSONB, nullable=True),
        sa.Column("timeout_block_height", sa.BigInteger, nullable=True),
        sa.Column("boltz_blinding_key", sa.String(66), nullable=True),
        # LND payment tracking
        sa.Column("lnd_payment_hash", sa.String(64), nullable=True),
        sa.Column("lnd_payment_status", sa.String(20), nullable=True),
        # Claim transaction
        sa.Column("claim_tx_hex", sa.Text, nullable=True),
        sa.Column("claim_txid", sa.String(64), nullable=True),
        # Status tracking
        sa.Column(
            "status",
            sa.Enum(
                "created",
                "paying_invoice",
                "invoice_paid",
                "claiming",
                "claimed",
                "completed",
                "failed",
                "cancelled",
                "refunded",
                name="boltz_swap_status",
            ),
            default="created",
            nullable=False,
        ),
        sa.Column("boltz_status", sa.String(40), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("status_history", JSONB, default=list, nullable=True),
        # Recovery tracking
        sa.Column("recovery_attempted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovery_count", sa.Integer, default=0, nullable=False),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_boltz_swaps_status", "boltz_swaps", ["status"])
    op.create_index("idx_boltz_swaps_api_key_id", "boltz_swaps", ["api_key_id"])

    # ── Audit Logs ────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "api_key_id",
            UUID(as_uuid=True),
            sa.ForeignKey("api_keys.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("api_key_name", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False, index=True),
        sa.Column("resource", sa.String(128), nullable=False),
        sa.Column("details", JSONB, nullable=True),
        sa.Column("amount_sats", sa.BigInteger, nullable=True),
        sa.Column("success", sa.Boolean, default=True, nullable=False),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )
    op.create_index("idx_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("idx_audit_logs_action", "audit_logs", ["action"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("boltz_swaps")
    op.drop_table("api_keys")
