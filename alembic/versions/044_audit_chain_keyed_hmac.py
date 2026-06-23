# SPDX-License-Identifier: MIT
"""Anchor the audit-log hash chain under the keyed HMAC.

Revision ID: 044_audit_chain_keyed_hmac
Revises: 043_braiins_deposit_channel_open
Create Date: 2026-06-18 00:00:00.000000

The audit-log hash chain is a keyed MAC: each ``entry_hash`` is an
HMAC-SHA256 over the entry payload, keyed with a value derived from
SECRET_KEY. This walks the table in ``created_at`` order and writes
``prev_hash`` / ``entry_hash`` using that keyed function so the on-disk
chain matches ``AuditLog.compute_hash()``.

This is a one-time anchoring, not a tamper-recovery mechanism: it asserts
the current on-disk rows as the baseline. ``verify_chain`` detects any
tampering thereafter, and only a holder of SECRET_KEY can produce valid
hashes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import timezone
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "044_audit_chain_keyed_hmac"
down_revision: Union[str, None] = "043_braiins_deposit_channel_open"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Must match app.core.security._AUDIT_CHAIN_CONTEXT.
_AUDIT_CHAIN_CONTEXT = b"agent-wallet/audit-chain/v1"


def _chain_key() -> bytes:
    from app.core.config import settings

    return hmac.new(
        settings.secret_key.encode("utf-8"),
        _AUDIT_CHAIN_CONTEXT,
        hashlib.sha256,
    ).digest()


def _compute_hash(row: sa.engine.Row, prev_hash: str | None, key: bytes) -> str:
    created_at = row.created_at
    if created_at is None:
        created_at_iso = ""
    else:
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        else:
            created_at = created_at.astimezone(timezone.utc)
        created_at_iso = created_at.isoformat()
    payload = json.dumps(
        {
            "id": str(row.id),
            "api_key_id": str(row.api_key_id),
            "api_key_name": row.api_key_name,
            "action": row.action,
            "resource": row.resource,
            "details": row.details,
            "amount_sats": row.amount_sats,
            "success": row.success,
            "error_message": row.error_message,
            "ip_address": row.ip_address,
            "prev_hash": prev_hash or "",
            "created_at": created_at_iso,
        },
        sort_keys=True,
        default=str,
    )
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def upgrade() -> None:
    bind = op.get_bind()
    key = _chain_key()
    rows = bind.execute(
        sa.text(
            "SELECT id, api_key_id, api_key_name, action, resource, "
            "details, amount_sats, success, error_message, ip_address, "
            "created_at "
            "FROM audit_logs ORDER BY created_at ASC, id ASC"
        )
    ).fetchall()

    prev_hash: str | None = None
    rewritten = 0
    for row in rows:
        entry_hash = _compute_hash(row, prev_hash, key)
        bind.execute(
            sa.text("UPDATE audit_logs SET prev_hash = :prev_hash, entry_hash = :entry_hash WHERE id = :id"),
            {"prev_hash": prev_hash, "entry_hash": entry_hash, "id": row.id},
        )
        prev_hash = entry_hash
        rewritten += 1

    print(f"044_audit_chain_keyed_hmac: anchored {rewritten} audit rows under the keyed chain")


def downgrade() -> None:
    # No-op: reverting would leave the chain hashed under the keyed
    # function while older code expected a bare digest, which has no
    # operational value.
    pass
