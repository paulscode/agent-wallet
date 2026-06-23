# SPDX-License-Identifier: MIT
"""Persistent ``anonymize_runtime_state`` reader/writer.

The ``value`` column is encrypted under
``MultiFernet(FERNET_KEYS)`` so a DB-snapshot adversary cannot read
circuit-rebuild bucket levels, decoy histograms, or the redactor
allow-list directly. Migration ``020a/020b`` rewrites the column from
cleartext JSONB to encrypted ``BYTEA``; this module is the single
read/write entry point that hides the encryption transition from
call sites.

The ``key`` column is restricted to a registry
constant (`ANONYMIZE_RUNTIME_STATE_KEYS`) so ad-hoc writes from new
code paths require an explicit registry update + CI grep. The
helper rejects writes whose key is not in the registry.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymize_session import AnonymizeRuntimeState

from .crypto import MultiFernetBundle
from .metadata import ANONYMIZE_RUNTIME_STATE_KEYS


class RuntimeStateKeyRejectedError(ValueError):
    """Raised when a write targets a key not in
    :data:`ANONYMIZE_RUNTIME_STATE_KEYS`."""


def _assert_key_in_registry(key: str) -> None:
    if key not in ANONYMIZE_RUNTIME_STATE_KEYS:
        raise RuntimeStateKeyRejectedError(
            f"runtime-state key {key!r} is not in "
            "ANONYMIZE_RUNTIME_STATE_KEYS — add it to the registry "
            "in app/services/anonymize/metadata.py before writing."
        )


def _serialize_payload(payload: Any, *, bundle: MultiFernetBundle | None) -> bytes:
    """Encode ``payload`` to bytes for the ``value`` column.

    With a bundle, returns the Fernet ciphertext; without, returns
    cleartext UTF-8 JSON (the pre-020a path; the application layer
    transitions to bundle-encryption when the migration completes).
    """
    cleartext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if bundle is None:
        return cleartext
    return bundle.encrypt(cleartext)


def _deserialize_payload(raw: bytes, *, bundle: MultiFernetBundle | None) -> Any:
    """Inverse of :func:`_serialize_payload`."""
    if bundle is not None:
        try:
            cleartext = bundle.decrypt(raw)
        except Exception:
            # The bundle could not decrypt — try cleartext interpretation
            # (pre-020a row) so the caller can run the rewrite path.
            cleartext = raw
    else:
        cleartext = raw
    return json.loads(cleartext.decode("utf-8"))


async def read_runtime_state(
    db: AsyncSession,
    *,
    key: str,
    bundle: MultiFernetBundle | None = None,
) -> Any | None:
    """Return the deserialized ``value`` for ``key``, or ``None``."""
    _assert_key_in_registry(key)
    stmt = select(AnonymizeRuntimeState).where(AnonymizeRuntimeState.key == key)
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return _deserialize_payload(row.value, bundle=bundle)


async def write_runtime_state(
    db: AsyncSession,
    *,
    key: str,
    payload: Any,
    bundle: MultiFernetBundle | None = None,
) -> AnonymizeRuntimeState:
    """Upsert the ``value`` for ``key``.

    Idempotent against repeated calls with the same payload (the
    DB row is updated in-place). The caller is expected to commit;
    this helper does NOT commit so it can compose with the
    orchestrator's transaction.
    """
    _assert_key_in_registry(key)
    encoded = _serialize_payload(payload, bundle=bundle)

    stmt = select(AnonymizeRuntimeState).where(AnonymizeRuntimeState.key == key)
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        row = AnonymizeRuntimeState(
            key=key,
            value=encoded,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(row)
    else:
        row.value = encoded
        row.updated_at = datetime.now(timezone.utc)
    return row


async def delete_runtime_state(db: AsyncSession, *, key: str) -> bool:
    """Remove the row for ``key``. Returns True iff a row was deleted."""
    _assert_key_in_registry(key)
    from sqlalchemy import delete

    stmt = delete(AnonymizeRuntimeState).where(AnonymizeRuntimeState.key == key)
    result = await db.execute(stmt)
    return bool(result.rowcount)  # type: ignore[attr-defined]


__all__ = [
    "RuntimeStateKeyRejectedError",
    "read_runtime_state",
    "write_runtime_state",
    "delete_runtime_state",
]
