# SPDX-License-Identifier: MIT
"""Hop idempotency helpers (/ item 23 /).

Every external side-effect in a hop is preceded by a persisted
``hop_attempt_started`` event keyed on a per-attempt
``hop_idempotency_key``. On recovery the orchestrator queries the
external system rather than blindly retrying, so a duplicate request
produced by a re-attempt cannot create two boltz swaps / two LN
payments / two chain broadcasts.

The key is a keyed-HMAC with a per-row 128-bit nonce (
brittleness fix): ``HMAC(key, nonce || session_id || hop_index ||
canonical_payload)``. The per-row nonce defeats the rainbow-table
attack against a leaked HMAC key — without the nonce the attacker
could enumerate the small ``(hop_index, hop_kind, attempt)`` space.

Bounded-retention key set:
* ``ANONYMIZE_HOP_IDEMPOTENCY_KEY_FERNET`` is an ordered set; index 0 is
  the active signing key.
* The key generation index is recorded in
  ``anonymize_session_event.hop_idempotency_key_generation`` so a
  scheduled key purge can null only the columns whose generating key
  has been retired.
* Rotation cadence and retention horizon are wired to
  ``ANONYMIZE_HOP_IDEMPOTENCY_KEY_ROTATION_DAYS`` /
  ``ANONYMIZE_HOP_IDEMPOTENCY_KEY_RETENTION_DAYS``; the recurring
  rotation task lives in the same module pattern as
  ``reuse_detection`` (filled in alongside the gc.py rotation pass).

This module ships:
* :func:`make_hop_idempotency_key` — derive the key for a (session,
  hop_index, hop_kind, attempt, payload) tuple.
* :func:`make_per_row_nonce` — fresh 128-bit nonce per attempt.

The persistence (encrypting the nonce with Fernet, recording the
generation index) lands when the event-log writer ships in the
orchestrator.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from app.models.anonymize_session import AnonymizeSessionEvent

# Per-row nonce length. 128 bits is the published floor.
_NONCE_BYTES: Final[int] = 16


def make_per_row_nonce() -> bytes:
    """Generate a fresh 128-bit nonce for the next hop attempt."""
    return secrets.token_bytes(_NONCE_BYTES)


def canonicalize_payload(payload: dict | bytes | None) -> bytes:
    """Canonicalize a hop payload into bytes for the HMAC input.

    ``dict`` payloads are sorted-keys JSON-encoded. ``bytes`` are
    passed through. ``None`` is the empty byte string. The output is
    stable across Python versions (no insertion-order leakage).
    """
    if payload is None:
        return b""
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, dict):
        import json

        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    raise TypeError(f"unsupported payload type: {type(payload)!r}")


def make_hop_idempotency_key(
    *,
    key_bytes: bytes,
    nonce: bytes,
    session_id: bytes,
    hop_index: int,
    hop_kind: str,
    attempt: int,
    payload: dict | bytes | None = None,
) -> str:
    """Derive a hop idempotency key.

    Returns a 64-char lowercase hex string suitable for the
    ``anonymize_session_event.hop_idempotency_key`` column.

    All inputs are mandatory keyword arguments so a future regression
    that reuses the wrong session_id / hop_index combination is
    obvious at the call site. ``key_bytes`` is the active HMAC key
    (32 bytes); ``nonce`` is the per-attempt 128-bit value.
    """
    if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
        raise ValueError("key_bytes must be 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != _NONCE_BYTES:
        raise ValueError(f"nonce must be {_NONCE_BYTES} bytes")
    if not isinstance(session_id, bytes) or len(session_id) != 16:
        raise ValueError("session_id must be a 16-byte UUID value")
    if hop_index < 0:
        raise ValueError("hop_index must be non-negative")
    if attempt < 0:
        raise ValueError("attempt must be non-negative")

    # MAC input layout: nonce || session_id || hop_index_u32_be ||
    # hop_kind_utf8 || \x00 || attempt_u32_be || canonical_payload.
    # The \x00 separator after the hop_kind prevents a payload that
    # starts with bytes resembling a different hop_kind from
    # producing the same MAC under a colliding (session, index, attempt).
    parts = [
        nonce,
        session_id,
        hop_index.to_bytes(4, "big"),
        hop_kind.encode("utf-8"),
        b"\x00",
        attempt.to_bytes(4, "big"),
        canonicalize_payload(payload),
    ]
    mac = hmac.new(key_bytes, b"".join(parts), hashlib.sha256)
    return mac.hexdigest()


# --------------------------------------------------------------------
# Hop_attempt_started/completed event persistence.
# --------------------------------------------------------------------


from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class HopAttemptKey:
    """Per-hop-attempt identifier the persistence helpers track."""

    session_id: UUID
    hop_index: int
    hop_kind: str
    attempt: int
    idempotency_key: str
    nonce: bytes
    key_generation: int


async def fetch_existing_hop_attempt(
    db: AsyncSession,
    *,
    idempotency_key: str,
) -> "AnonymizeSessionEvent | None":
    """Look up a previously-recorded hop_attempt event by idempotency key.

    The contract: every external side-effect is preceded by a
    persisted ``hop_attempt_started`` event. Recovery queries this
    function instead of blindly retrying — if a matching key already
    exists, the orchestrator queries the external system to find the
    side-effect's status rather than issuing a duplicate request.
    """
    from app.models.anonymize_session import AnonymizeSessionEvent

    stmt = select(AnonymizeSessionEvent).where(AnonymizeSessionEvent.hop_idempotency_key == idempotency_key).limit(1)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def record_hop_attempt_started(
    db: AsyncSession,
    *,
    key: HopAttemptKey,
    detail: dict | None = None,
) -> "AnonymizeSessionEvent":
    """Persist the ``hop_attempt_started`` event before the side-effect runs.

    Idempotent against re-runs: if a matching event already exists,
    return it unchanged. The pre-write check uses
    :func:`fetch_existing_hop_attempt` so concurrent attempts at the
    *same* key collapse to one row.
    """
    from app.models.anonymize_session import AnonymizeSessionEvent

    existing = await fetch_existing_hop_attempt(db, idempotency_key=key.idempotency_key)
    if existing is not None:
        return existing
    row = AnonymizeSessionEvent(
        session_id=key.session_id,
        ts=datetime.now(timezone.utc),
        kind="hop_attempt_started",
        detail_json=dict(detail or {}),
        hop_idempotency_key=key.idempotency_key,
        hop_idempotency_key_generation=key.key_generation,
        hop_idempotency_nonce_enc=key.nonce,
    )
    db.add(row)
    return row


DispatcherAction = "issue_side_effect | verify_remote_state | completed_idempotent_no_op"


def dispatcher_decision(
    *,
    started_event: "AnonymizeSessionEvent | None",
    completed_event: "AnonymizeSessionEvent | None",
) -> str:
    """Pure decision for the hop-attempt dispatcher.

    Three outcomes:

    * ``"issue_side_effect"`` — no prior attempt recorded. The caller
      writes ``hop_attempt_started`` AND issues the external request
      in the same transaction.
    * ``"verify_remote_state"`` — a ``hop_attempt_started`` row
      exists but no ``hop_attempt_completed``. The caller queries the
      external system (Boltz / chain backend) to find the side
      effect's status; on success it writes the completed event,
      on failure it routes to ``awaiting_reconciliation``.
    * ``"completed_idempotent_no_op"`` — both events exist; the
      session has already advanced past this hop. The caller
      returns the recorded result.

    The contract is: "timeouts are reconciliation triggers,
    not retries". This helper encodes that as the rule
    ``started without completed → verify_remote_state``.
    """
    if started_event is None:
        return "issue_side_effect"
    if completed_event is None:
        return "verify_remote_state"
    return "completed_idempotent_no_op"


async def fetch_completed_hop_attempt(
    db: AsyncSession,
    *,
    idempotency_key: str,
) -> "AnonymizeSessionEvent | None":
    """Look up a ``hop_attempt_completed`` row matching ``idempotency_key``."""
    from app.models.anonymize_session import AnonymizeSessionEvent

    stmt = (
        select(AnonymizeSessionEvent)
        .where(AnonymizeSessionEvent.hop_idempotency_key == idempotency_key)
        .where(AnonymizeSessionEvent.kind == "hop_attempt_completed")
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def dispatch_hop_attempt(
    db: AsyncSession,
    *,
    idempotency_key: str,
) -> str:
    """Higher-level dispatcher that fetches both events + returns the action.

    Wraps :func:`dispatcher_decision` so callers don't have to do
    two separate queries. The caller still controls the side-effect
    + audit-event writes; this just centralizes the decision.
    """
    from app.models.anonymize_session import AnonymizeSessionEvent

    stmt = (
        select(AnonymizeSessionEvent)
        .where(AnonymizeSessionEvent.hop_idempotency_key == idempotency_key)
        .where(AnonymizeSessionEvent.kind.in_(["hop_attempt_started", "hop_attempt_completed"]))
    )
    rows = (await db.execute(stmt)).scalars().all()
    started = next((r for r in rows if r.kind == "hop_attempt_started"), None)
    completed = next((r for r in rows if r.kind == "hop_attempt_completed"), None)
    return dispatcher_decision(
        started_event=started,
        completed_event=completed,
    )


async def record_hop_attempt_completed(
    db: AsyncSession,
    *,
    key: HopAttemptKey,
    detail: dict | None = None,
) -> "AnonymizeSessionEvent":
    """Persist the ``hop_attempt_completed`` event after the side-effect resolves.

    Mirrors :func:`record_hop_attempt_started`. The orchestrator's
    contract is: every started must be followed by a completed (or
    a state_change to ``failed``/``awaiting_reconciliation``); the
    pair lets recovery distinguish "still in flight" from "already
    finished" without re-issuing.
    """
    from app.models.anonymize_session import AnonymizeSessionEvent

    row = AnonymizeSessionEvent(
        session_id=key.session_id,
        ts=datetime.now(timezone.utc),
        kind="hop_attempt_completed",
        detail_json=dict(detail or {}),
        hop_idempotency_key=key.idempotency_key,
        hop_idempotency_key_generation=key.key_generation,
        hop_idempotency_nonce_enc=key.nonce,
    )
    db.add(row)
    return row


# --------------------------------------------------------------------
# Hop-idempotency-key purge ordering.
# --------------------------------------------------------------------


async def can_purge_hop_idempotency_key_generation(
    db: AsyncSession,
    *,
    generation: int,
    rotated_out_at_unix_s: float,
    retention_days: int,
    destination_retention_days: int,
    now_unix_s: float | None = None,
) -> tuple[bool, str | None]:
    """Conjunctive predicate for purging a key generation.

    A generation is purged only when **all** of these hold:

    1. ``now - rotated_out_at >= retention_days * 86400`` — the
       retention horizon has elapsed.
    2. No event rows reference this generation that belong to
       *non-terminal* sessions.
    3. No event rows reference this generation that belong to
       terminal sessions still inside the destination-retention
       window (``completed_at >= now - destination_retention_days``).

    Returns ``(can_purge, deferral_reason)``. When ``can_purge=False``
    the reason describes which clause failed; the orchestrator emits
    a ``key_purge_deferred`` event with that reason.
    """
    import time
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from app.models.anonymize_session import (
        ANONYMIZE_TERMINAL_STATUSES,
        AnonymizeSession,
        AnonymizeSessionEvent,
    )

    now = now_unix_s if now_unix_s is not None else time.time()
    horizon_s = float(retention_days) * 86400.0
    if (now - rotated_out_at_unix_s) < horizon_s:
        remaining = horizon_s - (now - rotated_out_at_unix_s)
        return False, (f"retention horizon not yet reached ({remaining:.0f} s remaining)")

    # Clause 2: any non-terminal session referenced by this generation?
    nonterminal_stmt = (
        select(AnonymizeSession.id)
        .join(
            AnonymizeSessionEvent,
            AnonymizeSessionEvent.session_id == AnonymizeSession.id,
        )
        .where(AnonymizeSessionEvent.hop_idempotency_key_generation == generation)
        .where(AnonymizeSession.status.notin_(list(ANONYMIZE_TERMINAL_STATUSES)))
        .where(AnonymizeSession.deleted_at.is_(None))
        .limit(1)
    )
    result = await db.execute(nonterminal_stmt)
    if result.scalar_one_or_none() is not None:
        return False, "generation still referenced by a non-terminal session"

    # Clause 3: any terminal-but-recent session referenced?
    cutoff = datetime.fromtimestamp(now, tz=timezone.utc) - timedelta(days=destination_retention_days)
    recent_stmt = (
        select(AnonymizeSession.id)
        .join(
            AnonymizeSessionEvent,
            AnonymizeSessionEvent.session_id == AnonymizeSession.id,
        )
        .where(AnonymizeSessionEvent.hop_idempotency_key_generation == generation)
        .where(AnonymizeSession.status.in_(list(ANONYMIZE_TERMINAL_STATUSES)))
        .where(AnonymizeSession.completed_at >= cutoff)
        .where(AnonymizeSession.deleted_at.is_(None))
        .limit(1)
    )
    result = await db.execute(recent_stmt)
    if result.scalar_one_or_none() is not None:
        return False, ("generation still referenced by a terminal session inside the destination-retention window")

    return True, None


async def has_hop_attempt_completed(
    db: AsyncSession,
    *,
    idempotency_key: str,
) -> bool:
    """True iff a ``hop_attempt_completed`` row exists for ``idempotency_key``."""
    from app.models.anonymize_session import AnonymizeSessionEvent

    stmt = (
        select(AnonymizeSessionEvent)
        .where(AnonymizeSessionEvent.hop_idempotency_key == idempotency_key)
        .where(AnonymizeSessionEvent.kind == "hop_attempt_completed")
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is not None


__all__ = [
    "make_per_row_nonce",
    "canonicalize_payload",
    "make_hop_idempotency_key",
    "HopAttemptKey",
    "fetch_existing_hop_attempt",
    "fetch_completed_hop_attempt",
    "record_hop_attempt_started",
    "record_hop_attempt_completed",
    "has_hop_attempt_completed",
    "can_purge_hop_idempotency_key_generation",
    "dispatcher_decision",
    "dispatch_hop_attempt",
]
