# SPDX-License-Identifier: MIT
"""Retention-pass driver — destination redaction + event GC + bitfield.

The retention pass has ten steps now (the original
seven plus pass 8 swap-anchor severance pass 9
hop-idempotency-key null, and pass 10 decoy chain-anchor
redact). All ten run inside one DB transaction, gated by the
``anonymize_session.gc_passes_completed`` bitfield so a crash mid-
redaction can never leave a half-redacted row visible.

``ALL_PASSES_MASK = 0b1111111111`` (10 bits).

The pass walks sessions where ``status IN (terminal_states) AND
completed_at < now - ANONYMIZE_DESTINATION_RETENTION_DAYS`` (
active-session safety). For each, runs the unfinished bits from the
bitfield within a single ``BEGIN ... COMMIT`` and updates the bitfield
incrementally.

The LN-source path needs passes 1–9; pass 10 is gated on the on-chain
self-source ``anonymize_decoy_output`` table.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.core.config import settings
from app.models.anonymize_session import (
    ANONYMIZE_TERMINAL_STATUSES,
    AnonymizeSession,
)

# Bit layout. Each pass maps to a single bit; once all
# bits are set, the session row is fully redacted and the bitfield
# value equals ALL_PASSES_MASK.
GC_PASS_PIPELINE_TRUNCATE = 1 << 0  # pipeline_json + final_score truncation
GC_PASS_EVENT_COLLAPSE = 1 << 1  # event row delete or collapse
GC_PASS_REUSE_KEY_PURGE = 1 << 2  # sentinel-overwrite of dest_blake2b_keyed
GC_PASS_CHAIN_ANCHOR_REDACT = 1 << 3  # output_txid / output_vout / claim_tx_hex
GC_PASS_FINGERPRINT_COARSEN = 1 << 4  # completed_at, script_type, bin_index
GC_PASS_LAST_ERROR_NULL = 1 << 5  # null last_error
GC_PASS_FINGERPRINT_COLUMNS = 1 << 6  # widened set
GC_PASS_SWAP_ANCHOR_SEVER = 1 << 7  # sentinel UUID for swap_id columns
GC_PASS_HOP_IDEMPOTENCY_KEY_NULL = 1 << 8  # null hop_idempotency_key
GC_PASS_DECOY_CHAIN_ANCHOR_REDACT = 1 << 9  # on-chain self-source only

ALL_PASSES_MASK = 0b1111111111  # 10 bits


# Ordered list of (label, bit) pairs — used by the retention driver
# to log progress and by tests to introspect the bit layout.
GC_PASSES_ORDERED: tuple[tuple[str, int], ...] = (
    ("pipeline_truncate", GC_PASS_PIPELINE_TRUNCATE),
    ("event_collapse", GC_PASS_EVENT_COLLAPSE),
    ("reuse_key_purge", GC_PASS_REUSE_KEY_PURGE),
    ("chain_anchor_redact", GC_PASS_CHAIN_ANCHOR_REDACT),
    ("fingerprint_coarsen", GC_PASS_FINGERPRINT_COARSEN),
    ("last_error_null", GC_PASS_LAST_ERROR_NULL),
    ("fingerprint_columns", GC_PASS_FINGERPRINT_COLUMNS),
    ("swap_anchor_sever", GC_PASS_SWAP_ANCHOR_SEVER),
    ("hop_idempotency_key_null", GC_PASS_HOP_IDEMPOTENCY_KEY_NULL),
    ("decoy_chain_anchor_redact", GC_PASS_DECOY_CHAIN_ANCHOR_REDACT),
)


def is_pass_complete(bitfield: int, pass_bit: int) -> bool:
    """True iff the given pass bit is set on the bitfield."""
    return (bitfield & pass_bit) == pass_bit


def mark_pass_complete(bitfield: int, pass_bit: int) -> int:
    """Return ``bitfield`` with ``pass_bit`` set."""
    return bitfield | pass_bit


def all_passes_complete(bitfield: int) -> bool:
    """True iff every retention pass has been recorded as complete."""
    return (bitfield & ALL_PASSES_MASK) == ALL_PASSES_MASK


def remaining_passes(bitfield: int) -> list[tuple[str, int]]:
    """Return ``[(label, bit), ...]`` of passes not yet recorded."""
    return [(label, bit) for label, bit in GC_PASSES_ORDERED if not is_pass_complete(bitfield, bit)]


# --------------------------------------------------------------------
# amended / item 116 — bitfield rollover discipline.
# --------------------------------------------------------------------


def assert_passes_form_contiguous_bit_run() -> None:
    """Bits assigned to passes must form a contiguous run.

    Adding a new pass requires:
    1. Strictly-greater bit position (no gaps).
    2. Extending ``ALL_PASSES_MASK`` to cover the new bit.
    3. Registering the new pass label in ``GC_PASSES_ORDERED``.

    This helper enforces all three at startup. A future pass that
    skips a bit position (e.g., uses ``1 << 11`` while bit 10 is
    unused) trips the invariant.
    """
    bits = sorted(bit for _, bit in GC_PASSES_ORDERED)
    expected = [1 << i for i in range(len(bits))]
    if bits != expected:
        raise ValueError(
            f"GC_PASSES_ORDERED bits are not a contiguous run starting "
            f"at bit 0: got {[hex(b) for b in bits]}, expected "
            f"{[hex(b) for b in expected]}"
        )

    union = 0
    for _, bit in GC_PASSES_ORDERED:
        union |= bit
    if union != ALL_PASSES_MASK:
        raise ValueError(
            f"ALL_PASSES_MASK = {hex(ALL_PASSES_MASK)} does not equal "
            f"the union of GC_PASSES_ORDERED bits ({hex(union)}). "
            "Adding a new pass requires updating both."
        )


def assert_passes_registry_covers_documented_set() -> None:
    """Every documented gc pass must appear in the registry.

    The registry is the source of truth for the gc.py ``run_*_pass``
    functions and the column-disposition CI gate. A drift
    (e.g., a developer adds a constant ``GC_PASS_FOO`` but forgets to
    register it in ``GC_PASSES_ORDERED``) would silently leave the
    pass running but unobservable.
    """
    documented = {
        GC_PASS_PIPELINE_TRUNCATE,
        GC_PASS_EVENT_COLLAPSE,
        GC_PASS_REUSE_KEY_PURGE,
        GC_PASS_CHAIN_ANCHOR_REDACT,
        GC_PASS_FINGERPRINT_COARSEN,
        GC_PASS_LAST_ERROR_NULL,
        GC_PASS_FINGERPRINT_COLUMNS,
        GC_PASS_SWAP_ANCHOR_SEVER,
        GC_PASS_HOP_IDEMPOTENCY_KEY_NULL,
        GC_PASS_DECOY_CHAIN_ANCHOR_REDACT,
    }
    registered = {bit for _, bit in GC_PASSES_ORDERED}
    missing = documented - registered
    if missing:
        raise ValueError(f"gc passes documented but not in registry: {sorted(hex(b) for b in missing)}")


# --------------------------------------------------------------------
# Active-session safety in retention passes.
# --------------------------------------------------------------------


@dataclass(frozen=True)
class RetentionWindow:
    """Resolves the cutoff for "ready to redact" sessions.

    The retention pass filters strictly on
    ``status IN (terminal_states) AND completed_at < cutoff`` so a
    non-terminal session whose ``created_at`` is past the retention
    days is never touched (it is still in flight).
    """

    cutoff: datetime
    retention_days: int

    @classmethod
    def from_settings(cls, *, now: datetime | None = None) -> "RetentionWindow":
        days = int(settings.anonymize_destination_retention_days)
        n = now or datetime.now(timezone.utc)
        return cls(cutoff=n - timedelta(days=days), retention_days=days)


def active_session_safety_filter(now: datetime | None = None) -> ColumnElement[bool]:
    """Return a SQLAlchemy ``where`` clause for retention-eligible sessions.

    Use as::

        stmt = (
            select(AnonymizeSession)
            .where(active_session_safety_filter())
            .where(AnonymizeSession.gc_passes_completed != ALL_PASSES_MASK)
        )
    """
    window = RetentionWindow.from_settings(now=now)
    if window.retention_days <= 0:
        # Retention disabled — return a never-true predicate so gc.py
        # is a no-op.
        return AnonymizeSession.id.is_(None)
    terminal = list(ANONYMIZE_TERMINAL_STATUSES)
    return (
        AnonymizeSession.status.in_(terminal)
        & (AnonymizeSession.completed_at.is_not(None))
        & (AnonymizeSession.completed_at < window.cutoff)
        & (AnonymizeSession.deleted_at.is_(None))
    )


async def fetch_retention_eligible_sessions(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> list[AnonymizeSession]:
    """Read the next batch of sessions ready for retention.

    Bounded by ``limit`` so a long-running batch can't starve the
    rest of the dashboard. Caller is expected to take the
    transactional bitfield path per session.
    """
    stmt = (
        select(AnonymizeSession)
        .where(active_session_safety_filter(now=now))
        .where(AnonymizeSession.gc_passes_completed != ALL_PASSES_MASK)
        .order_by(AnonymizeSession.completed_at.asc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


# --------------------------------------------------------------------
# Destination retention pass (gc bit 3).
# --------------------------------------------------------------------


async def run_chain_anchor_redact_pass(
    db: AsyncSession,
    session: AnonymizeSession,
    *,
    now: datetime | None = None,
) -> bool:
    """Null destination + chain anchors after retention.

    Idempotent: running twice on the same row is a no-op (the bitfield
    bit is already set on the second pass and the function short-
    circuits). Caller wraps this in the per-session
    transaction.

    Returns ``True`` if the pass mutated anything, ``False`` if it was
    already complete.
    """
    from .crypto import DESTINATION_REDACTED_SENTINEL

    if is_pass_complete(session.gc_passes_completed, GC_PASS_CHAIN_ANCHOR_REDACT):
        return False

    # destination ciphertext → sentinel.
    session.destination_address_enc = DESTINATION_REDACTED_SENTINEL
    # chain anchors → null.
    session.output_txid = None
    session.output_vout = None
    # The claim_tx_hex's scriptPubKey IS the destination address, so
    # null it on the same schedule.
    session.claim_tx_hex = None
    # Stamp the redaction time (bucket-quantization happens in pass 7).
    session.destination_address_redacted_at = now or datetime.now(timezone.utc)

    session.gc_passes_completed = mark_pass_complete(session.gc_passes_completed, GC_PASS_CHAIN_ANCHOR_REDACT)
    return True


# --------------------------------------------------------------------
# / pass-5 last_error nulling.
# --------------------------------------------------------------------


async def run_last_error_null_pass(
    db: AsyncSession,
    session: AnonymizeSession,
) -> bool:
    """Null ``last_error`` after retention."""
    if is_pass_complete(session.gc_passes_completed, GC_PASS_LAST_ERROR_NULL):
        return False
    session.last_error = None
    session.gc_passes_completed = mark_pass_complete(session.gc_passes_completed, GC_PASS_LAST_ERROR_NULL)
    return True


async def run_reuse_key_purge_pass(
    db: AsyncSession,
    session: AnonymizeSession,
) -> bool:
    """Sentinel-overwrite ``destination_address_blake2b_keyed``
    once the row is past retention.

    The row's generating reuse-detection key is purged on schedule
    ; overwriting the hash with the all-zeros
    sentinel makes the row's contribution to the reuse-detection
    lookup uncomputable, and the partial index that excludes the
    sentinel prevents it from being matched against future
    candidates.
    """
    if is_pass_complete(session.gc_passes_completed, GC_PASS_REUSE_KEY_PURGE):
        return False
    from .metadata import REUSE_DETECTION_SENTINEL

    session.destination_address_blake2b_keyed = REUSE_DETECTION_SENTINEL
    session.gc_passes_completed = mark_pass_complete(session.gc_passes_completed, GC_PASS_REUSE_KEY_PURGE)
    return True


async def run_hop_idempotency_key_null_pass(
    db: AsyncSession,
    session: AnonymizeSession,
) -> bool:
    """Null ``hop_idempotency_key`` + ``hop_idempotency_nonce_enc``
    on every retained event row regardless of the
    ``ANONYMIZE_RETAIN_REDACTED_HISTORY_ROWS`` mode.

    Idempotent: re-running against a session whose events have
    already been nulled is a bitfield set with no row mutation.
    """
    if is_pass_complete(
        session.gc_passes_completed,
        GC_PASS_HOP_IDEMPOTENCY_KEY_NULL,
    ):
        return False

    from sqlalchemy import update

    from app.models.anonymize_session import AnonymizeSessionEvent

    await db.execute(
        update(AnonymizeSessionEvent)
        .where(AnonymizeSessionEvent.session_id == session.id)
        .values(
            hop_idempotency_key=None,
            hop_idempotency_key_generation=None,
            hop_idempotency_nonce_enc=None,
        )
    )
    session.gc_passes_completed = mark_pass_complete(
        session.gc_passes_completed,
        GC_PASS_HOP_IDEMPOTENCY_KEY_NULL,
    )
    return True


# --------------------------------------------------------------------
# Anonymize-fingerprint columns nulling.
# --------------------------------------------------------------------


async def run_fingerprint_columns_pass(
    db: AsyncSession,
    session: AnonymizeSession,
) -> bool:
    """widened by — null operator + reconciliation columns.

    Idempotent. The column set covers operator handles,
    reconciliation bookkeeping, fingerprint-shape booleans, and the
    pipeline_schema_version major-generation quantization. The
    swap-anchor severance (sentinel-UUID write) is a separate pass
    (pass 8) because it depends on cascade completion.
    """
    if is_pass_complete(session.gc_passes_completed, GC_PASS_FINGERPRINT_COLUMNS):
        return False

    # widened set.
    session.used_preconsolidation = None
    session.broadcast_deadline_unix_s = None
    session.self_broadcast_attempted_at_ts = None
    session.reverse_payment_chunks_k = None
    session.delay_until_ts = None
    session.inter_leg_delay_until_ts = None

    # widened: operator + reconciliation columns.
    session.submarine_operator_id = None
    session.reverse_operator_id = None
    session.awaiting_reconciliation_reason = None
    session.pre_reconciliation_status = None
    session.last_reconciliation_attempt_ts = None
    session.claim_broadcast_at_ts = None
    session.funding_has_change = None
    session.reconciliation_attempts = 0

    # Quantize pipeline_schema_version to its major generation.
    # MAJOR*10+MINOR encoding ⇒ // 10 preserves only MAJOR.
    if session.pipeline_schema_version is not None:
        session.pipeline_schema_version = (session.pipeline_schema_version // 10) * 10

    session.gc_passes_completed = mark_pass_complete(session.gc_passes_completed, GC_PASS_FINGERPRINT_COLUMNS)
    return True


# --------------------------------------------------------------------
# Fingerprint-coarsen pass body.
# --------------------------------------------------------------------


def _bucket_quantize_unix_s(ts_unix_s: float, bucket_seconds: int) -> int:
    return (int(ts_unix_s) // max(1, bucket_seconds)) * bucket_seconds


def _bin_index_for(bin_amount_sat: int) -> int:
    """Replace bin_amount_sat with its index in the published bin set."""
    bins = sorted(settings.anonymize_amount_bins_list)
    for i, b in enumerate(bins):
        if b == bin_amount_sat:
            return i
    # Fallback: bin not in current set (e.g., an older row whose bin
    # set has since changed). Use index -1 so the row is still
    # decodable but distinguishable from a known bin.
    return -1


# --------------------------------------------------------------------
# Row-locked cascade-redaction predicate.
# --------------------------------------------------------------------


# --------------------------------------------------------------------
# Swap-anchor severance pass.
# --------------------------------------------------------------------


# sentinel UUID, mirrored from migration 016.
_SWAP_ANCHOR_SENTINEL_UUID_STR: str = "00000000-0000-0000-0000-000000000000"


def swap_anchor_sentinel_uuid() -> UUID:
    """Return the sentinel UUID written by gc-pass-8 swap-anchor severance.

    The migration's pre-INSERT trigger refuses to admit this value
    unless the session-local GUC ``anonymize.gc_writer = 'on'`` is
    set; the gc-writer code path enables that GUC inside its
    transaction.
    """
    from uuid import UUID

    return UUID(_SWAP_ANCHOR_SENTINEL_UUID_STR)


async def run_swap_anchor_severance_pass(
    db: AsyncSession,
    session: AnonymizeSession,
) -> bool:
    """Replace swap_id columns with the sentinel UUID.

    Pre-conditions:

    1. The chain-anchor pass has run (its bit is set on
       ``gc_passes_completed``).
    2. The cross-reference predicate confirms no other
       anonymize session references each swap row (re-checked here
       inside the orchestrator's row-level lock).

    On any pre-condition failure, the pass returns False (the bit
    stays unset; gc retries on the next sweep). When the conditions
    are satisfied, the swap-id columns are rewritten to the sentinel
    UUID and the bit is marked.

    The sentinel-write must happen with the
    ``anonymize.gc_writer = 'on'`` GUC enabled (the orchestrator's
    retention transaction sets it). On SQLite test runs the trigger
    doesn't exist, so the write succeeds without the GUC; production
    against PostgreSQL depends on the trigger's gate.
    """
    if is_pass_complete(session.gc_passes_completed, GC_PASS_SWAP_ANCHOR_SEVER):
        return False
    if not is_pass_complete(session.gc_passes_completed, GC_PASS_CHAIN_ANCHOR_REDACT):
        return False

    sentinel = swap_anchor_sentinel_uuid()
    mutated_any = False

    if session.submarine_swap_id is not None and session.submarine_swap_id != sentinel:
        if await is_boltz_swap_safe_to_cascade_redact(
            db,
            boltz_swap_id=session.submarine_swap_id,
            excluding_session_id=session.id,
        ):
            session.submarine_swap_id = sentinel
            mutated_any = True

    if session.reverse_swap_id is not None and session.reverse_swap_id != sentinel:
        if await is_boltz_swap_safe_to_cascade_redact(
            db,
            boltz_swap_id=session.reverse_swap_id,
            excluding_session_id=session.id,
        ):
            session.reverse_swap_id = sentinel
            mutated_any = True

    session.gc_passes_completed = mark_pass_complete(session.gc_passes_completed, GC_PASS_SWAP_ANCHOR_SEVER)
    return mutated_any or True


# --------------------------------------------------------------------
# Chain-anchor cascade onto boltz_swap.
# --------------------------------------------------------------------


# --------------------------------------------------------------------
# Decoy-output retention (pass 10).
# --------------------------------------------------------------------


async def run_decoy_chain_anchor_redact_pass(
    db: AsyncSession,
    session: AnonymizeSession,
) -> bool:
    """Decoy-output retention pass.

    For every ``anonymize_decoy_output`` row whose parent session
    matches ``session.id``:

    * Null ``address``, ``value_sat``, ``session_account``,
      ``derivation_index`` (per-row chain-anchor + derivation
      attributes).
    * For decoys whose ``spent_at`` is set, additionally null
      ``outpoint``. Unspent decoys preserve ``outpoint`` (residual
      #34) because the wallet still owns the UTXO.
    * Replace ``session_id`` with the all-zeros sentinel
      UUID so post-retention rows do not contend with fresh decoy
      issuance.

    Idempotent. LN-source deployments have no rows, so the pass is a
    no-op-with-bit-set; on-chain self-source deployments run the actual
    redaction.
    """
    if is_pass_complete(session.gc_passes_completed, GC_PASS_DECOY_CHAIN_ANCHOR_REDACT):
        return False

    from app.models.anonymize_session import AnonymizeDecoyOutput

    sentinel = swap_anchor_sentinel_uuid()

    stmt = select(AnonymizeDecoyOutput).where(AnonymizeDecoyOutput.session_id == session.id)
    result = await db.execute(stmt)
    rows = list(result.scalars().all())

    for row in rows:
        row.address = None
        row.value_sat = None
        row.session_account = None
        row.derivation_index = None
        if row.spent_at is not None:
            row.outpoint = None
        row.session_id = sentinel  # type: ignore[assignment]

    session.gc_passes_completed = mark_pass_complete(session.gc_passes_completed, GC_PASS_DECOY_CHAIN_ANCHOR_REDACT)
    return True


async def fetch_decoy_catchup_sessions(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> list[AnonymizeSession]:
    """Recurring decoy-retention catch-up.

    Returns sessions that:

    * Have *some* retention pass completed (``gc_passes_completed != 0``
      so the row is past the redaction horizon), but
    * Have **not** completed pass 10 (decoy chain-anchor redact).

    The recurring orchestrator task calls this every
    ``ANONYMIZE_GC_CATCHUP_INTERVAL_S`` and re-runs
    :func:`run_decoy_chain_anchor_redact_pass` for each row. Bounded
    by ``limit`` to keep the scan off the dashboard's critical path.
    """
    stmt = (
        select(AnonymizeSession)
        .where(active_session_safety_filter(now=now))
        .where(AnonymizeSession.gc_passes_completed != 0)
        .where((AnonymizeSession.gc_passes_completed.op("&")(GC_PASS_DECOY_CHAIN_ANCHOR_REDACT)) == 0)
        .order_by(AnonymizeSession.completed_at.asc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def cascade_redact_boltz_swap_anchors(
    db: AsyncSession,
    *,
    boltz_swap_id: UUID,
    excluding_session_id: UUID | None = None,
) -> bool:
    """Null the chain-anchor columns on a referenced ``boltz_swap`` row.

    Caller is expected to have already taken the row-level
    lock on the swap row (see :func:`is_boltz_swap_safe_to_cascade_redact`).
    The function:

    1. Re-checks the live-reference predicate inside this call (the
       lock prevents a concurrent INSERT from re-introducing a
       reference, but defense in depth).
    2. Nulls ``claim_txid`` (the on-chain anchor that decodes back to
       our destination through any chain backend).
    3. ``boltz_swap_id`` ⇒ all other chain-anchored fields known
       to the BoltzSwap model — emits an
       ``output_chain_refs_redacted`` event-equivalent return value
       (the event-write itself is the orchestrator's job).

    Returns True iff the cascade ran (i.e., the predicate passed and
    the row was mutated). Gated by
    ``ANONYMIZE_BOLTZ_SWAP_REDACT_ON_ANONYMIZE_RETENTION``; when
    that flag is False, the cascade is suppressed and the function
    returns False without touching the row.
    """
    if not settings.anonymize_boltz_swap_redact_on_anonymize_retention:
        return False
    if not await is_boltz_swap_safe_to_cascade_redact(
        db,
        boltz_swap_id=boltz_swap_id,
        excluding_session_id=excluding_session_id,
    ):
        return False

    from app.models.boltz_swap import BoltzSwap

    swap = await db.get(BoltzSwap, boltz_swap_id)
    if swap is None:
        return False
    swap.claim_txid = None
    return True


async def is_boltz_swap_safe_to_cascade_redact(
    db: AsyncSession,
    *,
    boltz_swap_id: UUID,
    excluding_session_id: UUID | None = None,
) -> bool:
    """Predicate gating the chain-anchor cascade.

    The cascade onto a ``boltz_swap`` row may proceed only when no
    *other* anonymize session references the same swap row (which
    would mean a live cross-reference is still load-bearing). The
    caller takes a row-level lock on the swap row (``SELECT FOR
    UPDATE``) and re-checks this predicate inside the lock to defeat
    the create-vs-redact race.

    ``excluding_session_id`` is the session being redacted; we do
    NOT count its own references against the predicate.
    """
    from app.models.anonymize_session import AnonymizeSession

    if boltz_swap_id is None:
        return False
    stmt = (
        select(AnonymizeSession.id)
        .where(
            (AnonymizeSession.submarine_swap_id == boltz_swap_id) | (AnonymizeSession.reverse_swap_id == boltz_swap_id)
        )
        .where(AnonymizeSession.deleted_at.is_(None))
    )
    if excluding_session_id is not None:
        stmt = stmt.where(AnonymizeSession.id != excluding_session_id)
    stmt = stmt.limit(1)
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is None


# --------------------------------------------------------------------
# Event-kind collapse on retention.
# --------------------------------------------------------------------


def select_next_pass_for_session(gc_passes_completed: int) -> tuple[str, int] | None:
    """Pick the next GC pass to run for a session.

    Returns ``(pass_name, pass_bit)`` of the lowest unset bit in the
    registry, or ``None`` when every pass has completed.

    The scheduler walks sessions through their passes one at a time
    so a single transaction stays small and a crashed pass leaves
    the bitfield in a recoverable state.
    """
    for name, bit in GC_PASSES_ORDERED:
        if (gc_passes_completed & bit) == 0:
            return (name, bit)
    return None


def gc_tick_due(
    *,
    last_successful_at_unix_s: float | None,
    interval_s: int | None = None,
    now_unix_s: float | None = None,
) -> bool:
    """Pure decision: should the GC scheduler fire now?

    Defaults to ``ANONYMIZE_GC_TICK_INTERVAL_S`` (settings) when the
    caller doesn't override. A ``None`` last-run timestamp means "fresh
    deployment, run immediately".
    """
    import time as _time

    if last_successful_at_unix_s is None:
        return True
    interval = int(interval_s) if interval_s is not None else int(settings.anonymize_gc_tick_interval_s)
    if interval <= 0:
        return True
    now = now_unix_s if now_unix_s is not None else _time.time()
    return (now - float(last_successful_at_unix_s)) >= float(interval)


def refund_locked_event_hard_horizon_days() -> int:
    """Resolve the hard-horizon day count.

    ``ANONYMIZE_REFUND_LOCKED_EVENT_HARD_HORIZON_DAYS = 0`` means
    "auto" — the default is twice the destination-retention window.
    Operators that need a tighter floor configure an explicit value.
    """
    explicit = int(settings.anonymize_refund_locked_event_hard_horizon_days)
    if explicit > 0:
        return explicit
    return 2 * int(settings.anonymize_destination_retention_days)


def is_refund_locked_event_exempt(
    *,
    event_kind: str,
    refund_utxo_spent: bool,
    event_age_days: float,
) -> bool:
    """Should the event-collapse pass skip this row?

    The ``anonymize_refund_locked`` event records that the wallet has
    an unspent refund UTXO under a do-not-spend label. Collapsing
    this row inside the normal retention window erases the
    operator's only first-class evidence that a refund is locked,
    which is recoverable but adds operator friction.

    Two exit conditions clear the exemption:
    * The refund UTXO has been spent (the row is no longer load-bearing).
    * ``event_age_days`` exceeds the hard horizon (operator-bounded;
      defaults to ``2 × destination_retention_days``).
    """
    if event_kind != "anonymize_refund_locked":
        return False
    if refund_utxo_spent:
        return False
    return event_age_days < float(refund_locked_event_hard_horizon_days())


async def run_event_collapse_pass(
    db: AsyncSession,
    session: AnonymizeSession,
    *,
    retain_redacted_history: bool | None = None,
) -> bool:
    """Delete or collapse ``anonymize_session_event`` rows.

    Two modes:

    * ``ANONYMIZE_RETAIN_REDACTED_HISTORY_ROWS=false`` (default) —
      *delete* every event row for this session. The session-detail
      UI past retention shows only the minimal shape.
    * ``=true`` — *collapse* the timeline into a single
      ``kind="redacted_history"`` row with ``ts`` rounded to the
      audit-bucket boundary and ``detail_json={}``. Operators with
      support-ticket retention obligations opt in.

    ``hop_idempotency_key`` is nulled on every retained
    row regardless of mode.

    Idempotent. Rows are queried via ``session_id`` so the function
    is safe to re-run after a crash.
    """
    if is_pass_complete(session.gc_passes_completed, GC_PASS_EVENT_COLLAPSE):
        return False

    from sqlalchemy import delete

    from app.models.anonymize_session import AnonymizeSessionEvent

    if retain_redacted_history is None:
        retain_redacted_history = bool(settings.anonymize_retain_redacted_history_rows)

    # Always delete every existing event row first.
    stmt = delete(AnonymizeSessionEvent).where(AnonymizeSessionEvent.session_id == session.id)
    await db.execute(stmt)

    if retain_redacted_history:
        bucket_seconds = int(settings.anonymize_audit_bucket_s)
        completed_at = session.completed_at or datetime.now(timezone.utc)
        ts = completed_at
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        rounded = (int(ts.timestamp()) // max(1, bucket_seconds)) * bucket_seconds
        marker = AnonymizeSessionEvent(
            session_id=session.id,
            ts=datetime.fromtimestamp(rounded, tz=timezone.utc),
            kind="redacted_history",
            detail_json={},
            truncated_at=datetime.now(timezone.utc),
            hop_idempotency_key=None,
            hop_idempotency_key_generation=None,
            hop_idempotency_nonce_enc=None,
        )
        db.add(marker)

    session.gc_passes_completed = mark_pass_complete(session.gc_passes_completed, GC_PASS_EVENT_COLLAPSE)
    return True


# --------------------------------------------------------------------
# Pipeline_json + final_score_report_json truncation.
# --------------------------------------------------------------------


async def run_pipeline_json_truncate_pass(
    db: AsyncSession,
    session: AnonymizeSession,
) -> bool:
    """Truncate ``pipeline_json`` and ``final_score_report_json``.

    On retention expiry:
    * ``pipeline_json`` is reduced to
      ``{"schema_version", "source_kind", "bin_amount_sat" | "bin_index"}``
      so the residual row carries the minimum needed to render the
      session-history UI.
    * ``final_score_report_json`` is reduced to ``{"tier", "cap"}`` —
      score-explanation breakdown is dropped.
    * When ``bin_set_id`` exists on the row, propagate it
      into the truncated ``pipeline_json`` so the bin index remains
      decodable across bin-set drift.

    Idempotent. Run *before* the fingerprint-coarsen pass so
    that pass can rewrite ``bin_amount_sat`` → ``bin_index`` against
    the truncated dict shape.
    """
    if is_pass_complete(session.gc_passes_completed, GC_PASS_PIPELINE_TRUNCATE):
        return False

    pipeline = session.pipeline_json or {}
    if isinstance(pipeline, dict):
        truncated: dict = {
            "schema_version": pipeline.get("schema_version", session.pipeline_schema_version),
        }
        # The source kind is the only "shape" attribute we keep.
        src = pipeline.get("source")
        if isinstance(src, dict) and "kind" in src:
            truncated["source_kind"] = src["kind"]
        elif isinstance(pipeline.get("source_kind"), str):
            truncated["source_kind"] = pipeline["source_kind"]
        else:
            truncated["source_kind"] = session.source_kind
        # Carry whichever amount form is present; the fingerprint-
        # coarsen pass replaces ``bin_amount_sat`` with ``bin_index``.
        if "bin_amount_sat" in pipeline:
            truncated["bin_amount_sat"] = pipeline["bin_amount_sat"]
        if "bin_index" in pipeline:
            truncated["bin_index"] = pipeline["bin_index"]
        # bin-set-history anchor.
        if session.bin_set_id is not None:
            truncated["bin_set_id"] = int(session.bin_set_id)
        session.pipeline_json = truncated

    final = session.final_score_report_json
    if isinstance(final, dict):
        session.final_score_report_json = {
            "tier": final.get("tier"),
            "cap": final.get("cap"),
        }

    session.gc_passes_completed = mark_pass_complete(session.gc_passes_completed, GC_PASS_PIPELINE_TRUNCATE)
    return True


async def run_fingerprint_coarsen_pass(
    db: AsyncSession,
    session: AnonymizeSession,
) -> bool:
    """Coarsen ``completed_at`` + ``destination_script_type``
    + ``bin_amount_sat`` after retention.

    Bucket-quantize ``completed_at`` to ``ANONYMIZE_AUDIT_BUCKET_S`` so
    the second-precision timestamp can no longer be cross-referenced
    against chain-side candidate sets. Replace ``destination_script_type``
    with the literal ``"redacted"``. Replace ``bin_amount_sat`` with
    its index in the published bin set + propagate the index into
    ``pipeline_json``.
    """
    if is_pass_complete(session.gc_passes_completed, GC_PASS_FINGERPRINT_COARSEN):
        return False

    bucket_seconds = int(settings.anonymize_audit_bucket_s)

    # Round completed_at down to the bucket start.
    if session.completed_at is not None:
        rounded = _bucket_quantize_unix_s(session.completed_at.timestamp(), bucket_seconds)
        session.completed_at = datetime.fromtimestamp(rounded, tz=timezone.utc)

    # Destination_script_type → "redacted".
    session.destination_script_type = "redacted"

    # Replace bin_amount_sat with bin_index.
    bin_index = _bin_index_for(session.bin_amount_sat)
    session.bin_amount_sat = bin_index

    # Propagate bin_index into pipeline_json.
    pipeline = session.pipeline_json or {}
    if isinstance(pipeline, dict):
        pipeline = dict(pipeline)
        pipeline["bin_index"] = bin_index
        pipeline.pop("bin_amount_sat", None)
        session.pipeline_json = pipeline

    session.gc_passes_completed = mark_pass_complete(session.gc_passes_completed, GC_PASS_FINGERPRINT_COARSEN)
    return True


__all__ = [
    "GC_PASS_PIPELINE_TRUNCATE",
    "GC_PASS_EVENT_COLLAPSE",
    "GC_PASS_REUSE_KEY_PURGE",
    "GC_PASS_CHAIN_ANCHOR_REDACT",
    "GC_PASS_FINGERPRINT_COARSEN",
    "GC_PASS_LAST_ERROR_NULL",
    "GC_PASS_FINGERPRINT_COLUMNS",
    "GC_PASS_SWAP_ANCHOR_SEVER",
    "GC_PASS_HOP_IDEMPOTENCY_KEY_NULL",
    "GC_PASS_DECOY_CHAIN_ANCHOR_REDACT",
    "ALL_PASSES_MASK",
    "GC_PASSES_ORDERED",
    "is_pass_complete",
    "mark_pass_complete",
    "all_passes_complete",
    "remaining_passes",
    "RetentionWindow",
    "active_session_safety_filter",
    "fetch_retention_eligible_sessions",
    "run_chain_anchor_redact_pass",
    "run_last_error_null_pass",
    "run_reuse_key_purge_pass",
    "run_hop_idempotency_key_null_pass",
    "run_fingerprint_columns_pass",
    "run_fingerprint_coarsen_pass",
    "run_event_collapse_pass",
    "refund_locked_event_hard_horizon_days",
    "is_refund_locked_event_exempt",
    "select_next_pass_for_session",
    "gc_tick_due",
    "run_pipeline_json_truncate_pass",
    "is_boltz_swap_safe_to_cascade_redact",
    "cascade_redact_boltz_swap_anchors",
    "swap_anchor_sentinel_uuid",
    "run_swap_anchor_severance_pass",
    "run_decoy_chain_anchor_redact_pass",
    "fetch_decoy_catchup_sessions",
    "assert_passes_form_contiguous_bit_run",
    "assert_passes_registry_covers_documented_set",
]
