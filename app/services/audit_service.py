# SPDX-License-Identifier: MIT
"""
Audit logging service — records all API operations for accountability.

Every payment, channel open, swap initiation, and admin action is
logged with the API key, action, outcome, and relevant details.
Each entry includes a hash chain linking to the previous entry for
tamper detection.
"""

import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import audit_chain_hmac
from app.models.api_key import APIKey
from app.models.audit_chain_state import HIGH_WATER_ROW_ID, AuditChainState
from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

# Latches once the first unsigned anchor is emitted so the warning is
# not repeated on every retention cycle / heartbeat.
_warned_unsigned_anchor = False


def _sign_high_water(entry_count: int, head_hash: str | None, *, secret: str | None = None) -> str:
    """Keyed signature binding the recorded count to the head hash."""
    return audit_chain_hmac(f"{entry_count}:{head_hash or ''}", secret=secret)


def _high_water_signature_valid(state: AuditChainState) -> bool:
    """True when the stored signature matches under the current or previous key.

    Accepting ``SECRET_KEY_PREVIOUS`` keeps the high-water row verifiable
    across a key rotation, mirroring the row-hash chain's rotation
    fallback. The row is re-signed under the current key on the next
    append.
    """
    expected = _sign_high_water(state.entry_count, state.head_hash)
    if hmac.compare_digest(expected, state.state_hmac or ""):
        return True
    prev = settings.secret_key_previous
    if prev:
        expected_prev = _sign_high_water(state.entry_count, state.head_hash, secret=prev)
        if hmac.compare_digest(expected_prev, state.state_hmac or ""):
            return True
    return False


async def _load_high_water(db: AsyncSession) -> AuditChainState | None:
    return (
        await db.execute(select(AuditChainState).where(AuditChainState.id == HIGH_WATER_ROW_ID))
    ).scalar_one_or_none()


async def _count_audit_rows(db: AsyncSession) -> int:
    return int((await db.execute(select(func.count(AuditLog.id)))).scalar() or 0)


async def _record_high_water(db: AsyncSession, entry_count: int, head_hash: str | None) -> None:
    """Upsert the signed high-water row to ``entry_count`` / ``head_hash``.

    The caller must already hold the chain advisory lock (every call site
    does), so the read-modify-write needs no extra serialization.
    """
    entry_count = max(0, int(entry_count))
    state = await _load_high_water(db)
    signature = _sign_high_water(entry_count, head_hash)
    if state is None:
        db.add(
            AuditChainState(
                id=HIGH_WATER_ROW_ID,
                entry_count=entry_count,
                head_hash=head_hash,
                state_hmac=signature,
            )
        )
    else:
        state.entry_count = entry_count
        state.head_hash = head_hash
        state.state_hmac = signature
        state.updated_at = datetime.now(timezone.utc)


async def _bump_high_water_on_append(db: AsyncSession, head_hash: str | None) -> None:
    """Advance the high-water count by one authorized append.

    Bootstraps from the live row count the first time it runs (so an
    existing table adopts its current size as the baseline), then tracks
    by increment so the per-append cost stays O(1).

    A row that is *present but does not verify* is treated as tampering,
    NOT re-baselined: re-signing a fresh count over it would heal the
    mismatch and launder evidence of a truncation an attacker is trying
    to hide. Instead the bad row is left untouched so ``check_high_water``
    keeps reporting it until an operator deliberately re-anchors.
    """
    state = await _load_high_water(db)
    if state is None:
        # First run on this table — adopt the current (now-flushed) size
        # as the baseline.
        await _record_high_water(db, await _count_audit_rows(db), head_hash)
        return
    if not _high_water_signature_valid(state):
        # Present but unverifiable — leave it as a latched tamper signal.
        return
    await _record_high_water(db, state.entry_count + 1, head_hash)


async def check_high_water(db: AsyncSession) -> dict:
    """Compare the live audit row count against the signed high-water.

    Returns ``{"present": bool, "ok": bool, "reason": str|None,
    "recorded_count": int|None, "live_count": int}``. ``ok`` is False when
    the live count has fallen below the recorded authorized count
    (tail/any truncation) or the high-water signature does not verify.
    A missing high-water row is reported as ``present=False, ok=True`` —
    nothing has been recorded to contradict yet.
    """
    # Serialize the recorded-state read and the live-count read against
    # writers under the same advisory lock appends/prunes take, so no
    # append or prune can commit *between* the two reads and produce a
    # spurious ``live < recorded`` verdict. The lock is transaction-scoped
    # and reentrant, so the prune path (which already holds it when it
    # calls verify_chain) is unaffected; a standalone verify acquires it
    # briefly and blocks only against a concurrent writer.
    await _acquire_chain_lock(db)
    state = await _load_high_water(db)
    live_count = await _count_audit_rows(db)
    if state is None:
        return {"present": False, "ok": True, "reason": None, "recorded_count": None, "live_count": live_count}
    if not _high_water_signature_valid(state):
        return {
            "present": True,
            "ok": False,
            "reason": "high-water signature mismatch",
            "recorded_count": state.entry_count,
            "live_count": live_count,
        }
    if live_count < state.entry_count:
        return {
            "present": True,
            "ok": False,
            "reason": "row count below recorded high-water (truncation)",
            "recorded_count": state.entry_count,
            "live_count": live_count,
        }
    return {
        "present": True,
        "ok": True,
        "reason": None,
        "recorded_count": state.entry_count,
        "live_count": live_count,
    }


async def _get_last_hash(db: AsyncSession) -> tuple[str | None, datetime | None]:
    """Return (entry_hash, created_at) of the most recent audit log entry."""
    result = await db.execute(
        select(AuditLog.entry_hash, AuditLog.created_at)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(1)
    )
    row = result.first()
    if row is None:
        return None, None
    return row[0], row[1]


async def _acquire_chain_lock(db: AsyncSession) -> None:
    """Serialize hash-chain writers with a PostgreSQL advisory lock.

    On a non-PostgreSQL backend (SQLite in tests) advisory locks are
    unavailable, so the call is skipped. On PostgreSQL a lock-acquisition
    failure is propagated rather than swallowed: silently proceeding would let
    two concurrent writers read the same ``prev_hash`` and fork the chain,
    which the previous blanket ``except: pass`` masked.
    """
    dialect = ""
    try:
        bind = db.get_bind()
        dialect = bind.dialect.name
    except Exception:  # noqa: BLE001 — best-effort dialect probe
        dialect = ""
    if dialect != "postgresql":
        return
    await db.execute(text("SELECT pg_advisory_xact_lock(42)"))


async def _finalize_entry(db: AsyncSession, entry: AuditLog) -> None:
    """Set prev_hash and entry_hash, then commit.

    Uses a PostgreSQL advisory lock to serialize hash-chain writes,
    preventing concurrent requests from forking the chain.
    Falls back gracefully on non-PostgreSQL backends (e.g. SQLite in tests).
    """
    await _acquire_chain_lock(db)
    # Stamp id and created_at deterministically before computing the hash.
    # SQLAlchemy's default= callables only fire at flush/INSERT time, but
    # compute_hash() reads both fields, so we need values here that will
    # match the values persisted to the row.
    if entry.id is None:
        entry.id = uuid4()
    try:
        prev_hash, prev_created_at = await _get_last_hash(db)
    except Exception:
        prev_hash, prev_created_at = None, None
    if entry.created_at is None:
        now = datetime.now(timezone.utc)
        # Ensure strictly-increasing timestamps so the chain has a
        # deterministic walk order even under rapid-fire inserts on
        # backends with low timestamp resolution.
        if prev_created_at is not None:
            if prev_created_at.tzinfo is None:
                prev_created_at = prev_created_at.replace(tzinfo=timezone.utc)
            if now <= prev_created_at:
                now = prev_created_at + timedelta(microseconds=1)
        entry.created_at = now
    entry.prev_hash = prev_hash
    entry.entry_hash = entry.compute_hash()
    db.add(entry)
    # Flush so the new row is visible to the high-water count, then
    # advance the signed high-water within the same transaction so the
    # append and its recorded count commit atomically.
    await db.flush()
    await _bump_high_water_on_append(db, entry.entry_hash)
    await db.commit()


async def verify_chain(
    db: AsyncSession,
    limit: int | None = None,
    batch_size: int = 1000,
) -> dict:
    """Walk the audit log in insertion order and verify every entry's hash.

    By default verifies every row in the table by streaming entries in
    fixed-size batches keyed off ``(created_at, id)`` so the verifier
    runs in bounded memory regardless of table size. Passing ``limit``
    caps the number of rows checked (used by the legacy admin endpoint
    for backwards compatibility).

    Returns a summary: ``{"checked": N, "ok": bool, "first_bad_id": str|None,
    "first_bad_reason": str|None}``.

    The walk seeds ``prev`` from the first row's own ``prev_hash`` rather
    than insisting it be ``None``. Retention pruning deletes the oldest
    rows, so after a cut the surviving head legitimately links back to a
    row that no longer exists; seeding from it keeps the chain verifiable
    across retention cycles without ever rewriting a surviving row's hash.
    Every link *after* the head is still checked strictly.
    """
    from sqlalchemy import and_, or_

    _unset = object()
    prev: Any = _unset
    checked = 0
    cursor_created_at: datetime | None = None
    cursor_id: UUID | None = None

    while True:
        remaining = None if limit is None else limit - checked
        if remaining is not None and remaining <= 0:
            break
        page_size = batch_size if remaining is None else min(batch_size, remaining)

        query = select(AuditLog).order_by(AuditLog.created_at.asc(), AuditLog.id.asc()).limit(page_size)
        if cursor_created_at is not None and cursor_id is not None:
            # Cursor pagination on the composite (created_at, id) key.
            query = query.where(
                or_(
                    AuditLog.created_at > cursor_created_at,
                    and_(
                        AuditLog.created_at == cursor_created_at,
                        AuditLog.id > cursor_id,
                    ),
                )
            )
        result = await db.execute(query)
        entries = list(result.scalars().all())
        if not entries:
            break

        for entry in entries:
            if prev is _unset:
                # Head row: accept its back-link as the chain root (it may
                # point at a row removed by retention pruning).
                prev = entry.prev_hash
            elif not hmac.compare_digest(str(entry.prev_hash or ""), str(prev or "")):
                return {
                    "checked": checked,
                    "ok": False,
                    "first_bad_id": str(entry.id),
                    "first_bad_reason": "prev_hash mismatch",
                }
            expected = entry.compute_hash()
            if not hmac.compare_digest(str(expected), str(entry.entry_hash or "")):
                # Rotation fallback: rows written under the prior SECRET_KEY
                # still validate against SECRET_KEY_PREVIOUS, so a chain stays
                # verifiable across a key rotation (current + previous keys may
                # coexist in one chain) without a destructive full re-anchor.
                # The prev_hash linkage above is key-agnostic (it compares
                # stored hashes), so a mixed-key chain links correctly.
                prev_secret = settings.secret_key_previous
                if not (
                    prev_secret
                    and hmac.compare_digest(
                        str(entry.compute_hash(secret=prev_secret)),
                        str(entry.entry_hash or ""),
                    )
                ):
                    return {
                        "checked": checked,
                        "ok": False,
                        "first_bad_id": str(entry.id),
                        "first_bad_reason": "entry_hash mismatch",
                    }
            prev = entry.entry_hash
            cursor_created_at = entry.created_at
            cursor_id = entry.id
            checked += 1

        if len(entries) < page_size:
            break

    # A full verification also reconciles the live row count against the
    # signed high-water, so removal of the newest rows (which the
    # surviving-row walk above cannot detect) is caught here.
    if limit is None:
        hw = await check_high_water(db)
        if not hw["ok"]:
            return {
                "checked": checked,
                "ok": False,
                "first_bad_id": None,
                "first_bad_reason": hw["reason"],
            }

    return {"checked": checked, "ok": True, "first_bad_id": None, "first_bad_reason": None}


async def log_action(
    db: AsyncSession,
    api_key: APIKey,
    action: str,
    resource: str,
    details: Optional[dict] = None,
    amount_sats: Optional[int] = None,
    success: bool = True,
    error_message: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    """Record an action in the audit log."""
    entry = AuditLog(
        api_key_id=api_key.id,
        api_key_name=api_key.name,
        action=action,
        resource=resource,
        details=details,
        amount_sats=amount_sats,
        success=success,
        error_message=error_message,
        ip_address=ip_address,
    )
    await _finalize_entry(db, entry)

    level = logging.INFO if success else logging.WARNING
    logger.log(
        level,
        "AUDIT: key=%s action=%s resource=%s sats=%s success=%s",
        api_key.name,
        action,
        resource,
        amount_sats,
        success,
    )
    return entry


async def log_dashboard_action(
    db: AsyncSession,
    dashboard_key_id: UUID,
    action: str,
    resource: str,
    details: Optional[dict] = None,
    amount_sats: Optional[int] = None,
    success: bool = True,
    error_message: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    """Record a dashboard-initiated action in the audit log."""
    entry = AuditLog(
        api_key_id=dashboard_key_id,
        api_key_name="__dashboard__",
        action=action,
        resource=resource,
        details=details,
        amount_sats=amount_sats,
        success=success,
        error_message=error_message,
        ip_address=ip_address,
    )
    await _finalize_entry(db, entry)

    level = logging.INFO if success else logging.WARNING
    logger.log(
        level,
        "AUDIT: key=__dashboard__ action=%s resource=%s sats=%s success=%s",
        action,
        resource,
        amount_sats,
        success,
    )
    return entry


async def prune_audit_log(
    db: AsyncSession,
    cutoff: datetime,
    dashboard_key_id: UUID,
) -> dict:
    """Delete audit-log rows older than ``cutoff`` while keeping the chain verifiable.

    Pruning removes the oldest rows, so the surviving head's ``prev_hash``
    then references a row that no longer exists. ``verify_chain`` seeds
    its walk from the head's own back-link, so the chain stays verifiable
    across retention cycles without rewriting any surviving row's hash.

    The chain is verified *before* anything is deleted. Because the chain
    is keyed (only a SECRET_KEY holder can produce valid hashes), a chain
    that fails verification means the table was altered out of band. In
    that case pruning refuses to run — it neither deletes nor rewrites —
    and raises a security alert, leaving the inconsistency intact for an
    operator to resolve deliberately via the re-anchor admin action. It
    never silently rewrites hashes to make a broken chain look valid.

    Steps:

    1. Acquires the same advisory lock used by ``_finalize_entry`` so
       writers cannot interleave.
    2. Verifies the chain; skips (and alerts) if it does not verify.
    3. Deletes rows with ``created_at < cutoff``.
    4. Appends a synthetic ``audit_truncate`` anchor entry chained off
       the current tail, recording ``deleted_count`` and
       ``truncated_before`` so the retention event itself is auditable.

    Returns ``{"deleted": N, "anchor_id": str|None, "skipped": bool}``.
    """
    await _acquire_chain_lock(db)

    from sqlalchemy import delete, func

    # Verify before touching anything. A keyed chain that fails to verify
    # was altered out of band; refuse to prune rather than rewrite over it.
    try:
        verify_summary = await verify_chain(db, limit=None)
    except Exception:  # noqa: BLE001 — never delete over a verify error
        verify_summary = {"ok": False, "first_bad_reason": "verify raised"}
    if not verify_summary.get("ok", True):
        try:
            from app.services.alert_service import send_alert

            await send_alert(
                "audit_chain_broken",
                "Audit log chain failed verification; retention pruning skipped.",
                details={
                    "first_bad_id": verify_summary.get("first_bad_id"),
                    "first_bad_reason": verify_summary.get("first_bad_reason"),
                },
            )
        except Exception:  # noqa: BLE001 — alerting must not mask the skip
            pass
        logger.error(
            "Audit chain failed verification (first_bad_id=%s reason=%s) — "
            "retention pruning skipped; resolve via the re-anchor action.",
            verify_summary.get("first_bad_id"),
            verify_summary.get("first_bad_reason"),
        )
        return {"deleted": 0, "anchor_id": None, "skipped": True}

    deleted_result = await db.execute(
        delete(AuditLog).where(AuditLog.created_at < cutoff).execution_options(synchronize_session=False)
    )
    deleted_count = int(deleted_result.rowcount or 0)  # type: ignore[attr-defined]

    # Retention is an authorized decrease, so lower the signed high-water
    # by exactly the rows removed. The anchor append below (when present)
    # advances it by one again. An existing, valid high-water is adjusted
    # by subtraction; otherwise the subsequent append re-baselines from
    # the live count.
    if deleted_count > 0:
        hw_state = await _load_high_water(db)
        if hw_state is not None and _high_water_signature_valid(hw_state):
            await _record_high_water(db, hw_state.entry_count - deleted_count, hw_state.head_hash)

    anchor_id: str | None = None
    if deleted_count > 0:
        # Append an anchor so the retention event itself is auditable. It
        # chains off the (intact) current tail; the new head's dangling
        # back-link is handled by verify_chain's head seeding. If the
        # table is now empty the anchor would be a confusing lone row, so
        # skip it.
        survivor_count = (await db.execute(select(func.count(AuditLog.id)))).scalar() or 0
        if survivor_count > 0:
            anchor = AuditLog(
                api_key_id=dashboard_key_id,
                api_key_name="__retention__",
                action="audit_truncate",
                resource="audit_log",
                details={
                    "deleted_count": deleted_count,
                    "truncated_before": cutoff.astimezone(timezone.utc).isoformat(),
                },
                success=True,
            )
            await _finalize_entry(db, anchor)
            anchor_id = str(anchor.id)
        else:
            await db.commit()
    else:
        # Nothing to do — commit any advisory-lock side effects so the
        # transaction doesn't dangle.
        await db.commit()

    logger.info(
        "Audit log pruned: deleted=%d anchor_id=%s",
        deleted_count,
        anchor_id,
    )
    # Ship a signed external anchor every retention cycle (even when nothing
    # was deleted) carrying this cycle's in-process ``deleted`` count, so an
    # off-box observer can enforce ``count_now >= count_prev - deleted_now`` and
    # detect front-truncation by a DB-write attacker.
    await emit_audit_anchor(db, deleted=deleted_count)
    return {
        "deleted": deleted_count,
        "anchor_id": anchor_id,
        "skipped": False,
    }


async def current_anchor(db: AsyncSession) -> dict:
    """Snapshot the chain's externally-anchorable head state.

    Returns ``{count, head_id, head_hash, oldest_created_at,
    newest_created_at}``. ``head_hash`` is the keyed ``entry_hash`` of the
    newest row, which a SECRET_KEY-less DB-write attacker cannot forge.

    This snapshot is what ``emit_audit_anchor`` signs and ships to the external
    alert sink so an off-box observer holds anchors the database attacker
    cannot reach. See ``emit_audit_anchor`` for how the observer uses the
    signed ``deleted`` count carried alongside this snapshot to detect
    front-truncation.
    """
    from sqlalchemy import func

    count = int((await db.execute(select(func.count(AuditLog.id)))).scalar() or 0)
    bounds = (await db.execute(select(func.min(AuditLog.created_at), func.max(AuditLog.created_at)))).one()
    oldest, newest = bounds[0], bounds[1]

    head = (
        await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(1))
    ).scalar_one_or_none()

    def _iso(dt: datetime | None) -> str | None:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    return {
        "count": count,
        "head_id": str(head.id) if head is not None else None,
        "head_hash": head.entry_hash if head is not None else None,
        "oldest_created_at": _iso(oldest),
        "newest_created_at": _iso(newest),
    }


async def emit_audit_anchor(db: AsyncSession, *, deleted: int = 0) -> dict:
    """Sign and push the current chain head/count to the external alert sink.

    The keyed hash chain detects *modification* of audit rows by a DB-write
    attacker, but not *deletion of the oldest rows* (front-truncation), which
    is indistinguishable from legitimate retention pruning from inside the
    database. Shipping a signed anchor to an off-box receiver closes that gap.

    ``deleted`` is the number of rows the prune that just ran removed
    **in-process** (0 for a heartbeat anchor where no pruning happened). It is
    carried inside the webhook payload, which is HMAC-signed with
    ``ALERT_WEBHOOK_SHARED_SECRET``, so an attacker who lacks that shared secret
    cannot forge or inflate it. That is what makes reconciliation sound: the
    receiver, holding the signed anchor stream, enforces

        count_now >= count_prev - deleted_now

    Because legitimate adds only *increase* the count and legitimate prunes
    decrease it by exactly the signed ``deleted`` they report, the only way the
    live count can fall *below* ``count_prev - deleted_now`` is rows removed out
    of band (front-truncation) — which the attacker cannot account for without
    forging a signed anchor. The guarantee therefore holds only when
    ``ALERT_WEBHOOK_SHARED_SECRET`` is configured; without it the anchor ships
    unauthenticated and the receiver cannot trust it. Best-effort — never raises.

    Returns the anchor snapshot (with ``deleted`` merged in), also surfaced by
    the admin verify endpoint.
    """
    anchor = await current_anchor(db)
    anchor["deleted"] = int(deleted)
    if settings.alert_webhook_url and not settings.alert_webhook_shared_secret:
        global _warned_unsigned_anchor
        if not _warned_unsigned_anchor:
            logger.warning(
                "Emitting audit-chain anchor UNSIGNED — ALERT_WEBHOOK_SHARED_SECRET "
                "is not set, so the off-box receiver cannot authenticate it and "
                "front-truncation detection does not hold."
            )
            _warned_unsigned_anchor = True
    try:
        from app.services.alert_service import send_alert

        await send_alert(
            "audit_anchor",
            f"Audit chain anchor: {anchor['count']} rows, head {anchor['head_id']}, deleted {anchor['deleted']}",
            details=anchor,
        )
    except Exception:  # noqa: BLE001 — anchoring is best-effort
        logger.debug("Audit anchor emit failed", exc_info=True)
    return anchor


async def reanchor_chain(
    db: AsyncSession,
    actor_key_id: UUID,
    actor_name: str,
) -> dict:
    """Recompute the whole chain under the current key — a deliberate, logged operator action.

    Verification fails legitimately after a database restore or a
    SECRET_KEY rotation (the latter changes the derived chain key), and
    the routine retention prune refuses to run until the chain verifies.
    This recovers from that state explicitly: it re-walks every row in
    insertion order, re-links ``prev_hash`` from the genesis, and
    recomputes ``entry_hash`` under the current key.

    Unlike the prune path it makes no judgement about whether the chain
    *should* verify — re-anchoring is the operator asserting "this is the
    new baseline." To keep that assertion accountable, it records its own
    ``audit_chain_reanchor`` entry (actor + the pre-re-anchor verification
    verdict + row count) as part of the freshly re-anchored chain, so the
    recovery is itself part of the tamper-evident record rather than a
    silent rewrite.

    Returns ``{"reanchored": N, "was_consistent": bool, "first_bad_id": str|None}``.
    """
    await _acquire_chain_lock(db)

    try:
        pre = await verify_chain(db, limit=None)
    except Exception:  # noqa: BLE001
        pre = {"ok": False, "first_bad_id": None, "first_bad_reason": "verify raised"}

    survivors_query = await db.execute(select(AuditLog).order_by(AuditLog.created_at.asc(), AuditLog.id.asc()))
    survivors = list(survivors_query.scalars().all())
    prev: str | None = None
    for row in survivors:
        row.prev_hash = prev
        row.entry_hash = row.compute_hash()
        prev = row.entry_hash

    anchor = AuditLog(
        api_key_id=actor_key_id,
        api_key_name=actor_name,
        action="audit_chain_reanchor",
        resource="audit_log",
        details={
            "reanchored_count": len(survivors),
            "was_consistent": bool(pre.get("ok", False)),
            "pre_first_bad_id": pre.get("first_bad_id"),
            "pre_first_bad_reason": pre.get("first_bad_reason"),
        },
        success=True,
    )
    await _finalize_entry(db, anchor)

    # Re-anchoring is the operator's deliberate "this is the new baseline"
    # action, so it re-establishes the signed high-water under the current
    # key even when the prior one no longer verifies (e.g. after a key
    # rotation). This is the one place a non-verifying high-water is reset
    # rather than left latched — normal appends never heal it.
    await _record_high_water(db, await _count_audit_rows(db), anchor.entry_hash)
    await db.commit()

    logger.warning(
        "Audit chain re-anchored by %s: rows=%d was_consistent=%s pre_first_bad_id=%s",
        actor_name,
        len(survivors),
        pre.get("ok", False),
        pre.get("first_bad_id"),
    )

    # Re-anchoring re-bases the entire tamper-evident chain under the
    # current key, so an operator should be notified out-of-band whenever
    # it happens — especially when the chain did not verify beforehand.
    try:
        from app.services.alert_service import send_alert

        await send_alert(
            "audit_chain_reanchor",
            f"Audit chain re-anchored by {actor_name}: {len(survivors)} rows, "
            f"was_consistent={bool(pre.get('ok', False))}",
            details={
                "actor_name": actor_name,
                "reanchored_count": len(survivors),
                "was_consistent": bool(pre.get("ok", False)),
                "pre_first_bad_id": str(pre.get("first_bad_id")) if pre.get("first_bad_id") else None,
            },
        )
    except Exception:  # noqa: BLE001 — alerting must never block the operation
        logger.exception("Failed to emit audit_chain_reanchor alert")

    return {
        "reanchored": len(survivors),
        "was_consistent": bool(pre.get("ok", False)),
        "first_bad_id": pre.get("first_bad_id"),
    }
