# SPDX-License-Identifier: MIT
"""Celery tasks driving the channel-mix executor.

A single ``process_channel_mix_run`` task walks the per-channel state
machine for one :class:`ChannelMixRun`, opens each channel, waits for
broadcast, and (when configured) seeds inbound via Boltz. A separate
periodic ``recover_channel_mix_runs`` task picks up any run left in a
non-terminal state after a worker crash.

State transitions on the per-channel JSON entries (see
:func:`app.models.channel_mix_run.make_channel_entry`):

* ``open_state``: queued → opening → open_pending → open_active
  (or open_failed at any of opening / open_pending).
* ``seed_state``: queued → swapping → seeded (or seed_failed); skipped
  whenever the planner didn't ask for a follow-on seed.

The task is per-channel atomic, not whole-plan atomic — a failure on
one channel doesn't abort the others. The run-wide ``state`` rolls up
to ``partial_failure`` when at least one channel ends in
``open_failed`` / ``seed_failed`` and at least one channel reaches
``open_active``.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select

from app.core.database import get_db_context
from app.models.channel_mix_run import (
    ChannelMixRun,
    ChannelMixRunState,
)
from app.tasks.boltz_tasks import celery_app, track_task

logger = logging.getLogger(__name__)


def _run_async(coro: Any) -> Any:
    """Run an async coroutine on a fresh event loop (Celery workers
    have no running loop)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def _open_one_channel(db, run: ChannelMixRun, channel_idx: int) -> None:
    """Drive one channel's open state through the LND open-channel
    surface.

    Mutates ``run.channels[channel_idx]`` in place; the caller is
    responsible for committing the surrounding transaction. The
    transaction lock taken by :func:`_run_one_mix` ensures only one
    worker advances a given run at a time, so the in-memory
    ``open_state`` check at function entry is a sufficient guard against
    double-open.
    """
    from app.services.lnd_service import lnd_service

    entry = run.channels[channel_idx]
    if entry["open_state"] != "queued":
        return  # already opened / failed; nothing to do

    entry["open_state"] = "opening"
    run.channels[channel_idx] = entry

    pubkey = entry["peer_pubkey"]
    host = entry["peer_host"]
    capacity_sats = int(entry["capacity_sats"])
    push_sat = int(entry["push_sat"])

    # Connect the peer first; LND ``OpenChannel`` requires the peer to
    # be one of our connected peers.
    _ok, connect_err = await lnd_service.connect_peer(pubkey, host)
    # ``already_connected`` is fine — only treat genuine failures as
    # errors.
    if connect_err and "already connected" not in str(connect_err).lower():
        entry["open_state"] = "open_failed"
        entry["open_error"] = f"connect failed: {connect_err}"[:512]
        # No channel means no seed step — promote the seed slot to a
        # terminal "skipped" so the run-wide rollup can settle.
        if entry["seed_state"] == "queued":
            entry["seed_state"] = "skipped"
        run.channels[channel_idx] = entry
        await _audit_channel_open(
            db,
            run,
            entry,
            channel_idx,
            success=False,
            error_message=f"connect failed: {connect_err}",
        )
        return

    result, error = await lnd_service.open_channel(
        node_pubkey=pubkey,
        local_funding_amount=capacity_sats,
        push_sat=push_sat,
    )
    if error or not isinstance(result, dict):
        entry["open_state"] = "open_failed"
        entry["open_error"] = f"open failed: {error or 'no result'}"[:512]
        if entry["seed_state"] == "queued":
            entry["seed_state"] = "skipped"
        run.channels[channel_idx] = entry
        await _audit_channel_open(
            db,
            run,
            entry,
            channel_idx,
            success=False,
            error_message=f"open failed: {error or 'no result'}",
        )
        return

    entry["open_state"] = "open_pending"
    txid = result.get("funding_txid_str") or result.get("funding_txid_bytes_hex")
    if txid:
        entry["open_txid"] = str(txid)
    run.channels[channel_idx] = entry
    await _audit_channel_open(db, run, entry, channel_idx, success=True)


async def _seed_one_channel(db, run: ChannelMixRun, channel_idx: int) -> None:
    """Issue a Boltz reverse swap to seed inbound on this channel.

    Only fires once the channel is active (so the LN payment can route
    out through it). For channels whose strategy is ``push_only`` or
    whose ``expected_inbound_seed_sats`` is 0, the seed step is
    skipped at row-creation time and never enters this function.

    Mutates ``run.channels[channel_idx]`` in place; the caller is
    responsible for committing the surrounding transaction.
    """
    from app.services.boltz_service import boltz_service
    from app.services.lnd_service import lnd_service

    entry = run.channels[channel_idx]
    if entry["seed_state"] != "queued":
        return
    if entry["open_state"] != "open_active":
        return  # wait for the channel to become active first

    amount = int(entry["expected_inbound_seed_sats"])
    if amount <= 0:
        entry["seed_state"] = "skipped"
        run.channels[channel_idx] = entry
        return

    # Derive a wallet-controlled destination address for the swap
    # output. We claim the on-chain back to ourselves; the meaningful
    # effect is the LN-side shift on this channel.
    addr_result, addr_err = await lnd_service.new_address(address_type="p2wkh")
    if addr_err or not isinstance(addr_result, dict):
        entry["seed_state"] = "seed_failed"
        entry["seed_error"] = f"derive address: {addr_err or 'no result'}"[:512]
        run.channels[channel_idx] = entry
        return
    destination = addr_result.get("address")
    if not destination:
        entry["seed_state"] = "seed_failed"
        entry["seed_error"] = "derive address: no address returned"
        run.channels[channel_idx] = entry
        return

    entry["seed_state"] = "swapping"
    run.channels[channel_idx] = entry

    swap_row, swap_err = await boltz_service.create_reverse_swap(
        db,
        api_key_id=run.api_key_id,
        invoice_amount_sats=amount,
        destination_address=destination,
        outgoing_chan_id=None,  # let LND pick; the channel that's most-loaded should win
    )
    if swap_err or swap_row is None:
        entry["seed_state"] = "seed_failed"
        entry["seed_error"] = f"create swap: {swap_err or 'no swap'}"[:512]
        run.channels[channel_idx] = entry
        return

    entry["seed_swap_id"] = str(swap_row.id)
    # We're not waiting for the swap to settle here — the existing
    # ``process_boltz_swap`` Celery task drives it to completion. Mark
    # seeded once the swap is dispatched; a periodic reconciler maps
    # the final swap status back into the run if needed.
    entry["seed_state"] = "seeded"
    run.channels[channel_idx] = entry


def _confirmations_for(channels: list[dict]) -> dict[str, dict]:
    """Stub — caller injects active-channel data via ``await_open_active``."""
    return {}


async def _refresh_open_pending_states(db, run: ChannelMixRun) -> None:
    """For each channel in ``open_pending``, ask LND whether the channel
    is now active and, if so, transition to ``open_active``. The same
    routine drives the seed step's gating."""
    from app.services.lnd_service import lnd_service

    pending_indices = [
        i for i, entry in enumerate(run.channels)
        if entry["open_state"] == "open_pending"
    ]
    if not pending_indices:
        return

    active_channels, error = await lnd_service.get_channels()
    if error or not isinstance(active_channels, list):
        return  # can't tell; try again next tick

    # Look up by remote pubkey since funding txid mapping varies across
    # LND versions.
    by_pubkey: dict[str, dict] = {}
    for ch in active_channels:
        pk = (ch.get("remote_pubkey") or "").lower()
        if pk:
            by_pubkey[pk] = ch

    for idx in pending_indices:
        entry = run.channels[idx]
        match = by_pubkey.get((entry["peer_pubkey"] or "").lower())
        if match is None or not match.get("active"):
            continue
        entry["open_state"] = "open_active"
        run.channels[idx] = entry


def _rollup_state(run: ChannelMixRun) -> ChannelMixRunState:
    """Compute the run-wide state from the per-channel sub-states."""
    if not run.channels:
        return ChannelMixRunState.COMPLETE
    any_active = any(c["open_state"] == "open_active" for c in run.channels)
    any_failed = any(
        c["open_state"] == "open_failed" or c["seed_state"] == "seed_failed"
        for c in run.channels
    )
    all_terminal_open = all(
        c["open_state"] in ("open_active", "open_failed") for c in run.channels
    )
    all_terminal_seed = all(
        c["seed_state"] in ("skipped", "seeded", "seed_failed") for c in run.channels
    )
    if all_terminal_open and all_terminal_seed:
        if any_failed and any_active:
            return ChannelMixRunState.PARTIAL_FAILURE
        if any_failed and not any_active:
            return ChannelMixRunState.PARTIAL_FAILURE
        return ChannelMixRunState.COMPLETE
    return ChannelMixRunState.IN_PROGRESS


async def _audit_channel_open(
    db,
    run: ChannelMixRun,
    entry: dict[str, Any],
    channel_idx: int,
    *,
    success: bool,
    error_message: str | None = None,
) -> None:
    """Record one channel-mix open attempt in the audit log.

    Mirrors the direct ``/dashboard/api/channel/open`` audit-log row so
    operators reviewing the audit chain see executor-driven opens with
    the same shape they see for hand-driven ones. The row is keyed by
    the run's ``api_key_id``, with the api-key name resolved live so a
    v1-initiated run audits under the real admin key's name (and a
    dashboard-initiated run audits under the dashboard sentinel name).

    Uses its **own** database session — ``log_action`` /
    ``log_dashboard_action`` commit internally to advance the hash
    chain, and committing on the tick's session would release the row
    lock the tick holds. The audit chain is keyed and gap-tolerant, so
    a crash between the tick's commit and the audit write loses the
    audit row but not the run state (which is the durable record).

    Each audit write is its own checkout from the connection pool, so
    a 6-channel plan opens (at most) six sequential audit sessions in
    addition to the tick's main session. The sessions are checked back
    in immediately after each ``log_*`` call commits, so a single
    executor tick never holds more than two pool connections at a time
    (the tick's locked session + the in-flight audit session).
    """
    from app.dashboard import DASHBOARD_KEY_ID
    from app.models.api_key import APIKey
    from app.services.audit_service import log_action, log_dashboard_action

    details = {
        "mix_run_id": str(run.id),
        "channel_idx": channel_idx,
        "peer_alias": entry.get("peer_alias"),
        "peer_pubkey": entry.get("peer_pubkey"),
        "push_sat": int(entry.get("push_sat") or 0),
        "open_txid": entry.get("open_txid"),
    }
    amount = int(entry["capacity_sats"])

    async with get_db_context() as audit_db:
        if run.api_key_id == DASHBOARD_KEY_ID:
            # Dashboard-initiated run — fast path, no key lookup needed.
            await log_dashboard_action(
                audit_db,
                run.api_key_id,
                "channel_mix_open",
                "channel",
                amount_sats=amount,
                details=details,
                success=success,
                error_message=error_message,
            )
            return
        # v1-initiated run — resolve the admin key's real name so the
        # audit row attributes the open to the operator, not the
        # dashboard sentinel.
        api_key = (
            await audit_db.execute(select(APIKey).where(APIKey.id == run.api_key_id))
        ).scalar_one_or_none()
        if api_key is None:
            # Key was deleted between execute time and now — fall back
            # to the dashboard helper so the audit chain still gets a
            # row; the api_key_id on the row remains the original
            # operator's key id for traceability.
            await log_dashboard_action(
                audit_db,
                run.api_key_id,
                "channel_mix_open",
                "channel",
                amount_sats=amount,
                details=details,
                success=success,
                error_message=error_message,
            )
            return
        await log_action(
            audit_db,
            api_key,
            "channel_mix_open",
            "channel",
            amount_sats=amount,
            details=details,
            success=success,
            error_message=error_message,
        )


async def _run_one_mix(run_id: UUID) -> dict[str, Any]:
    """One tick of the executor — drives ``run_id`` forward as far as
    it can go right now.

    The whole tick runs under a single transaction with a row-level
    lock (``SELECT ... FOR UPDATE``) on the :class:`ChannelMixRun`. Two
    Celery workers racing on the same run id — e.g. the dashboard's
    initial enqueue plus the periodic ``recover_channel_mix_runs`` —
    serialize at the lock, so a second worker only sees state after the
    first worker's tick commits. The per-channel state machine inside
    each tick is therefore single-writer, and the in-memory
    ``open_state == "queued"`` checks in :func:`_open_one_channel` are
    sufficient to prevent double-broadcasts of the same funding tx.
    Workers that lose the race exit and re-queue via Celery's retry.
    """
    async with get_db_context() as db:
        row_result = await db.execute(
            select(ChannelMixRun)
            .where(ChannelMixRun.id == run_id)
            .with_for_update()
        )
        run = row_result.scalar_one_or_none()
        if run is None:
            return {"status": "missing"}
        if run.state in (ChannelMixRunState.COMPLETE, ChannelMixRunState.CANCELLED):
            return {"status": str(run.state.value)}

        # In-memory state transition; commit happens once at the end so
        # the row lock stays held through the per-channel work.
        run.state = ChannelMixRunState.IN_PROGRESS
        run.updated_at = _utc_now()

        # 1) Open queued channels.
        for idx in range(len(run.channels)):
            if run.channels[idx]["open_state"] == "queued":
                await _open_one_channel(db, run, idx)

        # 2) Promote open_pending → open_active where confirmation has
        #    landed.
        await _refresh_open_pending_states(db, run)

        # 3) Issue seed swaps on channels now active.
        for idx in range(len(run.channels)):
            if (
                run.channels[idx]["seed_state"] == "queued"
                and run.channels[idx]["open_state"] == "open_active"
            ):
                await _seed_one_channel(db, run, idx)

        # 4) Roll up the run-wide state.
        new_state = _rollup_state(run)
        if new_state != run.state:
            run.state = new_state
            if new_state in (ChannelMixRunState.COMPLETE, ChannelMixRunState.PARTIAL_FAILURE):
                run.completed_at = _utc_now()
        run.updated_at = _utc_now()

        # Single commit at the end — releases the row lock and flushes
        # every per-channel transition the tick made.
        await db.commit()
        return {"status": str(run.state.value)}


@celery_app.task(
    bind=True,
    name="process_channel_mix_run",
    max_retries=200,
)
@track_task("process_channel_mix_run")
def process_channel_mix_run(self, run_id: str) -> dict[str, Any]:
    """Drive one channel-mix run forward.

    Retries with a constant backoff until the run reaches a terminal
    state; the per-channel state machine ensures each retry only
    advances the work that hasn't completed yet.
    """
    try:
        result: dict[str, Any] = _run_async(_run_one_mix(UUID(run_id)))
    except Exception:  # noqa: BLE001
        logger.exception("channel-mix executor: tick failed for %s", run_id)
        raise self.retry(countdown=30)
    if result.get("status") in ("complete", "partial_failure", "cancelled"):
        return result
    # Still in progress — re-queue.
    raise self.retry(countdown=30)


async def _run_recover_mix_runs() -> dict[str, Any]:
    """Pick up any channel-mix run left in a non-terminal state. The
    periodic Celery beat tick calls this so a worker crash mid-run
    self-heals without operator intervention."""
    async with get_db_context() as db:
        result = await db.execute(
            select(ChannelMixRun).where(
                ChannelMixRun.state.in_(
                    [
                        ChannelMixRunState.QUEUED,
                        ChannelMixRunState.IN_PROGRESS,
                    ]
                )
            )
        )
        rows = list(result.scalars().all())
    if not rows:
        return {"recovered": 0}
    for row in rows:
        process_channel_mix_run.delay(str(row.id))
    return {"recovered": len(rows)}


@celery_app.task(name="recover_channel_mix_runs")
@track_task("recover_channel_mix_runs")
def recover_channel_mix_runs() -> dict[str, Any]:
    """Periodic scan that re-enqueues channel-mix runs stuck after a crash."""
    return _run_async(_run_recover_mix_runs())


__all__ = [
    "process_channel_mix_run",
    "recover_channel_mix_runs",
]
