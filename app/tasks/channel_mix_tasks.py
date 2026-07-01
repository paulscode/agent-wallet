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
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select

from app.core.database import get_db_context
from app.models.channel_mix_run import (
    BOOTSTRAP_ROUND_TERMINAL_STATES,
    TERMINAL_RUN_STATES,
    ChannelMixRun,
    ChannelMixRunState,
    finalize_run,
    make_bootstrap_round_entry,
)
from app.tasks.boltz_tasks import celery_app, track_task

logger = logging.getLogger(__name__)

# Bootstrap executor tunables. A round's drain may fail to route out the
# brand-new channel until gossip/pathfinding settles (plan §7.1); retry a
# bounded number of times before giving up on the round.
BOOTSTRAP_MAX_SWAP_ATTEMPTS = 4
# A round's assigned peer may be briefly unreachable (connect failure =
# transient — plan §7.5). Retry the connect this many ticks before
# escalating to the next eligible peer, so a permanently-down peer can't
# wedge the round forever (the §7 "stop cleanly, never retry forever" rule).
BOOTSTRAP_MAX_CONNECT_ATTEMPTS = 3
# LND's ConnectPeer is fire-and-forget: it returns "connection … initiated"
# before the TCP + Noise handshake completes (typically ~1s later). The
# immediately-following OpenChannel would then race ahead and be rejected with
# "peer … is not online". After connecting we poll ListPeers up to this many
# times (1s apart) within the same tick so the peer is actually connected
# before we open. Bounded so a genuinely-unreachable peer still escalates.
BOOTSTRAP_PEER_CONNECT_WAIT_POLLS = 15
# LND retains an on-chain "anchor reserve" to fee-bump force-closes: 10k sat per
# anchor channel, capped at 100k (see LND's AnchorChanReservedValue /
# maxAnchorChanReservedValue). An open that would leave the wallet below this
# reserve is rejected with "reserved wallet balance invalidated". The bootstrap
# loop keeps earlier (drained) channels open, so the reserve grows each round —
# capacity must leave room for the existing channels PLUS the one being opened,
# or round 2+ fails.
BOOTSTRAP_ANCHOR_RESERVE_PER_CHAN = 10_000
BOOTSTRAP_MAX_ANCHOR_RESERVE = 100_000


def _run_async(coro: Any) -> Any:
    """Run an async coroutine on a fresh event loop (Celery workers
    have no running loop)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        # Close the shared LND client on the loop it was created on, before we
        # tear that loop down. The lnd_service singleton caches an
        # httpx.AsyncClient bound to this loop; if we left it open it would be
        # reused on the next tick's (different) loop and raise "Event loop is
        # closed". A clean aclose() here also avoids leaking the connection pool.
        try:
            from app.services.lnd_service import lnd_service

            loop.run_until_complete(lnd_service.close())
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ─── Auto-resolution backstops (recovery plan §3) ─────────────────
#
# Two complementary mechanisms transition a wedged channel/round to a
# terminal state even when the user never clicks Cancel, so a single
# stuck run can't lock the one-active-run guard forever:
#
#   §3.1 confirmed-dead — precise, no false positives: a channel that
#        LND reports force-closing / waiting-close, or that has vanished
#        from both the active and pending-open sets, is genuinely gone.
#   §3.2 hard wall-clock backstop — per *waiting state* (not per run):
#        a single open/swap wait that blows ``CHANNEL_MIX_WAIT_HARD_TIMEOUT``
#        is failed even if §3.1 can't classify the stall.


async def _channel_confirmed_dead(channel_point: str) -> Optional[bool]:
    """Is the channel at ``channel_point`` (``txid:vout``) genuinely gone?

    Returns:
      * ``True``  — force-closing / waiting-close / pending-close, or
        absent from *both* the pending-open and active sets (abandoned).
      * ``False`` — still pending-open (merely slow) or active (alive).
      * ``None``  — can't tell right now (LND error) → caller retries.

    Matches by **channel point**, not pubkey, because repeat-peer
    multi-channel plans can hold several channels to one peer (recovery
    plan §3.1). Reads the pending view first, then the active set, so the
    pending-open → active transition (which momentarily could be read as
    absent if ordered the other way) can never be misclassified as dead.
    """
    from app.services.lnd_service import lnd_service

    pending, perr = await lnd_service.get_pending_channels_detail()
    if perr or not isinstance(pending, list):
        return None
    for pch in pending:
        if pch.get("channel_point") == channel_point:
            if pch.get("type") == "pending_open":
                return False  # still confirming — slow, not dead
            return True  # waiting_close / pending_close / force_closing

    active, aerr = await lnd_service.get_channels()
    if aerr or not isinstance(active, list):
        return None
    for ch in active:
        if ch.get("channel_point") == channel_point:
            return False  # present (active or merely inactive) — not dead

    # Absent from both the pending and active sets → the funding tx was
    # dropped/replaced or the channel fully closed: genuinely gone.
    return True


def _wait_hard_timed_out(since_iso: Optional[str], now: datetime) -> bool:
    """True once a single waiting state stamped at ``since_iso`` has blown
    the per-wait hard backstop (recovery plan §3.2)."""
    from app.services.channel_mix_planner import (
        CHANNEL_MIX_WAIT_HARD_TIMEOUT_MINUTES,
    )

    if not since_iso:
        return False
    try:
        since = datetime.fromisoformat(since_iso)
    except (TypeError, ValueError):
        return False
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    return (now - since).total_seconds() >= CHANNEL_MIX_WAIT_HARD_TIMEOUT_MINUTES * 60


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

    # connect_peer only initiates the connection; wait for it to actually land
    # before opening so OpenChannel doesn't race ahead and hit "peer not
    # online" (LND's ConnectPeer returns before the handshake completes).
    if not await _wait_peer_connected(pubkey):
        entry["open_state"] = "open_failed"
        entry["open_error"] = "connect failed: peer did not come online"[:512]
        if entry["seed_state"] == "queued":
            entry["seed_state"] = "skipped"
        run.channels[channel_idx] = entry
        await _audit_channel_open(
            db,
            run,
            entry,
            channel_idx,
            success=False,
            error_message="connect failed: peer did not come online",
        )
        return

    result, error = await lnd_service.open_channel(
        pubkey,
        capacity_sats,
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
    # Stamp the per-wait timer (recovery plan §3.2) and the funding vout so
    # the auto-resolution backstops can build this channel's channel point.
    entry["open_pending_since"] = _utc_now().isoformat()
    txid = result.get("funding_txid")
    if txid:
        entry["open_txid"] = str(txid)
    output_index = result.get("output_index")
    if output_index is not None:
        entry["open_output_index"] = int(output_index)
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


async def _resolve_stuck_parallel_channels(
    db, run: ChannelMixRun, *, skip_indices: "set[int] | None" = None
) -> None:
    """Fail any parallel channel wedged in ``open_pending`` that's either
    confirmed-dead (§3.1) or past the per-wait hard backstop (§3.2).

    Mutates ``run.channels`` in place; the caller's ``_rollup_state`` then
    rolls the run up to ``partial_failure`` (terminal), freeing the
    one-active-run guard without user action. A merely-slow channel (still
    in pending-open, within the backstop) is left untouched.

    ``skip_indices`` are channels opened on the current tick — skipped so a
    just-broadcast funding tx LND hasn't registered yet isn't mistaken for
    abandoned (checked next tick instead)."""
    skip = skip_indices or set()
    now = _utc_now()
    for idx, entry in enumerate(run.channels):
        if idx in skip:
            continue
        if entry.get("open_state") != "open_pending":
            continue
        # Only build a channel point when BOTH the txid and the funding
        # vout are known. A legacy row persisted before this feature has
        # no ``open_output_index`` — guessing vout 0 could match the wrong
        # output and mis-classify a healthy channel as gone, so skip the
        # confirmed-dead probe for those and let the hard timeout (which
        # is also absent on legacy rows → never fires) stay conservative.
        # Such a run is still force-cancellable by the user (recovery §1).
        channel_point = None
        oidx = entry.get("open_output_index")
        if entry.get("open_txid") and oidx is not None:
            channel_point = f"{entry['open_txid']}:{int(oidx)}"
        reason = None
        if channel_point:
            dead = await _channel_confirmed_dead(channel_point)
            if dead:
                reason = "the channel was force-closed or abandoned before it confirmed"
        if reason is None and _wait_hard_timed_out(entry.get("open_pending_since"), now):
            reason = "the channel didn't confirm within the safety window"
        if reason is None:
            continue
        entry["open_state"] = "open_failed"
        entry["open_error"] = reason[:512]
        # No channel means no seed step — settle the seed slot so the
        # rollup can reach a terminal state.
        if entry.get("seed_state") == "queued":
            entry["seed_state"] = "skipped"
        run.channels[idx] = entry
        run.warnings.append(
            f"Channel to {entry.get('peer_alias') or 'peer'}: stopped "
            f"automatically — {reason}."
        )


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


# ─── Bootstrap (capital-efficient inbound) executor ───────────────
#
# The bootstrap loop opens one channel, drains its outbound back on-chain
# via a Boltz reverse swap, waits for the claim to CONFIRM, then recycles
# the returned capital into the next open. Unlike the parallel path it is
# strictly sequential and settle-aware. See
# ``internal_docs/inbound_bootstrap_plan.md`` and
# ``braiins_deposit_service`` (whose open→swap→settle state machine this
# mirrors).


def _set_bootstrap_param(run: ChannelMixRun, key: str, value: Any) -> None:
    """Mutate one key of the plain-JSON ``bootstrap_params`` column.

    ``bootstrap_params`` is a plain ``JSON`` column (not a ``MutableDict``),
    so an in-place key set wouldn't be flushed — reassign the whole dict to
    flag the attribute dirty."""
    params = dict(run.bootstrap_params or {})
    if value is None:
        params.pop(key, None)
    else:
        params[key] = value
    run.bootstrap_params = params


def _bootstrap_flag_stuck_if_waiting(
    run: ChannelMixRun, entry: dict[str, Any], idx: int, what: str
) -> None:
    """Surface a non-fatal "taking longer than expected" note when a round
    has waited on a single confirmation past ``BOOTSTRAP_STUCK_MINUTES``.

    Lazily stamps ``waiting_since`` on first entry to a waiting state and
    never auto-fails or moves funds (plan §7.2). The note lives on
    ``run.error_message`` (cleared when the round advances)."""
    from app.services.channel_mix_planner import BOOTSTRAP_STUCK_MINUTES

    now = _utc_now()
    since_iso = entry.get("waiting_since")
    if not since_iso:
        entry["waiting_since"] = now.isoformat()
        run.channels[idx] = entry
        return
    try:
        since = datetime.fromisoformat(since_iso)
    except (TypeError, ValueError):
        return
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    if (now - since).total_seconds() >= BOOTSTRAP_STUCK_MINUTES * 60:
        run.error_message = (
            f"Round {entry.get('round_index')}: {what} is taking longer than "
            "expected to confirm — this can happen when fees are low. It will "
            "continue on its own; no action needed."
        )


def _bootstrap_clear_waiting(run: ChannelMixRun, entry: dict[str, Any]) -> None:
    """Reset the stuck timer + clear any stuck note when a round advances
    out of a waiting state."""
    if entry.get("waiting_since"):
        entry["waiting_since"] = None
    if run.error_message:
        run.error_message = None


def _bootstrap_switch_to_next_peer(run: ChannelMixRun, entry: dict[str, Any], reason: str) -> bool:
    """Mark the current peer tried and move the round to the next eligible
    peer (plan §7.5). Returns False when the catalog is exhausted (the
    caller then fails the round). Resets the per-peer connect counter."""
    tried = set(entry.get("tried_pubkeys") or [])
    tried.add(entry["peer_pubkey"])
    nxt = next(
        (p for p in _bootstrap_eligible_peers(run) if p.node_id_hex not in tried),
        None,
    )
    if nxt is None:
        return False
    entry["peer_pubkey"] = nxt.node_id_hex
    entry["peer_host"] = nxt.address
    entry["peer_alias"] = nxt.alias
    entry["tried_pubkeys"] = list(tried)
    entry["connect_attempts"] = 0
    entry["open_error"] = f"{reason}, trying {nxt.alias}"[:512]
    return True


async def _bootstrap_resolve_stuck_round(
    db, run: ChannelMixRun, entry: dict[str, Any], idx: int
) -> bool:
    """Auto-resolve a wedged in-flight bootstrap round (recovery plan §3).

    Fails the round (terminal for the round) when its channel is
    confirmed-dead — force-closed/abandoned, §3.1, which also closes the
    deferred force-close case §7.11 — or when its current wait has blown
    the per-wait hard backstop (§3.2). Returns True if the round was
    failed (the caller then stops advancing it; the run-level rollup turns
    it into ``partial_failure``).

    ``open_failed`` vs ``swap_failed`` is keyed on whether a drain swap was
    already created (``swap_id``): before the swap the channel never went
    productive (open_failed); after, the channel opened but couldn't be
    drained (swap_failed)."""
    now = _utc_now()
    channel_point = None
    if entry.get("open_txid"):
        channel_point = (
            f"{entry['open_txid']}:{int(entry.get('open_output_index') or 0)}"
        )

    reason = None
    if channel_point:
        dead = await _channel_confirmed_dead(channel_point)
        if dead:
            reason = "the channel was force-closed or abandoned before the round finished"
    if reason is None and _wait_hard_timed_out(entry.get("waiting_since"), now):
        reason = "the round didn't confirm within the safety window"
    if reason is None:
        return False

    fail_state = "swap_failed" if entry.get("swap_id") else "open_failed"
    _bootstrap_clear_waiting(run, entry)
    entry["state"] = fail_state
    if fail_state == "swap_failed":
        entry["swap_error"] = reason[:512]
    else:
        entry["open_error"] = reason[:512]
    run.channels[idx] = entry
    run.warnings.append(
        f"Round {entry.get('round_index')}: stopped automatically — {reason}."
    )
    return True


def _bootstrap_inflight_index(run: ChannelMixRun) -> int | None:
    """Index of the single non-terminal round, or None if every round is
    terminal (settled / failed). The loop is sequential so there is at
    most one in-flight round."""
    for i, entry in enumerate(run.channels):
        if entry.get("state") not in BOOTSTRAP_ROUND_TERMINAL_STATES:
            return i
    return None


def _bootstrap_settled_count(run: ChannelMixRun) -> int:
    return sum(1 for e in run.channels if e.get("state") == "settled")


def _bootstrap_target_reached(run: ChannelMixRun) -> bool:
    target = run.target_inbound_sats
    return target is not None and int(run.realized_inbound_sats or 0) >= int(target)


def _bootstrap_duration_exceeded(run: ChannelMixRun, now: datetime) -> bool:
    from app.services.channel_mix_planner import BOOTSTRAP_MAX_DURATION_MINUTES

    started = run.started_at
    if started is None:
        return False
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return (now - started).total_seconds() >= BOOTSTRAP_MAX_DURATION_MINUTES * 60


def _bootstrap_awaiting_timed_out(run: ChannelMixRun, now: datetime) -> bool:
    """True once the wallet has sat in AWAITING_FUNDS past the tolerance
    window (the recyclable balance never recovered)."""
    from app.services.channel_mix_planner import (
        BOOTSTRAP_AWAITING_FUNDS_TIMEOUT_MINUTES,
    )

    since_iso = (run.bootstrap_params or {}).get("awaiting_since")
    if not since_iso:
        return False
    try:
        since = datetime.fromisoformat(since_iso)
    except (TypeError, ValueError):
        return False
    if since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    return (now - since).total_seconds() >= BOOTSTRAP_AWAITING_FUNDS_TIMEOUT_MINUTES * 60


async def _bootstrap_feerate_sat_vb() -> float:
    """Medium-priority feerate for sizing the open fee, with a
    conservative fallback when the mempool oracle is unreachable."""
    from app.services.channel_mix_planner import FALLBACK_SAT_PER_VB

    try:
        from app.services.mempool_fee_service import mempool_fee_service

        fees, err = await mempool_fee_service.get_recommended_fees()
        if fees and not err:
            v = fees.get("halfHourFee") or fees.get("hourFee")
            if isinstance(v, (int, float)) and v > 0:
                return float(v)
    except Exception:  # noqa: BLE001
        pass
    return float(FALLBACK_SAT_PER_VB)


def _bootstrap_eligible_peers(run: ChannelMixRun):
    """Re-derive the ordered eligible peer pool from the stored
    selection inputs (the schedule isn't pre-materialized).

    Seeds the weighted-random selection identically to plan time
    (``secret_key`` + the stored selection inputs), so every tick — and
    the original plan — reproduce the same provider order."""
    from app.core.config import settings
    from app.services.channel_mix_planner import peer_selection_seed, select_peers

    params = run.bootstrap_params or {}
    network = params.get("network", "mainnet")
    peer_mix_mode = params.get("peer_mix_mode", "recommended_diverse")
    manual_picks = tuple(params.get("manual_picks") or ())
    include_marginal = bool(params.get("include_marginal_routing"))
    seed = peer_selection_seed(
        secret=settings.secret_key,
        network=network,
        peer_mix_mode=peer_mix_mode,
        manual_picks=manual_picks,
        include_marginal_routing=include_marginal,
    )
    peers, _axes = select_peers(
        network=network,
        channel_count=64,  # large: we want the full ordered pool, not a cap
        mode=peer_mix_mode,
        manual_picks=manual_picks,
        include_marginal_routing=include_marginal,
        rng_seed=seed,
    )
    return peers


def _bootstrap_next_peer(run: ChannelMixRun, round_index: int):
    """Round-robin pick across the eligible pool (spread first, then
    repeat — plan §11.2). Returns None when no peer is eligible."""
    peers = _bootstrap_eligible_peers(run)
    if not peers:
        return None
    return peers[round_index % len(peers)]


async def _wait_peer_connected(pubkey: str) -> bool:
    """Poll ListPeers until ``pubkey`` shows as connected, up to
    ``BOOTSTRAP_PEER_CONNECT_WAIT_POLLS`` times (1s apart).

    connect_peer is asynchronous — it returns "connection … initiated"
    before the handshake finishes — so opening a channel immediately after
    races the connection and LND rejects it with "peer … is not online".
    A short in-tick wait closes that window (the connect completes in ~1s).
    Returns True once the peer is connected, False if it never appears
    within the budget (the caller then treats it as a transient connect
    failure and retries/escalates). A ListPeers error is treated as
    "not yet" and retried — never a hard failure."""
    from app.services.lnd_service import lnd_service

    for attempt in range(BOOTSTRAP_PEER_CONNECT_WAIT_POLLS):
        pubs, err = await lnd_service.list_peer_pubkeys()
        if not err and pubs is not None and pubkey in pubs:
            return True
        # Don't sleep after the final probe.
        if attempt < BOOTSTRAP_PEER_CONNECT_WAIT_POLLS - 1:
            await asyncio.sleep(1.0)
    return False


async def _advance_bootstrap_round(db, run: ChannelMixRun, idx: int) -> None:
    """Advance one bootstrap round by a single chain-observable step.

    Mutates ``run.channels[idx]`` in place + re-assigns it (to flag the
    MutableList dirty); the caller commits. Run-level finalization
    (start next round / stop) is the caller's job — this only drives the
    per-round state machine and updates the run's running totals on
    settle."""
    from app.services.boltz_service import boltz_service
    from app.services.channel_mix_planner import (
        BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS,
        BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS,
        BOOTSTRAP_ROUTING_FEE_PCT,
    )
    from app.services.lnd_service import lnd_service

    entry = run.channels[idx]
    state = entry.get("state")

    # ── opening: connect + open (idempotent on open_txid) ──
    if state == "opening":
        if entry.get("open_txid"):
            entry["state"] = "open_pending"
            run.channels[idx] = entry
            return

        sat_per_vb = await _bootstrap_feerate_sat_vb()

        _ok, conn_err = await lnd_service.connect_peer(
            entry["peer_pubkey"], entry["peer_host"]
        )
        if conn_err and "already connected" not in str(conn_err).lower():
            # Connect failure = transient (peer briefly offline) — retry a
            # bounded number of ticks, then escalate to the next peer so a
            # permanently-down peer can't wedge the round (plan §7.5 + §7).
            attempts = int(entry.get("connect_attempts", 0)) + 1
            entry["connect_attempts"] = attempts
            if attempts < BOOTSTRAP_MAX_CONNECT_ATTEMPTS:
                entry["open_error"] = f"connect (retry {attempts}): {conn_err}"[:512]
                run.channels[idx] = entry
                return
            if not _bootstrap_switch_to_next_peer(run, entry, f"peer unreachable ({conn_err})"):
                entry["state"] = "open_failed"
                entry["open_error"] = f"connect: {conn_err}"[:512]
                run.channels[idx] = entry
                await _audit_channel_open(
                    db, run, _bootstrap_audit_entry(entry), idx,
                    success=False, error_message=f"connect: {conn_err}",
                )
                return
            run.channels[idx] = entry
            return

        # connect_peer only *initiates* the connection (LND returns before the
        # handshake completes), so wait until the peer is actually connected
        # before opening — otherwise OpenChannel races ahead and is rejected
        # with "peer … is not online". If it never comes online within the
        # in-tick budget, treat it exactly like a connect failure: retry a
        # bounded number of ticks, then escalate to the next peer (§7.5).
        if not await _wait_peer_connected(entry["peer_pubkey"]):
            attempts = int(entry.get("connect_attempts", 0)) + 1
            entry["connect_attempts"] = attempts
            if attempts < BOOTSTRAP_MAX_CONNECT_ATTEMPTS:
                entry["open_error"] = (
                    f"connect (retry {attempts}): peer did not come online"
                )[:512]
                run.channels[idx] = entry
                return
            if not _bootstrap_switch_to_next_peer(
                run, entry, "peer did not come online"
            ):
                entry["state"] = "open_failed"
                entry["open_error"] = "connect: peer did not come online"[:512]
                run.channels[idx] = entry
                await _audit_channel_open(
                    db, run, _bootstrap_audit_entry(entry), idx,
                    success=False, error_message="connect: peer did not come online",
                )
                return
            run.channels[idx] = entry
            return

        result, open_err = await lnd_service.open_channel(
            entry["peer_pubkey"],
            int(entry["capacity_sats"]),
            sat_per_vbyte=max(1, int(sat_per_vb)),
            push_sat=0,
        )
        if open_err or not result or not result.get("funding_txid"):
            # "peer not online" right after a successful connect is a transient
            # LND race: the funding manager's connected-peer set can lag the
            # ConnectPeer RPC return by a moment, so the immediately-following
            # OpenChannel is rejected even though the peer is reachable. Retry
            # the SAME peer a bounded number of ticks (reusing the per-peer
            # connect counter, which _bootstrap_switch_to_next_peer resets)
            # before escalating — otherwise every fresh-connection open trips
            # this and the round burns through the whole peer catalog for
            # nothing. Mirrors the connect-retry policy (plan §7.5).
            err_text = str(open_err or "").lower()
            if open_err and "reserved wallet balance" in err_text:
                # LND's anchor-channel reserve grew (earlier drained channels
                # stay open), so this round's baked capacity now leaves too
                # little on-chain. The error is wallet-level, NOT peer-specific,
                # so cycling peers is futile — shrink capacity by one
                # anchor-reserve unit and retry the SAME peer, bounded, until it
                # fits or would drop below the per-channel floor.
                from app.services.channel_mix_planner import PER_CHANNEL_FLOOR_SATS

                shrinks = int(entry.get("reserve_shrink_attempts", 0)) + 1
                entry["reserve_shrink_attempts"] = shrinks
                new_cap = (
                    int(entry.get("capacity_sats", 0))
                    - BOOTSTRAP_ANCHOR_RESERVE_PER_CHAN
                )
                max_shrinks = (
                    BOOTSTRAP_MAX_ANCHOR_RESERVE // BOOTSTRAP_ANCHOR_RESERVE_PER_CHAN
                )
                if new_cap >= PER_CHANNEL_FLOOR_SATS and shrinks <= max_shrinks:
                    entry["capacity_sats"] = new_cap
                    entry["open_error"] = (
                        f"resizing for LND anchor reserve (retry {shrinks})"
                    )[:512]
                    run.channels[idx] = entry
                    return
                # Can't fit even at the floor — fail the round cleanly rather
                # than cycle peers that will all hit the same wallet reserve.
                entry["state"] = "open_failed"
                entry["open_error"] = f"open: {open_err}"[:512]
                run.channels[idx] = entry
                await _audit_channel_open(
                    db, run, _bootstrap_audit_entry(entry), idx,
                    success=False, error_message=f"open: {open_err}",
                )
                return
            if open_err and ("not online" in err_text or "not connected" in err_text):
                attempts = int(entry.get("connect_attempts", 0)) + 1
                entry["connect_attempts"] = attempts
                if attempts < BOOTSTRAP_MAX_CONNECT_ATTEMPTS:
                    entry["open_error"] = (
                        f"open (retry {attempts}): peer not online yet"
                    )[:512]
                    run.channels[idx] = entry
                    return
            # Hard, pre-broadcast (no funds moved): try the next eligible
            # peer for this round (plan §7.5), else fail the round.
            if not _bootstrap_switch_to_next_peer(
                run, entry, f"open rejected ({open_err or 'no funding_txid'})"
            ):
                entry["state"] = "open_failed"
                entry["open_error"] = f"open: {open_err or 'no funding_txid'}"[:512]
                run.channels[idx] = entry
                await _audit_channel_open(
                    db, run, _bootstrap_audit_entry(entry), idx,
                    success=False, error_message=f"open: {open_err}",
                )
                return
            run.channels[idx] = entry
            return

        entry["open_txid"] = result["funding_txid"]
        entry["open_output_index"] = int(result.get("output_index", 0) or 0)
        entry["state"] = "open_pending"
        entry["open_error"] = None
        run.channels[idx] = entry
        # Persist the funding txid immediately — the open-idempotency guard
        # (top of this branch) is only durable once committed, so a crash
        # before the tick's final commit must not lose it and re-broadcast
        # a second funding tx (mirrors Braiins ``channel_open_txid``;
        # double-opening would double-spend the recyclable capital). Safe
        # to commit mid-tick: sessions are ``expire_on_commit=False`` and a
        # concurrent tick that grabs the row now just sees ``open_pending``.
        await db.commit()
        await _audit_channel_open(
            db, run, _bootstrap_audit_entry(entry), idx, success=True
        )
        return

    # ── open_pending: poll until the channel is active ──
    if state == "open_pending":
        channel_point = f"{entry.get('open_txid')}:{int(entry.get('open_output_index') or 0)}"
        is_active, _ch, err = await lnd_service.channel_is_active(channel_point)
        if err is not None:
            return  # transient LND error — retry next tick
        if not is_active:
            _bootstrap_flag_stuck_if_waiting(run, entry, idx, "the channel open")
            await _bootstrap_resolve_stuck_round(db, run, entry, idx)
            return  # still confirming (or just auto-failed)
        _bootstrap_clear_waiting(run, entry)
        entry["state"] = "open_active"
        run.channels[idx] = entry
        return

    # ── open_active: size the drain from the LIVE channel + create swap ──
    if state == "open_active":
        channels, err = await lnd_service.get_channels()
        if err or not isinstance(channels, list):
            return  # transient
        match = None
        for ch in channels:
            if (ch.get("remote_pubkey") or "").lower() == (
                entry["peer_pubkey"] or ""
            ).lower() and ch.get("active"):
                match = ch
                break
        if match is None:
            # The channel was active (we reached open_active) but isn't in
            # the active set now — a transient race, OR it force-closed
            # mid-round. Stamp the per-wait timer and let the backstops
            # decide; a transient race clears on the next tick.
            _bootstrap_flag_stuck_if_waiting(run, entry, idx, "the channel open")
            await _bootstrap_resolve_stuck_round(db, run, entry, idx)
            return  # not active yet (race) — retry

        local = int(match.get("local_balance", 0) or 0)
        reserve = int(match.get("local_chan_reserve_sat", 0) or 0)
        commit = int(match.get("commit_fee", 0) or 0)
        unsettled = int(match.get("unsettled_balance", 0) or 0)
        chan_id = str(match.get("chan_id") or "")
        drainable = max(0, local - reserve - commit - unsettled)
        drain = int(drainable / (1.0 + BOOTSTRAP_ROUTING_FEE_PCT))
        drain = min(drain, BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS)

        if drain < BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS:
            # The live channel can't be drained by swap (below Boltz min).
            # The channel is fine (100% outbound, usable) but this round
            # builds no inbound. Settle it as a no-op and let the run-level
            # logic stop cleanly.
            entry["expected_inbound_sats"] = 0
            entry["recycled_sats"] = 0
            entry["swap_error"] = "drainable below Boltz minimum — channel kept as outbound"
            entry["state"] = "settled"
            run.channels[idx] = entry
            run.warnings.append(
                f"Round {entry.get('round_index')}: channel opened but its drainable "
                "amount fell below the Boltz minimum — kept as outbound."
            )
            run.total_fees_sats = int(run.total_fees_sats or 0) + int(
                entry.get("open_fee_sats") or 0
            )
            return

        addr_result, addr_err = await lnd_service.new_address(address_type="p2wkh")
        if addr_err or not isinstance(addr_result, dict) or not addr_result.get("address"):
            return  # transient — retry next tick
        destination = addr_result["address"]

        swap_row, swap_err = await boltz_service.create_reverse_swap(
            db=db,
            api_key_id=run.api_key_id,
            invoice_amount_sats=drain,
            destination_address=destination,
            outgoing_chan_id=chan_id,  # pin the drain to the new channel
        )
        if swap_err or swap_row is None:
            attempts = int(entry.get("swap_attempts", 0)) + 1
            entry["swap_attempts"] = attempts
            if attempts >= BOOTSTRAP_MAX_SWAP_ATTEMPTS:
                entry["state"] = "swap_failed"
                entry["swap_error"] = f"create swap: {swap_err or 'no swap'}"[:512]
            else:
                entry["swap_error"] = f"create swap (retry {attempts}): {swap_err}"[:512]
            run.channels[idx] = entry
            return

        entry["swap_id"] = str(swap_row.id)
        entry["drain_target_sats"] = drain
        entry["expected_inbound_sats"] = drain
        entry["state"] = "swap_pending"
        entry["swap_error"] = None
        entry["waiting_since"] = None  # fresh stuck-timer for the swap wait
        run.channels[idx] = entry
        # Persist the swap link immediately — the swap-idempotency guard
        # (never create a second reverse swap for a round that has a
        # ``swap_id``, plan §8) is only durable once committed. A crash
        # before the tick's final commit must not lose it and re-create a
        # second swap on resume (which would drain the channel twice).
        await db.commit()

        # Drive the LN payment + claim via the existing Boltz task.
        try:
            from app.tasks.boltz_tasks import process_boltz_swap

            process_boltz_swap.delay(str(swap_row.id))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "bootstrap: couldn't enqueue process_boltz_swap for %s: %s "
                "(boltz recovery beat will pick it up)",
                swap_row.id,
                exc,
            )
        return

    # ── swap_pending: wait for the claim to CONFIRM (the recycle gate) ──
    if state == "swap_pending":
        from app.models.boltz_swap import BoltzSwap, SwapStatus

        swap_id = entry.get("swap_id")
        if not swap_id:
            entry["state"] = "open_active"  # lost the link — re-create swap
            run.channels[idx] = entry
            return
        swap = (
            await db.execute(select(BoltzSwap).where(BoltzSwap.id == UUID(swap_id)))
        ).scalar_one_or_none()
        if swap is None:
            entry["state"] = "open_active"
            entry["swap_id"] = None
            run.channels[idx] = entry
            return

        # Surface the drain swap's on-chain txids live so the round card can
        # link them in the mempool explorer *while they confirm* (Boltz's
        # lockup and our claim/recycle sweep), not only after settle.
        if getattr(swap, "lockup_txid", None):
            entry["swap_lockup_txid"] = swap.lockup_txid
        if getattr(swap, "claim_txid", None):
            entry["swap_claim_txid"] = swap.claim_txid
        run.channels[idx] = entry

        if swap.status == SwapStatus.COMPLETED and swap.claim_txid:
            # Claim confirmed on-chain (COMPLETED already requires the
            # claim tx to have its confirmations — see boltz advance_swap).
            recycled = int(swap.onchain_amount_sats or 0)
            drain = int(entry.get("expected_inbound_sats") or 0)
            swap_fee = max(0, drain - recycled)
            entry["swap_claim_txid"] = swap.claim_txid
            entry["recycled_sats"] = recycled
            entry["swap_error"] = None
            _bootstrap_clear_waiting(run, entry)
            entry["state"] = "settled"
            run.channels[idx] = entry
            run.realized_inbound_sats = int(run.realized_inbound_sats or 0) + drain
            run.total_fees_sats = (
                int(run.total_fees_sats or 0)
                + int(entry.get("open_fee_sats") or 0)
                + swap_fee
            )
            return

        if swap.status in (
            SwapStatus.FAILED,
            SwapStatus.CANCELLED,
            SwapStatus.REFUNDED,
        ):
            # The LN payment couldn't route out the new channel, or Boltz
            # refunded its lockup — no funds moved for us, no inbound this
            # round. Bounded retry (a fresh channel often needs a moment
            # for gossip/pathfinding), then give up on the round.
            attempts = int(entry.get("swap_attempts", 0)) + 1
            entry["swap_attempts"] = attempts
            _bootstrap_clear_waiting(run, entry)
            if attempts >= BOOTSTRAP_MAX_SWAP_ATTEMPTS:
                entry["state"] = "swap_failed"
                entry["swap_error"] = f"drain failed ({swap.status.value})"[:512]
            else:
                # Re-create a swap on the next tick.
                entry["state"] = "open_active"
                entry["swap_id"] = None
                entry["swap_error"] = (
                    f"drain attempt {attempts} failed ({swap.status.value}); retrying"
                )[:512]
            run.channels[idx] = entry
            return

        # Still in flight (paying / claiming) — stay, flag if slow, poll.
        _bootstrap_flag_stuck_if_waiting(run, entry, idx, "the swap claim")
        await _bootstrap_resolve_stuck_round(db, run, entry, idx)
        return


def _bootstrap_audit_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Project a bootstrap round onto the flat shape ``_audit_channel_open``
    expects (it reads ``capacity_sats``, ``push_sat``, ``peer_*``,
    ``open_txid``)."""
    return {
        "peer_alias": entry.get("peer_alias"),
        "peer_pubkey": entry.get("peer_pubkey"),
        "peer_host": entry.get("peer_host"),
        "capacity_sats": int(entry.get("capacity_sats") or 0),
        "push_sat": 0,
        "open_txid": entry.get("open_txid"),
    }


async def _bootstrap_maybe_start_round(db, run: ChannelMixRun) -> None:
    """No round is in flight — decide whether to start a new one or
    finalize the run. Applies all the stop conditions + the chain-truth
    balance re-check (plan §6) before opening."""
    from app.services.channel_mix_planner import (
        BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS,
        BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS,
        BOOTSTRAP_HEADROOM_SATS,
        BOOTSTRAP_MAX_ROUNDS,
        PER_CHANNEL_FLOOR_SATS,
        bootstrap_capacity_cap,
        bootstrap_drain_for_capacity,
    )
    from app.services.channel_mix_planner import _open_fee_sats
    from app.services.lnd_service import lnd_service

    now = _utc_now()
    settled = _bootstrap_settled_count(run)

    # ── Stop conditions ──
    if run.stop_requested:
        # Cooperative cancel (plan §7.10): the in-flight round was allowed
        # to settle (this branch only runs when no round is in flight); we
        # finalize CANCELLED rather than COMPLETE so the run records that
        # the user stopped it early, not that it ran to its natural end.
        finalize_run(run, ChannelMixRunState.CANCELLED)
        run.warnings.append("Stopped after the current round at your request.")
        return
    if _bootstrap_target_reached(run):
        finalize_run(run, ChannelMixRunState.COMPLETE)
        return
    if settled >= BOOTSTRAP_MAX_ROUNDS:
        finalize_run(run, ChannelMixRunState.COMPLETE)
        run.warnings.append(f"Reached the {BOOTSTRAP_MAX_ROUNDS}-round cap.")
        return
    if _bootstrap_duration_exceeded(run, now):
        finalize_run(run, ChannelMixRunState.COMPLETE)
        run.warnings.append("Reached the maximum run duration.")
        return

    # ── Capital re-check from chain truth (plan §6) ──
    bal, err = await lnd_service.get_wallet_balance()
    if err or bal is None:
        run.state = ChannelMixRunState.IN_PROGRESS  # transient — retry
        return
    confirmed = int(bal.get("confirmed_balance", 0) or 0)
    sat_per_vb = await _bootstrap_feerate_sat_vb()
    open_fee = _open_fee_sats(1, sat_per_vb)
    # Reserve for LND's anchor-channel fee-bump reserve. It already holds
    # ``reserved_balance_anchor_chan`` for the existing channels; opening one
    # more needs another 10k (capped at 100k total). Leaving only the fixed
    # headroom worked for the first channel but fails from round 2 on, since
    # the earlier drained channels stay open and keep counting toward the
    # reserve ("reserved wallet balance invalidated").
    current_reserved = int(bal.get("reserved_balance_anchor_chan", 0) or 0)
    anchor_reserve = min(
        current_reserved + BOOTSTRAP_ANCHOR_RESERVE_PER_CHAN,
        BOOTSTRAP_MAX_ANCHOR_RESERVE,
    )
    headroom = max(BOOTSTRAP_HEADROOM_SATS, anchor_reserve)
    capacity = confirmed - open_fee - headroom
    # Cap so this round's drainable doesn't exceed the Boltz max — the
    # excess would strand as un-recyclable outbound. Leftover confirmed
    # balance stays on-chain and funds the next round (matches the
    # planner's estimate; plan §2).
    capacity = min(capacity, bootstrap_capacity_cap(BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS))

    if capacity < PER_CHANNEL_FLOOR_SATS:
        if settled == 0:
            finalize_run(run, ChannelMixRunState.STOPPED_INSUFFICIENT)
            run.warnings.append(
                "Not enough confirmed on-chain balance to open the first channel "
                f"(need ~{PER_CHANNEL_FLOOR_SATS + open_fee:,} sats)."
            )
            return
        # Transient: the prior swap's claim may still be confirming, or
        # the user may top up. Enter / stay AWAITING_FUNDS until timeout.
        if _bootstrap_awaiting_timed_out(run, now):
            finalize_run(run, ChannelMixRunState.STOPPED_INSUFFICIENT)
            run.warnings.append(
                "Stopped — recyclable balance stayed below the next channel for too long."
            )
            return
        if run.state != ChannelMixRunState.AWAITING_FUNDS:
            _set_bootstrap_param(run, "awaiting_since", now.isoformat())
        run.state = ChannelMixRunState.AWAITING_FUNDS
        return

    # Left AWAITING_FUNDS behind — clear the timer.
    if (run.bootstrap_params or {}).get("awaiting_since"):
        _set_bootstrap_param(run, "awaiting_since", None)

    drain_est = bootstrap_drain_for_capacity(
        capacity, boltz_max=BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS
    )
    if drain_est < BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS:
        # The remaining balance is too small to drain by swap. Stop cleanly
        # and leave it on-chain (spendable) rather than opening a channel we
        # can't recycle.
        finalize_run(run, ChannelMixRunState.COMPLETE)
        run.warnings.append(
            "Reached the practical limit — the remaining balance can't be "
            "drained by swap."
        )
        return

    peer = _bootstrap_next_peer(run, settled)
    if peer is None:
        finalize_run(run, ChannelMixRunState.COMPLETE)
        run.warnings.append("No eligible peer available to open another channel.")
        return

    entry = make_bootstrap_round_entry(
        round_index=settled,
        peer_alias=peer.alias,
        peer_pubkey=peer.node_id_hex,
        peer_host=peer.address,
        capacity_sats=capacity,
        drain_target_sats=drain_est,
        spendable_before_sats=confirmed,
        state="opening",
    )
    entry["open_fee_sats"] = open_fee
    run.channels.append(entry)
    run.state = ChannelMixRunState.IN_PROGRESS

    # Do the open now (idempotent) so a tick makes real progress.
    await _advance_bootstrap_round(db, run, len(run.channels) - 1)
    if run.channels[-1].get("state") == "open_failed":
        finalize_run(run, ChannelMixRunState.PARTIAL_FAILURE)


async def _advance_bootstrap(db, run: ChannelMixRun) -> None:
    """One tick of the bootstrap loop: advance the in-flight round one
    step, or (if none) start the next round / finalize the run."""
    idx = _bootstrap_inflight_index(run)
    if idx is not None:
        await _advance_bootstrap_round(db, run, idx)
        if _bootstrap_inflight_index(run) is not None:
            run.state = ChannelMixRunState.IN_PROGRESS
            return
        # The round finished this tick.
        last = run.channels[-1]
        if last.get("state") in ("open_failed", "swap_failed"):
            finalize_run(run, ChannelMixRunState.PARTIAL_FAILURE)
            return
        # Settled — fall through and try to start the next round.
    await _bootstrap_maybe_start_round(db, run)


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
        if run.state in TERMINAL_RUN_STATES:
            return {"status": str(run.state.value), "mode": run.mode}

        run.updated_at = _utc_now()

        # Bootstrap runs use the sequential settle-aware driver; the
        # parallel path below is untouched.
        if run.mode == "bootstrap":
            await _advance_bootstrap(db, run)
            await db.commit()
            return {"status": str(run.state.value), "mode": "bootstrap"}

        # In-memory state transition; commit happens once at the end so
        # the row lock stays held through the per-channel work.
        run.state = ChannelMixRunState.IN_PROGRESS

        # 1) Open queued channels. Track the indices opened on *this* tick
        #    so the auto-resolution step can skip them: LND may not have
        #    registered a just-broadcast funding tx yet, which would read
        #    as "abandoned" and false-fail a brand-new channel. They're
        #    checked on the next tick instead.
        opened_this_tick: set[int] = set()
        for idx in range(len(run.channels)):
            if run.channels[idx]["open_state"] == "queued":
                await _open_one_channel(db, run, idx)
                opened_this_tick.add(idx)

        # 2) Promote open_pending → open_active where confirmation has
        #    landed.
        await _refresh_open_pending_states(db, run)

        # 2b) Auto-resolve channels wedged in open_pending — confirmed
        #     force-closed/abandoned, or past the per-wait hard backstop
        #     (recovery plan §3) — so a stuck open can't pin the guard.
        #     Runs AFTER refresh so a channel that has actually gone active
        #     is already promoted out of open_pending (and thus never
        #     hard-timeout-failed despite a successful open); and skips
        #     channels opened this very tick (see step 1).
        await _resolve_stuck_parallel_channels(
            db, run, skip_indices=opened_this_tick
        )

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
            if new_state in (ChannelMixRunState.COMPLETE, ChannelMixRunState.PARTIAL_FAILURE):
                finalize_run(run, new_state)
            else:
                run.state = new_state
        run.updated_at = _utc_now()

        # Single commit at the end — releases the row lock and flushes
        # every per-channel transition the tick made.
        await db.commit()
        return {"status": str(run.state.value), "mode": run.mode}


@celery_app.task(
    bind=True,
    name="process_channel_mix_run",
    max_retries=200,
)
@track_task("process_channel_mix_run")
def process_channel_mix_run(self, run_id: str) -> dict[str, Any]:
    """Drive one channel-mix run forward.

    Parallel runs retry with a constant backoff until terminal; the
    per-channel state machine ensures each retry only advances work that
    hasn't completed yet.

    Bootstrap runs do NOT self-retry. A bootstrap run can span hours
    (each round ≈ open confirmations + claim confirmation), which exceeds
    any sane self-retry budget, so a tick advances the run as far as
    chain state allows and then exits; the periodic
    ``recover_channel_mix_runs`` beat re-enqueues it each cycle (plan §4).
    """
    try:
        result: dict[str, Any] = _run_async(_run_one_mix(UUID(run_id)))
    except Exception:  # noqa: BLE001
        logger.exception("channel-mix executor: tick failed for %s", run_id)
        raise self.retry(countdown=30)
    terminal = ("complete", "partial_failure", "cancelled", "stopped_insufficient")
    if result.get("status") in terminal:
        return result
    if result.get("mode") == "bootstrap":
        # Non-terminal bootstrap tick — the recover beat drives the long
        # haul (open/claim confirmations take minutes), so we exit rather
        # than burning the retry budget on a multi-hour run.
        return result
    # Parallel run still in progress — re-queue.
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
                        # Bootstrap runs waiting for the recyclable balance
                        # to recover (e.g. a swap claim still confirming).
                        ChannelMixRunState.AWAITING_FUNDS,
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
