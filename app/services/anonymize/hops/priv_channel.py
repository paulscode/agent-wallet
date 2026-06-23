# SPDX-License-Identifier: MIT
"""priv_channel hop — open + push + cooperative-close.

Drives the wallet through the throwaway private-channel hop:

1. **Open** (``HOPPING``): pick an auto-selected peer via
   :func:`peer_selection.select_auto_peer` honoring the
   blocklist + cooldown, then open an unannounced
   ``private=true`` channel with ``option_scid_alias`` so the
   funding outpoint stays out of the public gossip graph.
2. **Push** (``HOPPING``): once the channel is active, push the
   binned amount to the peer as an HTLC payment that routes
   through them to the next hop in the pipeline.
3. **Cooperative close** (``AWAITING_CHANNEL_CLOSE``): after a
   randomized 2–24 h delay throwaway-channel lifecycle,
   issue a cooperative close. ``force_close`` is NEVER automated
   here — the per-session loop surfaces the channel for operator
   intervention if the cooperative close times out.

The hop is idempotent: every external side-effect is bracketed by
``hop_attempt_started`` / ``hop_attempt_completed`` events so a
crash mid-step lets the next tick read persisted state and resume.

Production wires the adapters in :class:`PrivChannelHopDeps` to
live ``LNDService.open_channel`` / ``send_payment_v2`` /
``close_channel`` (cooperative-only). Tests inject mocks so the
hop body runs entirely without live LND.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.anonymize_session import AnonymizeSession, AnonymizeStatus

from ..hop_idempotency import (
    HopAttemptKey,
    has_hop_attempt_completed,
    make_hop_idempotency_key,
    record_hop_attempt_completed,
    record_hop_attempt_started,
)
from ..metadata import ANONYMIZE_LOGGER_NAME

logger = logging.getLogger(ANONYMIZE_LOGGER_NAME)


@dataclass
class PrivChannelHopDeps:
    """Adapters the priv_channel hop body calls into.

    Each returns ``(result, error)`` so the hop body records outcomes
    without raising into the per-session loop's retry budget.
    """

    # Auto-peer selection — returns a chosen :class:`PeerCandidate`
    # or None when no eligible peer exists.
    select_auto_peer: Callable[..., Awaitable[tuple[Any, Any]]]
    # LND ``open_channel`` with ``private=True, option_scid_alias=True``.
    # Returns ``(channel_point, error)`` — channel_point is the funding
    # outpoint string ``txid:vout``.
    lnd_open_private_channel: Callable[..., Awaitable[tuple[Any, Any]]]
    # LND ``list_channels`` or a per-channel state query that returns
    # whether the channel is ``active``. Returns ``(is_active, error)``.
    lnd_channel_is_active: Callable[..., Awaitable[tuple[Any, Any]]]
    # LND ``send_payment_v2`` to push HTLC across the channel.
    lnd_send_payment_through_channel: Callable[..., Awaitable[tuple[Any, Any]]]
    # LND ``close_channel`` with ``force=False`` (cooperative only).
    lnd_close_channel_cooperative: Callable[..., Awaitable[tuple[Any, Any]]]


@dataclass(frozen=True)
class PrivChannelHopOutcome:
    """Result of one priv_channel-hop step."""

    kind: str  # 'noop' | 'opened_channel' | 'pushed_payment' |
    # 'close_scheduled' | 'close_broadcast' | 'error'
    detail: str = ""


_NOOP = PrivChannelHopOutcome(kind="noop")


def _key_for(
    session: AnonymizeSession,
    hop_kind: str,
    attempt: int,
) -> HopAttemptKey:
    import hashlib

    sid_bytes = (
        session.id.bytes
        if hasattr(session.id, "bytes")
        else hashlib.blake2b(
            str(session.id).encode("utf-8"),
            digest_size=16,
        ).digest()
    )
    stable_nonce = hashlib.blake2b(
        b"%s|%s|%d" % (sid_bytes, hop_kind.encode("utf-8"), attempt),
        digest_size=16,
    ).digest()
    key_str = make_hop_idempotency_key(
        key_bytes=b"\x00" * 32,
        nonce=stable_nonce,
        session_id=sid_bytes,
        hop_index=0,
        hop_kind=hop_kind,
        attempt=attempt,
    )
    return HopAttemptKey(
        session_id=session.id,
        hop_index=0,
        hop_kind=hop_kind,
        attempt=attempt,
        idempotency_key=key_str,
        nonce=stable_nonce,
        key_generation=0,
    )


def sample_close_delay_s(rng: secrets.SystemRandom | None = None) -> float:
    """Sample a uniform-random close delay in 2–24 h."""
    rng = rng or secrets.SystemRandom()
    lo = int(settings.anonymize_throwaway_channel_close_delay_min_s)
    hi = int(settings.anonymize_throwaway_channel_close_delay_max_s)
    if hi < lo:
        return float(lo)
    return rng.uniform(float(lo), float(hi))


async def execute_priv_channel_hop_step(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: PrivChannelHopDeps,
) -> PrivChannelHopOutcome:
    """One per-session tick of the priv_channel-hop body.

    Dispatches on the session's current status. Each step is
    idempotent: a crash mid-step lets the next tick read persisted
    state and resume without re-issuing side effects.
    """
    if session.status == AnonymizeStatus.HOPPING.value:
        pj = session.pipeline_json or {}
        if not pj.get("priv_channel_id"):
            return await _step_open_channel(db, session, deps)
        if not pj.get("priv_channel_push_completed_at_ts"):
            return await _step_push_payment(db, session, deps)
        # Both open + push complete — schedule cooperative close.
        return _NOOP
    if session.status == AnonymizeStatus.AWAITING_CHANNEL_CLOSE.value:
        return await _step_close_channel(db, session, deps)
    return _NOOP


async def _step_open_channel(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: PrivChannelHopDeps,
) -> PrivChannelHopOutcome:
    """Pick a peer + open an unannounced channel."""
    key = _key_for(session, "priv_channel_open", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=key.idempotency_key,
    ):
        return PrivChannelHopOutcome(
            kind="noop",
            detail="channel_open_already_completed",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "select_peer"},
    )
    await db.flush()

    peer, err = await deps.select_auto_peer(session=session)
    if err is not None or peer is None:
        return PrivChannelHopOutcome(
            kind="error",
            detail=f"no_eligible_peer:{err}",
        )

    pubkey = peer.get("pubkey") if isinstance(peer, dict) else getattr(peer, "pubkey", "")
    if not pubkey:
        return PrivChannelHopOutcome(
            kind="error",
            detail="peer_returned_no_pubkey",
        )

    bin_amount = int(session.bin_amount_sat or 0)
    if bin_amount <= 0:
        return PrivChannelHopOutcome(
            kind="error",
            detail="bin_amount_sat must be positive",
        )

    channel_point, err = await deps.lnd_open_private_channel(
        peer_pubkey=pubkey,
        local_funding_amount_sat=bin_amount,
    )
    if err is not None or not channel_point:
        return PrivChannelHopOutcome(
            kind="error",
            detail=f"open_channel_failed:{err}",
        )

    # Record the auto-peer-chosen event so the audit chain
    # has the chosen-peer evidence (the pubkey is blinded by the
    # redactor before egress).
    try:
        from ..peer_selection import record_auto_peer_chosen

        await record_auto_peer_chosen(
            db,
            session_id=session.id,
            chosen_pubkey=str(pubkey),
            candidates_size=1,
        )
    except Exception as exc:  # noqa: BLE001
        # Audit-event failure is non-fatal; the per-session loop's
        # bounded-retry counter doesn't bump.
        logger.warning(
            "priv_channel %s: auto_peer_chosen event write failed: %s",
            session.id,
            exc,
        )

    pj = dict(session.pipeline_json or {})
    pj["priv_channel_id"] = str(channel_point)
    pj["priv_channel_peer_pubkey"] = str(pubkey)
    pj["priv_channel_opened_at_ts"] = datetime.now(timezone.utc).isoformat()
    session.pipeline_json = pj

    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"channel_point": str(channel_point), "peer": str(pubkey)},
    )
    return PrivChannelHopOutcome(
        kind="opened_channel",
        detail=str(channel_point),
    )


async def _step_push_payment(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: PrivChannelHopDeps,
) -> PrivChannelHopOutcome:
    """Push the binned amount across the freshly-opened channel.

    Waits for the channel to be active before issuing the HTLC.
    """
    pj = session.pipeline_json or {}
    channel_point = pj.get("priv_channel_id")
    if not channel_point:
        return PrivChannelHopOutcome(
            kind="error",
            detail="missing_channel_id",
        )

    is_active, err = await deps.lnd_channel_is_active(
        channel_point=channel_point,
    )
    if err is not None:
        return PrivChannelHopOutcome(
            kind="error",
            detail=f"channel_state_query:{err}",
        )
    if not is_active:
        return PrivChannelHopOutcome(
            kind="noop",
            detail="awaiting_channel_active",
        )

    key = _key_for(session, "priv_channel_push", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=key.idempotency_key,
    ):
        return PrivChannelHopOutcome(
            kind="noop",
            detail="push_already_completed",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "push_payment"},
    )
    await db.flush()

    bin_amount = int(session.bin_amount_sat or 0)
    result, err = await deps.lnd_send_payment_through_channel(
        channel_point=channel_point,
        amount_sat=bin_amount,
        session=session,
    )
    if err is not None:
        return PrivChannelHopOutcome(
            kind="error",
            detail=f"push_payment_failed:{err}",
        )

    pj = dict(session.pipeline_json or {})
    pj["priv_channel_push_completed_at_ts"] = datetime.now(timezone.utc).isoformat()
    # Sample the close delay NOW so a restart doesn't
    # re-sample and shift the close moment.
    pj["priv_channel_close_at_unix_s"] = datetime.now(timezone.utc).timestamp() + sample_close_delay_s()
    session.pipeline_json = pj
    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"push_result": str(result)[:80]},
    )
    return PrivChannelHopOutcome(
        kind="pushed_payment",
        detail=str(channel_point),
    )


async def _step_close_channel(
    db: AsyncSession,
    session: AnonymizeSession,
    deps: PrivChannelHopDeps,
) -> PrivChannelHopOutcome:
    """Issue a cooperative close after the sampled delay."""
    pj = session.pipeline_json or {}
    channel_point = pj.get("priv_channel_id")
    if not channel_point:
        return PrivChannelHopOutcome(
            kind="error",
            detail="missing_channel_id",
        )
    close_at = pj.get("priv_channel_close_at_unix_s")
    if close_at is not None:
        now = datetime.now(timezone.utc).timestamp()
        if now < float(close_at):
            return PrivChannelHopOutcome(
                kind="noop",
                detail="awaiting_close_delay",
            )

    key = _key_for(session, "priv_channel_close", attempt=1)
    if await has_hop_attempt_completed(
        db,
        idempotency_key=key.idempotency_key,
    ):
        return PrivChannelHopOutcome(
            kind="noop",
            detail="close_already_completed",
        )

    await record_hop_attempt_started(
        db,
        key=key,
        detail={"step": "cooperative_close"},
    )
    await db.flush()

    # Force_close NEVER automated.
    result, err = await deps.lnd_close_channel_cooperative(
        channel_point=channel_point,
    )
    if err is not None:
        return PrivChannelHopOutcome(
            kind="error",
            detail=f"close_failed:{err}",
        )
    await record_hop_attempt_completed(
        db,
        key=key,
        detail={"close_result": str(result)[:80]},
    )
    return PrivChannelHopOutcome(
        kind="close_broadcast",
        detail=str(channel_point),
    )


__all__ = [
    "PrivChannelHopOutcome",
    "PrivChannelHopDeps",
    "execute_priv_channel_hop_step",
    "sample_close_delay_s",
]
