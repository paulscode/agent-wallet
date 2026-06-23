# SPDX-License-Identifier: MIT
"""Sticky-peer reconciler — keeps the BOLT 12 gateway connected to
well-known payers (today: OCEAN) across gateway restarts, network
blips, and peer-side reboots.

Three independent paths cooperate to deliver this without races:

1. **Startup pass** (``run_startup_pass``): runs once when the
   wallet boots, after the gateway runtime is up. Scans all active
   default-receive offers, matches their descriptions against the
   well-known-payers registry, builds the desired sticky set, and
   pushes it to the gateway via ``SetStickyPeers``. Also kicks an
   explicit ``connect_peer`` for any peer that isn't already up so
   the BOLT 1 init handshake is in flight before the first offer
   request lands.

2. **Periodic reconciler** (``run_reconciler_loop``): a background
   task that re-pushes the desired set every
   ``RECONCILER_INTERVAL_S`` seconds. The push is idempotent
   (REPLACE semantics) so a gateway that lost its in-memory cache
   on restart rebuilds it on the next push. Also re-issues
   ``connect_peer`` for any sticky peer the gateway reports as
   missing — this is the slow-path recovery: even if the Rust
   on-disconnect handler somehow misses a flap, the periodic
   reconciler will dial again on the next tick.

3. **Rust on-disconnect handler** (``bolt12-gateway/src/sticky_peers.rs``):
   the fast path. When a sticky peer drops, the Rust loop sees it
   missing from ``peer_by_node_id`` and redials with exponential
   backoff. Goes through the same per-pubkey mutex as
   ``ConnectPeer`` so a concurrent Python dial doesn't race.

Coordination invariants:

* Python is the source of truth for "should this peer exist?" The
  gateway treats the sticky set as advisory cache — losing it on
  restart is fine, the next periodic push rebuilds it.
* The Rust ``ConnectPeer`` handler and the Rust on-disconnect loop
  funnel through the same per-pubkey async mutex, so two dials for
  the same pubkey can never race a duplicate connection through
  LDK.
* ``SetStickyPeers`` is REPLACE-semantics. Python computes the full
  desired set on every push; the gateway swaps atomically.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Iterable, Optional

from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_db_context
from app.models.bolt12_offer import Bolt12Offer, Bolt12OfferStatus
from app.services.bolt12.well_known_payers import (
    BOOTSTRAP_OM_PEERS,
    WELL_KNOWN_PAYERS,
    match_for_description,
)
from app.services.bolt12_gateway import StickyPeer

logger = logging.getLogger(__name__)

# How often the periodic reconciler re-pushes the sticky set and
# probes for missing peers. 30 s is a reasonable compromise: fast
# enough to recover from a missed gateway-side reconnect within a
# minute, slow enough not to spam the DB on a healthy wallet.
RECONCILER_INTERVAL_S: float = 30.0

# Each periodic dial of a missing peer is bounded so a stuck dial
# doesn't pin the reconciler task forever. 10 s is plenty for a
# healthy clearnet TCP+Noise handshake.
PER_PEER_DIAL_TIMEOUT_S: float = 10.0

# Serialises the read-then-push critical section across the
# periodic reconciler tick AND every out-of-band ``refresh_sticky_set``
# call from the offer-mint code paths. Without this lock the following
# race is observable:
#
#   1. Periodic reconciler reads DB (sees empty state)
#   2. Admin commits an OCEAN offer
#   3. Admin's refresh reads DB (sees OCEAN), pushes ``[OCEAN]``
#   4. Periodic reconciler push lands with stale ``[]``, overwriting
#      the refresh's correct push.
#
# Lock acquisition order is determined by ``asyncio.Lock``'s FIFO
# semantics, so the LAST pusher always reads the most recent
# committed DB state. The lock is held only over the DB read + RPC
# push (~10 ms typical) — never over the per-peer dials, which can
# block for seconds.
_sticky_push_lock = asyncio.Lock()


@dataclass(frozen=True, slots=True)
class DesiredPeer:
    """A peer Python wants the gateway to keep connected. Derived
    from the well-known-payers registry × the wallet's active
    default-receive offers."""

    label: str
    node_id: bytes
    address: str


async def _compute_desired_peers() -> tuple[DesiredPeer, ...]:
    """Scan all active default-receive offers and return the unique
    set of peers the wallet should keep connected.

    The result includes two classes of entries:

    * **Bootstrap OM peers** (always present, subject to the
      ``bolt12_auto_peer_well_known_payers`` flag and
      ``mainnet_only``): a small set of universally-gossiped,
      onion-message-capable third-party nodes whose
      ``node_announcement`` is cached by virtually every routing
      node on the network. They give us at least one viable
      ``offer_paths`` introduction node even before the operator
      configures their first well-known payer.

    * **Well-known payers**: dialed when at least one active
      default-receive offer has a matching description prefix. The
      payer's own node is kept as a peer for inbound reachability
      but is NOT used as an offer-paths introduction node — that
      assumption (a payer can trivially route to its own node) is
      broken for multi-node payer infrastructures (OCEAN being the
      driving example).

    De-duplicated by ``node_id`` (bootstrap entries take precedence
    over well-known-payer entries on collision; doesn't happen with
    current registry contents but the invariant keeps future
    additions safe). Skips mainnet-only entries when the wallet is
    on a non-mainnet network. Returns an empty tuple when:

    * BOLT 12 auto-peering is disabled
    * Both registries are empty
    * No active default-receive offer has a matching description
      AND no bootstrap entries apply to the current network
    """
    if not settings.bolt12_auto_peer_well_known_payers:
        return ()

    is_mainnet = settings.bitcoin_network == "bitcoin"
    matched: dict[bytes, DesiredPeer] = {}

    # Always-on bootstrap peers first so they take precedence on any
    # node_id collision with a well-known payer (shouldn't happen
    # given current registry contents, but cheap insurance).
    for boot in BOOTSTRAP_OM_PEERS:
        if boot.mainnet_only and not is_mainnet:
            continue
        try:
            node_id = bytes.fromhex(boot.node_id_hex)
        except ValueError:
            logger.warning(
                "sticky-peer reconciler: bootstrap OM peer %s node_id_hex is malformed (%r); skipped",
                boot.label,
                boot.node_id_hex,
            )
            continue
        if len(node_id) != 33:
            logger.warning(
                "sticky-peer reconciler: bootstrap OM peer %s node_id must decode to 33 bytes (got %d); skipped",
                boot.label,
                len(node_id),
            )
            continue
        if not boot.address:
            continue
        matched[node_id] = DesiredPeer(
            label=boot.label,
            node_id=node_id,
            address=boot.address,
        )

    if not WELL_KNOWN_PAYERS:
        return tuple(matched.values())

    # Read all active offers across all API keys. Originally this
    # filtered on ``is_default_receive=True``, but that misses a real
    # case: a user can rotate the default-receive pointer to a fresh
    # offer while a still-active prior offer continues to receive
    # from a well-known payer (e.g. Ocean kept paying the previous
    # offer string). The sticky-peer pin should track every active
    # offer that maps to a well-known payer, not only the canonical
    # one — otherwise the previous offer's inbound path silently
    # loses its persistent connection after a rotation.
    try:
        async with get_db_context() as db:
            rows = (
                await db.execute(
                    select(Bolt12Offer.description).where(
                        Bolt12Offer.status == Bolt12OfferStatus.ACTIVE,
                        Bolt12Offer.deleted_at.is_(None),
                    )
                )
            ).all()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "sticky-peer reconciler: failed to read active offers (%s); proceeding with bootstrap-only desired set",
            exc,
        )
        return tuple(matched.values())

    for (description,) in rows:
        if not description:
            continue
        payer = match_for_description(
            description,
            network=settings.bitcoin_network,
        )
        if payer is None:
            continue
        if payer.mainnet_only and not is_mainnet:
            continue
        try:
            node_id = bytes.fromhex(payer.node_id_hex)
        except ValueError:
            logger.warning(
                "sticky-peer reconciler: %s well-known payer node_id_hex is malformed (%r); skipped",
                payer.label,
                payer.node_id_hex,
            )
            continue
        if len(node_id) != 33:
            logger.warning(
                "sticky-peer reconciler: %s well-known payer node_id must decode to 33 bytes (got %d); skipped",
                payer.label,
                len(node_id),
            )
            continue
        if not payer.address:
            continue
        # De-dup on node_id: two offers pointing at the same payer
        # only contribute one entry, and we never let a payer
        # registry entry overwrite a bootstrap entry under the same
        # node_id (the invariant documented above).
        if node_id in matched:
            continue
        matched[node_id] = DesiredPeer(
            label=payer.label,
            node_id=node_id,
            address=payer.address,
        )
    return tuple(matched.values())


async def _push_sticky_set(desired: Iterable[DesiredPeer]) -> bool:
    """Replace the gateway's sticky set with ``desired``. Returns True
    on success, False on any failure (logged). Never raises."""
    # Local imports avoid an import cycle (runtime → reconciler →
    # runtime) and let us distinguish unimplemented from generic
    # gRPC failures for clearer operator diagnostics.
    from app.services.bolt12.runtime import _runtime
    from app.services.bolt12_gateway import GatewayUnimplementedError

    client = _runtime.client
    if client is None:
        return False
    sticky = tuple(StickyPeer(node_id=p.node_id, address=p.address) for p in desired)
    try:
        result = await client.set_sticky_peers(sticky)
    except GatewayUnimplementedError:
        # The gateway daemon is an older build that doesn't expose
        # the SetStickyPeers RPC. Log loudly once per tick so the
        # operator knows they need to upgrade — without this, the
        # Rust on-disconnect handler can't engage, and disconnects
        # fall back to "wait for the next periodic reconciler tick"
        # for recovery.
        logger.warning(
            "sticky-peer reconciler: gateway daemon does not "
            "implement SetStickyPeers — upgrade the bolt12-gateway "
            "binary to enable sub-second on-disconnect recovery. "
            "Falling back to periodic reconciler-only recovery."
        )
        return False
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "sticky-peer reconciler: SetStickyPeers failed (%s); "
            "the gateway's sticky set may be stale until the next "
            "reconciler tick",
            exc,
        )
        return False
    logger.debug(
        "sticky-peer reconciler: pushed %d peer(s) to the gateway (sticky_count=%d)",
        len(sticky),
        result.sticky_count,
    )
    return True


async def _dial_if_missing(desired: Iterable[DesiredPeer]) -> None:
    """For each desired peer the gateway reports as not currently
    connected, kick a ``connect_peer`` so the BOLT 1 init handshake
    is in flight before the next request needs them.

    Cheap when peers are already up — the gateway's ``ConnectPeer``
    short-circuits with ``already_connected=True`` after acquiring
    the per-pubkey lock.
    """
    from app.services.bolt12.runtime import _runtime  # local import: avoid cycle

    client = _runtime.client
    if client is None:
        return
    desired_list = list(desired)
    if not desired_list:
        return

    # One get_identity call to learn the current peer set, then dial
    # only the missing ones. Cheaper than calling connect_peer
    # unconditionally per peer.
    try:
        ident = await client.get_identity()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "sticky-peer reconciler: get_identity failed (%s); skipping per-peer dial probe this tick",
            exc,
        )
        return

    connected_ids: set[bytes] = {p.node_id for p in ident.peers}
    for peer in desired_list:
        if peer.node_id in connected_ids:
            continue
        try:
            await asyncio.wait_for(
                client.connect_peer(
                    node_id=peer.node_id,
                    address=peer.address,
                ),
                timeout=PER_PEER_DIAL_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "sticky-peer reconciler: dial to %s (%s) timed out — the Rust on-disconnect loop will keep retrying",
                peer.label,
                peer.address,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "sticky-peer reconciler: dial to %s (%s) failed (%s) — the Rust on-disconnect loop will keep retrying",
                peer.label,
                peer.address,
                exc,
            )


async def run_startup_pass() -> None:
    """One-shot reconciliation at process startup.

    Called from the BOLT 12 runtime's start hook after the gateway
    gRPC connection is up. Best-effort: every error is logged but
    never raised — the wallet must still boot if the reconciler is
    sick.
    """
    # Read + push under the shared lock so a concurrent ``refresh_sticky_set``
    # (e.g. from a fresh /receive/configure landing during startup)
    # can't have its push undone by a stale read from this pass.
    async with _sticky_push_lock:
        desired = await _compute_desired_peers()
        if not desired:
            logger.info(
                "sticky-peer reconciler: no desired peers at startup "
                "(no matching default-receive offers OR auto-peer disabled)"
            )
            # Push an empty set anyway so a previous-process leftover
            # cache doesn't keep stale entries.
            await _push_sticky_set(())
            return
        await _push_sticky_set(desired)
    # Dial probe runs OUTSIDE the lock — it can block for seconds on
    # a per-peer connect, and holding the lock that long would
    # serialise every refresh during startup.
    await _dial_if_missing(desired)


async def refresh_sticky_set() -> None:
    """Trigger an out-of-band recomputation + push of the sticky set.

    Called from the default-receive mint / reconfigure / promote
    code paths so a freshly-added well-known payer becomes sticky
    *immediately* (rather than waiting up to ``RECONCILER_INTERVAL_S``
    for the next periodic tick). Without this, a peer that drops in
    the post-configure window has no on-disconnect handler running
    yet, because the Rust loop only watches peers that are in the
    sticky set.

    Best-effort. Does NOT dial — the dial happened (or was attempted)
    inside ``_connect_well_known_payer`` already. This call is just
    about marking the peer sticky on the gateway.
    """
    if not settings.bolt12_enabled or not settings.bolt12_gateway_grpc:
        # No gateway means nothing to push to — caller's offer mint
        # still succeeds.
        return
    try:
        # Lock serialises with the periodic reconciler so a tick that
        # was mid-flight when this refresh's caller committed can't
        # overwrite the refresh's correct push with stale data.
        async with _sticky_push_lock:
            desired = await _compute_desired_peers()
            await _push_sticky_set(desired)
    except Exception:  # noqa: BLE001 — refresh must never fail caller
        logger.exception("sticky-peer reconciler: out-of-band refresh failed; the next periodic tick will catch up")


async def run_reconciler_loop(
    interval_s: float = RECONCILER_INTERVAL_S,
) -> None:
    """Long-running reconciler. Re-pushes the sticky set + dials any
    missing peer every ``interval_s`` seconds.

    Cancellation-safe. Never raises (besides ``CancelledError``).
    The loop is robust against a gateway-runtime drop: when
    ``_runtime.client`` is None, the push and dial helpers no-op
    and the next tick retries.
    """
    while True:
        desired: tuple[DesiredPeer, ...] = ()
        try:
            # Lock scope is JUST the read + push so we can't race a
            # concurrent ``refresh_sticky_set`` into overwriting its
            # fresh data with our stale snapshot.
            async with _sticky_push_lock:
                desired = await _compute_desired_peers()
                await _push_sticky_set(desired)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — reconciler must never die
            logger.exception("sticky-peer reconciler push crashed; continuing")
        # Dial probe runs OUTSIDE the lock — per-peer dials can
        # block for seconds (PER_PEER_DIAL_TIMEOUT_S) and we don't
        # want concurrent refreshes to wait that long.
        if desired:
            try:
                await _dial_if_missing(desired)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("sticky-peer reconciler dial crashed; continuing")
        try:
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            raise


# ── module-level task handle ─────────────────────────────────────

_reconciler_task: Optional[asyncio.Task[None]] = None


async def start_reconciler() -> None:
    """Spawn the reconciler background task. Idempotent — repeat
    calls are no-ops while the task is running."""
    global _reconciler_task
    if _reconciler_task is not None and not _reconciler_task.done():
        return
    # No point running the reconciler when BOLT 12 isn't configured —
    # ``_push_sticky_set`` and ``_dial_if_missing`` would no-op on
    # every tick because ``_runtime.client`` stays None. Cleaner to
    # skip entirely so the operator's process log doesn't show a
    # reconciler that's doing nothing.
    if not settings.bolt12_enabled or not settings.bolt12_gateway_grpc:
        logger.info("sticky-peer reconciler: BOLT 12 disabled, not starting")
        return
    # Startup pass runs synchronously in lifespan; the background
    # loop runs after.
    try:
        await run_startup_pass()
    except Exception:  # noqa: BLE001
        logger.exception("sticky-peer reconciler startup pass failed")
    _reconciler_task = asyncio.create_task(
        run_reconciler_loop(),
        name="bolt12-sticky-peer-reconciler",
    )


async def stop_reconciler() -> None:
    """Cancel the reconciler task. Idempotent and exception-safe."""
    global _reconciler_task
    task = _reconciler_task
    _reconciler_task = None
    if task is None:
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass


def _reset_for_tests() -> None:
    """Cancel any leaked reconciler task. Tests only.

    Fire-and-forget cancel so a reconciler spawned by one test (e.g.
    via ``lifespan``) can't keep ticking into the next test's event
    loop. Async tests that need a clean awaited shutdown should call
    :func:`stop_reconciler` in their own teardown.
    """
    global _reconciler_task
    task = _reconciler_task
    _reconciler_task = None
    if task is not None and not task.done():
        task.cancel()


__all__ = [
    "DesiredPeer",
    "RECONCILER_INTERVAL_S",
    "run_reconciler_loop",
    "run_startup_pass",
    "start_reconciler",
    "stop_reconciler",
]
