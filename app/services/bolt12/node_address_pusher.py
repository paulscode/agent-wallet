# SPDX-License-Identifier: MIT
"""Periodic push of LND-known peer addresses to the gateway cache.

The gateway's ``Event::ConnectionNeeded`` handler consults an
in-memory cache of peer addresses when LDK has buffered an outbound
onion message (typically our BOLT 12 invoice reply on a fetchinvoice
round-trip) for a peer we're not yet connected to. Without this
cache, the gateway can't dial — its own ``NetworkGraph`` is empty by
design (no gossip consumption) — and the buffered message is
silently dropped on LDK's teardown timer. That's the 2026-06-04
Ocean wedge root cause.

This module reads from LND's ``DescribeGraph``, filters to the
top-N nodes by channel count, and pushes them to the gateway via
the streaming ``SetKnownNodeAddresses`` RPC. The wallet is
authoritative on freshness — the gateway has no built-in periodic
prune beyond a per-entry TTL on lookup (24 h ceiling), so callers
SHOULD push periodically so addresses retired from LND's graph age
out of the gateway's cache too.

Design notes:

* **Top-N by channel count** as the inclusion filter. LND graphs
  for a mature wallet hold ~50 k entries; the cache only needs the
  nodes most likely to be picked as a payer's reply-path
  introduction node. Channel count is a coarse but reliable proxy
  for "well-known routing peer."
* **Skip nodes with zero addresses.** A node in LND's graph with no
  gossiped addresses can't be dialed even if we cached it.
* **Best-effort scheduling.** A failed push logs at WARNING and the
  next tick retries. The cache is purely a routing optimisation;
  the gateway still handles ConnectionNeeded events (warns + drops)
  when the cache is stale or missing.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from app.services.bolt12_gateway import (
    Bolt12GatewayClient,
    KnownNodeAddresses,
)

logger = logging.getLogger(__name__)


async def collect_addresses_from_lnd(
    *,
    max_nodes: int,
) -> tuple[KnownNodeAddresses, ...]:
    """Pull the top-N nodes from LND's graph + filter to entries
    with at least one address.

    Returns the staged push payload — pure function modulo the LND
    call so tests can drive it with a stub ``lnd_service``.
    """
    from app.services.lnd_service import lnd_service

    data, error = await lnd_service.describe_graph(include_unannounced=False)
    if error:
        raise RuntimeError(f"LND describe_graph failed: {error}")
    if data is None:
        return ()
    return _build_payload(data.get("nodes") or [], max_nodes=max_nodes)


def _build_payload(
    raw_nodes: list[dict],
    *,
    max_nodes: int,
) -> tuple[KnownNodeAddresses, ...]:
    """Filter LND ``describe_graph.nodes`` into a gateway push.

    Pulled out as a pure helper so unit tests don't need a mocked
    LND client.
    """
    if max_nodes <= 0:
        return ()

    # Two-pass: first decode + filter to entries with at least one
    # address, then sort + truncate. Channel count comes from a
    # second LND call in production; the size-1 stand-in here uses
    # the gossip-known address count as a coarse tiebreak so the
    # filter stays stable when channel counts aren't available.
    candidates: list[tuple[int, KnownNodeAddresses]] = []
    for node in raw_nodes:
        pubkey_hex = node.get("pub_key") or ""
        try:
            node_id = bytes.fromhex(pubkey_hex)
        except ValueError:
            continue
        if len(node_id) != 33:
            continue

        addresses: list[str] = []
        for entry in node.get("addresses") or []:
            addr = (entry or {}).get("addr")
            if not addr or not addr.strip():
                continue
            addresses.append(addr)
        if not addresses:
            continue

        # Stable ordering: .onion first if present (gateway dials
        # via SOCKS5 and .onion is what works inside the
        # bolt12-internal docker network). Clearnet entries follow
        # in source order so a payer's preferred address survives.
        # ``enumerate`` captures the original index before sort
        # mutates the list — ``addresses.index(a)`` would observe
        # the partially-sorted intermediate state and shuffle ties
        # arbitrarily.
        indexed = list(enumerate(addresses))
        indexed.sort(key=lambda pair: (".onion" not in pair[1], pair[0]))
        addresses = [addr for _, addr in indexed]

        try:
            ts = int(node.get("last_update") or 0)
        except (TypeError, ValueError):
            ts = 0

        try:
            channel_count = int(node.get("num_channels") or 0)
        except (TypeError, ValueError):
            channel_count = 0

        candidates.append(
            (
                channel_count,
                KnownNodeAddresses(
                    node_id=node_id,
                    addresses=tuple(addresses),
                    node_announcement_timestamp=ts,
                ),
            )
        )

    # Sort descending by channel count so the top-N covers the
    # well-connected hubs first (most likely reply-path intros).
    candidates.sort(key=lambda x: x[0], reverse=True)
    return tuple(entry for _, entry in candidates[:max_nodes])


async def push_once(
    client: Bolt12GatewayClient,
    *,
    max_nodes: int,
) -> int:
    """Run one push cycle. Returns the count of entries the gateway
    accepted. Raises on transport or validation errors so the
    caller can decide whether to log + retry."""
    payload = await collect_addresses_from_lnd(max_nodes=max_nodes)
    if not payload:
        logger.info(
            "bolt12 node-address push: LND graph had no entries with addresses; "
            "skipping push (cache will rely on prior contents)",
        )
        return 0
    result = await client.set_known_node_addresses(payload)
    logger.info(
        "bolt12 node-address push: %d entries accepted (sent=%d)",
        result.accepted_count,
        len(payload),
    )
    return int(result.accepted_count)


async def run_node_address_pusher(
    client_getter: Callable[[], Bolt12GatewayClient | None],
    stop_event: asyncio.Event,
    *,
    interval_s: int,
    max_nodes: int,
) -> None:
    """Background loop. Returns when ``stop_event`` is set.

    ``client_getter`` is a no-arg callable returning the current
    ``Bolt12GatewayClient`` or ``None`` when the runtime is in a
    reconnecting state. Looking the client up each tick (rather
    than capturing one at start) lets the pusher cooperate with the
    runtime's reconnect-on-disconnect flow without restarting the
    task.
    """
    if interval_s <= 0:
        logger.info("bolt12 node-address pusher: disabled (interval <= 0)")
        return

    # Tick interval when the previous tick failed (client unavailable
    # or push raised). Tuned to recover quickly from both the
    # startup race (api comes up before gateway) and gateway
    # restarts, without spamming a sick LND. Capped at the configured
    # ``interval_s`` so the failure path is always at least as fast
    # as the happy path.
    failure_interval_s = min(60, interval_s)

    logger.info(
        "bolt12 node-address pusher: starting, interval=%ds failure_interval=%ds max_nodes=%d",
        interval_s,
        failure_interval_s,
        max_nodes,
    )

    # Fire one push immediately on start so the cache is warm
    # before the first inbound invreq lands; subsequent pushes
    # follow the interval.
    while not stop_event.is_set():
        client = client_getter()
        sleep_s: float = float(interval_s)
        if client is None:
            # Gateway is reconnecting; wake more frequently so the
            # push fires within ``failure_interval_s`` of the
            # reconnect rather than waiting the full hour.
            logger.debug(
                "bolt12 node-address pusher: gateway client unavailable, skipping tick",
            )
            sleep_s = float(failure_interval_s)
        else:
            try:
                accepted = await push_once(client, max_nodes=max_nodes)
                try:
                    from app.services.bolt12.runtime import mark_node_address_push

                    mark_node_address_push(accepted)
                except Exception:  # noqa: BLE001
                    pass
            except Exception as exc:  # noqa: BLE001
                # Push is best-effort. A transient LND or gateway
                # blip should not crash the task; retry on the
                # shorter failure cadence so we recover within
                # ~minute even if the configured interval is hours.
                logger.warning(
                    "bolt12 node-address pusher: tick failed (retrying in %ds): %s",
                    failure_interval_s,
                    exc,
                )
                sleep_s = float(failure_interval_s)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=sleep_s)
        except asyncio.TimeoutError:
            continue
        break

    logger.info("bolt12 node-address pusher: stopped")


__all__ = [
    "collect_addresses_from_lnd",
    "push_once",
    "run_node_address_pusher",
]
