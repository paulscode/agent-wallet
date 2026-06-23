# SPDX-License-Identifier: MIT
"""Tests for the BOLT 12 node-address pusher.

Pins:
* the LND-graph → ``KnownNodeAddresses`` filter shape (skip
  addressless nodes, skip malformed pubkeys, top-N by channel
  count, .onion preferred).
* push_once happy path (calls the gateway client with the staged
  payload).
* run loop is best-effort (tick failure logs + continues).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.bolt12.node_address_pusher import (
    _build_payload,
    push_once,
    run_node_address_pusher,
)
from app.services.bolt12_gateway import (
    KnownNodeAddresses,
    SetKnownNodeAddressesResult,
)


def _node(pub_hex: str, addrs: list[str], *, channels: int = 0, ts: int = 0) -> dict:
    return {
        "pub_key": pub_hex,
        "addresses": [{"network": "tcp", "addr": a} for a in addrs],
        "num_channels": channels,
        "last_update": ts,
    }


# ── _build_payload ────────────────────────────────────────────────


def test_filters_out_addressless_nodes() -> None:
    """A node without an address can't be dialed even if cached.
    Pin so a future "include for completeness" change can't bloat
    the push with unusable entries."""
    pub = "02" + "11" * 32
    payload = _build_payload(
        [
            _node(pub, [], channels=10),
            _node("02" + "22" * 32, ["1.2.3.4:9735"], channels=5),
        ],
        max_nodes=100,
    )
    pubs = {e.node_id for e in payload}
    assert bytes.fromhex(pub) not in pubs
    assert bytes.fromhex("02" + "22" * 32) in pubs


def test_filters_out_malformed_pubkey() -> None:
    """A malformed pubkey (wrong length or non-hex) must be skipped
    silently — the gateway's RPC handler also validates, but
    catching it here keeps a single bad row from poisoning the
    push attempt."""
    payload = _build_payload(
        [
            _node("not-hex", ["a:9735"], channels=10),
            _node("0011", ["b:9735"], channels=10),  # too short
            _node("02" + "33" * 32, ["c:9735"], channels=10),  # OK
        ],
        max_nodes=100,
    )
    assert len(payload) == 1
    assert payload[0].node_id == bytes.fromhex("02" + "33" * 32)


def test_top_n_by_channel_count() -> None:
    """The cache size is bounded; the inclusion filter must favour
    well-connected nodes. Pin descending-by-channels so a refactor
    that breaks the sort key (or flips ascending) gets caught."""
    nodes = [_node("02" + f"{i:02x}" * 32, ["a:9735"], channels=i) for i in range(1, 10)]
    payload = _build_payload(nodes, max_nodes=3)
    # Top 3 by channels = nodes 9, 8, 7.
    counts = [n.node_id[-1] for n in payload]
    assert counts == [9, 8, 7]


def test_onion_address_listed_first() -> None:
    """Inside the gateway's docker network the SOCKS5 proxy
    successfully reaches .onion. Putting .onion first means the
    gateway tries the most-likely-to-work address before a
    clearnet IP that may be unreachable from inside the network."""
    payload = _build_payload(
        [
            _node(
                "02" + "44" * 32,
                ["1.2.3.4:9735", "abc.onion:9735", "5.6.7.8:9735"],
                channels=1,
            ),
        ],
        max_nodes=100,
    )
    assert len(payload) == 1
    assert payload[0].addresses == ("abc.onion:9735", "1.2.3.4:9735", "5.6.7.8:9735")


def test_max_nodes_zero_returns_empty() -> None:
    """A misconfigured max_nodes=0 must produce zero entries (not
    crash, not push the whole graph). Pinned so a future tweak to
    the slice bound can't accidentally invert."""
    payload = _build_payload(
        [_node("02" + "55" * 32, ["x:9735"], channels=5)],
        max_nodes=0,
    )
    assert payload == ()


# ── push_once ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_push_once_calls_client_with_staged_payload(monkeypatch) -> None:
    """The happy path: LND returns a graph, the helper filters it,
    the gateway client receives the staged payload exactly. Pins
    the wiring so a future refactor that drops the payload on the
    floor regresses."""
    fake_data = {
        "nodes": [
            _node("02" + "66" * 32, ["x.onion:9735"], channels=10, ts=42),
        ],
    }
    fake_lnd = MagicMock()
    fake_lnd.describe_graph = AsyncMock(return_value=(fake_data, None))
    monkeypatch.setattr("app.services.lnd_service.lnd_service", fake_lnd)

    fake_client = MagicMock()
    fake_client.set_known_node_addresses = AsyncMock(
        return_value=SetKnownNodeAddressesResult(accepted_count=1),
    )

    accepted = await push_once(fake_client, max_nodes=100)
    assert accepted == 1

    fake_client.set_known_node_addresses.assert_awaited_once()
    sent_payload = fake_client.set_known_node_addresses.await_args.args[0]
    assert len(sent_payload) == 1
    assert isinstance(sent_payload[0], KnownNodeAddresses)
    assert sent_payload[0].node_announcement_timestamp == 42


@pytest.mark.asyncio
async def test_push_once_skips_when_lnd_graph_empty(monkeypatch) -> None:
    """An empty graph (or one with no address-having nodes) must
    skip the RPC call entirely — pushing an empty stream would
    REPLACE the gateway's cache with nothing and undo any prior
    successful push. Pin so the "no nodes ⇒ no call" guard
    survives."""
    fake_lnd = MagicMock()
    fake_lnd.describe_graph = AsyncMock(return_value=({"nodes": []}, None))
    monkeypatch.setattr("app.services.lnd_service.lnd_service", fake_lnd)

    fake_client = MagicMock()
    fake_client.set_known_node_addresses = AsyncMock()
    accepted = await push_once(fake_client, max_nodes=100)
    assert accepted == 0
    fake_client.set_known_node_addresses.assert_not_awaited()


@pytest.mark.asyncio
async def test_push_once_raises_on_lnd_error(monkeypatch) -> None:
    """An LND failure should propagate so the caller's logging
    captures it. The run-loop wraps push_once in a try/except so
    transient failures don't kill the task."""
    fake_lnd = MagicMock()
    fake_lnd.describe_graph = AsyncMock(return_value=(None, "boom"))
    monkeypatch.setattr("app.services.lnd_service.lnd_service", fake_lnd)

    fake_client = MagicMock()
    with pytest.raises(RuntimeError, match="describe_graph failed"):
        await push_once(fake_client, max_nodes=100)


# ── run_node_address_pusher ───────────────────────────────────────


@pytest.mark.asyncio
async def test_run_loop_skips_when_client_unavailable(monkeypatch) -> None:
    """If ``client_getter`` returns ``None`` (gateway reconnecting),
    the tick must skip without raising and the next tick try again.
    Pin so a future refactor that captures the client at start
    instead can't break the reconnect cooperation."""
    fake_lnd = MagicMock()
    fake_lnd.describe_graph = AsyncMock(return_value=({"nodes": []}, None))
    monkeypatch.setattr("app.services.lnd_service.lnd_service", fake_lnd)

    stop = asyncio.Event()
    task = asyncio.create_task(
        run_node_address_pusher(
            lambda: None,
            stop,
            interval_s=10,
            max_nodes=100,
        ),
    )
    # Give it a beat to attempt one tick, then stop.
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=2.0)


@pytest.mark.asyncio
async def test_run_loop_swallows_tick_exception(monkeypatch) -> None:
    """A failed tick must NOT crash the task — the next interval
    retries. Pin so a refactor that lets an LND error bubble out of
    the loop can't take down node-address-pusher for the rest of
    the process lifetime."""
    fake_lnd = MagicMock()
    fake_lnd.describe_graph = AsyncMock(side_effect=RuntimeError("synthetic"))
    monkeypatch.setattr("app.services.lnd_service.lnd_service", fake_lnd)

    fake_client = MagicMock()
    stop = asyncio.Event()
    task = asyncio.create_task(
        run_node_address_pusher(
            lambda: fake_client,
            stop,
            interval_s=10,
            max_nodes=100,
        ),
    )
    await asyncio.sleep(0.05)
    assert not task.done(), "tick failure must not kill the task"
    stop.set()
    await asyncio.wait_for(task, timeout=2.0)


@pytest.mark.asyncio
async def test_run_loop_zero_interval_disables() -> None:
    """``interval_s=0`` is the documented "disable the pusher" knob.
    The task must return immediately without any ticks."""
    stop = asyncio.Event()
    await asyncio.wait_for(
        run_node_address_pusher(
            lambda: None,
            stop,
            interval_s=0,
            max_nodes=100,
        ),
        timeout=2.0,
    )


@pytest.mark.asyncio
async def test_run_loop_uses_short_backoff_when_client_unavailable(
    monkeypatch,
) -> None:
    """Critical recovery behaviour: when the gateway is unavailable
    (startup race or mid-operation restart) the pusher MUST poll
    on the shorter ``failure_interval_s`` cadence, not the full
    ``interval_s``. Without this, the cache stays empty for an hour
    after a gateway restart even though the gateway recovers in
    seconds. Pin so a future refactor that re-introduces the
    full-interval sleep regresses the startup recovery window."""
    sleeps: list[float] = []

    async def _fake_wait_for(coro, timeout):
        # Close the coroutine LDK-style — we don't actually wait on
        # the stop event; we record the timeout and exit fast so
        # the loop ticks repeatedly.
        coro.close()
        sleeps.append(timeout)
        if len(sleeps) >= 3:
            # Break out of the loop after three observations.
            raise asyncio.CancelledError
        raise asyncio.TimeoutError

    monkeypatch.setattr(
        "app.services.bolt12.node_address_pusher.asyncio.wait_for",
        _fake_wait_for,
    )

    stop = asyncio.Event()
    with pytest.raises(asyncio.CancelledError):
        await run_node_address_pusher(
            lambda: None,  # client always unavailable
            stop,
            interval_s=3600,
            max_nodes=100,
        )

    # Every sleep MUST be the failure interval (60), not the
    # configured 3600. ``failure_interval_s`` is ``min(60,
    # interval_s)`` so the cap survives a misconfigured tiny
    # interval too.
    assert sleeps == [60.0, 60.0, 60.0], f"expected failure-interval sleeps, got {sleeps}"


@pytest.mark.asyncio
async def test_run_loop_uses_short_backoff_when_push_fails(monkeypatch) -> None:
    """Same backoff behaviour for failed pushes (e.g. gateway
    disconnected mid-RPC, LND graph blip). Without this, a single
    transient failure stretches recovery to the full interval."""
    fake_lnd = MagicMock()
    fake_lnd.describe_graph = AsyncMock(side_effect=RuntimeError("synthetic"))
    monkeypatch.setattr("app.services.lnd_service.lnd_service", fake_lnd)

    sleeps: list[float] = []

    async def _fake_wait_for(coro, timeout):
        coro.close()
        sleeps.append(timeout)
        if len(sleeps) >= 2:
            raise asyncio.CancelledError
        raise asyncio.TimeoutError

    monkeypatch.setattr(
        "app.services.bolt12.node_address_pusher.asyncio.wait_for",
        _fake_wait_for,
    )

    fake_client = MagicMock()
    stop = asyncio.Event()
    with pytest.raises(asyncio.CancelledError):
        await run_node_address_pusher(
            lambda: fake_client,
            stop,
            interval_s=3600,
            max_nodes=100,
        )
    assert sleeps == [60.0, 60.0], f"expected failure-interval sleeps, got {sleeps}"


@pytest.mark.asyncio
async def test_run_loop_uses_full_interval_after_success(monkeypatch) -> None:
    """The happy path uses the configured ``interval_s``. Pin so
    a refactor that confuses the success/failure branches doesn't
    accidentally run the slow pusher at the failure cadence."""
    fake_data = {
        "nodes": [
            _node("02" + "77" * 32, ["x:9735"], channels=1, ts=10),
        ],
    }
    fake_lnd = MagicMock()
    fake_lnd.describe_graph = AsyncMock(return_value=(fake_data, None))
    monkeypatch.setattr("app.services.lnd_service.lnd_service", fake_lnd)

    sleeps: list[float] = []

    async def _fake_wait_for(coro, timeout):
        coro.close()
        sleeps.append(timeout)
        raise asyncio.CancelledError

    monkeypatch.setattr(
        "app.services.bolt12.node_address_pusher.asyncio.wait_for",
        _fake_wait_for,
    )

    fake_client = MagicMock()
    fake_client.set_known_node_addresses = AsyncMock(
        return_value=SetKnownNodeAddressesResult(accepted_count=1),
    )

    stop = asyncio.Event()
    with pytest.raises(asyncio.CancelledError):
        await run_node_address_pusher(
            lambda: fake_client,
            stop,
            interval_s=3600,
            max_nodes=100,
        )
    assert sleeps == [3600.0], f"expected full-interval sleep after success, got {sleeps}"
