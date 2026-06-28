# SPDX-License-Identifier: MIT
"""Robustness tests for ``ElectrumClient`` internals.

Targets the read-loop / dispatch error branches that aren't reachable
via the happy-path protocol tests:

* ``_dispatch`` ignores non-dict / unknown-id / malformed messages
* ``_dispatch`` handles error responses where ``error`` is a string
  (some servers don't wrap in a dict)
* ``_dispatch`` handles error responses with missing ``code``/``message``
* read loop tolerates non-UTF-8 bytes and malformed JSON
* close while disconnected is a no-op
* request after close fails fast
"""

from __future__ import annotations

import asyncio

import pytest

from app.services.chain.electrum import (
    ElectrumClient,
    ElectrumDisconnectedError,
    ElectrumProtocolError,
)
from tests.unit._fake_electrum import FakeElectrumServer


@pytest.fixture
async def started_client():
    async with FakeElectrumServer() as server:
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        await client.start(wait_for_connect=True)
        try:
            yield client, server
        finally:
            await client.close()


# ─── _dispatch malformed messages ───────────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_ignores_non_dict_message(started_client):
    client, _server = started_client
    # Should not raise.
    client._dispatch("not-a-dict")  # type: ignore[arg-type]
    client._dispatch(["array"])  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_dispatch_ignores_response_with_unknown_id(started_client):
    client, _server = started_client
    # Unknown id → no future to resolve, must not raise.
    client._dispatch({"id": 999_999_999, "result": None})


@pytest.mark.asyncio
async def test_dispatch_ignores_response_with_non_int_id(started_client):
    client, _server = started_client
    # Non-integer id is silently dropped (we never issue such ids).
    client._dispatch({"id": "not-int", "result": None})


@pytest.mark.asyncio
async def test_dispatch_string_error_field(started_client):
    """Some servers send ``"error": "message"`` instead of a dict; the
    client must still raise a typed ``ElectrumProtocolError``."""
    client, _server = started_client
    fut: asyncio.Future = asyncio.get_event_loop().create_future()
    rid = 424242
    client._pending[rid] = fut
    client._dispatch({"id": rid, "error": "boom"})
    with pytest.raises(ElectrumProtocolError, match="boom"):
        await fut


@pytest.mark.asyncio
async def test_dispatch_dict_error_with_missing_fields(started_client):
    """Error dict with empty/missing fields uses safe defaults."""
    client, _server = started_client
    fut: asyncio.Future = asyncio.get_event_loop().create_future()
    rid = 535353
    client._pending[rid] = fut
    # Non-empty dict, but missing 'code' and 'message' keys → defaults
    # to (-1, "unknown"). Empty dict is falsy and would be treated as
    # success; we exercise the dict branch instead.
    client._dispatch({"id": rid, "error": {"data": "extra"}})
    with pytest.raises(ElectrumProtocolError, match="unknown"):
        await fut


@pytest.mark.asyncio
async def test_dispatch_unknown_notification_method_ignored(started_client):
    """Notifications for unknown methods must be silently dropped."""
    client, _server = started_client
    # Should not raise.
    client._dispatch({"method": "completely.unknown", "params": []})


@pytest.mark.asyncio
async def test_dispatch_headers_notification_with_array_params(started_client):
    """Electrum sends headers notifications as ``params=[{...}]``; the
    cached tip is updated from the first element."""
    client, _server = started_client
    client._dispatch(
        {
            "method": "blockchain.headers.subscribe",
            "params": [{"height": 901_234, "hex": "00" * 80}],
        }
    )
    # Allow the async tip update to schedule.
    await asyncio.sleep(0.01)
    assert client.cached_tip_height == 901_234


# ─── close + post-close behavior ────────────────────────────────────


@pytest.mark.asyncio
async def test_close_idempotent(started_client):
    """``close`` may be called twice without raising."""
    client, _server = started_client
    await client.close()
    await client.close()  # second call is a no-op


@pytest.mark.asyncio
async def test_request_after_close_raises(started_client):
    """After ``close``, ``request`` fails fast rather than hanging."""
    client, _server = started_client
    await client.close()
    with pytest.raises((ElectrumDisconnectedError, asyncio.TimeoutError, ConnectionError)):
        await client.request("server.ping", [], timeout=0.5)


# ─── pending requests cancelled on disconnect ───────────────────────


@pytest.mark.asyncio
async def test_pending_request_fails_when_server_disconnects(started_client):
    """In-flight requests must surface ``ElectrumDisconnectedError`` when
    the connection drops mid-call."""
    client, server = started_client

    # Set a handler that hangs so the request is in-flight when we cut
    # the connection.
    blocked = asyncio.Event()
    release = asyncio.Event()

    async def hang(_params):
        blocked.set()
        await release.wait()
        return None

    server.set_handler("blockchain.estimatefee", hang)
    task = asyncio.create_task(client.request("blockchain.estimatefee", [6], timeout=5.0))
    await asyncio.wait_for(blocked.wait(), timeout=2.0)
    await server.disconnect_all()
    with pytest.raises(ElectrumDisconnectedError):
        await task
    release.set()


# ─── ping failure forces reconnect ──────────────────────────────────


@pytest.mark.asyncio
async def test_ping_timeout_forces_transport_close_and_reconnect():
    """Regression for a Tor-circuit-silent-death bug.

    When the ``server.ping`` request times out, the ping loop must
    force the writer closed so the read_task unblocks and the
    supervisor's ``await read_task`` returns. Without this fix a
    silently-dead Tor circuit (no FIN, no RST) left the supervisor
    parked at ``await read_task`` for hours (until SO_KEEPALIVE
    finally fired) while every fee request 503'd with
    ``not connected``.

    The test:
    1. Connects to a fake server.
    2. Makes ``server.ping`` hang indefinitely so the wallet's ping
       times out at ``request_timeout_s``.
    3. Asserts the supervisor reconnects (initial ``connection_count``
       was 1; after the forced close + reconnect it is 2).
    """
    async with FakeElectrumServer() as server:
        # Ping handler that hangs longer than request_timeout_s.
        async def hang(_params):
            await asyncio.sleep(5.0)
            return None

        server.set_handler("server.ping", hang)

        client = ElectrumClient(
            server.url,
            connect_timeout_s=2.0,
            request_timeout_s=0.3,  # ping times out fast
            ping_interval_s=0.05,  # first ping fires almost immediately
        )
        try:
            await client.start(wait_for_connect=True)
            # Initial connect succeeded.
            assert server.connection_count == 1
            # Wait for the ping to fire + time out + supervisor reconnect.
            # Budget: ping_interval + request_timeout + reconnect-backoff.
            for _ in range(50):
                await asyncio.sleep(0.1)
                if server.connection_count >= 2:
                    break
            assert server.connection_count >= 2, (
                f"supervisor did not reconnect after ping timeout; connection_count={server.connection_count}"
            )
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_request_respawns_dead_supervisor():
    """If the supervisor task dies silently (unhandled exception in
    reconnect path), ``request()`` must respawn it on the next call
    rather than letting the connection stay dead until process
    restart.
    """
    async with FakeElectrumServer() as server:
        client = ElectrumClient(
            server.url,
            connect_timeout_s=2.0,
            request_timeout_s=2.0,
            ping_interval_s=60.0,
        )
        try:
            await client.start(wait_for_connect=True)
            assert server.connection_count == 1

            # Simulate the silent-death scenario: cancel the supervisor
            # AND force-clear ``_connected`` so the next ``request()``
            # has to wait — and during that wait the watchdog must
            # respawn the supervisor.
            sup = client._supervisor_task
            assert sup is not None
            sup.cancel()
            try:
                await sup
            except (asyncio.CancelledError, Exception):
                pass
            # Force the "looks disconnected" state ``request()`` checks.
            client._connected.clear()
            # Tear down the live transport so the new supervisor has to
            # connect fresh.
            await server.disconnect_all()
            await asyncio.sleep(0.1)

            # First request after the silent death should respawn the
            # supervisor and succeed.
            result = await client.request("server.ping", [], timeout=5.0)
            assert result is None  # ping returns null
            assert client._supervisor_task is not None
            assert not client._supervisor_task.done()
            assert server.connection_count >= 2
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_write_drain_timeout_surfaces_disconnect():
    """``writer.drain()`` must not park forever on a wedged transport.

    Regression for the Tor-circuit-silent-death pattern where the
    underlying TCP socket is ESTABLISHED at the kernel but the remote
    has stopped reading. Without a drain timeout the request hangs
    until SO_KEEPALIVE (default 2 h), wedging the supervisor.
    """
    client = ElectrumClient(
        "tcp://127.0.0.1:9999",
        connect_timeout_s=2.0,
        request_timeout_s=0.5,
    )

    class _StallWriter:
        def __init__(self) -> None:
            self.closed = False

        def write(self, _payload: bytes) -> None:
            pass

        async def drain(self) -> None:
            await asyncio.sleep(60)  # would hang forever without the cap

        def close(self) -> None:
            self.closed = True

    # Bind to the current loop so the injected "connected" state isn't
    # reset by the loop-change guard in ``request()`` (a real live
    # connection has ``_loop`` set to the loop it was established on).
    client._loop = asyncio.get_running_loop()
    client._writer = _StallWriter()  # type: ignore[assignment]
    client._connected.set()  # pretend we passed the wait

    with pytest.raises(ElectrumDisconnectedError) as exc_info:
        await asyncio.wait_for(
            client.request("server.ping", [], timeout=0.5),
            timeout=2.0,
        )
    assert "drain timed out" in str(exc_info.value)
    assert client._writer.closed is True  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_teardown_timeout_does_not_block_reconnect(monkeypatch):
    """``_teardown_connection`` caps ``writer.wait_closed`` at 3 s.

    Without the timeout, a dead Tor circuit could leave the TLS-
    shutdown handshake parked indefinitely, blocking the supervisor's
    reconnect cycle. Use a mock writer whose ``wait_closed`` hangs to
    verify the timeout fires.
    """
    from app.services.chain.electrum import ElectrumClient

    client = ElectrumClient(
        "tcp://127.0.0.1:9999",
        connect_timeout_s=1.0,
    )

    class _HangWriter:
        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            await asyncio.sleep(60)  # would block forever without the cap

    client._writer = _HangWriter()  # type: ignore[assignment]
    # Should complete within ~3.5 s, NOT 60 s.
    await asyncio.wait_for(
        client._teardown_connection(reason="test"),
        timeout=5.0,
    )


def test_rebind_loop_if_changed_rebuilds_state_across_loops():
    """The client is a process-wide singleton, but Celery runs each task
    on its own throwaway event loop. ``_rebind_loop_if_changed`` must
    rebuild the loop-bound asyncio state (Events/Locks) when the running
    loop changes — and be a no-op within a single loop.
    """
    client = ElectrumClient("tcp://electrs.test:50001")

    async def snapshot():
        client._rebind_loop_if_changed()
        # A second call on the SAME loop must not rebuild anything.
        before = client._connected
        client._rebind_loop_if_changed()
        assert client._connected is before
        return client._connected, client._write_lock, client._tip_lock, client._loop

    ev1, wl1, tl1, loop1 = asyncio.run(snapshot())
    ev2, wl2, tl2, loop2 = asyncio.run(snapshot())

    assert loop1 is not loop2  # genuinely different loops
    assert ev1 is not ev2  # _connected Event rebuilt on the new loop
    assert wl1 is not wl2  # _write_lock rebuilt
    assert tl1 is not tl2  # _tip_lock rebuilt
