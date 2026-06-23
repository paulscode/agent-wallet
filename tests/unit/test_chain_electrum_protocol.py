# SPDX-License-Identifier: MIT
"""Unit tests for ``ElectrumClient`` framing, dispatch and reconnect.

These tests use a real in-process TCP server
(:mod:`tests.unit._fake_electrum`) so they exercise the actual
asyncio framing layer rather than mocking it out.
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


async def _wait_until(predicate, *, timeout: float = 5.0, interval: float = 0.01) -> bool:
    """Poll ``predicate`` until true or ``timeout`` (wall-clock) elapses.

    Bounds the wait by elapsed time rather than a fixed iteration count, so
    a loaded CI machine gets the same generous deadline a fast one does.
    Returns the final predicate value for the caller to assert on.
    """
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return bool(predicate())


@pytest.mark.asyncio
async def test_handshake_populates_tip_height() -> None:
    async with FakeElectrumServer() as server:
        server.set_response(
            "blockchain.headers.subscribe",
            {"height": 850_001, "hex": "00" * 80},
        )
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        try:
            await client.start(wait_for_connect=True)
            assert client.cached_tip_height == 850_001
            # Handshake performed both calls.
            methods = [m for m, _ in server.calls]
            assert "server.version" in methods
            assert "blockchain.headers.subscribe" in methods
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_request_response_correlation() -> None:
    async with FakeElectrumServer() as server:
        server.set_response("blockchain.estimatefee", 0.00012345)
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        try:
            await client.start(wait_for_connect=True)
            result = await client.request("blockchain.estimatefee", [6])
            assert result == 0.00012345
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_protocol_error_raises_typed_exception() -> None:
    async with FakeElectrumServer() as server:
        server.set_error("blockchain.transaction.get", -32600, "missing tx")
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        try:
            await client.start(wait_for_connect=True)
            with pytest.raises(ElectrumProtocolError) as ei:
                await client.request("blockchain.transaction.get", ["00" * 32])
            assert ei.value.code == -32600
            assert "missing tx" in str(ei.value)
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_concurrent_requests_dispatched_correctly() -> None:
    """Many in-flight requests must each receive their own response."""
    async with FakeElectrumServer() as server:

        async def echo(params: list) -> int:
            await asyncio.sleep(0.01)
            return params[0] * 2

        server.set_handler("test.echo_double", echo)
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        try:
            await client.start(wait_for_connect=True)
            results = await asyncio.gather(*[client.request("test.echo_double", [i]) for i in range(20)])
            assert results == [i * 2 for i in range(20)]
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_headers_notification_updates_cached_tip() -> None:
    async with FakeElectrumServer() as server:
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        try:
            await client.start(wait_for_connect=True)
            assert client.cached_tip_height == 800_000

            await server.notify_headers(800_001)
            # Allow the read loop to dispatch.
            await _wait_until(lambda: client.cached_tip_height == 800_001)
            assert client.cached_tip_height == 800_001
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_scripthash_subscription_callback_invoked() -> None:
    async with FakeElectrumServer() as server:
        # subscribe() returns the current status (None when fresh).
        server.set_response("blockchain.scripthash.subscribe", None)
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        received: list[tuple[str, str | None]] = []

        async def on_change(sh: str, status: str | None) -> None:
            received.append((sh, status))

        try:
            await client.start(wait_for_connect=True)
            sh = "ab" * 32
            await client.subscribe_scripthash(sh, on_change)
            await server.notify_scripthash(sh, "deadbeef")
            await _wait_until(lambda: bool(received))
            assert received == [(sh, "deadbeef")]
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_subscription_replayed_on_reconnect() -> None:
    async with FakeElectrumServer() as server:
        server.set_response("blockchain.scripthash.subscribe", None)
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        try:
            await client.start(wait_for_connect=True)
            sh = "cd" * 32

            async def _noop(*_: object) -> None:
                pass

            await client.subscribe_scripthash(sh, _noop)
            assert server.calls.count(("blockchain.scripthash.subscribe", [sh])) == 1

            # Force the supervisor to reconnect.
            await server.disconnect_all()
            await _wait_until(
                lambda: server.connection_count >= 2 and client.is_connected,
                timeout=10.0,
            )
            assert server.connection_count >= 2
            # Wait for the subscription to replay on the new connection.
            await _wait_until(lambda: server.calls.count(("blockchain.scripthash.subscribe", [sh])) >= 2)
            assert server.calls.count(("blockchain.scripthash.subscribe", [sh])) >= 2
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_pending_request_fails_on_disconnect() -> None:
    async with FakeElectrumServer() as server:

        async def slow(_params: list) -> int:
            await asyncio.sleep(5.0)
            return 0

        server.set_handler("test.slow", slow)
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=10.0)
        try:
            await client.start(wait_for_connect=True)
            # Fire and disconnect.
            task = asyncio.create_task(client.request("test.slow", []))
            await asyncio.sleep(0.05)
            await server.disconnect_all()
            with pytest.raises(ElectrumDisconnectedError):
                await asyncio.wait_for(task, timeout=2.0)
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_subscription_cap_enforced() -> None:
    async with FakeElectrumServer() as server:
        server.set_response("blockchain.scripthash.subscribe", None)
        client = ElectrumClient(
            server.url,
            connect_timeout_s=2.0,
            request_timeout_s=2.0,
            max_subscriptions=2,
        )

        async def _noop(*_: object) -> None:
            pass

        try:
            await client.start(wait_for_connect=True)
            await client.subscribe_scripthash("00" * 32, _noop)
            await client.subscribe_scripthash("11" * 32, _noop)
            with pytest.raises(RuntimeError, match="cap"):
                await client.subscribe_scripthash("22" * 32, _noop)
            # Re-subscribing an existing scripthash is allowed.
            await client.subscribe_scripthash("00" * 32, _noop)
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_unsubscribe_removes_callback() -> None:
    async with FakeElectrumServer() as server:
        server.set_response("blockchain.scripthash.subscribe", None)
        server.set_response("blockchain.scripthash.unsubscribe", True)
        client = ElectrumClient(server.url, connect_timeout_s=2.0, request_timeout_s=2.0)
        received: list[str] = []

        async def cb(sh: str, _status: str | None) -> None:
            received.append(sh)

        try:
            await client.start(wait_for_connect=True)
            sh = "ee" * 32
            await client.subscribe_scripthash(sh, cb)
            await client.unsubscribe_scripthash(sh, cb)
            await server.notify_scripthash(sh, None)
            await asyncio.sleep(0.05)
            assert received == []
        finally:
            await client.close()


class TestBuildSSLContextHardening:
    """Regression guards for ``_build_ssl_context``.

    A non-onion host with verification enabled must NEVER fall back to
    ``CERT_NONE`` / disabled hostname checking — that path is reserved
    for ``.onion`` (Tor supplies the identity) or an explicit opt-out.
    """

    def test_clearnet_verify_keeps_full_tls_verification(self) -> None:
        import ssl as _ssl

        from app.services.chain.electrum_protocol import _build_ssl_context

        ctx = _build_ssl_context(verify=True, ca_cert="", server_hostname="electrum.example.com", is_onion=False)
        assert ctx.check_hostname is True
        assert ctx.verify_mode == _ssl.CERT_REQUIRED

    def test_onion_disables_verification_regardless_of_verify_flag(self) -> None:
        import ssl as _ssl

        from app.services.chain.electrum_protocol import _build_ssl_context

        ctx = _build_ssl_context(verify=True, ca_cert="", server_hostname="abc.onion", is_onion=True)
        assert ctx.check_hostname is False
        assert ctx.verify_mode == _ssl.CERT_NONE

    def test_clearnet_explicit_no_verify_opts_out(self) -> None:
        import ssl as _ssl

        from app.services.chain.electrum_protocol import _build_ssl_context

        ctx = _build_ssl_context(verify=False, ca_cert="", server_hostname="electrum.example.com", is_onion=False)
        assert ctx.verify_mode == _ssl.CERT_NONE
