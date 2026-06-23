# SPDX-License-Identifier: MIT
"""Tests for ``Bolt12GatewayClient`` against an in-process gRPC server.

We spin up a tiny ``grpc.aio`` server backed by a stub
``Bolt12GatewayServicer`` to validate the client without depending
on the Rust gateway binary. The Rust side is exercised separately by
``cargo test``.
"""

from __future__ import annotations

import asyncio

import grpc
import pytest
from grpc.aio import ServicerContext

from app.services.bolt12_gateway import (
    Bolt12GatewayClient,
    GatewayUnavailableError,
    GatewayUnimplementedError,
)
from app.services.bolt12_gateway._proto import (
    bolt12_gateway_pb2 as pb,
)
from app.services.bolt12_gateway._proto import (
    bolt12_gateway_pb2_grpc as pb_grpc,
)


class _FakeServicer(pb_grpc.Bolt12GatewayServicer):
    """In-memory implementation that records calls for assertions."""

    def __init__(self) -> None:
        self.identity_calls = 0
        self.send_calls: list[pb.SendOnionMessageRequest] = []
        self.connect_calls: list[pb.ConnectPeerRequest] = []
        self.create_path_calls: list[pb.CreateBlindedPathRequest] = []
        self.sticky_calls: list[pb.SetStickyPeersRequest] = []
        self.known_addr_calls: list[list[pb.NodeAddresses]] = []
        self.inbound_queue: asyncio.Queue[pb.InboundOnionMessage] = asyncio.Queue()
        self.unimplemented_send = False

    async def GetIdentity(self, request: pb.GetIdentityRequest, context: ServicerContext) -> pb.GetIdentityResponse:
        self.identity_calls += 1
        peer = pb.PeerInfo(
            node_id=b"\x02" + b"\x11" * 32,
            address="example:9735",
            inbound=False,
            advertises_onion_messages=True,
        )
        return pb.GetIdentityResponse(
            node_id=b"\x03" + b"\xab" * 32,
            connected_peers=1,
            peers=[peer],
            version="0.1.0-test",
        )

    async def SendOnionMessage(
        self, request: pb.SendOnionMessageRequest, context: ServicerContext
    ) -> pb.SendOnionMessageResponse:
        if self.unimplemented_send:
            await context.abort(grpc.StatusCode.UNIMPLEMENTED, "test stub")
        self.send_calls.append(request)
        return pb.SendOnionMessageResponse(send_id="send-1")

    async def CreateBlindedPath(
        self, request: pb.CreateBlindedPathRequest, context: ServicerContext
    ) -> pb.CreateBlindedPathResponse:
        self.create_path_calls.append(request)
        return pb.CreateBlindedPathResponse(path=pb.BlindedMessagePathBytes(serialized=b"\xde\xad\xbe\xef"))

    async def ConnectPeer(self, request: pb.ConnectPeerRequest, context: ServicerContext) -> pb.ConnectPeerResponse:
        self.connect_calls.append(request)
        return pb.ConnectPeerResponse(already_connected=False)

    async def SetStickyPeers(
        self, request: pb.SetStickyPeersRequest, context: ServicerContext
    ) -> pb.SetStickyPeersResponse:
        self.sticky_calls.append(request)
        return pb.SetStickyPeersResponse(sticky_count=len(request.peers))

    async def SetKnownNodeAddresses(
        self, request_iterator, context: ServicerContext
    ) -> pb.SetKnownNodeAddressesResponse:
        # Drain the client-streaming request into a per-call list so
        # tests can assert the exact wire shape the client emitted.
        captured: list[pb.NodeAddresses] = []
        async for msg in request_iterator:
            captured.append(msg)
        self.known_addr_calls.append(captured)
        return pb.SetKnownNodeAddressesResponse(
            accepted_count=len(captured),
        )

    async def StreamInbound(self, request: pb.StreamInboundRequest, context: ServicerContext):  # type: ignore[no-untyped-def]
        while True:
            msg = await self.inbound_queue.get()
            yield msg


@pytest.fixture
async def gateway() -> tuple[_FakeServicer, str]:
    """Start an in-process server, yield (servicer, target)."""
    servicer = _FakeServicer()
    server = grpc.aio.server()
    pb_grpc.add_Bolt12GatewayServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()
    try:
        yield servicer, f"127.0.0.1:{port}"
    finally:
        await server.stop(grace=0.1)


# ── unary RPCs ────────────────────────────────────────────────────


async def test_get_identity_returns_dataclass(gateway: tuple[_FakeServicer, str]) -> None:
    servicer, target = gateway
    async with Bolt12GatewayClient(target) as client:
        ident = await client.get_identity()
    assert servicer.identity_calls == 1
    assert len(ident.node_id) == 33 and ident.node_id[0] == 0x03
    assert ident.connected_peers == 1
    assert ident.version == "0.1.0-test"
    assert len(ident.peers) == 1
    peer = ident.peers[0]
    assert peer.address == "example:9735"
    assert peer.inbound is False
    assert peer.advertises_onion_messages is True


async def test_send_onion_message_direct(gateway: tuple[_FakeServicer, str]) -> None:
    servicer, target = gateway
    async with Bolt12GatewayClient(target) as client:
        result = await client.send_onion_message(
            payload=b"hello",
            payload_tlv_type=64,
            direct_node_id=b"\x02" + b"\x22" * 32,
        )
    assert result.send_id == "send-1"
    assert len(servicer.send_calls) == 1
    req = servicer.send_calls[0]
    assert req.payload == b"hello"
    assert req.payload_tlv_type == 64
    assert req.WhichOneof("destination") == "direct_node_id"
    assert req.direct_node_id == b"\x02" + b"\x22" * 32


async def test_send_onion_message_blinded(gateway: tuple[_FakeServicer, str]) -> None:
    servicer, target = gateway
    async with Bolt12GatewayClient(target) as client:
        await client.send_onion_message(
            payload=b"x",
            payload_tlv_type=66,
            blinded_path=b"\x01\x02\x03",
            reply_path=b"\xaa\xbb",
        )
    req = servicer.send_calls[0]
    assert req.WhichOneof("destination") == "blinded_path"
    assert req.blinded_path.serialized == b"\x01\x02\x03"
    assert req.reply_path.serialized == b"\xaa\xbb"


async def test_send_requires_exactly_one_destination(gateway: tuple[_FakeServicer, str]) -> None:
    _, target = gateway
    async with Bolt12GatewayClient(target) as client:
        with pytest.raises(ValueError, match="exactly one"):
            await client.send_onion_message(payload=b"", payload_tlv_type=64)
        with pytest.raises(ValueError, match="exactly one"):
            await client.send_onion_message(
                payload=b"",
                payload_tlv_type=64,
                direct_node_id=b"\x02" + b"\x00" * 32,
                blinded_path=b"\x01",
            )


async def test_create_blinded_path(gateway: tuple[_FakeServicer, str]) -> None:
    servicer, target = gateway
    async with Bolt12GatewayClient(target) as client:
        path = await client.create_blinded_path(
            introduction_node_candidates=[b"\x02" + b"\x33" * 32],
            dummy_hops=2,
            context=b"correlation-1",
        )
    assert path == b"\xde\xad\xbe\xef"
    req = servicer.create_path_calls[0]
    assert req.dummy_hops == 2
    assert req.context == b"correlation-1"
    assert list(req.introduction_node_candidates) == [b"\x02" + b"\x33" * 32]


async def test_create_blinded_path_validates_args(gateway: tuple[_FakeServicer, str]) -> None:
    _, target = gateway
    async with Bolt12GatewayClient(target) as client:
        with pytest.raises(ValueError, match="dummy_hops"):
            await client.create_blinded_path(
                introduction_node_candidates=[b"\x02" + b"\x33" * 32],
                dummy_hops=8,
            )
        with pytest.raises(ValueError, match="context"):
            await client.create_blinded_path(
                introduction_node_candidates=[b"\x02" + b"\x33" * 32],
                context=b"x" * 257,
            )
        with pytest.raises(ValueError, match="introduction-node"):
            await client.create_blinded_path(introduction_node_candidates=[])


async def test_connect_peer(gateway: tuple[_FakeServicer, str]) -> None:
    servicer, target = gateway
    async with Bolt12GatewayClient(target) as client:
        result = await client.connect_peer(
            node_id=b"\x02" + b"\x44" * 32,
            address="onion:9735",
        )
    assert result.already_connected is False
    assert servicer.connect_calls[0].address == "onion:9735"


async def test_connect_peer_validates_node_id(gateway: tuple[_FakeServicer, str]) -> None:
    _, target = gateway
    async with Bolt12GatewayClient(target) as client:
        with pytest.raises(ValueError, match="33 bytes"):
            await client.connect_peer(node_id=b"\x02", address="x:1")


# ── set_sticky_peers ──────────────────────────────────────────────


async def test_set_sticky_peers_pushes_set(gateway: tuple[_FakeServicer, str]) -> None:
    from app.services.bolt12_gateway import StickyPeer

    servicer, target = gateway
    async with Bolt12GatewayClient(target) as client:
        result = await client.set_sticky_peers(
            (
                StickyPeer(node_id=b"\x02" + b"\xaa" * 32, address="1.1.1.1:9735"),
                StickyPeer(node_id=b"\x03" + b"\xbb" * 32, address="2.2.2.2:9735"),
            ),
        )
    assert result.sticky_count == 2
    assert len(servicer.sticky_calls) == 1
    pushed = list(servicer.sticky_calls[0].peers)
    assert {p.address for p in pushed} == {"1.1.1.1:9735", "2.2.2.2:9735"}


async def test_set_sticky_peers_empty_set_clears(gateway: tuple[_FakeServicer, str]) -> None:
    # Push an empty set — used to clear a stale gateway cache (e.g.
    # when the wallet no longer has any matching default-receive
    # offers). The gateway must accept this and report sticky_count=0.
    servicer, target = gateway
    async with Bolt12GatewayClient(target) as client:
        result = await client.set_sticky_peers([])
    assert result.sticky_count == 0
    assert len(servicer.sticky_calls) == 1
    assert list(servicer.sticky_calls[0].peers) == []


async def test_set_sticky_peers_validates_node_id(gateway: tuple[_FakeServicer, str]) -> None:
    from app.services.bolt12_gateway import StickyPeer

    _, target = gateway
    async with Bolt12GatewayClient(target) as client:
        with pytest.raises(ValueError, match="33 bytes"):
            await client.set_sticky_peers(
                (StickyPeer(node_id=b"\x02", address="x:1"),),
            )


async def test_set_sticky_peers_validates_address(gateway: tuple[_FakeServicer, str]) -> None:
    from app.services.bolt12_gateway import StickyPeer

    _, target = gateway
    async with Bolt12GatewayClient(target) as client:
        with pytest.raises(ValueError, match="address"):
            await client.set_sticky_peers(
                (StickyPeer(node_id=b"\x02" + b"\xaa" * 32, address=""),),
            )


# ── set_known_node_addresses ──────────────────────────────────────


async def test_set_known_node_addresses_pushes_stream(
    gateway: tuple[_FakeServicer, str],
) -> None:
    """Happy path: a multi-entry push lands on the server with all
    fields verbatim. The wire is client-streaming, so the servicer
    drains an async iterator — pin the iteration semantics so a
    future refactor that batches into a single unary call regresses
    explicitly."""
    from app.services.bolt12_gateway import KnownNodeAddresses

    servicer, target = gateway
    async with Bolt12GatewayClient(target) as client:
        result = await client.set_known_node_addresses(
            (
                KnownNodeAddresses(
                    node_id=b"\x02" + b"\xaa" * 32,
                    addresses=("primary.onion:9735", "1.1.1.1:9735"),
                    node_announcement_timestamp=100,
                ),
                KnownNodeAddresses(
                    node_id=b"\x03" + b"\xbb" * 32,
                    addresses=("only.onion:9735",),
                    node_announcement_timestamp=200,
                ),
            ),
        )
    assert result.accepted_count == 2
    assert len(servicer.known_addr_calls) == 1
    pushed = servicer.known_addr_calls[0]
    assert len(pushed) == 2
    assert pushed[0].node_announcement_timestamp == 100
    assert list(pushed[0].addresses) == ["primary.onion:9735", "1.1.1.1:9735"]
    assert pushed[1].node_announcement_timestamp == 200
    assert list(pushed[1].addresses) == ["only.onion:9735"]


async def test_set_known_node_addresses_empty_set_clears_cache(
    gateway: tuple[_FakeServicer, str],
) -> None:
    """An empty push is a legitimate REPLACE-with-nothing call — the
    gateway's cache must be cleared. The client must not refuse the
    empty case; the responsibility for "should we skip an empty
    push?" lives in the caller (``node_address_pusher`` does)."""
    servicer, target = gateway
    async with Bolt12GatewayClient(target) as client:
        result = await client.set_known_node_addresses([])
    assert result.accepted_count == 0
    assert len(servicer.known_addr_calls) == 1
    assert servicer.known_addr_calls[0] == []


async def test_set_known_node_addresses_validates_node_id_length(
    gateway: tuple[_FakeServicer, str],
) -> None:
    """A wrong-length pubkey (32 vs 33 bytes is the most likely
    Python mistake) must fail client-side BEFORE we open the gRPC
    stream — burning a Tor round-trip on a known-bad payload is
    avoidable. Mirrors ``set_sticky_peers`` validation contract."""
    from app.services.bolt12_gateway import KnownNodeAddresses

    _, target = gateway
    async with Bolt12GatewayClient(target) as client:
        with pytest.raises(ValueError, match="33 bytes"):
            await client.set_known_node_addresses(
                (
                    KnownNodeAddresses(
                        node_id=b"\x02",  # too short
                        addresses=("x:1",),
                        node_announcement_timestamp=0,
                    ),
                ),
            )


async def test_set_known_node_addresses_validates_blank_address(
    gateway: tuple[_FakeServicer, str],
) -> None:
    """Blank / whitespace-only addresses would waste a dial-candidate
    slot. Reject client-side so we don't even ship them across the
    wire."""
    from app.services.bolt12_gateway import KnownNodeAddresses

    _, target = gateway
    async with Bolt12GatewayClient(target) as client:
        with pytest.raises(ValueError, match="addresses\\[1\\]"):
            await client.set_known_node_addresses(
                (
                    KnownNodeAddresses(
                        node_id=b"\x02" + b"\xcc" * 32,
                        addresses=("good:9735", "   "),
                        node_announcement_timestamp=0,
                    ),
                ),
            )


# ── status code mapping ───────────────────────────────────────────


async def test_unimplemented_translates(gateway: tuple[_FakeServicer, str]) -> None:
    servicer, target = gateway
    servicer.unimplemented_send = True
    async with Bolt12GatewayClient(target) as client:
        with pytest.raises(GatewayUnimplementedError):
            await client.send_onion_message(
                payload=b"",
                payload_tlv_type=64,
                direct_node_id=b"\x02" + b"\x55" * 32,
            )


async def test_not_connected_raises_unavailable() -> None:
    client = Bolt12GatewayClient("127.0.0.1:1")
    with pytest.raises(GatewayUnavailableError):
        await client.get_identity()


async def test_close_is_idempotent(gateway: tuple[_FakeServicer, str]) -> None:
    _, target = gateway
    client = Bolt12GatewayClient(target)
    await client.connect()
    await client.connect()  # second is a no-op
    await client.close()
    await client.close()  # idempotent


# ── streaming RPC ─────────────────────────────────────────────────


async def test_stream_inbound_yields_messages(gateway: tuple[_FakeServicer, str]) -> None:
    servicer, target = gateway

    # Pre-populate two messages.
    servicer.inbound_queue.put_nowait(
        pb.InboundOnionMessage(
            recv_id="r1",
            payload_tlv_type=66,
            payload=b"\xa0",
            received_at_ms=1700000000000,
        )
    )
    servicer.inbound_queue.put_nowait(
        pb.InboundOnionMessage(
            recv_id="r2",
            payload_tlv_type=66,
            payload=b"\xa1",
            reply_path=pb.BlindedMessagePathBytes(serialized=b"\xbb"),
            received_at_ms=1700000000001,
            inbound_context=b"ctx-2",
        )
    )

    received: list[tuple[str, bytes | None, bytes]] = []
    async with Bolt12GatewayClient(target) as client:
        async with client.stream_inbound() as stream:
            async for msg in stream:
                received.append((msg.recv_id, msg.reply_path, msg.inbound_context))
                if len(received) == 2:
                    break

    assert received == [
        ("r1", None, b""),
        ("r2", b"\xbb", b"ctx-2"),
    ]


async def test_stream_inbound_drops_heartbeats(gateway: tuple[_FakeServicer, str]) -> None:
    # Heartbeats interleaved with real messages must be swallowed by the
    # client and never surface to the consumer — they exist only to keep
    # the inbound-idle watchdog from tripping on a quiet stream.
    servicer, target = gateway

    servicer.inbound_queue.put_nowait(pb.InboundOnionMessage(heartbeat=True))
    servicer.inbound_queue.put_nowait(
        pb.InboundOnionMessage(
            recv_id="r1",
            payload_tlv_type=66,
            payload=b"\xa0",
            received_at_ms=1700000000000,
        )
    )
    servicer.inbound_queue.put_nowait(pb.InboundOnionMessage(heartbeat=True))
    servicer.inbound_queue.put_nowait(
        pb.InboundOnionMessage(
            recv_id="r2",
            payload_tlv_type=66,
            payload=b"\xa1",
            received_at_ms=1700000000001,
        )
    )

    received: list[str] = []
    async with Bolt12GatewayClient(target) as client:
        async with client.stream_inbound() as stream:
            async for msg in stream:
                received.append(msg.recv_id)
                if len(received) == 2:
                    break

    assert received == ["r1", "r2"]


async def test_stream_cancellation_is_clean(gateway: tuple[_FakeServicer, str]) -> None:
    _, target = gateway
    async with Bolt12GatewayClient(target) as client:
        async with client.stream_inbound() as stream:
            # Exit immediately without consuming anything.
            assert stream is not None
    # Should not raise.
