# SPDX-License-Identifier: MIT
"""Async gRPC client for the BOLT 12 onion-message gateway.

This module is the *only* boundary across which Python code talks to
the bare-LDK Rust gateway daemon. Everything in
``app/services/bolt12/`` (the codec) and the upcoming
``Bolt12Service`` orchestrator depends on this client through its
public dataclass surface — never on the generated protobuf types.

Threading model: built on ``grpc.aio``. The client owns one
long-lived ``grpc.aio.Channel``; method calls are coroutines. The
streaming RPC (``stream_inbound``) returns an async iterator; the
caller is responsible for cancelling the underlying call when done.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from types import TracebackType
from typing import Self

import grpc
from grpc.aio import AioRpcError

from app.services.bolt12_gateway._proto import bolt12_gateway_pb2 as pb
from app.services.bolt12_gateway._proto import bolt12_gateway_pb2_grpc as pb_grpc
from app.services.bolt12_gateway.errors import (
    GatewayRpcError,
    GatewayUnavailableError,
    GatewayUnimplementedError,
)
from app.services.bolt12_gateway.types import (
    ConnectPeerResult,
    GatewayIdentity,
    InboundMessage,
    KnownNodeAddresses,
    PeerInfo,
    SendResult,
    SetKnownNodeAddressesResult,
    SetStickyPeersResult,
    StickyPeer,
)

_log = logging.getLogger(__name__)

# Default per-call deadline. Onion-message sends are best-effort; the
# gateway returns once the message is enqueued, which is fast.
_DEFAULT_TIMEOUT_S = 10.0

# Keepalive so a silently-wedged gateway surfaces as a transport error
# rather than a permanently-blocked stream. gRPC pings the peer every
# ``keepalive_time_ms`` and tears the connection down if no ack arrives
# within ``keepalive_timeout_ms``; pinging is permitted even with no
# active calls so an idle channel still detects a dead peer.
_KEEPALIVE_TIME_MS = 30_000
_KEEPALIVE_TIMEOUT_MS = 10_000
_CHANNEL_OPTIONS: list[tuple[str, int]] = [
    ("grpc.keepalive_time_ms", _KEEPALIVE_TIME_MS),
    ("grpc.keepalive_timeout_ms", _KEEPALIVE_TIMEOUT_MS),
    ("grpc.keepalive_permit_without_calls", 1),
    ("grpc.http2.max_pings_without_data", 0),
]

# Upper bound on the gap between inbound stream messages. The gateway
# emits a heartbeat every 30 s (``INBOUND_HEARTBEAT_INTERVAL`` in
# ``bolt12-gateway/src/service.rs``), so on a healthy stream a message —
# real or heartbeat — always arrives well inside this window. A longer
# silence means the stream is wedged and should be torn down so the
# supervisor reconnects rather than blocking inbound processing
# indefinitely. Keep this comfortably above the heartbeat interval so a
# single dropped heartbeat can't trip a spurious reconnect.
_INBOUND_IDLE_TIMEOUT_S = 90.0


class Bolt12GatewayClient:
    """Async wrapper around the ``Bolt12Gateway`` gRPC service.

    Use as an async context manager, or call :meth:`connect` and
    :meth:`close` explicitly:

        async with Bolt12GatewayClient("bolt12-gateway:50061") as gw:
            ident = await gw.get_identity()
    """

    def __init__(
        self,
        target: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT_S,
        auth_token: str | None = None,
        tls_ca_cert_path: str | None = None,
        tls_client_cert_path: str | None = None,
        tls_client_key_path: str | None = None,
        tls_server_name: str | None = None,
    ) -> None:
        self._target = target
        self._timeout = timeout
        self._channel: grpc.aio.Channel | None = None
        self._stub: pb_grpc.Bolt12GatewayStub | None = None
        # Pre-build the per-call metadata so every RPC carries the
        # bearer token if one is configured. Empty token = no auth
        # header (matches gateway-side "no auth" mode).
        self._metadata: tuple[tuple[str, str], ...] = (("authorization", f"Bearer {auth_token}"),) if auth_token else ()
        # ── mTLS configuration ────────────────────────────────────
        # All three paths must be set together. We reject the half-
        # configured case at construction time so callers get a
        # crisp error instead of a confusing transport failure when
        # the first RPC fires.
        tls_paths = (
            tls_ca_cert_path,
            tls_client_cert_path,
            tls_client_key_path,
        )
        set_count = sum(1 for p in tls_paths if p)
        if set_count not in (0, 3):
            raise ValueError(
                "Bolt12GatewayClient TLS configuration is partial: "
                "tls_ca_cert_path, tls_client_cert_path and "
                "tls_client_key_path must be set together (or all "
                "unset for cleartext)."
            )
        self._tls_ca_cert_path = tls_ca_cert_path or None
        self._tls_client_cert_path = tls_client_cert_path or None
        self._tls_client_key_path = tls_client_key_path or None
        self._tls_server_name = tls_server_name or None

    # ── lifecycle ─────────────────────────────────────────────────

    async def connect(self) -> None:
        """Open the underlying gRPC channel. Idempotent."""
        if self._channel is not None:
            return
        if self._tls_ca_cert_path is not None:
            # mTLS: read all three PEM files from disk and build
            # ssl credentials. The gateway terminates TLS and
            # requires a client cert signed by the configured CA.
            # Bearer-token auth is still applied on top of the TLS
            # channel — two layers, two independent revocation
            # surfaces.
            with open(self._tls_ca_cert_path, "rb") as f:
                ca_cert = f.read()
            with open(self._tls_client_cert_path, "rb") as f:  # type: ignore[arg-type]
                client_cert = f.read()
            with open(self._tls_client_key_path, "rb") as f:  # type: ignore[arg-type]
                client_key = f.read()
            credentials = grpc.ssl_channel_credentials(
                root_certificates=ca_cert,
                private_key=client_key,
                certificate_chain=client_cert,
            )
            options: list[tuple[str, object]] = list(_CHANNEL_OPTIONS)
            if self._tls_server_name:
                options.append(("grpc.ssl_target_name_override", self._tls_server_name))
                # Overriding the name the server certificate is verified
                # against decouples TLS identity from the dial target. It is
                # appropriate when connecting by IP to a cert issued for a
                # hostname; flag it so a misconfiguration is visible.
                _log.warning(
                    "bolt12-gateway TLS server-name override active (cert verified as %r, not target %r)",
                    self._tls_server_name,
                    self._target,
                )
            self._channel = grpc.aio.secure_channel(
                self._target,
                credentials,
                options=options,
            )
            _log.info(
                "opened bolt12-gateway TLS channel to %s (ca=%s)",
                self._target,
                self._tls_ca_cert_path,
            )
        else:
            # Cleartext. Appropriate when the gateway sits on a
            # private docker network with ``internal: true`` and the
            # bearer token is the only credential in play.
            self._channel = grpc.aio.insecure_channel(self._target, options=list(_CHANNEL_OPTIONS))
            _log.debug("opened bolt12-gateway channel to %s", self._target)
        self._stub = pb_grpc.Bolt12GatewayStub(self._channel)

    async def close(self) -> None:
        """Close the underlying channel. Idempotent."""
        if self._channel is None:
            return
        ch = self._channel
        self._channel = None
        self._stub = None
        try:
            await ch.close()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            _log.exception("error closing bolt12-gateway channel")

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    def _require_stub(self) -> pb_grpc.Bolt12GatewayStub:
        if self._stub is None:
            raise GatewayUnavailableError("client not connected; call connect() first")
        return self._stub

    # ── unary RPCs ────────────────────────────────────────────────

    async def get_identity(self) -> GatewayIdentity:
        """Return the gateway's node-id and current peer state."""
        stub = self._require_stub()
        try:
            resp: pb.GetIdentityResponse = await stub.GetIdentity(
                pb.GetIdentityRequest(),
                timeout=self._timeout,
                metadata=self._metadata,
            )
        except AioRpcError as e:
            raise _translate(e) from e
        return GatewayIdentity(
            node_id=bytes(resp.node_id),
            connected_peers=resp.connected_peers,
            peers=tuple(_peer_from_pb(p) for p in resp.peers),
            version=resp.version,
            network=resp.network,
        )

    async def send_onion_message(
        self,
        *,
        payload: bytes,
        payload_tlv_type: int,
        direct_node_id: bytes | None = None,
        blinded_path: bytes | None = None,
        reply_path: bytes | None = None,
    ) -> SendResult:
        """Send a single onion message.

        Exactly one of ``direct_node_id`` (33-byte compressed pubkey)
        or ``blinded_path`` (serialized BOLT 12 ``BlindedPath``) must
        be provided. ``payload`` is the inner TLV stream — typically
        a serialized ``invoice_request`` or ``invoice``.
        """
        if (direct_node_id is None) == (blinded_path is None):
            raise ValueError("exactly one of direct_node_id or blinded_path must be set")
        stub = self._require_stub()

        req = pb.SendOnionMessageRequest(
            payload=payload,
            payload_tlv_type=payload_tlv_type,
        )
        if direct_node_id is not None:
            req.direct_node_id = direct_node_id
        else:
            assert blinded_path is not None
            req.blinded_path.serialized = blinded_path
        if reply_path is not None:
            req.reply_path.serialized = reply_path

        try:
            resp: pb.SendOnionMessageResponse = await stub.SendOnionMessage(
                req, timeout=self._timeout, metadata=self._metadata
            )
        except AioRpcError as e:
            raise _translate(e) from e
        return SendResult(send_id=resp.send_id)

    async def create_blinded_path(
        self,
        *,
        introduction_node_candidates: Iterable[bytes],
        dummy_hops: int = 0,
        context: bytes = b"",
    ) -> bytes:
        """Build a blinded message-path terminating at this gateway.

        Returns the serialized BOLT 12 ``BlindedPath`` bytes ready to
        embed in a TLV.
        """
        if dummy_hops < 0 or dummy_hops > 7:
            raise ValueError("dummy_hops must be in [0, 7]")
        if len(context) > 256:
            raise ValueError("context must be ≤ 256 bytes")
        candidates = [bytes(c) for c in introduction_node_candidates]
        if not candidates:
            raise ValueError("at least one introduction-node candidate required")

        stub = self._require_stub()
        req = pb.CreateBlindedPathRequest(
            introduction_node_candidates=candidates,
            dummy_hops=dummy_hops,
            context=context,
        )
        try:
            resp: pb.CreateBlindedPathResponse = await stub.CreateBlindedPath(
                req, timeout=self._timeout, metadata=self._metadata
            )
        except AioRpcError as e:
            raise _translate(e) from e
        return bytes(resp.path.serialized)

    async def connect_peer(self, *, node_id: bytes, address: str) -> ConnectPeerResult:
        """Connect to a peer. Idempotent."""
        if len(node_id) != 33:
            raise ValueError("node_id must be 33 bytes (compressed pubkey)")
        stub = self._require_stub()
        req = pb.ConnectPeerRequest(node_id=node_id, address=address)
        try:
            resp: pb.ConnectPeerResponse = await stub.ConnectPeer(req, timeout=self._timeout, metadata=self._metadata)
        except AioRpcError as e:
            raise _translate(e) from e
        return ConnectPeerResult(already_connected=resp.already_connected)

    async def set_sticky_peers(self, peers: tuple[StickyPeer, ...] | list[StickyPeer]) -> SetStickyPeersResult:
        """Replace the gateway's sticky-peer set.

        REPLACE semantics — entries absent from ``peers`` are dropped
        on the next reconnect-loop tick. Callers MUST push the full
        desired set every time; the gateway treats the wire payload
        as authoritative.

        Pushing on a schedule (e.g. every 30 s) recovers from a
        gateway restart that lost its in-memory cache — the next
        push rebuilds it from scratch.
        """
        for i, p in enumerate(peers):
            if len(p.node_id) != 33:
                raise ValueError(f"peers[{i}].node_id must be 33 bytes (compressed pubkey)")
            if not p.address:
                raise ValueError(f"peers[{i}].address must not be empty")
        stub = self._require_stub()
        req = pb.SetStickyPeersRequest(
            peers=[pb.StickyPeer(node_id=p.node_id, address=p.address) for p in peers],
        )
        try:
            resp: pb.SetStickyPeersResponse = await stub.SetStickyPeers(
                req,
                timeout=self._timeout,
                metadata=self._metadata,
            )
        except AioRpcError as e:
            raise _translate(e) from e
        return SetStickyPeersResult(sticky_count=resp.sticky_count)

    async def set_known_node_addresses(
        self,
        entries: tuple[KnownNodeAddresses, ...] | list[KnownNodeAddresses],
    ) -> SetKnownNodeAddressesResult:
        """Push the gateway's address-cache (REPLACE semantics).

        The gateway consults this cache from its
        ``Event::ConnectionNeeded`` handler when LDK has buffered an
        outbound onion message for a peer we're not yet connected
        to and neither the event hint nor the LDK ``NetworkGraph``
        carries an address. The cache is the load-bearing source on
        production: the gateway intentionally ignores gossip
        routing messages to keep its memory footprint small, so a
        peer we don't already peer with is unreachable without this
        push.

        Each call REPLACES the gateway's cache wholesale. Entries
        absent from ``entries`` are dropped immediately on the
        gateway side — callers MUST push the full desired set every
        time. The caller's freshness policy (how often the push
        runs, which subset of the LND graph it includes) is
        authoritative; the gateway only enforces a per-entry TTL on
        lookup as a safety net.

        Raises ``ValueError`` if any entry has a malformed
        ``node_id`` (must be 33 bytes) or a blank address. The
        gateway also validates server-side, so a partial validation
        on either side is enough to keep a bad row from poisoning
        the cache.
        """
        for i, e in enumerate(entries):
            if len(e.node_id) != 33:
                raise ValueError(f"entries[{i}].node_id must be 33 bytes (compressed pubkey)")
            for j, addr in enumerate(e.addresses):
                if not addr or not addr.strip():
                    raise ValueError(f"entries[{i}].addresses[{j}] must not be empty")
        stub = self._require_stub()

        # gRPC client-streaming: build an async iterator that yields
        # one NodeAddresses per entry. Buffered in memory because
        # the caller's input is already materialised (typically
        # 5 000 entries × ~100 B = 500 KB).
        async def _request_iter() -> AsyncIterator[pb.NodeAddresses]:
            for e in entries:
                yield pb.NodeAddresses(
                    node_id=e.node_id,
                    addresses=list(e.addresses),
                    node_announcement_timestamp=int(e.node_announcement_timestamp),
                )

        try:
            resp: pb.SetKnownNodeAddressesResponse = await stub.SetKnownNodeAddresses(
                _request_iter(),
                timeout=self._timeout,
                metadata=self._metadata,
            )
        except AioRpcError as e:
            raise _translate(e) from e
        return SetKnownNodeAddressesResult(accepted_count=resp.accepted_count)

    # ── server-streaming RPC ──────────────────────────────────────

    @asynccontextmanager
    async def stream_inbound(self) -> AsyncIterator[AsyncIterator[InboundMessage]]:
        """Async context manager yielding an iterator of inbound messages.

        Usage:

            async with client.stream_inbound() as stream:
                async for msg in stream:
                    handle(msg)

        Exiting the ``with`` block cancels the underlying call so the
        gateway can free resources promptly.
        """
        stub = self._require_stub()
        call = stub.StreamInbound(pb.StreamInboundRequest(), metadata=self._metadata)
        try:
            yield _wrap_inbound(call)
        finally:
            call.cancel()


# ── helpers ───────────────────────────────────────────────────────


async def _wrap_inbound(call: object) -> AsyncIterator[InboundMessage]:
    """Translate the raw streaming-call iterator into our dataclass.

    Each message is awaited with an idle deadline: if the gateway falls
    silent for longer than ``_INBOUND_IDLE_TIMEOUT_S`` the call is
    cancelled and the stream ends with a transport error, so the
    supervisor reconnects instead of blocking inbound processing.

    The gateway emits periodic heartbeat messages so the idle deadline
    measures *liveness*, not *traffic*: real onion messages can be
    arbitrarily far apart, but a heartbeat arrives well inside the
    window on a healthy stream. Heartbeats reset the deadline (like any
    received message) and are then dropped here — they carry no payload
    and must never reach the dispatcher.
    """
    iterator = call.__aiter__()  # type: ignore[attr-defined]
    try:
        while True:
            try:
                raw = await asyncio.wait_for(iterator.__anext__(), timeout=_INBOUND_IDLE_TIMEOUT_S)
            except StopAsyncIteration:
                return
            except asyncio.TimeoutError as e:
                call.cancel()  # type: ignore[attr-defined]
                raise GatewayUnavailableError(
                    f"inbound stream idle for {_INBOUND_IDLE_TIMEOUT_S:.0f}s"
                ) from e
            # Heartbeats exist only to reset the idle deadline above;
            # swallow them so the dispatcher never sees a payload-less
            # pseudo-message.
            if raw.heartbeat:
                continue
            yield _inbound_from_pb(raw)
    except AioRpcError as e:
        # Cancellation by the consumer is normal — swallow it.
        if e.code() == grpc.StatusCode.CANCELLED:
            return
        raise _translate(e) from e


def _peer_from_pb(p: pb.PeerInfo) -> PeerInfo:
    return PeerInfo(
        node_id=bytes(p.node_id),
        address=p.address,
        inbound=p.inbound,
        advertises_onion_messages=p.advertises_onion_messages,
    )


def _inbound_from_pb(m: pb.InboundOnionMessage) -> InboundMessage:
    reply = bytes(m.reply_path.serialized) if m.HasField("reply_path") else None
    # An empty reply path serializes as zero bytes — treat as "absent".
    if reply == b"":
        reply = None
    return InboundMessage(
        recv_id=m.recv_id,
        payload_tlv_type=m.payload_tlv_type,
        payload=bytes(m.payload),
        reply_path=reply,
        received_at_ms=m.received_at_ms,
        inbound_context=bytes(m.inbound_context),
    )


def _translate(e: AioRpcError) -> GatewayError:  # type: ignore[name-defined]
    """Map gRPC status codes to our typed exception hierarchy."""
    code = e.code()
    details = e.details() or ""
    if code == grpc.StatusCode.UNAVAILABLE:
        return GatewayUnavailableError(details)
    if code == grpc.StatusCode.UNIMPLEMENTED:
        return GatewayUnimplementedError(details)
    return GatewayRpcError(code.name if code else "UNKNOWN", details)


# Re-import for the `_translate` return-type annotation above.
from app.services.bolt12_gateway.errors import GatewayError  # noqa: E402
