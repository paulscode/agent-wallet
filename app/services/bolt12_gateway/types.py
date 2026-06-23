# SPDX-License-Identifier: MIT
"""Public dataclass types exposed by ``Bolt12GatewayClient``.

These wrap the generated protobuf messages so callers in
``app.services.*`` and ``app.api.*`` never see protobuf-generated
classes directly. That keeps the protobuf module under
``_proto/`` a private implementation detail and lets us swap codecs
without touching the rest of the codebase.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PeerInfo:
    """A peer we are (or were) connected to."""

    node_id: bytes
    address: str
    inbound: bool
    advertises_onion_messages: bool


@dataclass(frozen=True, slots=True)
class GatewayIdentity:
    """Snapshot returned by ``GetIdentity``."""

    node_id: bytes
    """Compressed secp256k1 public key (33 bytes)."""

    connected_peers: int
    peers: tuple[PeerInfo, ...]
    version: str
    network: str
    """Bitcoin network the gateway is configured for. One of
    ``"mainnet"``, ``"testnet"``, ``"signet"``, ``"regtest"``. Empty
    string when talking to a pre-network-field gateway build (treated
    as a hard error at startup so older gateways don't silently slip
    onto mainnet)."""


@dataclass(frozen=True, slots=True)
class InboundMessage:
    """One onion message delivered to us."""

    recv_id: str
    payload_tlv_type: int
    payload: bytes
    reply_path: bytes | None
    received_at_ms: int
    inbound_context: bytes
    """Echoes back the ``context`` bytes the sender bound to the
    blinded path this message arrived along. Empty bytes if the
    message arrived directly (not via one of our blinded paths)."""


@dataclass(frozen=True, slots=True)
class SendResult:
    """Acknowledgement returned by ``SendOnionMessage``."""

    send_id: str


@dataclass(frozen=True, slots=True)
class ConnectPeerResult:
    """Result of ``ConnectPeer``."""

    already_connected: bool


@dataclass(frozen=True, slots=True)
class StickyPeer:
    """One entry in the gateway's sticky-peer set."""

    node_id: bytes
    """Compressed secp256k1 public key (33 bytes)."""

    address: str
    """LDK ``SocketAddress`` Display string (``host:port`` or
    ``<onion>.onion:port``)."""


@dataclass(frozen=True, slots=True)
class SetStickyPeersResult:
    """Result of ``SetStickyPeers``."""

    sticky_count: int
    """Number of peers in the gateway's sticky set after the call.
    Echoed back so the caller can log a confirmation."""


@dataclass(frozen=True, slots=True)
class KnownNodeAddresses:
    """One entry in a ``SetKnownNodeAddresses`` push."""

    node_id: bytes
    """Compressed secp256k1 public key (33 bytes)."""

    addresses: tuple[str, ...]
    """Dial-strings in preferred order. ``host:port`` or
    ``<onion>.onion:port`` — the LDK ``SocketAddress::Display`` shape.
    Order is preserved on the gateway; ``try_addresses`` walks in
    order and stops at the first success, so list the most
    likely-to-succeed address first (typically ``.onion`` when the
    gateway dials through SOCKS5, then clearnet as fallback)."""

    node_announcement_timestamp: int
    """LND-side ``node_announcement.timestamp`` (unix seconds). Held
    by the gateway for diagnostic output."""


@dataclass(frozen=True, slots=True)
class SetKnownNodeAddressesResult:
    """Result of ``SetKnownNodeAddresses``."""

    accepted_count: int
    """Number of entries the gateway accepted (one per
    ``KnownNodeAddresses`` in the stream). Returned so the caller
    can confirm the push landed end-to-end."""
