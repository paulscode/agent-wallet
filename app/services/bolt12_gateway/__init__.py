# SPDX-License-Identifier: MIT
"""BOLT 12 onion-message gateway client.

Public surface for talking to the bare-LDK Rust gateway daemon
(``bolt12-gateway``) over gRPC.
"""

from app.services.bolt12_gateway.client import Bolt12GatewayClient
from app.services.bolt12_gateway.errors import (
    GatewayError,
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

__all__ = [
    "Bolt12GatewayClient",
    "ConnectPeerResult",
    "GatewayError",
    "GatewayIdentity",
    "GatewayRpcError",
    "GatewayUnavailableError",
    "GatewayUnimplementedError",
    "InboundMessage",
    "KnownNodeAddresses",
    "PeerInfo",
    "SendResult",
    "SetKnownNodeAddressesResult",
    "SetStickyPeersResult",
    "StickyPeer",
]
