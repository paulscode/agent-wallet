# SPDX-License-Identifier: MIT
"""Channel-open peer presets, selection, and capacity sizing.

Canonical source of truth for the channel-open peers used by the Braiins
on-chain deposit "channel" funding strategy. The two peers are
operator-configured via the ``braiins_deposit_channel_peer_*`` settings;
deployments that need a different routing partner can pin their own
pubkeys without code changes.

Selection is purely amount-driven (on the channel *capacity*, not the
bin): prefer the proper node when ``capacity >= proper_min``, else the
small-channels node when ``capacity >= small_min``, else ineligible.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

from app.core.config import settings

# BOLT2 channel reserve (~1% of capacity, unspendable by us) + the app's
# conservative send-cap haircut (another ~1%, mirrors
# ``_rebalance_max_sendable``). The channel must be sized so that
# ``capacity * (1 - RESERVE_PCT - SAFETY_PCT) >= invoice_amount_sats``.
RESERVE_PCT = 0.01
SAFETY_PCT = 0.01


@dataclass(frozen=True)
class ChannelPeer:
    key: str  # "main" | "small"
    pubkey: str
    host: str
    min_sats: int
    max_sats: int  # 0 = no cap
    label: str


def peer_presets() -> list[ChannelPeer]:
    """The configured channel-open peers, proper first.

    Empty pubkeys are filtered out (a peer that isn't configured isn't
    offered). Returns ``[]`` when nothing is configured.
    """
    out: list[ChannelPeer] = []
    if settings.braiins_deposit_channel_peer_pubkey:
        out.append(
            ChannelPeer(
                key="main",
                pubkey=settings.braiins_deposit_channel_peer_pubkey,
                host=settings.braiins_deposit_channel_peer_host,
                min_sats=int(settings.braiins_deposit_channel_peer_min_sats),
                max_sats=int(settings.braiins_deposit_channel_peer_max_sats),
                label="Megalithic (main node)",
            )
        )
    if settings.braiins_deposit_channel_peer_small_pubkey:
        out.append(
            ChannelPeer(
                key="small",
                pubkey=settings.braiins_deposit_channel_peer_small_pubkey,
                host=settings.braiins_deposit_channel_peer_small_host,
                min_sats=int(settings.braiins_deposit_channel_peer_small_min_sats),
                max_sats=int(settings.braiins_deposit_channel_peer_small_max_sats),
                label="Megalithic (small-channel node)",
            )
        )
    return out


def smallest_peer() -> Optional[ChannelPeer]:
    """The configured peer with the lowest minimum channel size — i.e. the
    one that defines the overall channel-open floor. ``None`` if no peers
    are configured. Used to bump a sub-minimum deposit up to the smallest
    channel a peer will accept."""
    peers = peer_presets()
    if not peers:
        return None
    return min(peers, key=lambda p: p.min_sats)


def select_peer_for_capacity(capacity_sats: int) -> Optional[ChannelPeer]:
    """Pick the peer whose accepted ``[min, max]`` the capacity falls into,
    preferring the proper (larger-min) node. ``None`` if no peer accepts
    a channel of this size (ineligible).

    Order of preference: ``capacity >= main.min`` → main; else
    ``capacity >= small.min`` → small; else ineligible. The optional
    per-peer ``max`` cap can shrink either band.
    """
    cap = int(capacity_sats)
    # Sort by descending min so the proper (higher-min) node is preferred.
    for peer in sorted(peer_presets(), key=lambda p: p.min_sats, reverse=True):
        if cap < peer.min_sats:
            continue
        if peer.max_sats and cap > peer.max_sats:
            continue
        return peer
    return None


def size_channel_capacity(invoice_amount_sats: int) -> int:
    """Smallest channel capacity whose usable outbound
    (``capacity - reserve - safety``) covers ``invoice_amount_sats``, plus
    a configurable headroom for fee drift between open and reverse-swap.

    ``capacity ≈ ceil(invoice / (1 - reserve - safety)) * (1 + headroom)``.
    """
    usable_fraction = max(0.0001, 1.0 - RESERVE_PCT - SAFETY_PCT)
    base = math.ceil(int(invoice_amount_sats) / usable_fraction)
    headroom = max(0.0, float(settings.braiins_deposit_channel_capacity_headroom_pct))
    return int(math.ceil(base * (1.0 + headroom)))
