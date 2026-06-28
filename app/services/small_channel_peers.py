# SPDX-License-Identifier: MIT
"""Curated registry of LN peers that accept small (~150k sat) channel opens.

Loaded from the bundled :file:`small_channel_peers.json` data file at
import time, then layered with operator overrides from
:envvar:`SMALL_CHANNEL_PEER_OVERRIDES_PATH` and recommended-default
selection from :envvar:`SMALL_CHANNEL_PEER_RECOMMENDED_DEFAULTS`.

The catalog is **mainnet-only** by design — every bundled pubkey is a
mainnet identity. Non-mainnet callers see an empty registry.

Background
----------
The Lightning Network's biggest routing operators reject channel opens
below ~400k–1M sats. That's a real barrier for new operators and small
wallets. Each entry below has been empirically tested by opening a real
~150k sat channel, with the data on fees, channel counts, and outbound
enable rates read from public gossip. See the user-facing guide at
``docs/small-channel-peers.md`` for the human-readable presentation.

Disabling
---------
Operators who don't want a bundled catalog can set
``SMALL_CHANNEL_PEER_CATALOG_ENABLED=false`` to surface an empty
catalog. Downstream code paths (the catalog endpoint, the dashboard
picker) degrade gracefully when the registry is empty.

Public API
----------
* :class:`SmallChannelPeer` — frozen dataclass for one peer.
* :data:`SMALL_CHANNEL_PEERS` — the loaded tuple after overrides apply.
* :func:`all_peers` / :func:`recommended_defaults` / :func:`for_amount`
  / :func:`cheapest_n` / :func:`healthy_routers` / :func:`by_fee_tier`
  / :func:`lookup` — filter/sort helpers consumed by callers.
* :data:`SNAPSHOT_DATE` — when the bundled snapshot was captured.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal, Mapping, Optional

from app.core.config import settings

logger = logging.getLogger(__name__)

FeeTier = Literal["very_low", "low", "moderate", "high", "hybrid", "flat_fee"]
ConnectivityTier = Literal["limited", "adequate", "well", "highly"]
CaveatKind = Literal["marginal_routing", "high_base_fee", "small_per_htlc_cap"]

# Healthy-router threshold used by :func:`healthy_routers`. The catalog's
# documented bottom-line copy treats ≥0.87 (87%) as the floor below which
# we explicitly flag a routing-health concern.
_HEALTHY_OUTBOUND_THRESHOLD = 0.87

_DATA_PATH = Path(__file__).resolve().parent / "small_channel_peers.json"


@dataclass(frozen=True, slots=True)
class PeerPolicy:
    """The typical outgoing channel policy across a peer's active edges.

    Values are medians (when several edges differ) or the uniform value
    (when the operator runs the same policy on every channel).
    """

    fee_base_msat: int
    fee_rate_milli_msat: int
    min_htlc_msat: int
    time_lock_delta: int
    max_htlc_msat: int


@dataclass(frozen=True, slots=True)
class PeerCaveat:
    """A structured note about a peer that the dashboard surfaces inline.

    The ``kind`` is a small enumerated set the dashboard knows how to
    render; ``detail`` carries kind-specific fields (e.g.
    ``outbound_enabled_pct`` for ``marginal_routing``). New kinds may be
    added by extending :data:`CaveatKind` and the dashboard's renderer.
    """

    kind: CaveatKind
    detail: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class SmallChannelPeer:
    """One peer in the small-channel catalog.

    Fields
    ------
    alias
        Short operator-facing identifier (e.g. ``"Babylon-4a"``). Mirrors
        the peer's gossiped alias when present.

    node_id_hex
        66-character compressed secp256k1 pubkey, hex-encoded. Validated
        to decode to exactly 33 bytes at load time.

    address
        Primary clearnet socket — typically ``host:port`` for IPv4 / DNS,
        ``[ipv6]:port`` for IPv6. Picked clearnet-first so dial logic
        works without a Tor proxy.

    tor_address
        Optional ``.onion:port`` fallback. ``None`` when the operator
        doesn't publish one.

    network
        Bitcoin network the pubkey lives on — ``"bitcoin"`` (mainnet)
        for every bundled entry.

    min_channel_size_sats
        Empirically-confirmed opening floor. A peer with ``150000`` here
        accepted a real 150k-sat channel during catalog construction.

    channels_count / capacity_btc / top_20_hub_connections
        Gossip-snapshot metrics, regenerated each re-probe run.
        ``top_20_hub_connections`` counts direct edges to the catalog's
        ranking-side top-20 hub set; informational only.

    outbound_enabled_ratio
        Share of the peer's gossiped edges where outbound forwarding is
        enabled (range 0.0–1.0). ``None`` when not sampled this snapshot.
        A healthy router sits above 0.87; the
        :class:`PeerCaveat` system flags peers materially below.

    typical
        Median outgoing policy across the peer's active edges. Drives the
        plain-language fee-tier label.

    fee_tier / connectivity_tier
        Coarse buckets used by UI surfaces to render badges + tiers
        without callers re-deriving them from the raw numbers.

    location
        Free-form short string ("Linode US (non-standard port)") used by
        the UI for geographic diversity hints. May be empty.

    tags
        Catalog-curation flags. ``"recommended_default"`` marks the ⭐
        peers a fresh wallet should pre-select.

    summary
        Short prose paragraph for the dashboard tooltip + the picker's
        "details" disclosure. One or two sentences, no markup.

    verified_at
        ISO-8601 date (YYYY-MM-DD) when the empirical probe last
        confirmed this peer.

    funding_txid
        Hex txid of the probe-opened channel. Provenance pointer for
        operators who want to verify the empirical claim themselves.

    caveats
        Structured notes the dashboard renders inline (marginal routing,
        high base fee, small per-HTLC cap, ...).
    """

    alias: str
    node_id_hex: str
    address: str
    tor_address: Optional[str]
    network: str

    min_channel_size_sats: int

    channels_count: int
    capacity_btc: float
    top_20_hub_connections: int
    outbound_enabled_ratio: Optional[float]

    typical: PeerPolicy
    fee_tier: FeeTier
    connectivity_tier: ConnectivityTier
    location: str
    tags: tuple[str, ...]
    summary: str

    verified_at: str
    funding_txid: str
    caveats: tuple[PeerCaveat, ...] = field(default_factory=tuple)


# ─── Loading ────────────────────────────────────────────────────────


def _decode_peer(raw: Mapping[str, Any]) -> SmallChannelPeer:
    """Validate one JSON entry and project it onto :class:`SmallChannelPeer`."""
    nid = raw["node_id_hex"]
    if len(nid) != 66:
        raise ValueError(f"node_id_hex must be 66 hex chars (got {len(nid)}): {nid!r}")
    nid_bytes = bytes.fromhex(nid)  # raises ValueError on non-hex chars
    if len(nid_bytes) != 33:
        raise ValueError(f"node_id_hex must decode to 33 bytes (got {len(nid_bytes)}): {nid!r}")

    typical_raw = raw["typical"]
    typical = PeerPolicy(
        fee_base_msat=int(typical_raw["fee_base_msat"]),
        fee_rate_milli_msat=int(typical_raw["fee_rate_milli_msat"]),
        min_htlc_msat=int(typical_raw["min_htlc_msat"]),
        time_lock_delta=int(typical_raw["time_lock_delta"]),
        max_htlc_msat=int(typical_raw["max_htlc_msat"]),
    )

    caveats_raw = raw.get("caveats") or ()
    caveats = tuple(PeerCaveat(kind=c["kind"], detail=dict(c.get("detail") or {})) for c in caveats_raw)

    outbound = raw.get("outbound_enabled_ratio")
    if outbound is not None:
        outbound = float(outbound)
        if not 0.0 <= outbound <= 1.0:
            raise ValueError(f"outbound_enabled_ratio out of range [0,1]: {outbound}")

    return SmallChannelPeer(
        alias=str(raw["alias"]),
        node_id_hex=nid,
        address=str(raw["address"]),
        tor_address=raw.get("tor_address"),
        network=str(raw["network"]),
        min_channel_size_sats=int(raw["min_channel_size_sats"]),
        channels_count=int(raw["channels_count"]),
        capacity_btc=float(raw["capacity_btc"]),
        top_20_hub_connections=int(raw["top_20_hub_connections"]),
        outbound_enabled_ratio=outbound,
        typical=typical,
        fee_tier=raw["fee_tier"],
        connectivity_tier=raw["connectivity_tier"],
        location=str(raw.get("location") or ""),
        tags=tuple(raw.get("tags") or ()),
        summary=str(raw.get("summary") or ""),
        verified_at=str(raw["verified_at"]),
        funding_txid=str(raw["funding_txid"]),
        caveats=caveats,
    )


def _load_bundled() -> tuple[str, tuple[SmallChannelPeer, ...]]:
    """Read and validate the bundled JSON. Raises on any schema error so
    a typo in the bundled data file fails fast at import — not on the
    first request a user makes."""
    with _DATA_PATH.open("r", encoding="utf-8") as fp:
        doc = json.load(fp)
    snapshot_date = str(doc["snapshot_date"])
    peers = tuple(_decode_peer(entry) for entry in doc["peers"])
    return snapshot_date, peers


def _apply_overrides(
    bundled: tuple[SmallChannelPeer, ...],
    overrides_path: str | None,
) -> tuple[SmallChannelPeer, ...]:
    """Layer the operator-supplied overrides file on top of bundled.

    Three semantics, keyed by ``node_id_hex``:

    * ``{"node_id_hex": "...", "blocked": true}`` — remove that pubkey
      from the catalog.
    * Entry whose pubkey matches a bundled one — replace bundled entry
      field-by-field. Operator-supplied fields win; omitted fields keep
      the bundled value.
    * New pubkey — append.

    A bad overrides file logs a warning and falls through to the bundled
    catalog unchanged — the bundled view is always usable.
    """
    if not overrides_path:
        return bundled
    path = Path(overrides_path)
    if not path.is_file():
        logger.warning("small-channel-peer overrides path %s does not exist; using bundled catalog", path)
        return bundled
    try:
        with path.open("r", encoding="utf-8") as fp:
            doc = json.load(fp)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("small-channel-peer overrides %s failed to parse (%s); using bundled catalog", path, exc)
        return bundled

    raw_entries = doc.get("peers") if isinstance(doc, Mapping) else doc
    if not isinstance(raw_entries, list):
        logger.warning("small-channel-peer overrides %s has no ``peers`` list; using bundled catalog", path)
        return bundled

    by_pubkey: dict[str, SmallChannelPeer] = {p.node_id_hex: p for p in bundled}
    for raw in raw_entries:
        if not isinstance(raw, Mapping):
            continue
        nid = raw.get("node_id_hex")
        if not isinstance(nid, str):
            continue
        if raw.get("blocked"):
            by_pubkey.pop(nid, None)
            continue
        if nid in by_pubkey:
            existing = by_pubkey[nid]
            merged = _merge_override(existing, raw)
            by_pubkey[nid] = merged
        else:
            try:
                by_pubkey[nid] = _decode_peer(raw)
            except (KeyError, ValueError) as exc:
                logger.warning("small-channel-peer overrides %s skipped %s (%s)", path, nid[:16], exc)
    return tuple(by_pubkey.values())


def _merge_override(existing: SmallChannelPeer, raw: Mapping[str, Any]) -> SmallChannelPeer:
    """Replace only the fields the override explicitly sets."""
    # Scalar passthroughs.
    overrides: dict[str, Any] = {}
    for key in (
        "alias",
        "address",
        "tor_address",
        "network",
        "min_channel_size_sats",
        "channels_count",
        "capacity_btc",
        "top_20_hub_connections",
        "outbound_enabled_ratio",
        "fee_tier",
        "connectivity_tier",
        "location",
        "summary",
        "verified_at",
        "funding_txid",
    ):
        if key in raw:
            overrides[key] = raw[key]
    if "tags" in raw:
        overrides["tags"] = tuple(raw["tags"] or ())
    if "typical" in raw:
        t = raw["typical"]
        overrides["typical"] = PeerPolicy(
            fee_base_msat=int(t["fee_base_msat"]),
            fee_rate_milli_msat=int(t["fee_rate_milli_msat"]),
            min_htlc_msat=int(t["min_htlc_msat"]),
            time_lock_delta=int(t["time_lock_delta"]),
            max_htlc_msat=int(t["max_htlc_msat"]),
        )
    if "caveats" in raw:
        overrides["caveats"] = tuple(PeerCaveat(kind=c["kind"], detail=dict(c.get("detail") or {})) for c in raw["caveats"])
    return replace(existing, **overrides) if overrides else existing


def _apply_recommended_overrides(
    peers: tuple[SmallChannelPeer, ...],
    operator_picks: str | None,
) -> tuple[SmallChannelPeer, ...]:
    """When the operator sets ``SMALL_CHANNEL_PEER_RECOMMENDED_DEFAULTS``,
    replace the bundled ``recommended_default`` tag selection with their
    picks (comma-separated pubkey hex). Pubkeys that aren't in the
    post-overrides catalog are silently skipped with a logged warning so
    the override is robust to typos."""
    if not operator_picks:
        return peers
    wanted = {p.strip().lower() for p in operator_picks.split(",") if p.strip()}
    if not wanted:
        return peers
    catalog_pubs = {p.node_id_hex for p in peers}
    unknown = wanted - catalog_pubs
    if unknown:
        logger.warning(
            "small-channel-peer recommended-default override mentions unknown pubkeys: %s",
            ", ".join(sorted(unknown))[:200],
        )
    out: list[SmallChannelPeer] = []
    for peer in peers:
        tags_without_default = tuple(t for t in peer.tags if t != "recommended_default")
        if peer.node_id_hex in wanted:
            tags_with_default = (*tags_without_default, "recommended_default")
            out.append(replace(peer, tags=tags_with_default))
        else:
            out.append(replace(peer, tags=tags_without_default))
    return tuple(out)


def _initialize() -> tuple[str, tuple[SmallChannelPeer, ...]]:
    """Build the runtime catalog, honouring the feature flag + overrides."""
    if not settings.small_channel_peer_catalog_enabled:
        # Surface an empty catalog with the bundled snapshot date so
        # downstream callers still have a defined ``SNAPSHOT_DATE``.
        try:
            snapshot_date, _ = _load_bundled()
        except Exception:  # noqa: BLE001 — degraded surface, never raise here
            snapshot_date = ""
        return snapshot_date, ()
    snapshot_date, bundled = _load_bundled()
    overrides_path = settings.small_channel_peer_overrides_path or None
    after_overrides = _apply_overrides(bundled, overrides_path)
    operator_picks = settings.small_channel_peer_recommended_defaults or None
    final = _apply_recommended_overrides(after_overrides, operator_picks)
    return snapshot_date, final


SNAPSHOT_DATE, SMALL_CHANNEL_PEERS = _initialize()


# ─── Helpers ────────────────────────────────────────────────────────


def _network_matches(peer: SmallChannelPeer, network: str) -> bool:
    return peer.network == network


def all_peers(*, network: str) -> tuple[SmallChannelPeer, ...]:
    """Return every peer in the catalog applicable to ``network``."""
    return tuple(p for p in SMALL_CHANNEL_PEERS if _network_matches(p, network))


def by_fee_tier(tier: FeeTier, *, network: str) -> tuple[SmallChannelPeer, ...]:
    """Subset filtered by :attr:`SmallChannelPeer.fee_tier`."""
    return tuple(p for p in all_peers(network=network) if p.fee_tier == tier)


def recommended_defaults(*, network: str) -> tuple[SmallChannelPeer, ...]:
    """Peers tagged ``recommended_default`` (the ⭐ peers).

    Used by the onboarding wizard to pre-select a sensible default.
    Order follows the bundled JSON.
    """
    return tuple(p for p in all_peers(network=network) if "recommended_default" in p.tags)


def healthy_routers(*, network: str) -> tuple[SmallChannelPeer, ...]:
    """Peers whose outbound-enabled ratio is at or above the healthy
    threshold. Peers without a sampled ratio are included on the
    benefit-of-the-doubt principle — the ratio is best-effort gossip
    sampling, not a hard quality gate."""
    out: list[SmallChannelPeer] = []
    for peer in all_peers(network=network):
        if peer.outbound_enabled_ratio is None or peer.outbound_enabled_ratio >= _HEALTHY_OUTBOUND_THRESHOLD:
            out.append(peer)
    return tuple(out)


def cheapest_n(n: int, *, network: str, min_capacity_btc: float = 1.0) -> tuple[SmallChannelPeer, ...]:
    """``n`` peers with the lowest median ppm, filtered to ones whose
    capacity is at least ``min_capacity_btc`` so the picker doesn't
    over-recommend small-capacity peers."""
    candidates = [p for p in all_peers(network=network) if p.capacity_btc >= min_capacity_btc]
    candidates.sort(key=lambda p: (p.typical.fee_rate_milli_msat, p.typical.fee_base_msat))
    return tuple(candidates[: max(0, n)])


def for_amount(amount_sats: int, *, network: str) -> tuple[SmallChannelPeer, ...]:
    """Peers whose :attr:`min_channel_size_sats` is at or below
    ``amount_sats``. Used by the picker's "fits this amount" filter."""
    return tuple(p for p in all_peers(network=network) if p.min_channel_size_sats <= amount_sats)


def lookup(node_id_hex: str, *, network: str) -> SmallChannelPeer | None:
    """Find a peer by pubkey on ``network``. ``None`` on miss."""
    needle = node_id_hex.lower()
    for peer in all_peers(network=network):
        if peer.node_id_hex.lower() == needle:
            return peer
    return None


__all__ = [
    "CaveatKind",
    "ConnectivityTier",
    "FeeTier",
    "PeerCaveat",
    "PeerPolicy",
    "SmallChannelPeer",
    "SMALL_CHANNEL_PEERS",
    "SNAPSHOT_DATE",
    "all_peers",
    "by_fee_tier",
    "cheapest_n",
    "for_amount",
    "healthy_routers",
    "lookup",
    "recommended_defaults",
]
