# SPDX-License-Identifier: MIT
"""Multi-channel mix planner.

Given a target Lightning capacity, a send/receive preference, a peer-mix
mode, and a current-fee snapshot, produces a :class:`Plan` describing
which catalog peers to open channels with, how to seed inbound on each,
and the on-chain amount the user needs to send the wallet.

The plan exposes two funding numbers — :attr:`Plan.minimum_sats` and
:attr:`Plan.recommended_sats` — because they answer different questions:

* ``minimum_sats`` — sum of channel capacities + open-fee at today's
  medium-priority feerate. Works on a perfectly stable day.
* ``recommended_sats`` — adds a close-fee reserve (so a freshly-opened
  channel can also be cleanly closed) and a fee-spike cushion (so a
  +50% mempool move doesn't strand the open). This is what the wizard
  pre-selects and what most users should send.

Architectural notes
-------------------
* This module is pure functions — no database, no I/O, no Celery. The
  fee oracle is injected (typically the live
  :func:`mempool_fee_service.get_recommended_fees` coroutine, but tests
  inject a stub) so the planner stays straight-line.
* Peer selection reads :mod:`app.services.small_channel_peers`.
  Marginal-routing peers are excluded from auto-picks; the user can opt
  in by passing them through ``manual_picks``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Literal, Optional, Sequence

from app.services.small_channel_peers import (
    SmallChannelPeer,
    all_peers,
    recommended_defaults,
)

# ─── Constants ─────────────────────────────────────────────────────

# Approximate vbytes burned by one channel-open transaction: one funding
# input, one funding output, one change output, taproot signatures. Real
# values vary by input count and witness shape; this is the conservative
# average across regtest-measured opens.
VBYTES_PER_CHANNEL_OPEN = 250

# Per-channel on-chain reserve sized so a future cooperative or anchor
# close can fee-bump at high feerate. LND wants ~10 k available; doubled
# gives headroom for a spike at close time.
CLOSE_RESERVE_SATS_PER_CHANNEL = 25_000

# Fee-spike cushion that absorbs a +50 % mempool move between deposit
# and channel-open broadcast. Floor of 10 k keeps the cushion meaningful
# on a one-channel plan even when current fees are low.
FEE_SPIKE_CUSHION_PCT = 0.50
FEE_SPIKE_CUSHION_FLOOR_SATS = 10_000

# Capacity reserve for one additional channel-open later. Off by default
# in the UI; user opts in by setting ``leave_room_for_one_more=True``.
FUTURE_CHANNEL_SLOT_SATS = 250_000

# Conservative fallback feerate used when the mempool oracle is
# unreachable. Picked so the resulting plan over-estimates the open fee
# rather than under-estimating it.
FALLBACK_SAT_PER_VB = 20

# Channel-count thresholds (sats of target Lightning capacity).
SINGLE_CHANNEL_CEILING_SATS = 600_000
TWO_CHANNEL_CEILING_SATS = 1_500_000
PER_CHANNEL_SOFT_CEILING_SATS = 2_000_000
PER_CHANNEL_FLOOR_SATS = 150_000

# Cap on the number of channels a single plan opens. Beyond this the
# user genuinely wants a manual flow.
MAX_CHANNELS_PER_PLAN = 6

# Healthy outbound ratio below which a peer's outbound-enabled rate is
# flagged as a yellow signal even when no caveat is present.
HEALTHY_OUTBOUND_RATIO = 0.87


# ─── Dataclasses ──────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Breakdown:
    """Component-by-component breakdown of the funding math.

    ``channel_capacity_sats`` + ``open_fees_sats`` = :attr:`Plan.minimum_sats`.
    Adding ``close_reserve_sats`` + ``fee_spike_cushion_sats`` +
    ``future_channel_slot_sats`` = :attr:`Plan.recommended_sats`.
    """

    channel_capacity_sats: int
    open_fees_sats: int
    close_reserve_sats: int
    fee_spike_cushion_sats: int
    future_channel_slot_sats: int


InboundSeedStrategy = Literal["boltz_reverse", "push_only", "rebalance_from"]


@dataclass(frozen=True, slots=True)
class ChannelOpen:
    """One channel in the plan.

    ``capacity`` is the funded channel size. ``push_sat`` shifts some of
    that capacity to the remote side at open time (the open is atomic;
    no separate transaction). ``expected_inbound_seed_sats`` is the
    additional remote balance the executor will seed via a follow-on
    reverse swap (the strategy field names which mechanism).
    """

    peer: SmallChannelPeer
    capacity: int
    push_sat: int
    expected_inbound_seed_sats: int
    inbound_seed_strategy: InboundSeedStrategy


@dataclass(frozen=True, slots=True)
class PlanDiagnostics:
    """Side-channel notes the wizard surfaces alongside the plan."""

    warnings: tuple[str, ...]
    fee_rate_sat_vb_medium: float
    fee_rate_sat_vb_high: float
    catalog_snapshot_date: str
    diversity_axes_satisfied: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Plan:
    """Output of :func:`plan_channel_mix`.

    The wizard renders ``minimum_sats`` and ``recommended_sats`` side
    by side. ``per_channel`` drives the per-channel list. ``breakdown``
    feeds the "Why the buffer?" disclosure.
    """

    minimum_sats: int
    recommended_sats: int
    breakdown: Breakdown
    per_channel: tuple[ChannelOpen, ...]
    diagnostics: PlanDiagnostics


# Fee oracle is an injectable async callable: takes no arguments,
# returns ``(fees_dict, error)`` where ``fees_dict`` carries
# ``fastestFee`` / ``halfHourFee`` / ``hourFee`` keys (mempool.space
# format) or ``None`` on error.
FeeOracle = Callable[[], Awaitable[tuple[Optional[dict], Optional[str]]]]

PeerMixMode = Literal["recommended_diverse", "cheapest_only", "manual_picks"]
OutboundOption = Literal[
    "receive_heavy",  # 75 % inbound
    "balanced",       # 50 / 50
    "send_heavy",     # 25 % inbound
    "custom",
]


# ─── Channel-count heuristic ──────────────────────────────────────


def derive_channel_count(target_capacity_sats: int) -> int:
    """Return the number of channels to open for ``target_capacity_sats``.

    The thresholds mirror the documented heuristics:

    * up to 600 k sats → 1 channel
    * up to 1.5 M sats → 2 channels
    * larger → split until per-channel ≤ 2 M sats

    The result is clamped to ``MAX_CHANNELS_PER_PLAN`` so a plan can't
    silently grow into manual-flow territory. The minimum is 1.
    """
    if target_capacity_sats <= 0:
        return 0
    if target_capacity_sats <= SINGLE_CHANNEL_CEILING_SATS:
        return 1
    if target_capacity_sats <= TWO_CHANNEL_CEILING_SATS:
        return 2
    n = math.ceil(target_capacity_sats / PER_CHANNEL_SOFT_CEILING_SATS)
    return max(1, min(n, MAX_CHANNELS_PER_PLAN))


# ─── Peer selection ───────────────────────────────────────────────


def _peer_has_marginal_routing(peer: SmallChannelPeer) -> bool:
    """True when the catalog flagged ``peer`` with a marginal-routing
    caveat. Such peers are excluded from auto-picks; the user has to
    pass them through ``manual_picks`` to include them in a plan."""
    for caveat in peer.caveats:
        if caveat.kind == "marginal_routing":
            return True
    return False


def _peer_routing_health_score(peer: SmallChannelPeer) -> float:
    """Lower is better. Used as a tiebreaker so a 100 %-enabled peer
    edges out a 79 %-enabled peer when fee parity holds."""
    if peer.outbound_enabled_ratio is None:
        # Unsampled — treat as neutral so the picker doesn't penalise a
        # peer the snapshot just didn't have time to probe.
        return 0.5
    return 1.0 - peer.outbound_enabled_ratio


def _peer_ppm_score(peer: SmallChannelPeer) -> tuple[int, int]:
    """Sort key for "cheapest first" — ppm then base."""
    return (
        peer.typical.fee_rate_milli_msat,
        peer.typical.fee_base_msat,
    )


def _location_bucket(peer: SmallChannelPeer) -> str:
    """Coarse geographic bucket so the diversity heuristic doesn't
    over-fit on exact location strings. Two peers hosted on the same
    cloud provider in the same continent fall in the same bucket and
    aren't both auto-picked."""
    loc = (peer.location or "").lower()
    if "russia" in loc:
        return "ru"
    if "germany" in loc:
        return "de"
    if "us" in loc or "linode us" in loc or "us-west" in loc or "us-east" in loc:
        return "us"
    if "cape town" in loc or "af-south" in loc:
        return "af"
    if "frankfurt" in loc or "eu-central" in loc:
        return "eu"
    if "oregon" in loc:
        return "us-west"
    return loc[:8] or "_unknown"


def _operator_bucket(peer: SmallChannelPeer) -> str:
    """Same-operator dedup key. Today we approximate via the alias
    prefix (operators tend to brand their nodes consistently); a future
    enhancement could index by AS or operator pubkey."""
    alias = (peer.alias or "").strip()
    head = alias.split(" ")[0] if alias else ""
    return head[:16].lower() or peer.node_id_hex[:16]


def select_peers(
    *,
    network: str,
    channel_count: int,
    mode: PeerMixMode,
    manual_picks: Sequence[str] = (),
    include_marginal_routing: bool = False,
) -> tuple[tuple[SmallChannelPeer, ...], tuple[str, ...]]:
    """Pick ``channel_count`` peers from the catalog by the requested
    mode. Returns ``(peers, diversity_axes_satisfied)``.

    Three modes:

    * ``recommended_diverse`` — always include at least one ⭐, then
      fill remaining slots optimising for geographic diversity, then
      operator diversity, then cheapest fee.
    * ``cheapest_only`` — strictly lowest-ppm peers that fit the
      catalog's healthy-router filter. No ⭐ guarantee.
    * ``manual_picks`` — use the user's pubkey list verbatim. The
      ``include_marginal_routing`` flag governs whether ⚠️ peers in
      ``manual_picks`` are honoured; defaults to ``False`` so a typo
      in the operator override doesn't silently route into a
      marginal-routing peer.
    """
    if channel_count <= 0:
        return (), ()

    if mode == "manual_picks":
        picked: list[SmallChannelPeer] = []
        all_catalog = {p.node_id_hex.lower(): p for p in all_peers(network=network)}
        for pub in manual_picks:
            peer = all_catalog.get(pub.lower())
            if peer is None:
                continue
            if _peer_has_marginal_routing(peer) and not include_marginal_routing:
                continue
            picked.append(peer)
            if len(picked) >= channel_count:
                break
        return tuple(picked), _diversity_axes(picked)

    catalog = [p for p in all_peers(network=network) if not _peer_has_marginal_routing(p)]
    if not catalog:
        return (), ()

    if mode == "cheapest_only":
        catalog.sort(key=lambda p: (_peer_ppm_score(p), _peer_routing_health_score(p)))
        chosen = catalog[:channel_count]
        return tuple(chosen), _diversity_axes(chosen)

    # ``recommended_diverse``: always include at least one ⭐, then fill
    # remaining slots maximising (a) geographic diversity, (b) operator
    # diversity, (c) cheapest fee.
    starred = list(recommended_defaults(network=network))
    starred = [p for p in starred if not _peer_has_marginal_routing(p)]
    starred.sort(key=lambda p: (_peer_ppm_score(p), _peer_routing_health_score(p)))

    chosen: list[SmallChannelPeer] = []
    if starred:
        chosen.append(starred[0])

    # Now fill remaining slots from the whole catalog (excluding marginal
    # routing + already picked).
    remaining_pool = [p for p in catalog if p not in chosen]
    while len(chosen) < channel_count and remaining_pool:
        used_locations = {_location_bucket(p) for p in chosen}
        used_operators = {_operator_bucket(p) for p in chosen}

        def diversity_key(peer: SmallChannelPeer) -> tuple:
            # Lower tuple sorts first.
            same_location = _location_bucket(peer) in used_locations
            same_operator = _operator_bucket(peer) in used_operators
            return (
                int(same_location),
                int(same_operator),
                _peer_ppm_score(peer),
                _peer_routing_health_score(peer),
            )

        remaining_pool.sort(key=diversity_key)
        chosen.append(remaining_pool.pop(0))

    return tuple(chosen), _diversity_axes(chosen)


def _diversity_axes(chosen: Sequence[SmallChannelPeer]) -> tuple[str, ...]:
    """Compute which diversity axes the chosen set actually achieved.
    Surfaces in :class:`PlanDiagnostics` so the wizard can show
    "why these peers" without re-deriving it."""
    if len(chosen) < 2:
        # A one-channel plan can't satisfy any cross-peer diversity axis.
        return ()
    axes: list[str] = []
    locations = {_location_bucket(p) for p in chosen}
    if len(locations) >= 2:
        axes.append("geographic")
    operators = {_operator_bucket(p) for p in chosen}
    if len(operators) >= 2:
        axes.append("operator")
    fee_tiers = {p.fee_tier for p in chosen}
    if len(fee_tiers) >= 2:
        axes.append("fee_tier")
    return tuple(axes)


# ─── Capacity allocation ──────────────────────────────────────────


def allocate_capacity(target_capacity_sats: int, channel_count: int) -> tuple[int, ...]:
    """Split ``target_capacity_sats`` across ``channel_count`` channels.

    Even split with the remainder absorbed by the first channel. Every
    slot is at least ``PER_CHANNEL_FLOOR_SATS``; if the target is too
    small to honour the floor across all slots, the lower channels get
    the floor and the first absorbs whatever's left (or the plan
    shrinks to fewer channels — that's the caller's responsibility via
    :func:`derive_channel_count`)."""
    if channel_count <= 0 or target_capacity_sats <= 0:
        return ()
    per = target_capacity_sats // channel_count
    if per < PER_CHANNEL_FLOOR_SATS:
        # Caller mis-routed us into too-many-channels territory; honour
        # the floor on every slot the target can afford and drop the
        # rest implicitly (the first slot absorbs the remainder).
        affordable = target_capacity_sats // PER_CHANNEL_FLOOR_SATS
        if affordable <= 0:
            return ()
        rem = target_capacity_sats - affordable * PER_CHANNEL_FLOOR_SATS
        return (PER_CHANNEL_FLOOR_SATS + rem,) + tuple([PER_CHANNEL_FLOOR_SATS] * (affordable - 1))
    rem = target_capacity_sats - per * channel_count
    return (per + rem,) + tuple([per] * (channel_count - 1))


# ─── Outbound/inbound seed planning ───────────────────────────────


def derive_seed_plan(
    capacities: Sequence[int],
    *,
    inbound_ratio: float,
    boltz_available: bool,
) -> tuple[tuple[int, int, InboundSeedStrategy], ...]:
    """For each channel, compute ``(push_sat, expected_inbound_seed_sats,
    inbound_seed_strategy)``.

    The inbound budget is ``capacity * inbound_ratio``. Of that, up to
    half can come from ``push_sat`` at open time (cheap, instant). The
    rest is left to a follow-on reverse swap; if Boltz is unavailable
    the strategy degrades to ``push_only`` and a warning is emitted by
    the caller.
    """
    out: list[tuple[int, int, InboundSeedStrategy]] = []
    inbound_ratio = max(0.0, min(1.0, inbound_ratio))
    for capacity in capacities:
        inbound_target = int(capacity * inbound_ratio)
        if not boltz_available:
            push = min(inbound_target, capacity // 2)
            seed = max(0, inbound_target - push)
            out.append((push, seed, "push_only"))
            continue
        push = min(inbound_target // 2, capacity // 4)
        seed = max(0, inbound_target - push)
        out.append((push, seed, "boltz_reverse"))
    return tuple(out)


# ─── Fee oracle + funding math ────────────────────────────────────


def _extract_fee_rates(payload: Optional[dict]) -> tuple[Optional[float], Optional[float]]:
    """Pull (medium, high) sat/vB from a mempool-shape response. Returns
    ``(None, None)`` when the payload doesn't carry expected keys."""
    if not isinstance(payload, dict):
        return None, None
    medium = payload.get("halfHourFee") or payload.get("hourFee")
    high = payload.get("fastestFee") or medium
    try:
        return (float(medium) if medium is not None else None,
                float(high) if high is not None else None)
    except (TypeError, ValueError):
        return None, None


async def _resolve_fee_rates(
    fee_oracle: Optional[FeeOracle],
) -> tuple[float, float, tuple[str, ...]]:
    """Returns ``(medium_sat_vb, high_sat_vb, warnings)``. Falls back to
    :data:`FALLBACK_SAT_PER_VB` when the oracle is unavailable so the
    plan still renders — just over-estimated. The warning surfaces in
    :class:`PlanDiagnostics`."""
    if fee_oracle is None:
        return (
            float(FALLBACK_SAT_PER_VB),
            float(FALLBACK_SAT_PER_VB),
            ("Mempool fee oracle unavailable — using conservative estimate of "
             f"{FALLBACK_SAT_PER_VB} sat/vB.",),
        )
    try:
        data, error = await fee_oracle()
    except Exception as exc:  # noqa: BLE001
        return (
            float(FALLBACK_SAT_PER_VB),
            float(FALLBACK_SAT_PER_VB),
            (f"Couldn't read mempool fees ({type(exc).__name__}) — using conservative estimate of "
             f"{FALLBACK_SAT_PER_VB} sat/vB.",),
        )
    if error or data is None:
        return (
            float(FALLBACK_SAT_PER_VB),
            float(FALLBACK_SAT_PER_VB),
            (f"Couldn't read mempool fees ({error or 'no data'}) — using conservative estimate of "
             f"{FALLBACK_SAT_PER_VB} sat/vB.",),
        )
    medium, high = _extract_fee_rates(data)
    if medium is None or high is None:
        return (
            float(FALLBACK_SAT_PER_VB),
            float(FALLBACK_SAT_PER_VB),
            (f"Mempool fee payload missing expected keys — using conservative estimate of "
             f"{FALLBACK_SAT_PER_VB} sat/vB.",),
        )
    return medium, high, ()


def _open_fee_sats(channel_count: int, sat_per_vb: float) -> int:
    return int(math.ceil(channel_count * VBYTES_PER_CHANNEL_OPEN * sat_per_vb))


def _fee_spike_cushion_sats(open_fee_at_medium: int, open_fee_at_high: int) -> int:
    """Cushion sized so a +50 % move from medium to high feerate is
    absorbed. Floor of :data:`FEE_SPIKE_CUSHION_FLOOR_SATS` keeps the
    cushion meaningful on tiny plans."""
    proportional = int(math.ceil(open_fee_at_medium * FEE_SPIKE_CUSHION_PCT))
    delta_to_high = max(0, open_fee_at_high - open_fee_at_medium)
    return max(FEE_SPIKE_CUSHION_FLOOR_SATS, proportional, delta_to_high)


# ─── Public entry ─────────────────────────────────────────────────


def _inbound_ratio_for_option(option: OutboundOption, custom_inbound_pct: Optional[float]) -> float:
    if option == "receive_heavy":
        return 0.75
    if option == "send_heavy":
        return 0.25
    if option == "custom" and custom_inbound_pct is not None:
        return max(0.0, min(1.0, float(custom_inbound_pct) / 100.0))
    return 0.50


async def plan_channel_mix(
    *,
    target_capacity_sats: int,
    outbound_option: OutboundOption,
    peer_mix_mode: PeerMixMode,
    network: str,
    catalog_snapshot_date: str,
    fee_oracle: Optional[FeeOracle],
    boltz_available: bool,
    leave_room_for_one_more: bool = False,
    custom_inbound_pct: Optional[float] = None,
    manual_picks: Sequence[str] = (),
    include_marginal_routing: bool = False,
) -> Plan:
    """Build a :class:`Plan` from the user's inputs.

    Pure async: the only I/O is the injected ``fee_oracle`` call. When
    the catalog is empty (non-mainnet, kill switch, no matching peers)
    the returned plan has no channels and ``per_channel == ()`` — the
    caller surfaces that as "no catalog peers fit your network."
    """
    warnings: list[str] = []

    channel_count = derive_channel_count(target_capacity_sats)
    peers, axes = select_peers(
        network=network,
        channel_count=channel_count,
        mode=peer_mix_mode,
        manual_picks=manual_picks,
        include_marginal_routing=include_marginal_routing,
    )
    # If the catalog couldn't satisfy the requested count, shrink the
    # plan to what the catalog can support and warn — the alternative
    # (silently returning fewer slots than capacity wants) would over-
    # commit each channel.
    if peers and len(peers) < channel_count:
        warnings.append(
            f"Catalog had {len(peers)} matching peer(s) for {channel_count} "
            "requested channels — plan reduced to fit."
        )
        channel_count = len(peers)

    if not peers:
        warnings.append(
            "No catalog peers match the selection — paste a pubkey in the "
            "wizard's custom mode to proceed."
        )

    capacities = allocate_capacity(target_capacity_sats, channel_count) if peers else ()
    if peers and not capacities:
        # ``allocate_capacity`` couldn't honour the per-channel floor.
        warnings.append(
            f"Target capacity below the {PER_CHANNEL_FLOOR_SATS}-sat "
            "per-channel floor — increase the target or open one channel manually."
        )
        peers = ()

    medium_sat_vb, high_sat_vb, fee_warnings = await _resolve_fee_rates(fee_oracle)
    warnings.extend(fee_warnings)

    if not boltz_available:
        warnings.append(
            "Boltz is unreachable — inbound seed steps are deferred; the "
            "channels will open at 100% outbound until Boltz returns."
        )

    if not include_marginal_routing and peer_mix_mode != "manual_picks":
        # Auto-pick path skipped marginal-routing peers. Inform users
        # who might have wondered why a high-channel peer like CoinGate
        # isn't in the selection.
        skipped = sum(
            1 for p in all_peers(network=network) if _peer_has_marginal_routing(p)
        )
        if skipped:
            warnings.append(
                f"{skipped} catalog peer(s) skipped from auto-pick (marginal "
                "routing health). Use 'Pick peers manually' to include them."
            )

    open_fee_at_medium = _open_fee_sats(channel_count, medium_sat_vb)
    open_fee_at_high = _open_fee_sats(channel_count, high_sat_vb)
    close_reserve = CLOSE_RESERVE_SATS_PER_CHANNEL * max(0, channel_count)
    fee_spike_cushion = _fee_spike_cushion_sats(open_fee_at_medium, open_fee_at_high) if channel_count else 0
    future_slot = FUTURE_CHANNEL_SLOT_SATS if (leave_room_for_one_more and channel_count) else 0

    seed_plan = derive_seed_plan(
        capacities,
        inbound_ratio=_inbound_ratio_for_option(outbound_option, custom_inbound_pct),
        boltz_available=boltz_available,
    )

    per_channel = tuple(
        ChannelOpen(
            peer=peer,
            capacity=capacity,
            push_sat=push,
            expected_inbound_seed_sats=seed,
            inbound_seed_strategy=strategy,
        )
        for peer, capacity, (push, seed, strategy) in zip(peers, capacities, seed_plan)
    )

    minimum_sats = sum(capacities) + open_fee_at_medium
    recommended_sats = minimum_sats + close_reserve + fee_spike_cushion + future_slot

    breakdown = Breakdown(
        channel_capacity_sats=sum(capacities),
        open_fees_sats=open_fee_at_medium,
        close_reserve_sats=close_reserve,
        fee_spike_cushion_sats=fee_spike_cushion,
        future_channel_slot_sats=future_slot,
    )

    # Surface marginal-routing flags on manually picked peers so the
    # wizard can render them inline.
    if include_marginal_routing and per_channel:
        for ch in per_channel:
            if _peer_has_marginal_routing(ch.peer):
                warnings.append(
                    f"{ch.peer.alias} carries a marginal-routing flag — "
                    "inbound HTLCs through this peer may fail."
                )

    return Plan(
        minimum_sats=minimum_sats,
        recommended_sats=recommended_sats,
        breakdown=breakdown,
        per_channel=per_channel,
        diagnostics=PlanDiagnostics(
            warnings=tuple(warnings),
            fee_rate_sat_vb_medium=medium_sat_vb,
            fee_rate_sat_vb_high=high_sat_vb,
            catalog_snapshot_date=catalog_snapshot_date,
            diversity_axes_satisfied=axes,
        ),
    )


__all__ = [
    "VBYTES_PER_CHANNEL_OPEN",
    "CLOSE_RESERVE_SATS_PER_CHANNEL",
    "FEE_SPIKE_CUSHION_PCT",
    "FEE_SPIKE_CUSHION_FLOOR_SATS",
    "FUTURE_CHANNEL_SLOT_SATS",
    "FALLBACK_SAT_PER_VB",
    "SINGLE_CHANNEL_CEILING_SATS",
    "TWO_CHANNEL_CEILING_SATS",
    "PER_CHANNEL_SOFT_CEILING_SATS",
    "PER_CHANNEL_FLOOR_SATS",
    "MAX_CHANNELS_PER_PLAN",
    "Breakdown",
    "ChannelOpen",
    "FeeOracle",
    "InboundSeedStrategy",
    "OutboundOption",
    "PeerMixMode",
    "Plan",
    "PlanDiagnostics",
    "allocate_capacity",
    "derive_channel_count",
    "derive_seed_plan",
    "plan_channel_mix",
    "select_peers",
]
