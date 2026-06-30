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


# ─── Bootstrap (capital-efficient inbound) constants ──────────────
#
# The bootstrap executor builds large inbound from a small deposit by
# recycling capital through open→drain→recycle rounds (see
# ``internal_docs/inbound_bootstrap_plan.md`` §2). These constants
# parameterise the *pure* economic simulation below; the executor sizes
# the live drain from the real channel and only uses these for the
# pre-run estimate.

# Per-channel undrainable lock-up estimate: the BOLT2 channel reserve
# (~1% of capacity) plus anchor/commitment overhead. Modelled as
# max(1% of capacity, floor) so a small channel still reserves a
# meaningful anchor cushion.
BOOTSTRAP_RESERVE_PCT = 0.01
BOOTSTRAP_RESERVE_FLOOR_SATS = 5_000

# Boltz reverse-swap service fee (percentage). The miner-fee component
# (lockup + claim legs) is estimated separately from the live feerate.
BOOTSTRAP_BOLTZ_FEE_PCT = 0.0025

# Approx vbytes for the two on-chain legs of a reverse swap the round
# ultimately pays for (Boltz lockup ~150 vB + our claim ~150 vB).
BOOTSTRAP_SWAP_VBYTES = 300

# Routing-fee budget for paying Boltz's hold invoice out the freshly
# opened channel (mirrors the Braiins-deposit 3% headroom). The
# channel's drainable outbound must cover the drain amount PLUS this
# budget, else the LN payment can't route and the round produces no
# inbound (plan §7.1).
BOOTSTRAP_ROUTING_FEE_PCT = 0.03

# Safety caps on the loop (plan §11.4).
BOOTSTRAP_MAX_ROUNDS = 40
# Spread rounds across distinct peers first; once the eligible catalog is
# exhausted, reuse peers up to this many channels each (plan §11.2).
BOOTSTRAP_MAX_CHANNELS_PER_PEER = 3
# Wall-clock cap (minutes) the executor enforces independently of the
# round cap; finalize COMPLETE with a note when either is hit.
BOOTSTRAP_MAX_DURATION_MINUTES = 24 * 60
# How long the executor tolerates AWAITING_FUNDS before giving up with
# STOPPED_INSUFFICIENT (the recyclable balance never recovered).
BOOTSTRAP_AWAITING_FUNDS_TIMEOUT_MINUTES = 90

# Per-round wall-clock estimate: funding confirmations to active (~3) +
# the claim confirmation (~1) ≈ 4 block-times (plan §2a).
BOOTSTRAP_CONFIRMATIONS_PER_ROUND = 4
BOOTSTRAP_BLOCK_MINUTES = 10

# How long a round may wait on a single on-chain confirmation (channel
# activation or swap-claim) before the executor surfaces a non-fatal
# "taking longer than expected" note — it never auto-fails or moves funds
# (plan §7.2, operator-runbook behavior).
BOOTSTRAP_STUCK_MINUTES = 90

# Boltz reverse-swap amount bounds — defaults mirror
# ``boltz_service.BOLTZ_MIN/MAX_AMOUNT_SATS``. Injectable so the planner
# stays free of the heavy boltz_service import and tests can vary them.
BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS = 25_000
BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS = 25_000_000

# Slack the executor leaves between the recyclable balance and a new
# channel open, so a small concurrent spend (Anonymize / Braiins / manual
# send draw from the same UTXO set) doesn't push an in-flight open into a
# insufficient-funds failure (plan §6, §7.4).
BOOTSTRAP_HEADROOM_SATS = 10_000


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


@dataclass(frozen=True, slots=True)
class BootstrapRound:
    """One round of the capital-efficient inbound bootstrap loop.

    A round opens a channel of ``capacity_sats`` then reverse-swaps
    ``drain_target_sats`` of its outbound back on-chain, leaving
    ≈ ``expected_inbound_sats`` of inbound on the channel. The fee
    fields are pre-run *estimates*; the executor recomputes the live
    drain from the actual channel.
    """

    peer: SmallChannelPeer
    capacity_sats: int
    drain_target_sats: int
    expected_inbound_sats: int
    est_open_fee_sats: int
    est_swap_fee_sats: int


@dataclass(frozen=True, slots=True)
class BootstrapPlan:
    """Output of :func:`derive_bootstrap_schedule`.

    The wizard renders ``initial_deposit_sats`` (what to send the wallet
    to start), ``expected_total_inbound_sats`` (what the loop builds),
    ``expected_rounds`` + ``est_duration_minutes`` (the time cost — the
    single biggest UX caveat), and ``expected_total_fees_sats`` (the
    money cost). ``residual_outbound_sats`` is what ends up locked as
    outbound + reserve across the opened channels.
    """

    initial_deposit_sats: int
    target_inbound_sats: Optional[int]
    expected_total_inbound_sats: int
    expected_total_fees_sats: int
    expected_rounds: int
    est_duration_minutes: int
    residual_outbound_sats: int
    rounds: tuple[BootstrapRound, ...]
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


# ─── Bootstrap schedule (pure economic model) ─────────────────────


def bootstrap_reserve_for_capacity(capacity_sats: int) -> int:
    """Undrainable per-channel lock-up (reserve + anchor overhead)."""
    return max(
        int(capacity_sats * BOOTSTRAP_RESERVE_PCT),
        BOOTSTRAP_RESERVE_FLOOR_SATS,
    )


def bootstrap_swap_miner_fee_sats(sat_per_vb: float) -> int:
    """Estimated miner fee for the two on-chain reverse-swap legs."""
    return int(math.ceil(BOOTSTRAP_SWAP_VBYTES * max(0.0, sat_per_vb)))


def bootstrap_capacity_cap(boltz_max: int) -> int:
    """Largest channel capacity worth opening in one round.

    Opening bigger than this would strand outbound the round can't drain
    by swap (the drain is capped at the Boltz max), so the loop caps the
    capacity here and lets the excess stay on-chain to fund later rounds.
    Mirrors the ``drain > boltz_max`` branch of :func:`_simulate_bootstrap`."""
    needed_drainable = int(math.ceil(boltz_max * (1.0 + BOOTSTRAP_ROUTING_FEE_PCT)))
    return needed_drainable + bootstrap_reserve_for_capacity(needed_drainable)


def bootstrap_drain_for_capacity(
    capacity_sats: int,
    *,
    boltz_max: int,
) -> int:
    """Largest reverse-swap drain a channel of ``capacity_sats`` supports.

    The drain (the LN payment out the channel) plus its routing-fee
    budget must fit inside the drainable outbound (capacity minus the
    undrainable reserve). Clamped to the Boltz maximum. This is the same
    sizing the executor applies to a *live* channel — here against the
    planned capacity for the estimate.
    """
    reserve = bootstrap_reserve_for_capacity(capacity_sats)
    drainable = max(0, capacity_sats - reserve)
    drain = int(drainable / (1.0 + BOOTSTRAP_ROUTING_FEE_PCT))
    return min(drain, boltz_max)


def _simulate_bootstrap(
    deposit_sats: int,
    *,
    sat_per_vb_medium: float,
    sat_per_vb_high: float,
    boltz_min: int,
    boltz_max: int,
    max_rounds: int,
    target_inbound_sats: Optional[int],
) -> tuple[list[tuple[int, int, int, int]], int, int, int]:
    """Simulate the open→drain→recycle loop from ``deposit_sats``.

    Returns ``(rounds, total_inbound, total_fees, residual_outbound)``
    where each ``rounds`` entry is
    ``(capacity_sats, drain_sats, open_fee_sats, swap_fee_sats)``.
    Pure and deterministic given the fee inputs — this is the economic
    core the unit tests pin (tapering, erosion, floor stop, Boltz-min
    stop). Peer assignment is layered on by the caller.
    """
    balance = int(deposit_sats)
    rounds: list[tuple[int, int, int, int]] = []
    total_inbound = 0
    total_fees = 0
    residual_outbound = 0
    # Use the high feerate for the swap legs so the estimate over- rather
    # than under-states the fee cost.
    swap_miner = bootstrap_swap_miner_fee_sats(sat_per_vb_high)
    open_fee = _open_fee_sats(1, sat_per_vb_medium)

    while len(rounds) < max_rounds:
        if balance - open_fee < PER_CHANNEL_FLOOR_SATS:
            break  # can't open another channel — natural stopping point
        capacity = balance - open_fee
        reserve = bootstrap_reserve_for_capacity(capacity)
        drainable = max(0, capacity - reserve)
        drain = int(drainable / (1.0 + BOOTSTRAP_ROUTING_FEE_PCT))
        leftover = 0
        if drain > boltz_max:
            # Cap the drain at the Boltz max and shrink the capacity so we
            # don't strand outbound we can't recycle.
            drain = boltz_max
            needed_drainable = int(math.ceil(drain * (1.0 + BOOTSTRAP_ROUTING_FEE_PCT)))
            capacity = needed_drainable + reserve
            leftover = (balance - open_fee) - capacity
        if drain < boltz_min:
            break  # channel too small to drain by swap (plan §7.8)
        swap_fee = int(math.ceil(drain * BOOTSTRAP_BOLTZ_FEE_PCT)) + swap_miner
        recycled = max(0, drain - swap_fee)

        rounds.append((capacity, drain, open_fee, swap_fee))
        total_inbound += drain
        total_fees += open_fee + swap_fee
        residual_outbound += capacity - drain
        balance = leftover + recycled

        if target_inbound_sats is not None and total_inbound >= target_inbound_sats:
            break

    return rounds, total_inbound, total_fees, residual_outbound


def _assign_bootstrap_peers(
    count: int,
    peers: Sequence[SmallChannelPeer],
    *,
    max_per_peer: int,
) -> tuple[list[SmallChannelPeer], bool]:
    """Round-robin assign ``count`` rounds across ``peers`` (spread
    first). Returns ``(assigned, over_cap)`` where ``over_cap`` is True
    when even spreading forces some peer past ``max_per_peer``."""
    if not peers:
        return [], False
    assigned = [peers[i % len(peers)] for i in range(count)]
    # ceil(count / len(peers)) is the most any one peer is used.
    max_used = math.ceil(count / len(peers)) if count else 0
    return assigned, max_used > max_per_peer


def derive_bootstrap_schedule(
    *,
    deposit_sats: Optional[int] = None,
    target_inbound_sats: Optional[int] = None,
    fee_rate_sat_vb_medium: float,
    fee_rate_sat_vb_high: float,
    peers: Sequence[SmallChannelPeer],
    catalog_snapshot_date: str,
    diversity_axes: tuple[str, ...] = (),
    boltz_available: bool = True,
    boltz_min: int = BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS,
    boltz_max: int = BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS,
    max_rounds: int = BOOTSTRAP_MAX_ROUNDS,
    max_channels_per_peer: int = BOOTSTRAP_MAX_CHANNELS_PER_PEER,
    extra_warnings: Sequence[str] = (),
) -> BootstrapPlan:
    """Build a :class:`BootstrapPlan` for one of the two framings.

    Exactly one of ``deposit_sats`` (budget framing — "I have X to
    start") or ``target_inbound_sats`` (target framing — "I want ~Y
    receivable") should be supplied. Target framing binary-searches the
    minimal deposit whose simulated total inbound reaches the target.

    When ``boltz_available`` is False the schedule is empty with a
    warning — bootstrap relies on reverse swaps, so it isn't offered when
    Boltz is unreachable at plan time (plan §7.1).

    Pure: no I/O. The fee rates are resolved by the caller (via the
    shared fee oracle) and the peers by ``select_peers``.
    """
    warnings: list[str] = list(extra_warnings)

    def _empty() -> BootstrapPlan:
        return BootstrapPlan(
            initial_deposit_sats=int(deposit_sats or 0),
            target_inbound_sats=target_inbound_sats,
            expected_total_inbound_sats=0,
            expected_total_fees_sats=0,
            expected_rounds=0,
            est_duration_minutes=0,
            residual_outbound_sats=0,
            rounds=(),
            diagnostics=PlanDiagnostics(
                warnings=tuple(warnings),
                fee_rate_sat_vb_medium=fee_rate_sat_vb_medium,
                fee_rate_sat_vb_high=fee_rate_sat_vb_high,
                catalog_snapshot_date=catalog_snapshot_date,
                diversity_axes_satisfied=diversity_axes,
            ),
        )

    if not boltz_available:
        warnings.append(
            "Boltz is unreachable — bootstrap can't run right now (it relies on "
            "reverse swaps). Try again once Boltz is reachable."
        )
        return _empty()

    if not peers:
        warnings.append(
            "No catalog peers match the selection — bootstrap can't run; "
            "paste a pubkey in the wizard's custom mode or try a different network."
        )
        return _empty()

    def _sim(dep: int) -> tuple[list[tuple[int, int, int, int]], int, int, int]:
        return _simulate_bootstrap(
            dep,
            sat_per_vb_medium=fee_rate_sat_vb_medium,
            sat_per_vb_high=fee_rate_sat_vb_high,
            boltz_min=boltz_min,
            boltz_max=boltz_max,
            max_rounds=max_rounds,
            target_inbound_sats=target_inbound_sats,
        )

    open_fee_one = _open_fee_sats(1, fee_rate_sat_vb_medium)
    min_deposit = PER_CHANNEL_FLOOR_SATS + open_fee_one

    if target_inbound_sats is not None:
        # Binary-search the minimal deposit that reaches the target.
        hi = max(int(target_inbound_sats), min_deposit)
        rounds_hi, inbound_hi, _f, _r = _sim(hi)
        if inbound_hi < target_inbound_sats:
            # Even a target-sized deposit can't reach it within the round
            # cap — return best effort with a warning.
            deposit = hi
            warnings.append(
                f"Reaches ~{inbound_hi:,} sats inbound in {len(rounds_hi)} round(s) "
                f"(capped at {max_rounds}) — short of the {int(target_inbound_sats):,} "
                "sats target. Deposit more to start, or accept the partial."
            )
        else:
            lo = min_deposit
            for _ in range(48):
                if lo >= hi:
                    break
                mid = (lo + hi) // 2
                _rounds_mid, inbound_mid, _fm, _rm = _sim(mid)
                if inbound_mid >= target_inbound_sats:
                    hi = mid
                else:
                    lo = mid + 1
            deposit = hi
    else:
        deposit = int(deposit_sats or 0)

    rounds_sim, total_inbound, total_fees, residual = _sim(deposit)

    if not rounds_sim:
        warnings.append(
            f"Deposit of {deposit:,} sats is below the one-channel floor "
            f"(~{min_deposit:,} sats needed to open + drain a single channel). "
            "Increase the amount to use bootstrap."
        )

    assigned, over_cap = _assign_bootstrap_peers(
        len(rounds_sim), peers, max_per_peer=max_channels_per_peer
    )
    if over_cap:
        warnings.append(
            f"Only {len(peers)} eligible peer(s) for {len(rounds_sim)} rounds — some "
            f"peers are reused more than {max_channels_per_peer} times. Routing "
            "diversity is reduced."
        )

    rounds = tuple(
        BootstrapRound(
            peer=assigned[i],
            capacity_sats=cap,
            drain_target_sats=drain,
            expected_inbound_sats=drain,
            est_open_fee_sats=open_fee,
            est_swap_fee_sats=swap_fee,
        )
        for i, (cap, drain, open_fee, swap_fee) in enumerate(rounds_sim)
    )

    est_duration_minutes = (
        len(rounds) * BOOTSTRAP_CONFIRMATIONS_PER_ROUND * BOOTSTRAP_BLOCK_MINUTES
    )
    if est_duration_minutes >= 120:
        warnings.append(
            f"This will take ~{est_duration_minutes // 60} hour(s) across "
            f"{len(rounds)} rounds and cost ~{total_fees:,} sats in fees — it runs "
            "in the background; you can keep using the wallet."
        )

    return BootstrapPlan(
        initial_deposit_sats=int(deposit),
        target_inbound_sats=target_inbound_sats,
        expected_total_inbound_sats=int(total_inbound),
        expected_total_fees_sats=int(total_fees),
        expected_rounds=len(rounds),
        est_duration_minutes=int(est_duration_minutes),
        residual_outbound_sats=int(residual),
        rounds=rounds,
        diagnostics=PlanDiagnostics(
            warnings=tuple(warnings),
            fee_rate_sat_vb_medium=fee_rate_sat_vb_medium,
            fee_rate_sat_vb_high=fee_rate_sat_vb_high,
            catalog_snapshot_date=catalog_snapshot_date,
            diversity_axes_satisfied=diversity_axes,
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
    "BOOTSTRAP_RESERVE_PCT",
    "BOOTSTRAP_RESERVE_FLOOR_SATS",
    "BOOTSTRAP_BOLTZ_FEE_PCT",
    "BOOTSTRAP_SWAP_VBYTES",
    "BOOTSTRAP_ROUTING_FEE_PCT",
    "BOOTSTRAP_MAX_ROUNDS",
    "BOOTSTRAP_MAX_CHANNELS_PER_PEER",
    "BOOTSTRAP_MAX_DURATION_MINUTES",
    "BOOTSTRAP_AWAITING_FUNDS_TIMEOUT_MINUTES",
    "BOOTSTRAP_CONFIRMATIONS_PER_ROUND",
    "BOOTSTRAP_BLOCK_MINUTES",
    "BOOTSTRAP_STUCK_MINUTES",
    "BOOTSTRAP_DEFAULT_BOLTZ_MIN_SATS",
    "BOOTSTRAP_DEFAULT_BOLTZ_MAX_SATS",
    "BOOTSTRAP_HEADROOM_SATS",
    "Breakdown",
    "BootstrapPlan",
    "BootstrapRound",
    "ChannelOpen",
    "FeeOracle",
    "InboundSeedStrategy",
    "OutboundOption",
    "PeerMixMode",
    "Plan",
    "PlanDiagnostics",
    "allocate_capacity",
    "bootstrap_capacity_cap",
    "bootstrap_drain_for_capacity",
    "bootstrap_reserve_for_capacity",
    "bootstrap_swap_miner_fee_sats",
    "derive_bootstrap_schedule",
    "derive_channel_count",
    "derive_seed_plan",
    "plan_channel_mix",
    "select_peers",
]
