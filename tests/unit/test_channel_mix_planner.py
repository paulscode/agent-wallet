# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`app.services.channel_mix_planner`.

The planner is pure functions; tests inject a stub fee oracle and read
out the resulting :class:`Plan` shape. Coverage:

* Channel-count heuristic at the boundary values.
* Capacity allocation respects the per-channel floor.
* Buffer math: ``recommended_sats > minimum_sats`` by the component sum,
  buffer scales with channel count, fee-spike cushion projects against
  the *high* feerate.
* Future-channel slot opt-in adds exactly its constant.
* Peer selection skips marginal_routing in auto modes, includes it on
  manual_picks (when explicitly opted in), and tries for geographic +
  operator + fee-tier diversity.
* Fee oracle: medium / high pulled correctly, fallback used + warning
  emitted when oracle is unreachable.
* Inbound seed plan: ``push_only`` when Boltz is unavailable;
  ``boltz_reverse`` when it is.
"""

from __future__ import annotations

from typing import Optional

import pytest

from app.services.channel_mix_planner import (
    CLOSE_RESERVE_SATS_PER_CHANNEL,
    FALLBACK_SAT_PER_VB,
    FEE_SPIKE_CUSHION_FLOOR_SATS,
    FUTURE_CHANNEL_SLOT_SATS,
    MAX_CHANNELS_PER_PLAN,
    PER_CHANNEL_FLOOR_SATS,
    VBYTES_PER_CHANNEL_OPEN,
    Breakdown,
    Plan,
    allocate_capacity,
    derive_channel_count,
    derive_seed_plan,
    plan_channel_mix,
    select_peers,
)


def _stub_oracle(medium: float, high: float):
    """Build a fee-oracle stub that returns ``{halfHourFee, fastestFee}``
    in mempool.space shape."""

    async def _f():
        return ({"halfHourFee": medium, "fastestFee": high, "hourFee": medium}, None)

    return _f


def _oracle_error():
    async def _f():
        return None, "connection refused"

    return _f


class TestDeriveChannelCount:
    def test_below_threshold_single_channel(self):
        assert derive_channel_count(150_000) == 1
        assert derive_channel_count(600_000) == 1

    def test_at_2_channel_threshold(self):
        # Just over single-channel ceiling.
        assert derive_channel_count(600_001) == 2
        # Just under the 2-channel ceiling.
        assert derive_channel_count(1_500_000) == 2

    def test_large_targets_split_by_2m_soft_ceiling(self):
        # 4 M sats → 2 channels (2 M each).
        assert derive_channel_count(4_000_000) == 2
        # 5 M sats → 3 channels (~1.67 M each).
        assert derive_channel_count(5_000_000) == 3

    def test_extremely_large_capped_at_plan_max(self):
        # 20 M sats would naively be 10 channels — capped at 6.
        assert derive_channel_count(20_000_000) == MAX_CHANNELS_PER_PLAN

    def test_zero_or_negative_returns_zero(self):
        assert derive_channel_count(0) == 0
        assert derive_channel_count(-1) == 0


class TestAllocateCapacity:
    def test_even_split_with_remainder_on_first(self):
        out = allocate_capacity(1_000_001, 2)
        assert out == (500_001, 500_000)

    def test_per_channel_floor_respected(self):
        # 1 M sats split across 10 channels would be 100 k each (below
        # the 150 k floor). The allocator drops to the number of
        # channels the budget can afford at the floor.
        out = allocate_capacity(1_000_000, 10)
        # 1_000_000 / 150_000 = 6 with 100_000 remainder.
        assert sum(out) == 1_000_000
        assert all(c >= PER_CHANNEL_FLOOR_SATS for c in out)

    def test_below_one_floor_returns_empty(self):
        out = allocate_capacity(100_000, 1)
        # 100 k is below the 150 k floor — no slots survive.
        assert out == ()


class TestDeriveSeedPlan:
    def test_balanced_with_boltz(self):
        out = derive_seed_plan((1_000_000,), inbound_ratio=0.5, boltz_available=True)
        assert len(out) == 1
        push, seed, strategy = out[0]
        assert strategy == "boltz_reverse"
        # 50 % inbound target = 500_000; up to half from push, the rest
        # from a follow-on swap.
        assert push + seed == 500_000

    def test_no_boltz_falls_back_to_push_only(self):
        out = derive_seed_plan((1_000_000,), inbound_ratio=0.5, boltz_available=False)
        push, seed, strategy = out[0]
        assert strategy == "push_only"
        # Without Boltz, push covers the inbound target up to half capacity.
        assert push == 500_000
        assert seed == 0

    def test_inbound_ratio_clamped(self):
        out = derive_seed_plan((1_000_000,), inbound_ratio=2.0, boltz_available=True)
        push, seed, _ = out[0]
        assert push + seed == 1_000_000  # clamped to 100 %


class TestPlanBufferMath:
    @pytest.mark.asyncio
    async def test_recommended_exceeds_minimum_by_buffer_sum(self):
        plan = await plan_channel_mix(
            target_capacity_sats=3_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        # Sanity: 3 M → 2 channels, both above the per-channel floor.
        assert len(plan.per_channel) == 2

        # ``minimum_sats = capacity + medium-priority open fees``.
        expected_min = (
            plan.breakdown.channel_capacity_sats
            + plan.breakdown.open_fees_sats
        )
        assert plan.minimum_sats == expected_min

        # ``recommended_sats = minimum + close-reserve + fee-spike + future-slot``.
        expected_rec = (
            expected_min
            + plan.breakdown.close_reserve_sats
            + plan.breakdown.fee_spike_cushion_sats
            + plan.breakdown.future_channel_slot_sats
        )
        assert plan.recommended_sats == expected_rec
        assert plan.recommended_sats > plan.minimum_sats

    @pytest.mark.asyncio
    async def test_close_reserve_scales_with_channel_count(self):
        small = await plan_channel_mix(
            target_capacity_sats=400_000,  # 1 channel
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        big = await plan_channel_mix(
            target_capacity_sats=3_000_000,  # 2 channels (above 1.5 M ceiling)
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        assert len(small.per_channel) == 1
        assert len(big.per_channel) == 2
        # 2 channels → 2× the close reserve.
        assert big.breakdown.close_reserve_sats == 2 * small.breakdown.close_reserve_sats
        assert small.breakdown.close_reserve_sats == CLOSE_RESERVE_SATS_PER_CHANNEL

    @pytest.mark.asyncio
    async def test_fee_spike_cushion_uses_high_feerate(self):
        # Fee spike component must reflect the *high* feerate, not
        # medium — otherwise the cushion under-estimates a real spike.
        plan = await plan_channel_mix(
            target_capacity_sats=3_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=5.0, high=50.0),  # 10× spike
            boltz_available=True,
        )
        # Open fee at medium: 2 × 250 × 5 = 2500. High: 2 × 250 × 50 = 25000.
        # Cushion must absorb the delta (22_500) — well above the
        # floor (10_000).
        assert plan.breakdown.fee_spike_cushion_sats >= 22_500

    @pytest.mark.asyncio
    async def test_fee_spike_cushion_honours_floor(self):
        # Tiny plan + flat feerate — cushion would round to <10 k but
        # must respect the floor.
        plan = await plan_channel_mix(
            target_capacity_sats=400_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=1.0, high=1.0),
            boltz_available=True,
        )
        assert plan.breakdown.fee_spike_cushion_sats >= FEE_SPIKE_CUSHION_FLOOR_SATS

    @pytest.mark.asyncio
    async def test_future_channel_slot_opt_in(self):
        without = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        with_slot = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
            leave_room_for_one_more=True,
        )
        assert without.breakdown.future_channel_slot_sats == 0
        assert with_slot.breakdown.future_channel_slot_sats == FUTURE_CHANNEL_SLOT_SATS
        assert with_slot.recommended_sats == without.recommended_sats + FUTURE_CHANNEL_SLOT_SATS


class TestPlanPeerSelection:
    @pytest.mark.asyncio
    async def test_recommended_diverse_includes_one_star_peer(self):
        plan = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        starred = [
            ch for ch in plan.per_channel
            if "recommended_default" in ch.peer.tags
        ]
        assert starred, "recommended_diverse must include at least one ⭐ peer"

    @pytest.mark.asyncio
    async def test_recommended_diverse_skips_marginal_routing(self):
        plan = await plan_channel_mix(
            target_capacity_sats=5_000_000,  # plenty of slots
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        # CoinGate is the bundled marginal-routing peer.
        coingate_pub = "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3"
        chosen_pubs = {ch.peer.node_id_hex for ch in plan.per_channel}
        assert coingate_pub not in chosen_pubs

    @pytest.mark.asyncio
    async def test_cheapest_only_orders_by_fee_rate(self):
        plan = await plan_channel_mix(
            target_capacity_sats=2_000_000,  # 2 channels
            outbound_option="balanced",
            peer_mix_mode="cheapest_only",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        rates = [ch.peer.typical.fee_rate_milli_msat for ch in plan.per_channel]
        assert rates == sorted(rates)

    @pytest.mark.asyncio
    async def test_manual_picks_honoured(self):
        babylon_pub = "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3"
        krut42_pub = "02961ed16db648f99ff5aa121a263420911d6b6011794f2a99b79397b5e8b2eed4"
        plan = await plan_channel_mix(
            target_capacity_sats=3_000_000,  # 2 channels available
            outbound_option="balanced",
            peer_mix_mode="manual_picks",
            manual_picks=[babylon_pub, krut42_pub],
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        chosen = [ch.peer.node_id_hex for ch in plan.per_channel]
        assert babylon_pub in chosen
        assert krut42_pub in chosen

    @pytest.mark.asyncio
    async def test_manual_picks_blocks_marginal_routing_by_default(self):
        coingate_pub = "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3"
        babylon_pub = "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3"
        plan = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="manual_picks",
            manual_picks=[coingate_pub, babylon_pub],
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        chosen = {ch.peer.node_id_hex for ch in plan.per_channel}
        assert coingate_pub not in chosen, "marginal-routing peer should be filtered without opt-in"
        assert babylon_pub in chosen

    @pytest.mark.asyncio
    async def test_manual_picks_includes_marginal_when_opted_in(self):
        coingate_pub = "0242a4ae0c5bef18048fbecf995094b74bfb0f7391418d71ed394784373f41e4f3"
        plan = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="manual_picks",
            manual_picks=[coingate_pub],
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
            include_marginal_routing=True,
        )
        chosen = {ch.peer.node_id_hex for ch in plan.per_channel}
        assert coingate_pub in chosen
        # Diagnostics should warn about the marginal-routing flag.
        joined = " ".join(plan.diagnostics.warnings)
        assert "marginal-routing" in joined

    @pytest.mark.asyncio
    async def test_diversity_axes_satisfied_for_multi_channel(self):
        plan = await plan_channel_mix(
            target_capacity_sats=4_000_000,  # 2 channels
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        assert len(plan.per_channel) >= 2
        # The diverse picker should satisfy at least one axis.
        assert plan.diagnostics.diversity_axes_satisfied


class TestPlanFeeOracleFallback:
    @pytest.mark.asyncio
    async def test_oracle_error_falls_back_to_conservative_rate(self):
        plan = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_oracle_error(),
            boltz_available=True,
        )
        assert plan.diagnostics.fee_rate_sat_vb_medium == float(FALLBACK_SAT_PER_VB)
        assert plan.diagnostics.fee_rate_sat_vb_high == float(FALLBACK_SAT_PER_VB)
        joined = " ".join(plan.diagnostics.warnings)
        assert "conservative estimate" in joined

    @pytest.mark.asyncio
    async def test_oracle_none_falls_back(self):
        plan = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=None,
            boltz_available=True,
        )
        joined = " ".join(plan.diagnostics.warnings)
        assert "conservative estimate" in joined


class TestPlanInboundSeed:
    @pytest.mark.asyncio
    async def test_boltz_unavailable_emits_warning_and_uses_push_only(self):
        plan = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=False,
        )
        for ch in plan.per_channel:
            assert ch.inbound_seed_strategy == "push_only"
        joined = " ".join(plan.diagnostics.warnings)
        assert "Boltz" in joined

    @pytest.mark.asyncio
    async def test_boltz_available_uses_reverse_swap(self):
        plan = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="bitcoin",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        for ch in plan.per_channel:
            assert ch.inbound_seed_strategy == "boltz_reverse"


class TestPlanEmptyCatalog:
    @pytest.mark.asyncio
    async def test_non_mainnet_yields_empty_plan_with_warning(self):
        plan = await plan_channel_mix(
            target_capacity_sats=2_000_000,
            outbound_option="balanced",
            peer_mix_mode="recommended_diverse",
            network="regtest",
            catalog_snapshot_date="2026-06-27",
            fee_oracle=_stub_oracle(medium=10.0, high=15.0),
            boltz_available=True,
        )
        assert plan.per_channel == ()
        joined = " ".join(plan.diagnostics.warnings)
        assert "catalog" in joined.lower()
