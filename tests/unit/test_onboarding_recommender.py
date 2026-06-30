# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`app.services.onboarding_recommender` (pure helpers).

The endpoint orchestration (running the planners) is covered by the integration
suite; here we pin the numeric mapping, the receive efficient-vs-fast decision,
and the card serializers (including the empty-plan → ``None`` fallback).
"""

from __future__ import annotations

from app.services.channel_mix_planner import (
    PER_CHANNEL_FLOOR_SATS,
    Breakdown,
    BootstrapPlan,
    BootstrapRound,
    ChannelOpen,
    Plan,
    PlanDiagnostics,
)
from app.services.onboarding_recommender import (
    EXPLORE_STARTER_SATS,
    RECEIVE_EFFICIENT_MIN_TARGET_SATS,
    bootstrap_card,
    clamp_to_floor,
    parallel_card,
    receive_default_is_efficient,
    receive_fast_capacity,
)
from app.services.small_channel_peers import lookup

_PEER_PUBKEY = "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3"


def _peer():
    p = lookup(_PEER_PUBKEY, network="bitcoin")
    assert p is not None
    return p


def _diag():
    return PlanDiagnostics(
        warnings=(),
        fee_rate_sat_vb_medium=10.0,
        fee_rate_sat_vb_high=15.0,
        catalog_snapshot_date="2026-06-27",
        diversity_axes_satisfied=(),
    )


class TestNumericHelpers:
    def test_clamp_below_floor_bumps(self):
        value, bumped = clamp_to_floor(10_000)
        assert value == PER_CHANNEL_FLOOR_SATS
        assert bumped is True

    def test_clamp_zero_or_none_not_flagged_as_bump(self):
        # No amount entered → clamp to floor but don't nag with a "raised" note.
        assert clamp_to_floor(0) == (PER_CHANNEL_FLOOR_SATS, False)
        assert clamp_to_floor(None) == (PER_CHANNEL_FLOOR_SATS, False)

    def test_clamp_above_floor_passes_through(self):
        assert clamp_to_floor(750_000) == (750_000, False)

    def test_receive_fast_capacity_grosses_up_for_inbound_share(self):
        # receive-heavy is 75% inbound → need ~1.333x capacity for the target.
        assert receive_fast_capacity(750_000) == 1_000_000

    def test_receive_default_efficient_only_for_large_targets_with_boltz(self):
        assert receive_default_is_efficient(RECEIVE_EFFICIENT_MIN_TARGET_SATS, True) is True
        assert receive_default_is_efficient(RECEIVE_EFFICIENT_MIN_TARGET_SATS - 1, True) is False
        # Never efficient when Boltz is unavailable.
        assert receive_default_is_efficient(5_000_000, False) is False


class TestCardSerializers:
    def test_parallel_card_empty_plan_is_none(self):
        empty = Plan(
            minimum_sats=0,
            recommended_sats=0,
            breakdown=Breakdown(0, 0, 0, 0, 0),
            per_channel=(),
            diagnostics=_diag(),
        )
        assert parallel_card(
            empty, target_capacity_sats=500_000, outbound_option="balanced",
            rationale="x",
        ) is None

    def test_parallel_card_shape(self):
        plan = Plan(
            minimum_sats=502_500,
            recommended_sats=540_000,
            breakdown=Breakdown(500_000, 2_500, 25_000, 12_500, 0),
            per_channel=(
                ChannelOpen(
                    peer=_peer(), capacity=500_000, push_sat=0,
                    expected_inbound_seed_sats=0, inbound_seed_strategy="boltz_reverse",
                ),
            ),
            diagnostics=_diag(),
        )
        card = parallel_card(
            plan, target_capacity_sats=500_000, outbound_option="custom",
            rationale="spend rationale",
        )
        assert card["strategy"] == "parallel"
        assert card["deposit_sats"] == 540_000
        assert card["minimum_deposit_sats"] == 502_500
        assert card["target_capacity_sats"] == 500_000
        assert card["outbound_option"] == "custom"
        assert card["estimate"] is None
        assert card["breakdown"]["close_reserve_sats"] == 25_000
        assert card["rationale"] == "spend rationale"

    def test_bootstrap_card_empty_is_none(self):
        empty = BootstrapPlan(
            initial_deposit_sats=0, target_inbound_sats=1_000_000,
            expected_total_inbound_sats=0, expected_total_fees_sats=0,
            expected_rounds=0, est_duration_minutes=0, residual_outbound_sats=0,
            rounds=(), diagnostics=_diag(),
        )
        assert bootstrap_card(empty, rationale="x") is None

    def test_bootstrap_card_shape(self):
        plan = BootstrapPlan(
            initial_deposit_sats=350_000,
            target_inbound_sats=1_500_000,
            expected_total_inbound_sats=1_600_000,
            expected_total_fees_sats=40_000,
            expected_rounds=5,
            est_duration_minutes=200,
            residual_outbound_sats=30_000,
            rounds=(
                BootstrapRound(
                    peer=_peer(), capacity_sats=345_000, drain_target_sats=330_000,
                    expected_inbound_sats=330_000, est_open_fee_sats=2_500,
                    est_swap_fee_sats=1_200,
                ),
            ),
            diagnostics=_diag(),
        )
        card = bootstrap_card(plan, rationale="receive efficient")
        assert card["strategy"] == "bootstrap"
        assert card["deposit_sats"] == 350_000
        assert card["target_inbound_sats"] == 1_500_000
        assert card["breakdown"] is None
        assert card["estimate"]["rounds"] == 5
        assert card["estimate"]["est_duration_minutes"] == 200
        assert card["estimate"]["expected_total_inbound_sats"] == 1_600_000
