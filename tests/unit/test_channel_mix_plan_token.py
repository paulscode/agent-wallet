# SPDX-License-Identifier: MIT
"""Unit tests for :mod:`app.services.channel_mix_plan_token`.

The token is HMAC-SHA256 keyed from a SECRET_KEY-derived subkey.
Required properties:

* The token round-trips: a plan signed and immediately verified passes.
* A field-by-field tampering changes the token (any single byte change
  to the plan body must invalidate the signature).
* A different SECRET_KEY produces a different token.
* Malformed tokens are rejected without raising.
"""

from __future__ import annotations

import pytest

from app.services.channel_mix_plan_token import sign_plan, verify_plan_token
from app.services.channel_mix_planner import (
    Breakdown,
    ChannelOpen,
    Plan,
    PlanDiagnostics,
)
from app.services.small_channel_peers import lookup


def _make_plan(*, capacity: int = 1_000_000, ppm_warning: str = "") -> Plan:
    babylon = lookup(
        "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3",
        network="bitcoin",
    )
    assert babylon is not None
    return Plan(
        minimum_sats=capacity + 2_500,
        recommended_sats=capacity + 40_000,
        breakdown=Breakdown(
            channel_capacity_sats=capacity,
            open_fees_sats=2_500,
            close_reserve_sats=25_000,
            fee_spike_cushion_sats=12_500,
            future_channel_slot_sats=0,
        ),
        per_channel=(
            ChannelOpen(
                peer=babylon,
                capacity=capacity,
                push_sat=0,
                expected_inbound_seed_sats=0,
                inbound_seed_strategy="boltz_reverse",
            ),
        ),
        diagnostics=PlanDiagnostics(
            warnings=(ppm_warning,) if ppm_warning else (),
            fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=15.0,
            catalog_snapshot_date="2026-06-27",
            diversity_axes_satisfied=(),
        ),
    )


class TestSignAndVerifyRoundTrip:
    def test_token_is_short_and_url_safe(self):
        token = sign_plan(_make_plan(), secret="x" * 64)
        # base64-url 256-bit digest without padding → 43 chars.
        assert len(token) == 43
        # No padding chars, no '+' / '/'.
        assert "=" not in token
        assert "+" not in token
        assert "/" not in token

    def test_round_trip_passes(self):
        plan = _make_plan()
        token = sign_plan(plan, secret="x" * 64)
        assert verify_plan_token(plan, token, secret="x" * 64) is True


class TestTamperingInvalidatesToken:
    def test_changing_capacity_invalidates(self):
        plan = _make_plan(capacity=1_000_000)
        token = sign_plan(plan, secret="x" * 64)
        # Build a tampered plan whose capacity is one sat off.
        tampered = _make_plan(capacity=1_000_001)
        assert verify_plan_token(tampered, token, secret="x" * 64) is False

    def test_changing_diagnostics_invalidates(self):
        plan = _make_plan(ppm_warning="")
        token = sign_plan(plan, secret="x" * 64)
        tampered = _make_plan(ppm_warning="bogus warning")
        assert verify_plan_token(tampered, token, secret="x" * 64) is False


class TestDifferentSecretsDiverge:
    def test_token_signed_with_secret_a_rejects_under_secret_b(self):
        plan = _make_plan()
        token_a = sign_plan(plan, secret="a" * 64)
        token_b = sign_plan(plan, secret="b" * 64)
        # Same plan, different secrets → different tokens.
        assert token_a != token_b
        # Token A doesn't verify under secret B.
        assert verify_plan_token(plan, token_a, secret="b" * 64) is False


class TestMalformedTokens:
    def test_empty_token_rejected(self):
        assert verify_plan_token(_make_plan(), "", secret="x" * 64) is False

    def test_garbage_token_rejected(self):
        assert verify_plan_token(_make_plan(), "not-a-token", secret="x" * 64) is False

    def test_non_string_token_rejected(self):
        assert verify_plan_token(_make_plan(), None, secret="x" * 64) is False  # type: ignore[arg-type]
        assert verify_plan_token(_make_plan(), 42, secret="x" * 64) is False  # type: ignore[arg-type]


# ─── BootstrapPlan also round-trips through the same token machinery ──


def _make_bootstrap_plan(*, deposit: int = 500_000, rounds_meta: str = ""):
    from app.services.channel_mix_planner import (
        BootstrapPlan,
        BootstrapRound,
    )
    from app.services.small_channel_peers import lookup

    babylon = lookup(
        "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3",
        network="bitcoin",
    )
    assert babylon is not None
    return BootstrapPlan(
        initial_deposit_sats=deposit,
        target_inbound_sats=None,
        expected_total_inbound_sats=2_000_000,
        expected_total_fees_sats=50_000,
        expected_rounds=1,
        est_duration_minutes=40,
        residual_outbound_sats=20_000,
        rounds=(
            BootstrapRound(
                peer=babylon,
                capacity_sats=deposit - 2_500,
                drain_target_sats=400_000,
                expected_inbound_sats=400_000,
                est_open_fee_sats=2_500,
                est_swap_fee_sats=1_200,
            ),
        ),
        diagnostics=PlanDiagnostics(
            warnings=(rounds_meta,) if rounds_meta else (),
            fee_rate_sat_vb_medium=10.0,
            fee_rate_sat_vb_high=15.0,
            catalog_snapshot_date="2026-06-27",
            diversity_axes_satisfied=(),
        ),
    )


class TestBootstrapPlanToken:
    def test_round_trip_passes(self):
        plan = _make_bootstrap_plan()
        token = sign_plan(plan)
        assert verify_plan_token(plan, token) is True

    def test_changing_deposit_invalidates(self):
        token = sign_plan(_make_bootstrap_plan(deposit=500_000))
        # A different deposit (different schedule) must not verify.
        assert verify_plan_token(_make_bootstrap_plan(deposit=600_000), token) is False

    def test_changing_a_round_field_invalidates(self):
        plan = _make_bootstrap_plan()
        token = sign_plan(plan)
        tampered = _make_bootstrap_plan(rounds_meta="injected-warning")
        assert verify_plan_token(tampered, token) is False

    def test_bootstrap_and_parallel_plans_do_not_collide(self):
        """A BootstrapPlan token must never validate a parallel Plan (the
        execute endpoint re-builds the right type per mode)."""
        bootstrap_token = sign_plan(_make_bootstrap_plan())
        assert verify_plan_token(_make_plan(), bootstrap_token) is False
