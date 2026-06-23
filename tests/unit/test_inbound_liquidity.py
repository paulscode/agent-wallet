# SPDX-License-Identifier: MIT
"""Parity tests for the Add-Receive-Capacity wizard.

The JS getters and helpers live in
``app/dashboard/static/dashboard.js``. As with
``test_onboarding_step.py``, we mirror each piece in Python so the
behaviour can be exercised in CI and any future JS change is caught
when the two diverge.

If you change the JS, update the matching helper below and re-run
this file.
"""

from __future__ import annotations

import math
from typing import Any, Optional

import pytest

# ── Constants mirrored from dashboard.js ────────────────────────────

BOLTZ_MIN_AMOUNT_SATS = 25_000
BOLTZ_MAX_AMOUNT_SATS = 25_000_000
INBOUND_SAFETY_MARGIN_SATS = 5_000
INBOUND_LOCAL_RESERVE_SATS = 10_000

SWAP_USER_STEP_INDEX = {
    "created": 0,
    "paying_invoice": 1,
    "invoice_paid": 1,
    "claiming": 2,
    "claimed": 2,
    "completed": 3,
}
SWAP_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "refunded"}


def swap_user_step_index(status: Optional[str]) -> int:
    """Mirror of the shared ``_swapUserStepIndex`` helper."""
    if not status:
        return 0
    return SWAP_USER_STEP_INDEX.get(status, 0)


def is_terminal_status(status: Optional[str]) -> bool:
    """Used by the localStorage clear logic."""
    return status in SWAP_TERMINAL_STATUSES


def inbound_capacity_sats(summary: Optional[dict]) -> int:
    """Mirror of ``inboundCapacitySats``."""
    if summary is None:
        return 0
    totals = summary.get("totals") or {}
    return totals.get("lightning_remote_sats") or 0


def inbound_local_balance_sats(summary: Optional[dict]) -> int:
    """Mirror of ``inboundLocalBalanceSats`` (reads the existing
    ``localBalance`` getter which dives into ``summary.lightning``)."""
    if summary is None:
        return 0
    lightning = summary.get("lightning") or {}
    return lightning.get("local_balance_sat") or 0


def inbound_has_active_channel(summary: Optional[dict]) -> bool:
    if summary is None:
        return False
    totals = summary.get("totals") or {}
    return (totals.get("num_active_channels") or 0) >= 1


def inbound_banner_kind(summary: Optional[dict], recv_amount_str: str) -> Optional[str]:
    """Mirror of ``inboundBannerKind``."""
    if summary is None:
        return None
    if not inbound_has_active_channel(summary):
        return None
    have = inbound_capacity_sats(summary)
    if have == 0:
        return "block"
    try:
        requested = int(recv_amount_str)
    except (TypeError, ValueError):
        requested = 0
    if requested > 0 and requested > have:
        return "short"
    return None


def inbound_channel_too_small(summary: Optional[dict]) -> bool:
    if summary is None:
        return False
    if not inbound_has_active_channel(summary):
        return False
    local = inbound_local_balance_sats(summary)
    return 0 < local < BOLTZ_MIN_AMOUNT_SATS


def inbound_suggested_amount(summary: Optional[dict], seed_recv_amount: int = 0) -> int:
    """Mirror of ``inboundSuggestedAmount``."""
    local = inbound_local_balance_sats(summary)
    if local <= 0:
        return 0
    have = inbound_capacity_sats(summary)
    if seed_recv_amount > 0:
        target = max(0, seed_recv_amount - have) + INBOUND_SAFETY_MARGIN_SATS
    else:
        target = local // 2
    ceiling = max(0, local - INBOUND_LOCAL_RESERVE_SATS)
    target = min(target, ceiling, BOLTZ_MAX_AMOUNT_SATS)
    target = max(target, BOLTZ_MIN_AMOUNT_SATS)
    if ceiling < BOLTZ_MIN_AMOUNT_SATS:
        return 0
    return target


def inbound_boltz_percentage_fee_sats(amount: int, boltz_fees: Optional[dict]) -> int:
    """Mirror of ``inboundBoltzPercentageFeeSats``."""
    fees = boltz_fees or {}
    pct = fees.get("fees_percentage") or 0
    return math.ceil(amount * pct / 100)


def inbound_boltz_miner_fee_sats(boltz_fees: Optional[dict]) -> int:
    fees = boltz_fees or {}
    return (fees.get("fees_miner_lockup") or 0) + (fees.get("fees_miner_claim") or 0)


def inbound_total_fee_sats(amount: int, boltz_fees: Optional[dict]) -> int:
    return inbound_boltz_percentage_fee_sats(amount, boltz_fees) + inbound_boltz_miner_fee_sats(boltz_fees)


def inbound_receive_onchain_sats(amount: int, boltz_fees: Optional[dict]) -> int:
    return max(0, amount - inbound_total_fee_sats(amount, boltz_fees))


def inbound_can_submit(
    amount: int,
    local_balance: int,
    loading: bool = False,
    boltz_reachable: bool = True,
) -> bool:
    """Mirror of ``inboundCanSubmit``. The ``boltz_reachable`` gate
    was added during gap fixes — submit is disabled when
    ``/cold-storage/fees`` hasn't produced a usable payload."""
    if loading:
        return False
    if not boltz_reachable:
        return False
    if amount < BOLTZ_MIN_AMOUNT_SATS:
        return False
    if amount > BOLTZ_MAX_AMOUNT_SATS:
        return False
    if amount > local_balance:
        return False
    return True


def inbound_channel_too_small(summary: Optional[dict]) -> bool:
    """Mirror of ``inboundChannelTooSmall``. True when a channel
    exists but its local balance can't cover even the Boltz
    minimum — wizard surfaces the non-actionable banner variant."""
    if summary is None:
        return False
    if not inbound_has_active_channel(summary):
        return False
    local = inbound_local_balance_sats(summary)
    return 0 < local < BOLTZ_MIN_AMOUNT_SATS


def inbound_max_addable_capacity(summary: Optional[dict]) -> int:
    """Mirror of ``inboundMaxAddableCapacity``. ``min(local - reserve,
    BOLTZ_MAX)``, clamped to non-negative. Used by the "you can add
    up to N sats" note when the user's seed exceeds capacity."""
    local = inbound_local_balance_sats(summary)
    if local <= 0:
        return 0
    ceiling = max(0, local - INBOUND_LOCAL_RESERVE_SATS)
    return min(ceiling, BOLTZ_MAX_AMOUNT_SATS)


def inbound_capped_by_seed(summary: Optional[dict], seed_recv_amount: int) -> bool:
    """Mirror of ``inboundCappedBySeed``. True when the user came
    from the soft-warning banner with an invoice amount their
    channel can't fully cover — even with the safety margin."""
    if seed_recv_amount <= 0:
        return False
    have = inbound_capacity_sats(summary)
    needed = max(0, seed_recv_amount - have) + INBOUND_SAFETY_MARGIN_SATS
    return inbound_max_addable_capacity(summary) < needed


def inbound_fees_loading(boltz_fees_fetched: bool) -> bool:
    """Mirror of ``inboundFeesLoading``. True until the first
    ``fetchBoltzFees`` attempt has resolved (success or failure)."""
    return not boltz_fees_fetched


def inbound_boltz_reachable(boltz_fees: Optional[dict], boltz_fees_fetched: bool = True) -> bool:
    """Mirror of ``inboundBoltzReachable``. Requires both:
    * The fetch has completed at least once (``boltz_fees_fetched``).
    * The resulting payload contains a numeric ``fees_percentage``.

    Splits the in-flight state from the genuine-failure state so the
    UI can pick between a spinner and a red banner."""
    if not boltz_fees_fetched:
        return False
    if boltz_fees is None:
        return False
    return isinstance(boltz_fees.get("fees_percentage"), (int, float))


def inbound_banner_payload(
    summary: Optional[dict],
    recv_amount_str: str,
) -> Optional[dict]:
    """Mirror of ``inboundBannerPayload``. Combines ``inbound_banner_kind``
    with ``inbound_channel_too_small`` into the struct the
    Receive-Lightning template reads. Returns ``None`` when no banner
    should render."""
    kind = inbound_banner_kind(summary, recv_amount_str)
    if not kind:
        return None
    if inbound_channel_too_small(summary):
        return {
            "tone": "warning",
            "text": ("Your channel is too small to add receive capacity automatically. Try opening a larger channel."),
            "cta": None,
        }
    if kind == "block":
        return {
            "tone": "block",
            "text": "You can't receive Lightning payments yet.",
            "cta": "Add receive capacity",
        }
    # 'short' — soft warning.
    have = inbound_capacity_sats(summary)
    return {
        "tone": "short",
        "text": f"You can only receive up to {have:,} sats right now.",
        "cta": "Add more capacity",
    }


def inbound_terminal_view(status: Optional[str]) -> Optional[str]:
    """Mirror of the JS poller branch that maps a terminal status to
    either the success view or the failed view (or ``None`` for
    non-terminal). Plan: ``refunded`` is presented as a failure
    even though it isn't strictly an error — the user's sats are
    safe, but the operation didn't achieve the user's goal."""
    if status == "completed":
        return "success"
    if status in SWAP_TERMINAL_STATUSES:
        return "failed"
    return None


def inbound_amount_error(amount: int, local_balance: int) -> str:
    """Mirror of ``inboundAmountError``. Returns the inline error
    string shown under the amount input, or empty string when the
    amount is acceptable. Note: this surfaces *user-typed* errors;
    the form-wide ``inboundBoltzReachable`` banner is independent."""
    if amount <= 0:
        return ""
    if amount < BOLTZ_MIN_AMOUNT_SATS:
        return f"Minimum is {BOLTZ_MIN_AMOUNT_SATS:,} sats."
    if amount > BOLTZ_MAX_AMOUNT_SATS:
        return f"Maximum is {BOLTZ_MAX_AMOUNT_SATS:,} sats."
    if amount > local_balance:
        return f"You only have {local_balance:,} sats available on your channel."
    return ""


def inbound_is_cancellable(status: Optional[str]) -> bool:
    """— only the ``created`` state shows the Cancel button."""
    return status == "created"


def inbound_should_show_claim_txid(status: Optional[str], claim_txid: str) -> bool:
    if not claim_txid:
        return False
    return status in ("claimed", "completed")


# ── Fixture builders ─────────────────────────────────────────────────


_BOLTZ_FEES = {
    "min": BOLTZ_MIN_AMOUNT_SATS,
    "max": BOLTZ_MAX_AMOUNT_SATS,
    "fees_percentage": 0.5,
    "fees_miner_lockup": 462,
    "fees_miner_claim": 333,
}


def _summary(
    *,
    onchain: int = 0,
    unconfirmed: int = 0,
    local: int = 0,
    remote: int = 0,
    active: int = 0,
    pending: int = 0,
) -> dict[str, Any]:
    """Build a summary payload shaped like /dashboard/api/summary."""
    return {
        "lightning": {
            "local_balance_sat": local,
            "remote_balance_sat": remote,
        },
        "totals": {
            "onchain_sats": onchain,
            "unconfirmed_sats": unconfirmed,
            "lightning_local_sats": local,
            "lightning_remote_sats": remote,
            "num_active_channels": active,
            "num_pending_channels": pending,
        },
    }


# ── Tests ────────────────────────────────────────────────────────────


class TestBannerKind:
    """Banner state machine."""

    def test_no_summary_returns_none(self):
        assert inbound_banner_kind(None, "100000") is None

    def test_no_active_channels_returns_none(self):
        # Pre-channel users live in the onboarding wizard's world, not
        # ours. We must not double up on prompts.
        assert inbound_banner_kind(_summary(active=0, remote=0), "100000") is None

    def test_zero_inbound_blocks(self):
        s = _summary(active=1, local=200_000, remote=0)
        assert inbound_banner_kind(s, "100000") == "block"

    def test_zero_inbound_blocks_even_without_recv_amount(self):
        # The block fires regardless of what (if anything) the user
        # has typed.
        s = _summary(active=1, local=200_000, remote=0)
        assert inbound_banner_kind(s, "") == "block"
        assert inbound_banner_kind(s, "0") == "block"

    def test_sufficient_inbound_returns_none(self):
        s = _summary(active=1, local=100_000, remote=200_000)
        assert inbound_banner_kind(s, "50000") is None

    def test_requested_exceeds_inbound_returns_short(self):
        s = _summary(active=1, local=200_000, remote=50_000)
        assert inbound_banner_kind(s, "100000") == "short"

    def test_requested_exactly_equals_inbound_returns_none(self):
        # Boundary: equal-to is fine; you can receive exactly that.
        s = _summary(active=1, local=200_000, remote=50_000)
        assert inbound_banner_kind(s, "50000") is None

    def test_garbage_recv_amount_treated_as_zero(self):
        # Defensive: the JS uses parseInt which returns NaN for
        # garbage; we coerce that to 0 and so should the parity.
        s = _summary(active=1, local=200_000, remote=50_000)
        assert inbound_banner_kind(s, "abc") is None


class TestSuggestedAmount:
    """Default form prefill."""

    def test_local_zero_returns_zero(self):
        assert inbound_suggested_amount(_summary(local=0, active=1)) == 0

    def test_local_below_boltz_floor_plus_reserve_returns_zero(self):
        # User has a tiny channel and can't even meet the Boltz min
        # after the local reserve — better to suggest 0 than a
        # disabled "25,000" the user can't action.
        s = _summary(local=20_000, active=1)
        assert inbound_suggested_amount(s) == 0

    def test_half_local_when_no_seed(self):
        # 200k channel → suggest 100k. local/2 = 100_000, ceiling
        # 190_000, so it's the local/2 branch that wins.
        s = _summary(local=200_000, active=1)
        assert inbound_suggested_amount(s) == 100_000

    def test_clamps_at_boltz_max(self):
        # Massive channel — suggest BOLTZ_MAX, not local/2.
        s = _summary(local=100_000_000, active=1)
        assert inbound_suggested_amount(s) == BOLTZ_MAX_AMOUNT_SATS

    def test_clamps_at_ceiling_when_local_just_above_floor(self):
        # local 35k, reserve 10k → ceiling 25k. local/2 = 17,500
        # gets bumped up to the BOLTZ_MIN floor of 25k (which equals
        # the ceiling, so it just barely fits).
        s = _summary(local=35_000, active=1)
        result = inbound_suggested_amount(s)
        assert result == 25_000

    def test_seed_recv_amount_overrides_half_local(self):
        # User came from the soft-warning banner having typed 120k.
        # remote = 30k → seed_recv - remote = 90k + 5k margin = 95k.
        s = _summary(local=200_000, active=1, remote=30_000)
        assert inbound_suggested_amount(s, seed_recv_amount=120_000) == 95_000

    def test_seed_recv_amount_clamped_to_ceiling(self):
        # Seed asks for more than local - reserve can cover.
        # local 50k, reserve 10k → ceiling 40k. Seed wants 100k; we
        # cap at the ceiling.
        s = _summary(local=50_000, active=1, remote=0)
        assert inbound_suggested_amount(s, seed_recv_amount=100_000) == 40_000

    def test_seed_when_already_covered_falls_to_floor(self):
        # Edge case: user typed 50k, remote already has 100k — the
        # banner wouldn't have fired, but if the user got here some
        # other way, the suggestion shouldn't be negative. Seed -
        # have = -50k → max(0, -50k) = 0 + margin = 5k → bumped to
        # BOLTZ_MIN.
        s = _summary(local=200_000, active=1, remote=100_000)
        assert inbound_suggested_amount(s, seed_recv_amount=50_000) == BOLTZ_MIN_AMOUNT_SATS


class TestFeeMath:
    """Combined and per-component fee calculations."""

    def test_percentage_fee_rounds_up(self):
        # 100_000 * 0.5% = 500 sats exactly. No rounding needed.
        assert inbound_boltz_percentage_fee_sats(100_000, _BOLTZ_FEES) == 500

    def test_percentage_fee_ceils_fractional(self):
        # 30_001 * 0.5% = 150.005 → ceil to 151.
        assert inbound_boltz_percentage_fee_sats(30_001, _BOLTZ_FEES) == 151

    def test_miner_fee_sums(self):
        assert inbound_boltz_miner_fee_sats(_BOLTZ_FEES) == 462 + 333

    def test_total_fee_combines_both(self):
        # 100_000 * 0.5% = 500 + 795 miner = 1295.
        assert inbound_total_fee_sats(100_000, _BOLTZ_FEES) == 1295

    def test_receive_onchain_amount_subtracts_fees(self):
        # 100_000 - 1295 = 98_705.
        assert inbound_receive_onchain_sats(100_000, _BOLTZ_FEES) == 98_705

    def test_receive_onchain_never_negative(self):
        # If the fee somehow exceeds the amount (impossible with the
        # min-25k floor but be defensive), return 0 rather than a
        # negative number.
        assert inbound_receive_onchain_sats(0, _BOLTZ_FEES) == 0

    def test_missing_fees_object_yields_zero(self):
        # If the Boltz fee fetch hasn't completed yet, the fee
        # estimate is 0 — not a crash.
        assert inbound_total_fee_sats(100_000, None) == 0


class TestCanSubmit:
    """Submit-button gate."""

    def test_below_min_disabled(self):
        assert not inbound_can_submit(24_999, local_balance=200_000)

    def test_at_min_enabled(self):
        assert inbound_can_submit(BOLTZ_MIN_AMOUNT_SATS, local_balance=200_000)

    def test_above_max_disabled(self):
        assert not inbound_can_submit(BOLTZ_MAX_AMOUNT_SATS + 1, local_balance=200_000_000)

    def test_at_max_enabled(self):
        assert inbound_can_submit(BOLTZ_MAX_AMOUNT_SATS, local_balance=BOLTZ_MAX_AMOUNT_SATS)

    def test_exceeds_local_disabled(self):
        # Channel balance is the wall — the swap requires sending
        # the full amount over Lightning, plus a routing fee buffer
        # that backend will deduct on top.
        assert not inbound_can_submit(150_000, local_balance=100_000)

    def test_loading_disabled(self):
        assert not inbound_can_submit(50_000, local_balance=200_000, loading=True)

    def test_boltz_unreachable_disabled(self):
        # Added during gap fixes: submitting against a
        # zero fee preview would mislead users on what they're
        # actually paying. Submit is gated on the fees fetch
        # returning a usable payload.
        assert not inbound_can_submit(100_000, local_balance=200_000, boltz_reachable=False)

    def test_happy_path(self):
        assert inbound_can_submit(100_000, local_balance=200_000)


class TestChannelTooSmall:
    """The non-actionable banner variant."""

    def test_no_summary_false(self):
        assert inbound_channel_too_small(None) is False

    def test_no_active_channels_false(self):
        # If the user has no active channels, the wizard handles the
        # state — we don't poach with a "too small" message.
        assert inbound_channel_too_small(_summary(active=0, local=1_000)) is False

    def test_zero_local_false(self):
        # Zero local with an active channel — possible after a
        # drained outbound — isn't "too small to add capacity",
        # it's "can't act at all". Surface a different message
        # path (the regular block banner).
        assert inbound_channel_too_small(_summary(active=1, local=0)) is False

    def test_just_below_boltz_min_true(self):
        assert inbound_channel_too_small(_summary(active=1, local=24_999)) is True

    def test_exactly_at_boltz_min_false(self):
        # Boundary: at exactly 25k the user can in principle swap
        # the full amount (no reserve), so we don't surface the
        # "too small" copy. The submit will be capped by ceiling
        # math, but the banner stays helpful.
        assert inbound_channel_too_small(_summary(active=1, local=BOLTZ_MIN_AMOUNT_SATS)) is False


class TestMaxAddableCapacity:
    """The upper bound for the capped-by-seed note."""

    def test_zero_local(self):
        assert inbound_max_addable_capacity(_summary(local=0)) == 0
        assert inbound_max_addable_capacity(None) == 0

    def test_normal_case_subtracts_reserve(self):
        # 200k local - 10k reserve = 190k available to swap.
        assert inbound_max_addable_capacity(_summary(local=200_000)) == 190_000

    def test_local_below_reserve_clamps_to_zero(self):
        # 5k local can't even cover the reserve — the ceiling
        # math underflows to 0 rather than negative.
        assert inbound_max_addable_capacity(_summary(local=5_000)) == 0

    def test_caps_at_boltz_max(self):
        # Huge channel — capped at Boltz max regardless of local.
        assert inbound_max_addable_capacity(_summary(local=100_000_000)) == BOLTZ_MAX_AMOUNT_SATS


class TestCappedBySeed:
    """The cap-explanation note's trigger. Fires only when the
    user came from the soft-warning banner with a recv-amount the
    channel can't fully cover."""

    def test_zero_seed_never_capped(self):
        # Generic entry point (e.g. from the onboarding wizard's
        # celebration link) has no seed; the note never shows.
        assert inbound_capped_by_seed(_summary(local=10_000), 0) is False
        assert inbound_capped_by_seed(_summary(local=10_000), -50) is False

    def test_seed_fits_within_max_addable_no_note(self):
        # 200k local → 190k addable. Seed asks for 50k; channel
        # can cover it comfortably. No note.
        assert inbound_capped_by_seed(_summary(local=200_000, remote=0), 50_000) is False

    def test_seed_exceeds_max_addable_triggers_note(self):
        # 50k local → 40k addable. Seed asks for 100k; needed =
        # 100k + 5k margin = 105k. 40k < 105k → capped, note shows.
        assert inbound_capped_by_seed(_summary(local=50_000, remote=0), 100_000) is True

    def test_inbound_already_partially_covers_seed(self):
        # 200k local → 190k addable. Seed 100k, already have 60k
        # inbound → only need 40k + 5k margin = 45k more. 45k < 190k,
        # no note.
        assert inbound_capped_by_seed(_summary(local=200_000, remote=60_000), 100_000) is False


class TestBoltzReachable:
    """Detection of an in-flight or failed ``fetchBoltzFees``.

    The three-state form has to distinguish:
      * loading — first fetch in flight; show a spinner.
      * unreachable — fetch completed but Boltz didn't return
        ``fees_percentage``; show the red banner.
      * reachable — happy path; show the form's fee preview.

    Without the loading-vs-unreachable split, the red banner would
    flash on first open while the Tor-routed fetch resolves."""

    def test_loading_state_not_reachable(self):
        # Before fetch resolves: not yet reachable, but also not
        # "unreachable" — the UI uses ``inbound_fees_loading`` to
        # distinguish.
        assert inbound_boltz_reachable(None, boltz_fees_fetched=False) is False
        assert inbound_fees_loading(boltz_fees_fetched=False) is True

    def test_fetched_with_none_payload_unreachable(self):
        # Fetch completed but the payload is None somehow — treat
        # as unreachable.
        assert inbound_boltz_reachable(None, boltz_fees_fetched=True) is False
        assert inbound_fees_loading(boltz_fees_fetched=True) is False

    def test_fetched_with_sentinel_default_unreachable(self):
        # Fetch completed but threw — boltzFees stays at the
        # sentinel ``{min: Infinity, max: -Infinity}``. No
        # fees_percentage → unreachable.
        assert (
            inbound_boltz_reachable(
                {"min": float("inf"), "max": float("-inf")},
                boltz_fees_fetched=True,
            )
            is False
        )

    def test_successful_payload_reachable(self):
        assert (
            inbound_boltz_reachable(
                {
                    "min": BOLTZ_MIN_AMOUNT_SATS,
                    "max": BOLTZ_MAX_AMOUNT_SATS,
                    "fees_percentage": 0.5,
                    "fees_miner_lockup": 462,
                    "fees_miner_claim": 333,
                },
                boltz_fees_fetched=True,
            )
            is True
        )

    def test_zero_percentage_still_reachable(self):
        # Edge: Boltz briefly advertising 0% (free promo) is a
        # legitimate "reachable" state, not a fetch failure.
        assert (
            inbound_boltz_reachable(
                {"fees_percentage": 0},
                boltz_fees_fetched=True,
            )
            is True
        )

    def test_loading_then_failed_flow(self):
        # Lifecycle: dialog opens → loading → fetch resolves with
        # an error → fetched=True but payload still bare → moves
        # from "loading" to "unreachable".
        assert inbound_fees_loading(boltz_fees_fetched=False) is True
        # transition →
        sentinel = {"min": float("inf"), "max": float("-inf")}
        assert inbound_fees_loading(boltz_fees_fetched=True) is False
        assert inbound_boltz_reachable(sentinel, boltz_fees_fetched=True) is False


class TestAmountError:
    """The inline validation error text shown under the amount
    input. Plan doesn't fix the exact strings, but the wizard
    relies on these to communicate why the submit button is
    disabled."""

    def test_no_error_when_empty(self):
        # Empty (or zero) input is the default state — don't yell
        # at the user before they've typed anything.
        assert inbound_amount_error(0, local_balance=200_000) == ""

    def test_below_min(self):
        msg = inbound_amount_error(10_000, local_balance=200_000)
        assert "25,000" in msg
        assert "minimum" in msg.lower()

    def test_above_max(self):
        msg = inbound_amount_error(BOLTZ_MAX_AMOUNT_SATS + 1, local_balance=BOLTZ_MAX_AMOUNT_SATS * 2)
        assert "25,000,000" in msg
        assert "maximum" in msg.lower()

    def test_exceeds_local(self):
        msg = inbound_amount_error(150_000, local_balance=100_000)
        assert "100,000" in msg
        assert "available" in msg.lower()

    def test_valid_amount_no_error(self):
        assert inbound_amount_error(100_000, local_balance=200_000) == ""


class TestSwapStepIndex:
    """The shared 0-3 progress mapping (lifted helper)."""

    @pytest.mark.parametrize(
        "status,expected",
        [
            ("created", 0),
            ("paying_invoice", 1),
            ("invoice_paid", 1),
            ("claiming", 2),
            ("claimed", 2),
            ("completed", 3),
        ],
    )
    def test_each_known_status(self, status, expected):
        assert swap_user_step_index(status) == expected

    def test_unknown_status_defaults_to_zero(self):
        # Future-proofing: if Boltz adds a status we don't know about
        # yet, render as "just started" rather than crash.
        assert swap_user_step_index("warming_up") == 0

    def test_empty_or_none_defaults_to_zero(self):
        assert swap_user_step_index(None) == 0
        assert swap_user_step_index("") == 0


class TestIsTerminalStatus:
    """The localStorage-clear gate."""

    @pytest.mark.parametrize(
        "status,expected",
        [
            ("completed", True),
            ("failed", True),
            ("cancelled", True),
            ("refunded", True),
            ("created", False),
            ("paying_invoice", False),
            ("invoice_paid", False),
            ("claiming", False),
            ("claimed", False),
            (None, False),
            ("", False),
            ("unknown", False),
        ],
    )
    def test_status(self, status, expected):
        assert is_terminal_status(status) is expected


class TestIsCancellable:
    """Cancel only visible in ``created``."""

    def test_only_created_is_cancellable(self):
        assert inbound_is_cancellable("created")

    def test_paying_invoice_is_not(self):
        # The backend endpoint accepts cancellation here, but the UI
        # hides it because the LN HTLC may already be in flight.
        assert not inbound_is_cancellable("paying_invoice")

    @pytest.mark.parametrize(
        "status",
        ["invoice_paid", "claiming", "claimed", "completed", "failed", None, ""],
    )
    def test_all_other_statuses_are_not(self, status):
        assert not inbound_is_cancellable(status)


class TestBannerPayload:
    """The composite struct the Receive-Lightning template renders.
    ``inbound_banner_payload`` combines ``banner_kind`` (block/short/null)
    with ``channel_too_small`` (does the user have *anywhere* near
    enough local balance?) to pick the right variant.

    The ``too_small`` branch wins over both ``block`` and ``short``
    because suggesting "add capacity" when the user can't actually
    do so would be a dead-end click."""

    def test_no_banner_returns_none(self):
        # Sufficient inbound, no banner.
        s = _summary(active=1, local=100_000, remote=200_000)
        assert inbound_banner_payload(s, "50000") is None

    def test_no_active_channel_returns_none(self):
        # Pre-channel users belong to the onboarding wizard.
        assert inbound_banner_payload(_summary(active=0), "100000") is None

    def test_block_kind_normal_channel(self):
        # Zero inbound, channel large enough to add capacity.
        s = _summary(active=1, local=200_000, remote=0)
        payload = inbound_banner_payload(s, "")
        assert payload is not None
        assert payload["tone"] == "block"
        assert payload["text"] == "You can't receive Lightning payments yet."
        assert payload["cta"] == "Add receive capacity"

    def test_short_kind_normal_channel(self):
        # Have 50k, asking for 100k.
        s = _summary(active=1, local=300_000, remote=50_000)
        payload = inbound_banner_payload(s, "100000")
        assert payload is not None
        assert payload["tone"] == "short"
        # Human-readable thousand separator per ``formatSats``.
        assert "50,000" in payload["text"]
        assert payload["cta"] == "Add more capacity"

    def test_too_small_overrides_block(self):
        # Zero inbound + tiny channel → suggest "add capacity"
        # would be a dead-end. Show the no-CTA variant instead.
        s = _summary(active=1, local=20_000, remote=0)
        payload = inbound_banner_payload(s, "")
        assert payload is not None
        assert payload["tone"] == "warning"
        assert "too small" in payload["text"]
        # No CTA — clicking it would just fail to find an actionable
        # amount.
        assert payload["cta"] is None

    def test_too_small_overrides_short(self):
        # Have a tiny amount of inbound + tiny local. Asking for
        # more than have triggers `short`, but too-small still
        # wins so we don't dangle an unreachable CTA.
        s = _summary(active=1, local=15_000, remote=5_000)
        payload = inbound_banner_payload(s, "20000")
        assert payload is not None
        assert payload["tone"] == "warning"
        assert payload["cta"] is None

    def test_text_uses_formatted_capacity(self):
        # Pin the exact format the user sees — thousand separators
        # via ``f"{:,}"`` (mirrors the JS ``formatSats`` helper).
        # Million-sat balances should read "1,234,567" not "1234567".
        s = _summary(active=1, local=2_000_000, remote=1_234_567)
        payload = inbound_banner_payload(s, "2000000")
        assert payload["tone"] == "short"
        assert "1,234,567" in payload["text"]


class TestTerminalViewRouting:
    """The poller maps a terminal swap status to either the
    ``success`` view or the ``failed`` view. Plan specifies
    that ``refunded`` lands on the failed view (presented to the
    user with the explanation that their sats are safe)."""

    def test_completed_routes_to_success(self):
        assert inbound_terminal_view("completed") == "success"

    @pytest.mark.parametrize("status", ["failed", "cancelled", "refunded"])
    def test_other_terminals_route_to_failed(self, status):
        # The UI deliberately presents ``refunded`` as a failure
        # to the user — even though it's not strictly an error
        # (their funds are back), it isn't the outcome they
        # asked for.
        assert inbound_terminal_view(status) == "failed"

    @pytest.mark.parametrize(
        "status",
        ["created", "paying_invoice", "invoice_paid", "claiming", "claimed"],
    )
    def test_in_flight_statuses_do_not_route(self, status):
        # Non-terminal statuses keep the user on the progress view
        # until the next poll.
        assert inbound_terminal_view(status) is None

    def test_none_status_does_not_route(self):
        # Initial state before the poller has fired.
        assert inbound_terminal_view(None) is None
        assert inbound_terminal_view("") is None

    def test_unknown_status_does_not_route(self):
        # Defensive: future Boltz status the wizard doesn't know
        # about. Stay on the progress view rather than racing to
        # success/failure.
        assert inbound_terminal_view("warming_up") is None


class TestClaimTxidVisibility:
    """The on-chain affordance only appears once the wallet has
    broadcast its claim — and only if the swap detail surfaces a
    txid for it."""

    def test_claimed_with_txid_visible(self):
        assert inbound_should_show_claim_txid("claimed", "deadbeef" * 8)

    def test_completed_with_txid_visible(self):
        assert inbound_should_show_claim_txid("completed", "deadbeef" * 8)

    def test_earlier_status_with_txid_hidden(self):
        # Defensive — even if the swap detail somehow surfaces a
        # claim txid before status flips to ``claimed``, don't
        # display it: status drives the user-visible "stage" copy
        # and the txid row would confuse the timeline.
        assert not inbound_should_show_claim_txid("paying_invoice", "deadbeef" * 8)
        assert not inbound_should_show_claim_txid("claiming", "deadbeef" * 8)

    def test_claimed_without_txid_hidden(self):
        # Polling race: status flipped to claimed but the txid
        # hasn't propagated to the response yet. Don't render an
        # empty txid row.
        assert not inbound_should_show_claim_txid("claimed", "")

    def test_none_status_hidden(self):
        assert not inbound_should_show_claim_txid(None, "deadbeef")
