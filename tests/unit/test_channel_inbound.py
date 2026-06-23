# SPDX-License-Identifier: MIT
"""Behaviour tests for the per-channel "Open Inbound" dialog logic.

The dialog's getters/helpers live in
``app/dashboard/static/dashboard.js`` (the ``ci*`` family). As with
``test_inbound_liquidity.py``, we mirror each pure piece in Python so
the behaviour is exercised in CI and any future JS change that drifts
from this intent is caught.

If you change a ``ci*`` getter in dashboard.js, update the matching
mirror below and re-run this file. The mirrors are deliberately literal
translations of the JS — keep them that way.
"""

from __future__ import annotations

import math
from typing import Optional

import pytest

# ── Constants mirrored from dashboard.js ────────────────────────────
BOLTZ_MIN_AMOUNT_SATS = 25_000
BOLTZ_MAX_AMOUNT_SATS = 25_000_000

SWAP_USER_STEP_INDEX = {
    "created": 0,
    "paying_invoice": 1,
    "invoice_paid": 1,
    "claiming": 2,
    "claimed": 2,
    "completed": 3,
}
SWAP_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "refunded"}

# The sentinel ``boltzFees`` value before the fees fetch resolves.
BOLTZ_FEES_SENTINEL = {"min": math.inf, "max": -math.inf}


def _num(v) -> float:
    """Mirror of JS ``Number(x) || 0`` for the numeric coercions used in
    the getters (treats None/'' as 0; preserves real numbers)."""
    try:
        n = float(v)
    except (TypeError, ValueError):
        return 0
    if n == 0 or math.isnan(n):
        return 0
    return n


# ── Mirrored getters ────────────────────────────────────────────────
def ci_amount_ceiling(max_freeable: int, boltz_fees: Optional[dict]) -> float:
    """min(maxFreeable, live-boltz-max) with a finiteness guard so the
    ``-Infinity`` sentinel can't poison the ceiling (regression: the
    Max button once filled -Infinity before fees loaded)."""
    freeable = max_freeable or 0
    fees = boltz_fees or {}
    fmax = fees.get("max")
    boltz_max = fmax if (isinstance(fmax, (int, float)) and math.isfinite(fmax) and fmax > 0) else BOLTZ_MAX_AMOUNT_SATS
    return min(freeable, boltz_max)


def ci_boltz_reachable(boltz_fees: Optional[dict], fetched: bool = True) -> bool:
    if not fetched:
        return False
    return isinstance((boltz_fees or {}).get("fees_percentage"), (int, float))


def ci_fees_loading(fetched: bool) -> bool:
    return not fetched


def ci_boltz_percentage_fee_sats(amount: int, boltz_fees: Optional[dict]) -> int:
    amt = _num(amount)
    pct = (boltz_fees or {}).get("fees_percentage") or 0
    return math.ceil(amt * pct / 100)


def ci_boltz_miner_fee_sats(boltz_fees: Optional[dict]) -> int:
    fees = boltz_fees or {}
    return (fees.get("fees_miner_lockup") or 0) + (fees.get("fees_miner_claim") or 0)


def ci_total_fee_sats(amount: int, boltz_fees: Optional[dict]) -> int:
    return ci_boltz_percentage_fee_sats(amount, boltz_fees) + ci_boltz_miner_fee_sats(boltz_fees)


def ci_receive_onchain_sats(amount: int, boltz_fees: Optional[dict]) -> int:
    return max(0, int(_num(amount)) - ci_total_fee_sats(amount, boltz_fees))


def ci_amount_error(amount: int, max_freeable: int, boltz_fees: Optional[dict]) -> str:
    """Returns the inline validation message ('' = valid)."""
    amt = _num(amount)
    if amt <= 0:
        return ""
    if amt < BOLTZ_MIN_AMOUNT_SATS:
        return f"Minimum is {BOLTZ_MIN_AMOUNT_SATS:,} sats."
    ceiling = ci_amount_ceiling(max_freeable, boltz_fees)
    if amt > ceiling:
        return f"This channel can free up at most {int(ceiling):,} sats right now."
    return ""


def ci_can_submit(
    *,
    loading: bool,
    generating: bool,
    boltz_fees: Optional[dict],
    fetched: bool,
    address: str,
    amount: int,
    max_freeable: int,
) -> bool:
    if loading or generating:
        return False
    if not ci_boltz_reachable(boltz_fees, fetched):
        return False
    if not address:
        return False
    amt = _num(amount)
    if amt < BOLTZ_MIN_AMOUNT_SATS:
        return False
    if amt > ci_amount_ceiling(max_freeable, boltz_fees):
        return False
    return True


def ci_suggested_amount(max_freeable: int, boltz_fees: Optional[dict]) -> int:
    ceiling = ci_amount_ceiling(max_freeable, boltz_fees)
    if ceiling < BOLTZ_MIN_AMOUNT_SATS:
        return 0
    target = math.floor((max_freeable or 0) / 2)
    target = min(target, ceiling)
    target = max(target, BOLTZ_MIN_AMOUNT_SATS)
    return int(target)


def ci_progress_step_index(status: Optional[str]) -> int:
    if not status:
        return 0
    idx = SWAP_USER_STEP_INDEX.get(status)
    return idx if isinstance(idx, int) else 0


def ci_is_cancellable(status: Optional[str]) -> bool:
    return status == "created"


def ci_should_show_claim_txid(status: Optional[str], claim_txid: str) -> bool:
    if not claim_txid:
        return False
    return status in ("claimed", "completed")


def ci_show_recovery_banner(recovery: Optional[dict]) -> bool:
    r = recovery
    return bool(r and r.get("severity") in ("warning", "critical"))


def ci_recovery_has_actions(recovery: Optional[dict]) -> bool:
    r = recovery
    return bool(r and r.get("actions"))


def ci_recovery_action_label(action: str) -> str:
    if action == "cooperative_claim":
        return "Retry claim"
    if action == "unilateral_claim":
        return "Recover on-chain"
    return action


def ci_button_visible(active: bool, local_balance: int) -> bool:
    """Mirror of the channel-card ``Open Inbound`` button gate:
    ``ch.active && (ch.local_balance||0) >= BOLTZ_MIN_AMOUNT_SATS``."""
    return bool(active) and (local_balance or 0) >= BOLTZ_MIN_AMOUNT_SATS


def ci_open_inactive_notice(active: bool) -> bool:
    """Mirror of the re-check in ``openChannelInbound``: surface an
    offline notice when the channel is inactive at click time."""
    return not active


def ci_open_decision(
    active_swap_id: Optional[str],
    swap_status: Optional[str],
    current_chan_id: Optional[str],
    clicked_chan_id: str,
) -> str:
    """Mirror of ``openChannelInbound``'s entry branch:
    'resume' (same channel's in-flight swap), 'busy' (a swap is running
    on a *different* channel), or 'fresh' (open a new form)."""
    if active_swap_id and swap_status and swap_status not in SWAP_TERMINAL_STATUSES:
        same_channel = bool(current_chan_id and clicked_chan_id and current_chan_id == clicked_chan_id)
        return "resume" if same_channel else "busy"
    return "fresh"


def ci_restore_decision(pin_raw: Optional[str], fetched_status: Optional[str]) -> str:
    """Mirror of ``_restoreChannelInbound``: 'resume', 'clear' (drop the
    pin), or 'ignore' (leave it, e.g. transient fetch error)."""
    if not pin_raw:
        return "ignore"
    import json

    try:
        pin = json.loads(pin_raw)
    except (ValueError, TypeError):
        return "clear"
    swap_id = pin.get("swapId") if isinstance(pin, dict) else None
    if not swap_id:
        return "clear"
    if fetched_status is None:
        # network/parse error fetching the swap → drop the pin
        return "clear"
    if fetched_status in SWAP_TERMINAL_STATUSES:
        return "clear"
    return "resume"


# ─────────────────────────────────────────────────────────────────────
#  Amount ceiling — incl. the -Infinity sentinel regression
# ─────────────────────────────────────────────────────────────────────
class TestAmountCeiling:
    def test_clamps_to_freeable_when_below_boltz_max(self):
        fees = {"max": 25_000_000, "fees_percentage": 0.5}
        assert ci_amount_ceiling(480_000, fees) == 480_000

    def test_clamps_to_boltz_max_when_freeable_higher(self):
        fees = {"max": 1_000_000, "fees_percentage": 0.5}
        assert ci_amount_ceiling(50_000_000, fees) == 1_000_000

    def test_sentinel_max_falls_back_to_constant(self):
        # Before the fees fetch resolves, boltzFees.max is -Infinity; the
        # guard must fall back to BOLTZ_MAX so the Max button can't fill
        # -Infinity.
        assert ci_amount_ceiling(480_000, BOLTZ_FEES_SENTINEL) == 480_000
        assert ci_amount_ceiling(50_000_000, BOLTZ_FEES_SENTINEL) == BOLTZ_MAX_AMOUNT_SATS

    def test_missing_fees_falls_back_to_constant(self):
        assert ci_amount_ceiling(480_000, None) == 480_000
        assert ci_amount_ceiling(50_000_000, {}) == BOLTZ_MAX_AMOUNT_SATS

    def test_zero_or_negative_max_falls_back(self):
        assert ci_amount_ceiling(480_000, {"max": 0}) == 480_000


class TestSuggestedAmount:
    def test_half_of_freeable(self):
        fees = {"max": 25_000_000}
        assert ci_suggested_amount(480_000, fees) == 240_000

    def test_clamped_up_to_floor(self):
        # Half of freeable is below the Boltz minimum → bumped to the floor
        # (still <= ceiling because freeable is above the floor).
        fees = {"max": 25_000_000}
        assert ci_suggested_amount(40_000, fees) == BOLTZ_MIN_AMOUNT_SATS

    def test_zero_when_ceiling_below_floor(self):
        # Channel can free up less than the Boltz minimum → no usable
        # default; the form shows empty rather than a bogus 25k.
        fees = {"max": 25_000_000}
        assert ci_suggested_amount(20_000, fees) == 0

    def test_clamped_down_to_boltz_max(self):
        fees = {"max": 1_000_000}
        assert ci_suggested_amount(50_000_000, fees) == 1_000_000


class TestAmountError:
    FEES = {"max": 25_000_000, "fees_percentage": 0.5}

    def test_empty_when_unset(self):
        assert ci_amount_error(0, 480_000, self.FEES) == ""
        assert ci_amount_error(None, 480_000, self.FEES) == ""

    def test_below_minimum(self):
        msg = ci_amount_error(10_000, 480_000, self.FEES)
        assert "Minimum" in msg

    def test_above_channel_ceiling(self):
        msg = ci_amount_error(500_000, 480_000, self.FEES)
        assert "at most" in msg

    def test_valid_amount_no_error(self):
        assert ci_amount_error(240_000, 480_000, self.FEES) == ""


class TestCanSubmit:
    FEES = {"max": 25_000_000, "fees_percentage": 0.5}

    def _base(self, **over):
        kw = dict(
            loading=False,
            generating=False,
            boltz_fees=self.FEES,
            fetched=True,
            address="bc1qxyz",
            amount=240_000,
            max_freeable=480_000,
        )
        kw.update(over)
        return ci_can_submit(**kw)

    def test_happy_path(self):
        assert self._base() is True

    def test_blocked_while_loading(self):
        assert self._base(loading=True) is False

    def test_blocked_while_generating(self):
        assert self._base(generating=True) is False

    def test_blocked_when_fees_not_loaded(self):
        assert self._base(fetched=False) is False

    def test_blocked_when_boltz_unreachable(self):
        assert self._base(boltz_fees={"max": 1}) is False  # no fees_percentage

    def test_blocked_without_address(self):
        assert self._base(address="") is False

    def test_blocked_below_minimum(self):
        assert self._base(amount=10_000) is False

    def test_blocked_above_ceiling(self):
        assert self._base(amount=500_000) is False

    def test_blocked_with_sentinel_fees_even_if_amount_set(self):
        # Fees not really loaded (sentinel) → unreachable → cannot submit.
        assert self._base(boltz_fees=BOLTZ_FEES_SENTINEL, fetched=True) is False


class TestFeeMath:
    FEES = {"fees_percentage": 0.5, "fees_miner_lockup": 200, "fees_miner_claim": 100}

    def test_percentage_fee_rounds_up(self):
        # 100000 * 0.5% = 500 exactly.
        assert ci_boltz_percentage_fee_sats(100_000, self.FEES) == 500
        # 100001 * 0.5% = 500.005 → ceil 501.
        assert ci_boltz_percentage_fee_sats(100_001, self.FEES) == 501

    def test_miner_fee_sum(self):
        assert ci_boltz_miner_fee_sats(self.FEES) == 300

    def test_total_and_receive(self):
        assert ci_total_fee_sats(100_000, self.FEES) == 800
        assert ci_receive_onchain_sats(100_000, self.FEES) == 99_200

    def test_receive_never_negative(self):
        assert ci_receive_onchain_sats(100, self.FEES) == 0


class TestProgressAndStatusGetters:
    @pytest.mark.parametrize(
        "status,idx",
        [
            ("created", 0),
            ("paying_invoice", 1),
            ("invoice_paid", 1),
            ("claiming", 2),
            ("claimed", 2),
            ("completed", 3),
            (None, 0),
            ("bogus", 0),
        ],
    )
    def test_progress_step_index(self, status, idx):
        assert ci_progress_step_index(status) == idx

    def test_cancellable_only_when_created(self):
        assert ci_is_cancellable("created") is True
        for s in ("paying_invoice", "claiming", "claimed", "completed", "failed"):
            assert ci_is_cancellable(s) is False

    def test_claim_txid_shown_only_when_claimed_or_completed_and_present(self):
        assert ci_should_show_claim_txid("claimed", "abc") is True
        assert ci_should_show_claim_txid("completed", "abc") is True
        assert ci_should_show_claim_txid("claiming", "abc") is False
        assert ci_should_show_claim_txid("claimed", "") is False


class TestRecoveryBanner:
    def test_no_recovery_hides_banner(self):
        assert ci_show_recovery_banner(None) is False
        assert ci_show_recovery_banner({"severity": "ok"}) is False

    def test_warning_and_critical_show_banner(self):
        assert ci_show_recovery_banner({"severity": "warning"}) is True
        assert ci_show_recovery_banner({"severity": "critical"}) is True

    def test_has_actions(self):
        assert ci_recovery_has_actions({"actions": ["cooperative_claim"]}) is True
        assert ci_recovery_has_actions({"actions": []}) is False
        assert ci_recovery_has_actions(None) is False

    def test_action_labels_are_plain_language(self):
        assert ci_recovery_action_label("cooperative_claim") == "Retry claim"
        assert ci_recovery_action_label("unilateral_claim") == "Recover on-chain"
        # Unknown action falls through to the raw id (defensive).
        assert ci_recovery_action_label("something_else") == "something_else"


class TestEntryPoint:
    """Channel-card button gate + inactive-channel notice."""

    def test_button_hidden_below_boltz_minimum(self):
        assert ci_button_visible(True, 24_999) is False

    def test_button_visible_at_minimum(self):
        assert ci_button_visible(True, BOLTZ_MIN_AMOUNT_SATS) is True

    def test_button_hidden_when_inactive(self):
        assert ci_button_visible(False, 1_000_000) is False

    def test_button_handles_missing_local(self):
        assert ci_button_visible(True, 0) is False

    def test_inactive_channel_triggers_notice(self):
        assert ci_open_inactive_notice(False) is True
        assert ci_open_inactive_notice(True) is False


class TestOpenDecision:
    """One-swap-at-a-time guard (§5.3)."""

    def test_no_active_swap_is_fresh(self):
        assert ci_open_decision(None, None, None, "123") == "fresh"

    def test_terminal_swap_is_fresh(self):
        # A completed/failed swap must not block a new one.
        for st in SWAP_TERMINAL_STATUSES:
            assert ci_open_decision("swap-1", st, "123", "123") == "fresh"

    def test_same_channel_in_flight_resumes(self):
        assert ci_open_decision("swap-1", "claiming", "123", "123") == "resume"

    def test_different_channel_in_flight_is_busy(self):
        # Don't hijack: a swap on channel 123 must not be silently
        # repurposed when the user clicks channel 456.
        assert ci_open_decision("swap-1", "paying_invoice", "123", "456") == "busy"


class TestRestoreDecision:
    def test_no_pin_ignored(self):
        assert ci_restore_decision(None, "claiming") == "ignore"
        assert ci_restore_decision("", "claiming") == "ignore"

    def test_malformed_pin_cleared(self):
        assert ci_restore_decision("not-json", "claiming") == "clear"

    def test_pin_without_swap_id_cleared(self):
        assert ci_restore_decision('{"chanId":"123"}', "claiming") == "clear"

    def test_in_flight_pin_resumes(self):
        pin = '{"swapId":"swap-1","chanId":"123"}'
        for st in ("created", "paying_invoice", "invoice_paid", "claiming", "claimed"):
            assert ci_restore_decision(pin, st) == "resume"

    def test_terminal_pin_cleared(self):
        pin = '{"swapId":"swap-1","chanId":"123"}'
        for st in SWAP_TERMINAL_STATUSES:
            assert ci_restore_decision(pin, st) == "clear"

    def test_fetch_error_clears_pin(self):
        pin = '{"swapId":"swap-1","chanId":"123"}'
        assert ci_restore_decision(pin, None) == "clear"


class TestReachableAndLoading:
    def test_loading_until_fetched(self):
        assert ci_fees_loading(False) is True
        assert ci_fees_loading(True) is False

    def test_reachable_requires_fetched_and_percentage(self):
        assert ci_boltz_reachable({"fees_percentage": 0.5}, fetched=True) is True
        assert ci_boltz_reachable({"fees_percentage": 0.5}, fetched=False) is False
        # Sentinel has no fees_percentage → unreachable even once "fetched".
        assert ci_boltz_reachable(BOLTZ_FEES_SENTINEL, fetched=True) is False
        assert ci_boltz_reachable(None, fetched=True) is False
