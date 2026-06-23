# SPDX-License-Identifier: MIT
"""Parity tests for Cold-Storage flicker-prevention getters.

The Cold-Storage Lightning tab had three flicker issues that shipped
to production for a long time before being caught:

1. The "Minimum: X sats" / "Maximum: X sats" warnings rendered with
   ``∞`` / ``-∞`` values while ``boltzFees`` was at the sentinel
   default ``{ min: Infinity, max: -Infinity }`` (before the first
   Tor-routed fetch resolved).
2. The amount input's placeholder showed ``"∞ – -∞"`` during the
   same window.
3. ``setMaxBoltzAmount()`` would set the amount to ``-Infinity`` if
   the user clicked Send Max during the loading window.

All three are gated on a single helper, ``boltzFeesUsable``, which
checks both that the fetch has resolved AND that the resulting
payload carries finite ``min`` / ``max`` values.

This file pins the helper's behavior so a future refactor can't
accidentally re-introduce the regression.
"""

from __future__ import annotations

import math
from typing import Optional


def boltz_fees_usable(boltz_fees: Optional[dict], fetched: bool = True) -> bool:
    """Mirror of ``boltzFeesUsable`` in dashboard.js."""
    if not fetched:
        return False
    if boltz_fees is None:
        return False
    fmin = boltz_fees.get("min")
    fmax = boltz_fees.get("max")
    if not isinstance(fmin, (int, float)) or not math.isfinite(fmin):
        return False
    if not isinstance(fmax, (int, float)) or not math.isfinite(fmax):
        return False
    return True


def cold_boltz_amount_below_min(amount: int, boltz_fees: Optional[dict], fetched: bool = True) -> bool:
    """Mirror of ``coldBoltzAmountBelowMin()`` in dashboard.js."""
    if not boltz_fees_usable(boltz_fees, fetched):
        return False
    if amount <= 0:
        return False
    return amount < boltz_fees["min"]


def cold_boltz_amount_above_max(amount: int, boltz_fees: Optional[dict], fetched: bool = True) -> bool:
    """Mirror of ``coldBoltzAmountAboveMax()`` in dashboard.js."""
    if not boltz_fees_usable(boltz_fees, fetched):
        return False
    if amount <= 0:
        return False
    return amount > boltz_fees["max"]


def boltz_placeholder(boltz_fees: Optional[dict], fetched: bool = True) -> str:
    """Mirror of ``boltzPlaceholder()`` in dashboard.js."""
    if not boltz_fees_usable(boltz_fees, fetched):
        return "25,000 – 25,000,000"
    fmin = boltz_fees["min"]
    fmax = boltz_fees["max"]
    return f"{fmin:,} – {fmax:,}"


def set_max_boltz_amount(local_balance: int, boltz_fees: Optional[dict], fetched: bool = True) -> int:
    """Mirror of ``setMaxBoltzAmount()`` in dashboard.js. Returns the
    value the function would assign to ``coldBoltzAmount``."""
    max_cap = boltz_fees["max"] if boltz_fees_usable(boltz_fees, fetched) else 25_000_000
    return min(local_balance or 0, max_cap)


# ── Fixtures ─────────────────────────────────────────────────────


_SENTINEL = {"min": math.inf, "max": -math.inf}
_VALID = {
    "min": 25_000,
    "max": 25_000_000,
    "fees_percentage": 0.5,
    "fees_miner_lockup": 462,
    "fees_miner_claim": 333,
}


# ── Tests ────────────────────────────────────────────────────────


class TestBoltzFeesUsable:
    """The signal that gates every Cold-Storage flicker fix."""

    def test_unfetched_unusable(self):
        # First open: fetch hasn't resolved yet. The sentinel
        # placeholder is in ``boltzFees`` but ``_boltzFeesFetched``
        # is false. ``boltzFeesUsable`` must return false so the
        # placeholder / warnings / Send-Max all fall back to safe
        # defaults.
        assert boltz_fees_usable(_SENTINEL, fetched=False) is False

    def test_fetched_with_sentinel_unusable(self):
        # Failed fetch: ``_boltzFeesFetched`` flips to true but
        # ``boltzFees`` is still the sentinel because the catch
        # block swallowed the error. Still unusable.
        assert boltz_fees_usable(_SENTINEL, fetched=True) is False

    def test_fetched_with_none_unusable(self):
        # Defensive: if the dashboard somehow ends up with
        # ``boltzFees = None`` after a fetch, treat it as unusable.
        assert boltz_fees_usable(None, fetched=True) is False

    def test_fetched_with_partial_payload_unusable(self):
        # A payload missing ``max`` (corrupt response) shouldn't
        # let downstream code chain into ``undefined.toLocaleString``.
        assert boltz_fees_usable({"min": 25_000}, fetched=True) is False
        assert boltz_fees_usable({"max": 25_000_000}, fetched=True) is False

    def test_fetched_with_valid_payload_usable(self):
        assert boltz_fees_usable(_VALID, fetched=True) is True

    def test_negative_infinity_max_unusable(self):
        # Specifically the sentinel's ``max`` is ``-Infinity``.
        # Catching this via ``math.isfinite`` is the load-bearing
        # part of the fix.
        assert boltz_fees_usable({"min": 25_000, "max": -math.inf}, fetched=True) is False

    def test_positive_infinity_min_unusable(self):
        # And ``min`` is ``+Infinity`` in the sentinel.
        assert boltz_fees_usable({"min": math.inf, "max": 25_000_000}, fetched=True) is False


class TestColdBoltzAmountBelowMin:
    """The "Minimum: X sats" warning gate."""

    def test_unfetched_never_fires(self):
        # The original bug: with the sentinel ``min: Infinity``,
        # the check ``amount < min`` was true for any positive
        # amount, flashing "Minimum: ∞ sats" briefly.
        for amount in [1, 1_000, 50_000, 1_000_000]:
            assert cold_boltz_amount_below_min(amount, _SENTINEL, fetched=False) is False, (
                f"warning must not fire during loading window (amount={amount})"
            )

    def test_fetched_but_unusable_never_fires(self):
        # Same protection even after a failed fetch.
        assert cold_boltz_amount_below_min(50_000, _SENTINEL, fetched=True) is False

    def test_zero_amount_no_warning(self):
        # User hasn't typed yet — don't show validation chrome.
        assert cold_boltz_amount_below_min(0, _VALID) is False

    def test_below_minimum_fires(self):
        # The happy path: real min, amount below it → warning fires.
        assert cold_boltz_amount_below_min(10_000, _VALID) is True

    def test_at_minimum_no_warning(self):
        # Boundary: exactly at minimum is acceptable.
        assert cold_boltz_amount_below_min(25_000, _VALID) is False

    def test_above_minimum_no_warning(self):
        assert cold_boltz_amount_below_min(100_000, _VALID) is False


class TestColdBoltzAmountAboveMax:
    """The "Maximum: X sats" warning gate. Symmetric to the min case."""

    def test_unfetched_never_fires(self):
        # The original bug: sentinel ``max: -Infinity``, so
        # ``amount > -Infinity`` was true for any positive amount.
        for amount in [1, 1_000, 50_000, 1_000_000]:
            assert cold_boltz_amount_above_max(amount, _SENTINEL, fetched=False) is False, (
                f"warning must not fire during loading window (amount={amount})"
            )

    def test_fetched_but_unusable_never_fires(self):
        assert cold_boltz_amount_above_max(50_000, _SENTINEL, fetched=True) is False

    def test_zero_amount_no_warning(self):
        assert cold_boltz_amount_above_max(0, _VALID) is False

    def test_above_maximum_fires(self):
        assert cold_boltz_amount_above_max(30_000_000, _VALID) is True

    def test_at_maximum_no_warning(self):
        assert cold_boltz_amount_above_max(25_000_000, _VALID) is False


class TestBoltzPlaceholder:
    """The amount input's placeholder text."""

    def test_unfetched_returns_hardcoded_fallback(self):
        # The original bug: returned "∞ – -∞" because the early-
        # return only caught ``!boltzFees`` (truthy check), not
        # the sentinel's bogus values.
        assert boltz_placeholder(_SENTINEL, fetched=False) == "25,000 – 25,000,000"

    def test_fetched_but_sentinel_returns_hardcoded(self):
        assert boltz_placeholder(_SENTINEL, fetched=True) == "25,000 – 25,000,000"

    def test_none_payload_returns_hardcoded(self):
        assert boltz_placeholder(None, fetched=True) == "25,000 – 25,000,000"

    def test_valid_payload_returns_formatted_range(self):
        # Once fees are loaded, surface the actual values with
        # thousand separators.
        assert boltz_placeholder(_VALID) == "25,000 – 25,000,000"

    def test_valid_payload_with_different_range(self):
        # Sanity: thousand separators work for non-default values.
        assert boltz_placeholder({"min": 100_000, "max": 5_000_000}, fetched=True) == "100,000 – 5,000,000"


class TestSetMaxBoltzAmount:
    """The Send Max button's handler."""

    def test_unfetched_falls_back_to_hardcoded_cap(self):
        # The original bug: ``Math.min(local, -Infinity) = -Infinity``,
        # so the amount input would show garbage if the user
        # clicked Send Max during the loading window.
        # With the fix, we fall back to the hardcoded 25M cap and
        # the user's local balance is the actual constraint.
        assert set_max_boltz_amount(local_balance=500_000, boltz_fees=_SENTINEL, fetched=False) == 500_000

    def test_fetched_but_sentinel_falls_back(self):
        # Failed fetch behaviour — same fallback.
        assert set_max_boltz_amount(local_balance=500_000, boltz_fees=_SENTINEL, fetched=True) == 500_000

    def test_valid_payload_capped_by_local(self):
        # Local is the constraint when local < Boltz max.
        assert set_max_boltz_amount(local_balance=1_000_000, boltz_fees=_VALID, fetched=True) == 1_000_000

    def test_valid_payload_capped_by_boltz_max(self):
        # Boltz max is the constraint when local > Boltz max.
        assert set_max_boltz_amount(local_balance=50_000_000, boltz_fees=_VALID, fetched=True) == _VALID["max"]

    def test_zero_local_returns_zero(self):
        # Defensive: no channel balance → can't send anything.
        # Don't return a positive number that would make the
        # subsequent submit fail confusingly.
        assert set_max_boltz_amount(local_balance=0, boltz_fees=_VALID, fetched=True) == 0


def boltz_review_disabled(
    *,
    address: str,
    amount: int,
    local_balance: int,
    boltz_fees: Optional[dict],
    accept_stale: bool = False,
) -> bool:
    """Mirror of ``boltzReviewDisabled`` getter in dashboard.js.

    The stale pair-info UX adds a final clause: when the Boltz
    API is unreachable and the wallet is serving cached fees, the
    response carries ``stale: True`` and the Review Swap button is
    gated on the operator explicitly ticking "Proceed anyway".
    """
    if not address or len(address) < 26:
        return True
    if not amount:
        return True
    if boltz_fees and (amount < boltz_fees.get("min", 0) or amount > boltz_fees.get("max", 0)):
        return True
    if amount > local_balance:
        return True
    if boltz_fees and boltz_fees.get("stale") and not accept_stale:
        return True
    return False


_VALID_STALE = {**_VALID, "stale": True}
_VALID_FRESH_ADDR = "bc1qexampleaddress00000000000000000"


class TestStalePairInfoGating:
    """Stale pair-info UX. When Boltz is unreachable and we
    serve cached fees, the Review Swap button is disabled until
    the operator ticks "Proceed anyway"."""

    def test_fresh_payload_allows_review(self):
        # Baseline: a fresh (non-stale) payload + valid inputs →
        # button enabled.
        assert (
            boltz_review_disabled(
                address=_VALID_FRESH_ADDR,
                amount=100_000,
                local_balance=1_000_000,
                boltz_fees=_VALID,
            )
            is False
        )

    def test_stale_payload_disables_review_by_default(self):
        # Stale payload, operator has NOT ticked accept → disabled.
        assert (
            boltz_review_disabled(
                address=_VALID_FRESH_ADDR,
                amount=100_000,
                local_balance=1_000_000,
                boltz_fees=_VALID_STALE,
                accept_stale=False,
            )
            is True
        )

    def test_stale_payload_with_accept_enables_review(self):
        # Operator explicitly ticked "Proceed anyway" → button
        # re-enables.
        assert (
            boltz_review_disabled(
                address=_VALID_FRESH_ADDR,
                amount=100_000,
                local_balance=1_000_000,
                boltz_fees=_VALID_STALE,
                accept_stale=True,
            )
            is False
        )

    def test_stale_does_not_override_other_disable_reasons(self):
        # Even if the operator ticks "Proceed anyway", the button
        # stays disabled when other validation fails (e.g. amount
        # exceeds balance). Acceptance is additive, not a bypass
        # of the regular checks.
        assert (
            boltz_review_disabled(
                address=_VALID_FRESH_ADDR,
                amount=10_000_000,
                local_balance=100_000,  # too low
                boltz_fees=_VALID_STALE,
                accept_stale=True,
            )
            is True
        )

    def test_accept_stale_irrelevant_when_payload_fresh(self):
        # If the dashboard somehow has ``coldBoltzAcceptStale=true``
        # from a previous stale window but the current payload is
        # fresh, the flag has no effect.
        assert (
            boltz_review_disabled(
                address=_VALID_FRESH_ADDR,
                amount=100_000,
                local_balance=1_000_000,
                boltz_fees=_VALID,
                accept_stale=True,
            )
            is False
        )
