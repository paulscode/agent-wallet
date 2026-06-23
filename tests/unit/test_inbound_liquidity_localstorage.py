# SPDX-License-Identifier: MIT
"""localStorage-persistence parity tests for the inbound-liquidity
wizard.

The wizard mirrors its in-progress ``swap_id`` to localStorage so a
mid-flow refresh resumes the progress view rather than dropping the
user into a dead-end. Three small predicates govern the
write/restore/clear lifecycle in JS; this file mirrors each as a
Python function and exercises the corner cases.

If you change the JS persistence behaviour, update the matching
helper below and re-run this file. Most regressions show up as
either a stale pin (phantom restore on next load) or an over-eager
clear (losing the progress view mid-flow).
"""

from __future__ import annotations

from typing import Optional

import pytest

SWAP_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "refunded"}


def should_persist_swap_id(status: Optional[str]) -> bool:
    """Mirror of the JS write gate. The wizard writes the pin the
    moment ``/cold-storage/initiate`` returns a non-terminal status
    (in practice always ``created``)."""
    if not status:
        return False
    return status not in SWAP_TERMINAL_STATUSES


def should_restore_progress_view(stored_swap_id: Optional[str], fetched_status: Optional[str]) -> bool:
    """Mirror of the JS restore gate. We resume the progress view
    only when:

    * localStorage has a swap-id pin, AND
    * fetching that swap returns a non-terminal status (i.e. it's
      still in flight).

    If the swap has already terminated, we silently drop the pin
    instead of resurrecting a stale UI."""
    if not stored_swap_id:
        return False
    if fetched_status is None:
        # Network error / 404 — caller will clear the pin separately.
        return False
    if fetched_status in SWAP_TERMINAL_STATUSES:
        return False
    return True


def should_clear_storage(fetched_status: Optional[str]) -> bool:
    """Mirror of the JS clear gate. The pin should be cleared when:

    * the swap reaches a terminal status, OR
    * the swap detail endpoint can't be reached (status None).

    Clearing on a terminal status prevents the next page load from
    re-routing the user to a "completed" view they've already
    dismissed. Clearing on a network error prevents the wizard from
    re-trying a dead pin on every load."""
    if fetched_status is None:
        return True
    return fetched_status in SWAP_TERMINAL_STATUSES


class TestShouldPersistSwapId:
    """Write-on-submit gate."""

    def test_created_persists(self):
        # Immediately after ``/cold-storage/initiate`` the swap is in
        # ``created`` — this is the only state we should ever write
        # in practice, but the table is enumerated below for safety.
        assert should_persist_swap_id("created") is True

    def test_paying_invoice_persists(self):
        # Could happen if the user closes + re-opens the dialog and
        # we want to re-pin. Defensive.
        assert should_persist_swap_id("paying_invoice") is True

    @pytest.mark.parametrize("status", ["completed", "failed", "cancelled", "refunded"])
    def test_terminal_statuses_do_not_persist(self, status):
        # If the caller ever tries to pin a terminal swap (e.g. a
        # race), refuse silently.
        assert should_persist_swap_id(status) is False

    def test_none_does_not_persist(self):
        assert should_persist_swap_id(None) is False

    def test_empty_string_does_not_persist(self):
        assert should_persist_swap_id("") is False


class TestShouldRestoreProgressView:
    """Restore-on-init gate."""

    def test_no_pin_does_not_restore(self):
        # First-time user, no prior swap.
        assert should_restore_progress_view(None, "created") is False
        assert should_restore_progress_view("", "created") is False

    def test_pin_with_in_flight_swap_restores(self):
        # Happy path: user refreshed during a swap that's still
        # running. Wizard should re-open on the progress view.
        for status in ["created", "paying_invoice", "invoice_paid", "claiming", "claimed"]:
            assert should_restore_progress_view("swap-abc", status) is True, (
                f"expected restore for in-flight status {status!r}"
            )

    @pytest.mark.parametrize("status", ["completed", "failed", "cancelled", "refunded"])
    def test_pin_with_terminal_swap_does_not_restore(self, status):
        # User refreshed AFTER the swap already wrapped up. Don't
        # bring them back to the wizard; the dashboard banner /
        # capacity readout will reflect the result.
        assert should_restore_progress_view("swap-abc", status) is False

    def test_pin_with_no_fetch_response_does_not_restore(self):
        # Network blip during init. We don't restore (would render
        # an empty progress view), but the clear gate decides
        # separately whether to drop the pin.
        assert should_restore_progress_view("swap-abc", None) is False


class TestShouldClearStorage:
    """Clear-pin gate."""

    @pytest.mark.parametrize("status", ["completed", "failed", "cancelled", "refunded"])
    def test_terminal_statuses_clear(self, status):
        # Wizard finished its job — drop the pin so the next load
        # doesn't keep re-checking a dead swap.
        assert should_clear_storage(status) is True

    def test_network_error_clears(self):
        # The detail endpoint returned None (404 / 502 / etc.).
        # Drop the pin so we don't retry forever; the user can
        # always start a fresh swap from the banner.
        assert should_clear_storage(None) is True

    @pytest.mark.parametrize("status", ["created", "paying_invoice", "invoice_paid", "claiming", "claimed"])
    def test_in_flight_statuses_do_not_clear(self, status):
        # Swap is still running — keep the pin so future page
        # loads continue resuming the progress view.
        assert should_clear_storage(status) is False


class TestLifecycleCombinations:
    """The three predicates compose into a small state machine.
    These tests pin the combined behaviour against the most-likely
    real-world flows."""

    def test_full_happy_path(self):
        # 1. User submits → status ``created`` → persist.
        assert should_persist_swap_id("created") is True
        # 2. User refreshes → restore on ``invoice_paid``.
        assert should_restore_progress_view("swap-abc", "invoice_paid") is True
        # 3. Swap completes → clear.
        assert should_clear_storage("completed") is True

    def test_failure_path(self):
        # 1. Persist on submit.
        assert should_persist_swap_id("created") is True
        # 2. Refresh mid-flight → restore.
        assert should_restore_progress_view("swap-abc", "paying_invoice") is True
        # 3. Swap fails → clear (so next load doesn't re-route to
        #    a failure view the user already acknowledged).
        assert should_clear_storage("failed") is True

    def test_user_cancels_path(self):
        # 1. Persist.
        assert should_persist_swap_id("created") is True
        # 2. User clicks Cancel → status flips to ``cancelled``.
        # 3. Cancel terminal status → clear.
        assert should_clear_storage("cancelled") is True

    def test_phantom_pin_after_completion(self):
        # If we forgot to clear (regression), a fresh page load
        # would call ``should_restore_progress_view`` with the
        # terminal status and refuse to restore. The pin sticks
        # around until the next clear, but at least the user
        # doesn't see a misleading "in-progress" view.
        # This is the safety net the test guards.
        assert should_restore_progress_view("stale-pin", "completed") is False


# ── () ─────────────
#
# Static-analysis tests that lock in the migration from
# ``localStorage`` to ``sessionStorage`` for the inbound-liquidity
# and cold-storage swap-id pins. ``sessionStorage`` is scoped to the
# browsing tab and cleared when the tab closes — a much shorter
# lifetime than ``localStorage`` (which survives the operator's
# entire browser profile) and consistent with the dashboard's
# session-only auth model.

import re as _re
from pathlib import Path as _Path

_DASHBOARD_JS = _Path(__file__).resolve().parents[2] / "app" / "dashboard" / "static" / "dashboard.js"


def _dashboard_js_text() -> str:
    return _DASHBOARD_JS.read_text(encoding="utf-8")


def test_inbound_swap_state_uses_session_storage_not_local_storage():
    """No ``localStorage`` calls reference the inbound/cold swap
    state keys — they must use ``sessionStorage``."""
    text = _dashboard_js_text()
    offending = _re.findall(
        r"localStorage\.(?:set|get|remove)Item\([^)]*"
        r"(?:INBOUND_LOCALSTORAGE_KEY|COLD_LOCALSTORAGE_KEY"
        r"|['\"]inboundActiveSwapId['\"]|['\"]coldActiveSwapId['\"])",
        text,
    )
    assert not offending, (
        "dashboard.js still calls localStorage for swap-state keys; "
        " requires sessionStorage instead. Offending matches: "
        f"{offending}"
    )


def test_swap_state_session_storage_calls_present():
    """Sanity check: the migration didn't silently remove all
    persistence (which would break refresh-resume)."""
    text = _dashboard_js_text()
    inbound_writes = _re.findall(
        r"sessionStorage\.(?:set|get|remove)Item\(\s*INBOUND_LOCALSTORAGE_KEY",
        text,
    )
    cold_writes = _re.findall(
        r"sessionStorage\.(?:set|get|remove)Item\(\s*COLD_LOCALSTORAGE_KEY",
        text,
    )
    assert inbound_writes, "INBOUND_LOCALSTORAGE_KEY no longer pinned to sessionStorage"
    assert cold_writes, "COLD_LOCALSTORAGE_KEY no longer pinned to sessionStorage"


def test_channel_inbound_swap_state_uses_session_storage_not_local_storage():
    """The per-channel "Open Inbound" swap pin is ephemeral swap
    state, so it lives in ``sessionStorage`` like the other swap
    pins — never ``localStorage``."""
    text = _dashboard_js_text()
    offending = _re.findall(
        r"localStorage\.(?:set|get|remove)Item\([^)]*"
        r"(?:CHANNEL_INBOUND_LOCALSTORAGE_KEY|['\"]chInboundActiveSwap['\"])",
        text,
    )
    assert not offending, (
        "dashboard.js uses localStorage for the per-channel swap pin; "
        f"it must use sessionStorage. Offending matches: {offending}"
    )


def test_channel_inbound_swap_state_session_storage_calls_present():
    """The per-channel swap pin is persisted (so a mid-swap refresh
    resumes the progress view) and read back on init."""
    text = _dashboard_js_text()
    calls = _re.findall(
        r"sessionStorage\.(?:set|get|remove)Item\(\s*CHANNEL_INBOUND_LOCALSTORAGE_KEY",
        text,
    )
    assert calls, "CHANNEL_INBOUND_LOCALSTORAGE_KEY is not pinned to sessionStorage"


def test_onboarding_skipped_remains_in_local_storage():
    """``onboardingSkipped`` deliberately stays in ``localStorage``
    so a dismissed wizard does not pop back up on every new tab —
     is scoped to *ephemeral swap state*, not user preferences."""
    text = _dashboard_js_text()
    assert "localStorage.getItem('onboardingSkipped')" in text or 'localStorage.getItem("onboardingSkipped")' in text, (
        "onboardingSkipped should remain a localStorage-backed preference (it is not ephemeral swap state)"
    )
