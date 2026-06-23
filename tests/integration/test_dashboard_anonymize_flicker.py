# SPDX-License-Identifier: MIT
"""Regression tests for Anonymize UI flicker/flash fixes.

Two unrelated flash patterns existed in the Anonymize tab and both
shipped to production for a long time before being caught:

1. **Calibrating-banner flash on first wizard open.** The
   ``anonymizeClockStatus`` state defaulted to ``'unknown'`` so the
   "Calibrating time sync…" amber banner appeared the instant the
   wizard mounted — even when the user's clock was perfectly
   healthy. The banner persisted for the duration of the Tor-routed
   ``/anonymize/policy`` fetch (2–10 s on cold circuits), then
   disappeared once a real status arrived. Fix: gate the banner on
   ``anonymizePolicyLoaded`` so it only shows after the first policy
   fetch resolves with a non-decisive status.

2. **Sessions-list "Loading…" flash on tab re-entry.** The watcher
   for ``activeTab === 'anonymize'`` re-fetched the sessions list
   non-silently on every tab activation. Re-entering the tab with
   already-populated rows briefly replaced them with the loading
   spinner. Fix: a new ``anonymizeSessionsHydrated`` flag tracks
   whether a successful fetch has landed; the watcher passes
   ``silent: true`` after the first hydration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import settings
from app.dashboard.auth import COOKIE_NAME

from .test_dashboard import _make_session_cookie, dashboard_client  # noqa: F401

_DASHBOARD_JS = Path(__file__).resolve().parents[2] / ("app/dashboard/static/dashboard.js")


@pytest.fixture(autouse=True)
def _set_dashboard_token():
    original = settings.dashboard_token
    settings.dashboard_token = "test-dashboard-token"
    yield
    settings.dashboard_token = original


@pytest.fixture(scope="module")
def dashboard_js() -> str:
    # The dashboard.js source is what carries the watcher + the
    # ``anonymizeFetchSessions`` body. dashboard.html only carries
    # the templates that bind to those identifiers.
    return _DASHBOARD_JS.read_text(encoding="utf-8")


class TestAnonymizeFlickerTemplate:
    """Pin the Anonymize tab's flicker-prevention wires in the
    rendered HTML template."""

    @pytest.fixture
    def auth_cookies(self, dashboard_client):
        cookie = _make_session_cookie()
        dashboard_client.cookies.set(COOKIE_NAME, cookie)
        return {COOKIE_NAME: cookie}

    @pytest.mark.asyncio
    async def test_calibrating_banner_gated_on_policy_loaded(self, dashboard_client, auth_cookies):
        # The calibrating banner's x-show MUST require
        # ``anonymizePolicyLoaded`` so the amber banner doesn't flash
        # while the initial Tor-routed /anonymize/policy fetch is
        # still in flight. Without this gate, the default
        # ``anonymizeClockStatus = 'unknown'`` matched the banner
        # condition and showed for the duration of the fetch (2–10 s
        # on cold Tor circuits) even when the user's clock was
        # healthy.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        gated = (
            'x-show="anonymizePolicyLoaded && anonymizeTorBootstrapReady '
            "&& (anonymizeClockStatus === 'unknown' || "
            "anonymizeClockStatus === 'warming_up')\""
        )
        assert gated in html, (
            "Calibrating-banner x-show must include "
            "``anonymizePolicyLoaded`` so it doesn't flash before "
            "the first /anonymize/policy fetch resolves."
        )

    @pytest.mark.asyncio
    async def test_other_clock_banners_remain_gated_on_status(self, dashboard_client, auth_cookies):
        # The "unhealthy" banners and the "refreshing time check"
        # indicator all gate on specific clockStatus values that the
        # default ``'unknown'`` doesn't match. Pin those wires so a
        # future "simplify the gating" refactor can't accidentally
        # remove the status discrimination and re-introduce a
        # default-visible flash.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert ("anonymizeClockStatus === 'unhealthy' && anonymizeClockSkewMs != null") in html, (
            "Unhealthy-with-skew banner must gate on the unhealthy "
            "status so the default 'unknown' state doesn't flash a "
            "red banner on wizard open."
        )
        assert ("anonymizeClockStatus === 'unhealthy' && anonymizeClockSkewMs == null") in html, (
            "Unhealthy-without-skew banner must gate on the "
            "unhealthy status so the default 'unknown' state doesn't "
            "flash a red banner on wizard open."
        )
        assert (
            "anonymizeClockWarmupCompletesAt != null "
            "&& (anonymizeClockStatus === 'healthy' "
            "|| anonymizeClockStatus === 'unhealthy')"
        ) in html, (
            "Refreshing-indicator must gate on warmupCompletesAt + "
            "a decisive status so the default state (both falsy) "
            "doesn't flash the refresh spinner on wizard open."
        )

    @pytest.mark.asyncio
    async def test_no_sessions_message_gated_on_loading(self, dashboard_client, auth_cookies):
        # Pin the existing gating for the "No anonymize sessions yet"
        # message. The three-way guard (length === 0 && !loading &&
        # !error) is what keeps the message from flashing during the
        # initial fetch window.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert ("anonymizeSessions.length === 0 && !anonymizeSessionsLoading && !anonymizeSessionsError") in html, (
            "The 'No anonymize sessions yet' message must remain "
            "gated on (empty && !loading && !error) to avoid a "
            "flash during the initial fetch."
        )

    @pytest.mark.asyncio
    async def test_tor_bootstrap_banner_template_gated_on_negation(self, dashboard_client, auth_cookies):
        # The Tor banner gates on ``!anonymizeTorBootstrapReady`` so
        # the default true value keeps it hidden. A regression that
        # inverted the x-show would re-introduce a flash.
        resp = await dashboard_client.get("/dashboard/")
        html = resp.text
        assert 'x-show="!anonymizeTorBootstrapReady"' in html, (
            "Tor-bootstrap banner must gate on "
            "``!anonymizeTorBootstrapReady`` so the default true "
            "value keeps the banner hidden on initial render."
        )


class TestAnonymizeFlickerJsState:
    """Pin the JS-side state and watcher behaviour. The template
    tests above cover x-show wires; these tests cover the dashboard.js
    state defaults + the watcher's silent-on-rehydrate call shape."""

    def test_sessions_hydrated_default_false(self, dashboard_js):
        # The flag must default to false so the very first activation
        # (no data yet) still surfaces "Loading…" while the fetch is
        # in flight. Flipping it to true would silently swallow that
        # initial feedback.
        assert "anonymizeSessionsHydrated: false" in dashboard_js, (
            "``anonymizeSessionsHydrated`` must default to false so the first fetch still surfaces the Loading spinner."
        )

    def test_sessions_hydrated_flag_set_on_success(self, dashboard_js):
        # The flag is set inside the try-block of
        # ``anonymizeFetchSessions`` so a failed fetch doesn't
        # accidentally enable the silent-mode optimization (which
        # would hide the "Loading…" feedback for users whose first
        # fetch errored).
        assert "this.anonymizeSessionsHydrated = true" in dashboard_js, (
            "anonymizeFetchSessions must set "
            "``anonymizeSessionsHydrated = true`` on success so "
            "subsequent tab re-activations can refetch silently."
        )

    def test_tab_watcher_uses_silent_on_rehydrate(self, dashboard_js):
        # The activeTab watcher passes ``silent`` based on the
        # hydrated flag so re-activating the tab doesn't replace
        # already-populated rows with "Loading…". The un-fixed form
        # was ``anonymizeFetchSessions()`` with no args.
        assert (
            "anonymizeFetchSessions(\n"
            "                        {silent: this.anonymizeSessionsHydrated},\n"
            "                    )"
        ) in dashboard_js, (
            "Tab watcher must pass "
            "``{silent: this.anonymizeSessionsHydrated}`` so the "
            "sessions list doesn't flash 'Loading…' on tab re-entry."
        )

    def test_clock_status_default_unknown(self, dashboard_js):
        # Pin the default. The whole reason the calibrating-banner
        # gating is needed is because the default matches the
        # banner's x-show condition. If a future change flipped the
        # default to ``'healthy'`` the gating would still be
        # protective — but pin the default so the protection
        # contract stays explicit.
        assert "anonymizeClockStatus: 'unknown'" in dashboard_js, (
            "Default ``anonymizeClockStatus`` must be ``'unknown'`` "
            "so the calibrating-banner gate on "
            "``anonymizePolicyLoaded`` carries its load."
        )

    def test_tor_bootstrap_default_true(self, dashboard_js):
        # Default true means the Tor banner is hidden until a fetch
        # reports a negative result. Flipping this to false would
        # re-introduce a default-visible flash.
        assert "anonymizeTorBootstrapReady: true" in dashboard_js, (
            "Default ``anonymizeTorBootstrapReady`` must be ``true`` "
            "so the Tor banner is hidden until a fetch returns a "
            "negative result."
        )
