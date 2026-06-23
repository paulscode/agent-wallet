# SPDX-License-Identifier: MIT
"""Regression guards for dashboard request resilience.

Pins these contracts:

* Default read timeout — ``api()`` applies a DEFAULT timeout to
  idempotent reads (method-aware), with a key-presence opt-out, and
  NO default on mutations.
* Guarded poller — a reusable poller (``_poll``/``_stopPoll``) with an
  in-flight guard, and every network poller migrated onto it.
* Per-section degradation UX — per-section load-error state + a
  "Retry" affordance for the ``fetchAll`` stragglers (channels /
  payments / transactions).
* Rate-limited detail advance — the braiins detail-read ``advance()``
  is rate-limited per session (server-side; tested directly).

The JS guards are regex-against-source (the SPA isn't headless-testable
here) so a silent refactor that drops a guard is caught.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_DASH_JS = _REPO / "app" / "dashboard" / "static" / "dashboard.js"
_DASH_HTML = _REPO / "app" / "dashboard" / "templates" / "dashboard.html"


def _js() -> str:
    return _DASH_JS.read_text(encoding="utf-8")


def _html() -> str:
    return _DASH_HTML.read_text(encoding="utf-8")


# ── default read timeout ──────────────────────────────────────────────


def test_default_read_timeout_constant_exists() -> None:
    assert re.search(r"const\s+DEFAULT_READ_TIMEOUT_MS\s*=\s*\d+", _js()), (
        "DEFAULT_READ_TIMEOUT_MS constant must define the read default"
    )


def test_apisend_applies_method_aware_default_with_keypresence_optout() -> None:
    """``_apiSend`` must apply the default ONLY to non-mutating methods,
    and decide via key PRESENCE (so ``timeoutMs: 0`` opts a read out)."""
    js = _js()
    m = re.search(
        r"async\s+_apiSend\s*\([^)]*\)\s*\{(?P<body>.+?)\n\s{8}\},",
        js,
        re.DOTALL,
    )
    assert m, "_apiSend() body not found"
    body = m.group("body")
    # Key-presence check (not truthiness) so 0 is distinguishable.
    assert "hasOwnProperty" in body and "timeoutMs" in body, (
        "default must branch on whether opts supplied timeoutMs (key presence), not its truthiness"
    )
    # Method-aware: default only for reads.
    assert "_isMutatingMethod(method)" in body, "default must be gated on a method check so mutations get none"
    assert "DEFAULT_READ_TIMEOUT_MS" in body, "the read default must be applied in _apiSend"


# ── guarded poller utility + migrations ───────────────────────────────


def test_poll_utility_exists_with_inflight_guard() -> None:
    js = _js()
    assert re.search(r"_poll\s*\(\s*key\s*,\s*fn\s*,\s*opts\s*\)", js), "_poll(key, fn, opts) utility must exist"
    assert "_stopPoll(key)" in js, "_stopPoll(key) must exist"
    # The guard: skip a tick while the previous run is still in flight.
    m = re.search(r"_poll\s*\([^)]*\)\s*\{(?P<body>.+?)\n\s{8}\},", js, re.DOTALL)
    assert m and "inFlight" in m.group("body"), "_poll must keep an in-flight flag to skip overlapping ticks"


# Every network poller must go through ``_poll`` with its stable key.
# Missing one means that feature can pile up again.
_EXPECTED_POLL_KEYS = (
    "summary",
    "activity",
    "channels",
    "anonymizeClock",
    "anonymizeSessions",
    "recvInvoice",
    "coldSwap",
    "onboarding",
    "inboundSwap",
    "braiinsQuotes",
    "braiinsDetail",
)


@pytest.mark.parametrize("key", _EXPECTED_POLL_KEYS)
def test_network_poller_goes_through_poll(key: str) -> None:
    assert f"_poll('{key}'" in _js(), (
        f"network poller '{key}' must be migrated onto _poll (in-flight guard + default timeout)"
    )


def test_per_tx_confirmation_poll_uses_poll() -> None:
    # Keyed per-txid, so assert the key prefix form.
    assert "_poll('txconf:'" in _js(), "per-tx confirmation poll must go through _poll keyed by txid"


def test_no_unguarded_setinterval_for_migrated_network_pollers() -> None:
    """The migrated fetch loops must not be re-introduced as raw
    ``setInterval`` calls. Allowed setIntervals are local-only timers
    (countdowns / clipboard) and the ``_poll`` utility itself."""
    js = _js()
    # Grab the argument of each setInterval( ... call's first line.
    offenders = []
    for m in re.finditer(r"setInterval\(([^\n]*)", js):
        frag = m.group(1)
        # The _poll internal timer + local countdown/clipboard timers
        # are fine; flag anything that looks like it fetches.
        if re.search(r"fetch[A-Z]|pollSwapStatus|RefreshClock|Poll", frag):
            offenders.append(frag.strip())
    assert not offenders, f"network pollers must use _poll, not raw setInterval: {offenders}"


# ── per-section degradation UX ────────────────────────────────────────


@pytest.mark.parametrize(
    "field,fetch_fn",
    [
        ("channelsError", "fetchChannels"),
        ("paymentsError", "fetchPayments"),
        ("transactionsError", "fetchTransactions"),
    ],
)
def test_section_has_error_state_and_retry(field: str, fetch_fn: str) -> None:
    js = _js()
    html = _html()
    # State field declared + cleared/set by the fetch fn.
    assert f"{field}:" in js, f"{field} state field must be declared"
    fn = re.search(rf"async\s+{fetch_fn}\(\)\s*\{{(?P<b>.+?)}}\s*,", js, re.DOTALL)
    assert fn, f"{fetch_fn}() not found"
    assert field in fn.group("b"), (
        f"{fetch_fn}() must set/clear {field} so a poll refresh failure "
        f"surfaces a per-section error (not just initial load)"
    )
    # Template: an error block + a Retry button bound to the fetch fn.
    assert field in html, f"{field} must gate a template error block"
    assert f"{fetch_fn}()" in html, (
        f"a Retry affordance must call {fetch_fn}() so the user can recover a failed section without a full reload"
    )


# ── rate-limited detail advance (server) ──────────────────────────────


def test_should_advance_braiins_detail_throttles_within_window(monkeypatch):
    from app.dashboard import api as dash_api

    monkeypatch.setattr(
        dash_api.settings,
        "braiins_deposit_detail_advance_min_interval_s",
        3,
    )
    dash_api._BRAIINS_DETAIL_ADVANCE_LAST.clear()
    sid = "sess-throttle-1"
    # First read: advance.
    assert dash_api._should_advance_braiins_detail(sid, now=100.0) is True
    # Within the 3 s window: skip.
    assert dash_api._should_advance_braiins_detail(sid, now=101.0) is False
    assert dash_api._should_advance_braiins_detail(sid, now=102.9) is False
    # Past the window: advance again.
    assert dash_api._should_advance_braiins_detail(sid, now=103.0) is True
    # ...and the new timestamp re-arms the throttle.
    assert dash_api._should_advance_braiins_detail(sid, now=104.0) is False


def test_should_advance_braiins_detail_is_per_session(monkeypatch):
    from app.dashboard import api as dash_api

    monkeypatch.setattr(
        dash_api.settings,
        "braiins_deposit_detail_advance_min_interval_s",
        3,
    )
    dash_api._BRAIINS_DETAIL_ADVANCE_LAST.clear()
    # Different sessions don't throttle each other.
    assert dash_api._should_advance_braiins_detail("a", now=100.0) is True
    assert dash_api._should_advance_braiins_detail("b", now=100.0) is True


def test_should_advance_braiins_detail_disabled_when_interval_zero(monkeypatch):
    from app.dashboard import api as dash_api

    monkeypatch.setattr(
        dash_api.settings,
        "braiins_deposit_detail_advance_min_interval_s",
        0,
    )
    dash_api._BRAIINS_DETAIL_ADVANCE_LAST.clear()
    sid = "sess-disabled"
    # interval 0 → never throttle.
    assert dash_api._should_advance_braiins_detail(sid, now=100.0) is True
    assert dash_api._should_advance_braiins_detail(sid, now=100.0) is True
