# SPDX-License-Identifier: MIT
"""Behaviour tests for the Tor Health panel's plain-language verdict.

The ``torHealthSummary`` getter and ``_torHealthAggregateState`` live in
``app/dashboard/static/dashboard.js``. As with the other dashboard
JS-mirror suites, we translate the pure logic into Python so the
non-technical verdict (ok / reconnecting / problem) is exercised in CI.

Keep these mirrors in sync with the JS.
"""

from __future__ import annotations

from typing import Optional


def tor_aggregate_state(d: dict) -> Optional[str]:
    rank = {"closed": 0, "half_open": 1, "open": 2}
    candidates = [d.get("tor_breaker_state")]
    if d.get("tor_split_mode_enabled"):
        candidates.append(d.get("tor_lnd_breaker_state"))
    worst, worst_rank = None, -1
    for s in candidates:
        r = rank.get(s)
        if r is None:
            continue
        if r > worst_rank:
            worst, worst_rank = s, r
    return worst


def tor_health_tone(d: Optional[dict]) -> Optional[str]:
    """Mirror of ``torHealthSummary`` → just the tone."""
    if not d:
        return None
    worst = tor_aggregate_state(d) or "closed"
    boot = d.get("bootstrap_progress")
    boot_known = boot is not None
    not_bootstrapped = boot_known and float(boot) < 100
    circuit_down = d.get("circuit_established") is False
    network_down = d.get("network_liveness") == "down"
    if worst == "open" or circuit_down or network_down:
        return "down"
    if worst == "half_open" or not_bootstrapped:
        return "warn"
    return "ok"


def _healthy(**over) -> dict:
    d = {
        "tor_breaker_state": "closed",
        "circuit_established": True,
        "network_liveness": "up",
        "bootstrap_progress": 100,
    }
    d.update(over)
    return d


class TestTorHealthVerdict:
    def test_none_data_is_none(self):
        assert tor_health_tone(None) is None

    def test_all_good_is_ok(self):
        assert tor_health_tone(_healthy()) == "ok"

    def test_open_breaker_is_down(self):
        assert tor_health_tone(_healthy(tor_breaker_state="open")) == "down"

    def test_circuit_not_established_is_down(self):
        assert tor_health_tone(_healthy(circuit_established=False)) == "down"

    def test_network_down_is_down(self):
        assert tor_health_tone(_healthy(network_liveness="down")) == "down"

    def test_half_open_is_warn(self):
        assert tor_health_tone(_healthy(tor_breaker_state="half_open")) == "warn"

    def test_partial_bootstrap_is_warn(self):
        assert tor_health_tone(_healthy(bootstrap_progress=60)) == "warn"

    def test_unknown_values_do_not_penalise(self):
        # null bootstrap / "unknown" liveness / null circuit with a closed
        # breaker should read as OK, not a false alarm.
        assert tor_health_tone(_healthy(bootstrap_progress=None, network_liveness="unknown", circuit_established=None)) == "ok"

    def test_split_mode_uses_worst_pool(self):
        d = _healthy(tor_split_mode_enabled=True, tor_breaker_state="closed", tor_lnd_breaker_state="open")
        assert tor_health_tone(d) == "down"

    def test_split_mode_half_open_pool_is_warn(self):
        d = _healthy(tor_split_mode_enabled=True, tor_breaker_state="closed", tor_lnd_breaker_state="half_open")
        assert tor_health_tone(d) == "warn"
