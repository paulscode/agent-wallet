# SPDX-License-Identifier: MIT
"""Tor metrics endpoint shape + render tests.

The metrics endpoint must:
  - Render valid Prometheus text format (# HELP / # TYPE / value).
  - Use a stable label set across scrapes (failed probes → -1
    sentinel, never a missing metric).
  - Map breaker state strings to numeric gauge values.

The JSON status endpoint mirrors the metrics endpoint's underlying
probes; we cover the rendering + the breaker-mapping helper here
and let the JSON endpoint be exercised via integration tests.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.api.tor_metrics import (
    _breaker_state_to_gauge,
    _render,
)

# ── _render output shape ──────────────────────────────────────────


def test_render_emits_help_type_and_value_lines() -> None:
    out = _render(
        [
            ("tor_bootstrap_progress", "Tor bootstrap %", "gauge", 100),
            ("tor_active_circuits", "Number of active circuits.", "gauge", 7),
        ]
    )
    lines = out.strip().splitlines()
    # Each metric → 3 lines (HELP + TYPE + value).
    assert lines[0] == "# HELP tor_bootstrap_progress Tor bootstrap %"
    assert lines[1] == "# TYPE tor_bootstrap_progress gauge"
    assert lines[2] == "tor_bootstrap_progress 100"
    assert lines[3] == "# HELP tor_active_circuits Number of active circuits."
    assert lines[5] == "tor_active_circuits 7"


def test_render_integer_valued_gauges_print_without_decimal() -> None:
    """Prometheus is permissive about floats but the integer form is
    cleaner for human inspection. Integers stay integer-shaped."""
    out = _render([("test_metric", "h", "gauge", 42.0)])
    assert "test_metric 42\n" in out
    assert "test_metric 42.0\n" not in out


def test_render_handles_float_values() -> None:
    out = _render([("test_metric", "h", "gauge", 3.14)])
    assert "test_metric 3.14\n" in out


def test_render_ends_with_trailing_newline() -> None:
    """Prometheus exposition format requires a trailing newline; some
    parsers reject a metric block that doesn't end with \\n."""
    out = _render([("a", "h", "gauge", 1)])
    assert out.endswith("\n")


# ── _breaker_state_to_gauge mapping ───────────────────────────────


def test_breaker_state_closed_is_zero() -> None:
    assert _breaker_state_to_gauge("closed") == 0


def test_breaker_state_half_open_is_one() -> None:
    assert _breaker_state_to_gauge("half_open") == 1


def test_breaker_state_open_is_two() -> None:
    assert _breaker_state_to_gauge("open") == 2


def test_breaker_state_unknown_is_negative_one() -> None:
    """The -1 sentinel signals "state not understood" to scrapers
    without dropping the metric (which would change the label set)."""
    assert _breaker_state_to_gauge("mystery_state") == -1


# ── Probe cache: repeated scrapes don't hammer Tor ────────────────


@pytest.mark.asyncio
async def test_cached_probes_reuses_within_ttl() -> None:
    """Within _PROBE_CACHE_TTL_S the helper must return the cached
    result without re-probing Tor — Prometheus scrapes can land
    several per second during incidents and the control port is
    rate-limited."""
    # Pre-seed cache with a fresh entry.
    import time

    import app.api.tor_metrics as mod

    mod._cache.clear()
    mod._cache.update(
        {
            "ts": time.monotonic(),
            "boot": "seeded",
            "circuits": [],
            "guards": [],
            "net_live": True,
        }
    )

    # No probes should run while the cache is hot.
    with (
        patch("app.services.anonymize.tor.probe_tor_bootstrap_status") as boot_probe,
        patch("app.services.anonymize.tor.probe_tor_circuit_status") as circ_probe,
    ):
        result = await mod._cached_probes()

    assert result["boot"] == "seeded"
    boot_probe.assert_not_called()
    circ_probe.assert_not_called()


@pytest.mark.asyncio
async def test_cached_probes_repopulates_after_ttl_expires() -> None:
    """After the TTL elapses the next scrape re-probes Tor and
    rewrites the cache."""
    import time

    import app.api.tor_metrics as mod

    mod._cache.clear()
    # Backdate the cache so the TTL is expired.
    mod._cache.update(
        {
            "ts": time.monotonic() - (mod._PROBE_CACHE_TTL_S + 1),
            "boot": "stale",
            "circuits": [],
            "guards": [],
            "net_live": None,
        }
    )

    from unittest.mock import AsyncMock

    with (
        patch(
            "app.services.anonymize.tor.probe_tor_bootstrap_status",
            AsyncMock(return_value="fresh"),
        ),
        patch(
            "app.services.anonymize.tor.probe_tor_circuit_status",
            AsyncMock(return_value=([], None)),
        ),
        patch(
            "app.services.anonymize.tor.probe_entry_guards",
            AsyncMock(return_value=([], None)),
        ),
        patch(
            "app.services.anonymize.tor.probe_network_liveness",
            AsyncMock(return_value=(True, None)),
        ),
    ):
        result = await mod._cached_probes()

    assert result["boot"] == "fresh"


def test_newnym_total_is_a_real_counter_not_a_gauge() -> None:
    """``tor_newnym_total`` is declared as a counter
    by the renderer; it must INCREMENT per successful
    NEWNYM emission, not flip 1/0 from a "has fired at least
    once" indicator."""
    from app.api.tor_metrics import _newnym_total_across_pools
    from app.services.tor_watchdog import _STATE, _STATE_LND

    # Reset both pool counters.
    _STATE.newnym_fired_total = 0
    _STATE_LND.newnym_fired_total = 0

    # Bump each by a different amount — the metric should sum.
    _STATE.newnym_fired_total = 3
    _STATE_LND.newnym_fired_total = 5
    assert _newnym_total_across_pools() == 8


def test_sighup_total_is_a_real_counter_not_a_gauge() -> None:
    """Mirror of the NEWNYM counter test."""
    from app.api.tor_metrics import _sighup_total_across_pools
    from app.services.tor_watchdog import _STATE, _STATE_LND

    _STATE.sighup_fired_total = 0
    _STATE_LND.sighup_fired_total = 0
    _STATE.sighup_fired_total = 2
    _STATE_LND.sighup_fired_total = 1
    assert _sighup_total_across_pools() == 3


def test_per_listener_metric_uses_plan_specified_name_and_label() -> None:
    """The per-listener metric is documented as
    ``tor_listener_socks_round_trip_success{listener,port}``.
    Operators building Prometheus dashboards
    must find the metric under THAT exact name + label key. This
    test pins the contract so a future renaming has to update
    the documented name and the code together."""
    from unittest.mock import patch

    from app.api.tor_metrics import _render_per_listener_metrics

    fake_snap = {
        "boltz_submarine": {
            "port": 9050,
            "ok": True,
            "last_probe_age_s": 12,
            "last_error": None,
        },
        "boltz_reverse": {
            "port": 9051,
            "ok": False,
            "last_probe_age_s": 30,
            "last_error": "boom",
        },
    }
    with patch(
        "app.services.tor_per_listener_probe.get_snapshot",
        return_value=fake_snap,
    ):
        text = _render_per_listener_metrics()

    # Documented metric name.
    assert "tor_listener_socks_round_trip_success" in text, (
        "metric name must match the documented identifier — operators built "
        "Prometheus dashboards against this name and will scrape "
        "this exact identifier."
    )
    # Documented label key.
    assert 'listener="boltz_submarine"' in text, (
        "label key must be ``listener`` (not ``name``) to match "
        "the documented contract. PromQL queries would silently "
        "return empty if the label key differs."
    )
    assert 'port="9050"' in text
    # And the legacy name MUST be gone.
    assert "tor_listener_ok" not in text, (
        "the pre.15-alignment name ``tor_listener_ok`` was "
        "renamed; if this assertion fires, both names are present "
        "and downstream consumers might pin the wrong one."
    )


@pytest.mark.asyncio
async def test_cached_probes_swallows_probe_failures() -> None:
    """A probe that raises must NOT propagate — the metrics endpoint
    has to return a body even when Tor is wedged (so Prometheus can
    record the -1 sentinel)."""
    import app.api.tor_metrics as mod

    mod._cache.clear()

    from unittest.mock import AsyncMock

    with (
        patch(
            "app.services.anonymize.tor.probe_tor_bootstrap_status",
            AsyncMock(side_effect=RuntimeError("control port down")),
        ),
        patch(
            "app.services.anonymize.tor.probe_tor_circuit_status",
            AsyncMock(side_effect=RuntimeError("control port down")),
        ),
        patch(
            "app.services.anonymize.tor.probe_entry_guards",
            AsyncMock(side_effect=RuntimeError("control port down")),
        ),
        patch(
            "app.services.anonymize.tor.probe_network_liveness",
            AsyncMock(side_effect=RuntimeError("control port down")),
        ),
    ):
        result = await mod._cached_probes()

    # All probes failed → all values None/empty, but no exception escapes.
    assert result["boot"] is None
    assert result["circuits"] == []
    assert result["guards"] == []
    assert result["net_live"] is None
