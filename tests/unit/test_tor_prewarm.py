# SPDX-License-Identifier: MIT
"""HS descriptor pre-warm tests.

Pins:
  - The candidate URL list dedupes by (host, port) and skips
    clearnet entries (only .onion URLs trigger descriptor fetch).
  - The total-budget timeout is respected — slow probes don't
    extend startup beyond the cap.
  - Failures are non-fatal — a single broken onion doesn't poison
    the whole batch.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from app.services.tor_prewarm import (
    _collect_known_onions,
    prewarm_known_onions,
)

# ── URL collection ────────────────────────────────────────────────


def test_collects_onion_urls_only(monkeypatch) -> None:
    """A mix of clearnet + onion URLs must surface ONLY the .onions
    — clearnet endpoints don't need pre-warm (no HS descriptor)."""
    monkeypatch.setattr(
        "app.core.config.settings.lnd_rest_url",
        "https://lnd.local:8080",  # clearnet
    )
    monkeypatch.setattr(
        "app.core.config.settings.boltz_onion_url",
        "http://boltzzzbnus4m7mta3cxmflnps4fp7dueu2tgurstbvrbt6xswzcocyd.onion/api/v2",
    )
    monkeypatch.setattr(
        "app.core.config.settings.boltz_submarine_onion_url",
        "",
    )
    monkeypatch.setattr(
        "app.core.config.settings.boltz_reverse_onion_url",
        "",
    )
    onions = _collect_known_onions()
    assert any(".onion" in u for u in onions)
    assert not any("lnd.local" in u for u in onions)


def test_collects_dedupes_by_host_port(monkeypatch) -> None:
    """Two settings pointing at the same .onion:port must
    deduplicate — pre-warming twice is wasted work."""
    onion = "http://boltzzzbnus4m7mta3cxmflnps4fp7dueu2tgurstbvrbt6xswzcocyd.onion/api/v2"
    monkeypatch.setattr(
        "app.core.config.settings.lnd_rest_url",
        "https://lnd.local:8080",
    )
    monkeypatch.setattr(
        "app.core.config.settings.boltz_onion_url",
        onion,
    )
    monkeypatch.setattr(
        "app.core.config.settings.boltz_submarine_onion_url",
        onion,
    )
    monkeypatch.setattr(
        "app.core.config.settings.boltz_reverse_onion_url",
        onion,
    )
    # Force empty operator registry so the test isn't sensitive to
    # the on-disk file state.
    with patch(
        "app.services.anonymize.operators.load_operator_registry",
        return_value=[],
    ):
        onions = _collect_known_onions()
    # Three settings pointed at the same (host, port) — must collapse
    # to one entry.
    assert len(onions) == 1


def test_collects_skips_empty_settings(monkeypatch) -> None:
    """Empty strings (unset overrides) must not show up as
    candidates — would cause a urlparse to ".onion"-less URLs."""
    monkeypatch.setattr(
        "app.core.config.settings.lnd_rest_url",
        "",
    )
    monkeypatch.setattr(
        "app.core.config.settings.boltz_onion_url",
        "",
    )
    monkeypatch.setattr(
        "app.core.config.settings.boltz_submarine_onion_url",
        "",
    )
    monkeypatch.setattr(
        "app.core.config.settings.boltz_reverse_onion_url",
        "",
    )
    with patch(
        "app.services.anonymize.operators.load_operator_registry",
        return_value=[],
    ):
        onions = _collect_known_onions()
    assert onions == []


# ── Prewarm execution ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_returns_empty_when_no_onions_configured(monkeypatch) -> None:
    """No candidates → empty result dict, no network calls."""
    with patch(
        "app.services.tor_prewarm._collect_known_onions",
        return_value=[],
    ):
        result = await prewarm_known_onions()
    assert result == {}


@pytest.mark.asyncio
async def test_partial_failure_is_non_fatal() -> None:
    """One URL succeeds, one fails — the whole batch still returns
    with per-URL outcomes."""
    urls = [
        "http://aaa.onion/",
        "http://bbb.onion/",
    ]

    async def fake_prewarm(url):
        # First URL OK, second URL fail.
        if "aaa" in url:
            return (url, True, None)
        return (url, False, "connect timeout")

    with (
        patch(
            "app.services.tor_prewarm._collect_known_onions",
            return_value=urls,
        ),
        patch(
            "app.services.tor_prewarm._prewarm_one",
            side_effect=fake_prewarm,
        ),
    ):
        result = await prewarm_known_onions()

    assert result["http://aaa.onion/"] is True
    assert result["http://bbb.onion/"] is False


@pytest.mark.asyncio
async def test_overall_budget_caps_runtime() -> None:
    """A probe that hangs past the budget must NOT block startup.
    Anything that didn't finish within budget is reported as
    ``False`` (best-effort)."""
    urls = ["http://aaa.onion/"]

    async def slow_prewarm(_url):
        # Sleep way past the budget.
        await asyncio.sleep(60)
        return ("http://aaa.onion/", True, None)

    # Patch the budget to a tiny window so the test is fast.
    with (
        patch(
            "app.services.tor_prewarm._collect_known_onions",
            return_value=urls,
        ),
        patch(
            "app.services.tor_prewarm._PREWARM_BUDGET_S",
            0.2,
        ),
        patch(
            "app.services.tor_prewarm._prewarm_one",
            slow_prewarm,
        ),
    ):
        result = await prewarm_known_onions()

    # The slow probe got cancelled → reported False.
    assert result["http://aaa.onion/"] is False
